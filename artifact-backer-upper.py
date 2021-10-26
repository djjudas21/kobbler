#!/usr/bin/env python
import os, sys, logging, argparse, tarfile, socket, subprocess, shutil, traceback
from datetime import datetime
from logging.handlers import RotatingFileHandler
from S3Utils import S3Backup
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import secrets
import pyAesCrypt

logger = None

'''
    NAME: artifact-backer-upper
    AUTHOR: Terry Hurcombe <terry.hurcombe@fasthosts.com>
    DESCRIPTION:

    A python script to invoke etcd backups and upload the resulting archive to an S3 bucket.

    S3 credentials are read from the shared credentials file, see https://boto3.amazonaws.com/v1/documentation/api/latest/guide/configuration.html

    Backup archive lifecycle is managed by S3 BucketLifecycle policy. 

    Upon a successful backup and upload, node-exporter is updated to reflect the current epoch. This data is available under the metric last_artifact_backup

    The script utilises a rotating logfile handler, logs can be found at /var/log/artifact-backer-upper.log, to increase the loglevel, specify --loglevel
    parameter (see --help for more detail), be aware that DEBUG is very verbose as it debugs boto3 calls to S3

    Typically the script can be run without passing any command line arguments as sane defaults are set, see --help for more information.

    The script provides methods to list (--list) existing backup archives and manual removal (--remove) of archives from the S3 bucket, see --help for more detail

    The script will run under both python2 and python3, python2 lacks SNI support so SSL verification is automatcially disabled when running under python2, this
    will generate lots of InsecureRequestWarnings.

'''

'''
  CONFIG PARAM: SSL_VERIFY

  Boolean denoting whether or not we verify SSL at the S3 server. 
'''
SSL_VERIFY = True

''' 
  CONFIG PARAM: LOG_FILE

  The location of our log files

'''
LOG_FILE='/var/log/artifact-backer-upper.log'


'''
  CONFIG PARAM: MAX_LOGSIZE_BYTES

  The number of bytes a logfile can grow before it is rotated
'''
MAX_LOGSIZE_BYTES=512000


''' 
  CONFIG PARAM: MAX_LOG_FILES

  The number of logfiles to keep on disk

'''
MAX_LOG_FILES=5

# create a class that bases off S3Utils.S3Backup,
class BackupETCD(S3Backup):
    ETCDCTL_PORT=2379

    # instantiator, this must take at least the same args as S3Backup
    def __init__(self, **kwargs):
        # init the base class
        S3Backup.__init__(self, **kwargs)


    def create_etcd_snapshot(self, cacert, cert, key, etcd_api=3, hostname=socket.gethostname()):
        if not hostname:
            raise ValueError("Unable to determine this hosts name")
        
        filename = '/tmp/snapshot-{}.db'.format(datetime.now().strftime("%d-%m-%Y-%H.%M.%S"))
        
        self.logger.info("create etcd snapshot {}".format(filename))
        env = os.environ.copy()
        env["ETCDCTL_API"] = str(etcd_api)

        # this would be better done via python-etcd3 but will suffice for now
        out = subprocess.check_output(
            [
                '/usr/bin/etcdctl', 'snapshot', 'save', filename, 
                '--cacert={}'.format(cacert), '--cert={}'.format(cert), '--key={}'.format(key),
                '--endpoints=https://{}:{}'.format(hostname, BackupETCD.ETCDCTL_PORT)
            ],
            env=env
        )
        self.logger.debug(out)
        self.logger.debug("etcd snapshot created at {} ({} bytes)".format(filename, os.path.getsize(filename)))
        return filename


    def etcd_openshift_4(self):
        path = args.work_dir + '/artifact-backup'
        host_path = "/host{}".format(path)

        logging.info("Backup etcd type Openshift4, path={} host_path={}".format(path, host_path))

        shutil.rmtree(host_path, ignore_errors=True) 
        os.mkdir(host_path)

        env = os.environ.copy()

        out = subprocess.check_output(
            ['/usr/sbin/chroot', '/host', '/usr/local/bin/cluster-backup.sh', path],
            env=env
        )
        #shutil.move(host_path, path)
        logging.debug(out)
        return host_path


    def tar_backup_content(self, filename, sources):
        self.filename = filename
        logging.info("tarring backup to {} with content {}".format(filename, ",".join(sources)))
        tar = tarfile.open(self.filename, "w:gz")
        for item in sources:
            arcname = os.path.basename(item)
            tar.add(item, arcname=arcname)
        tar.close()
        logging.info("tarring complete.")
        self.status = True        
        return filename


def encrypt_blob(blob, public_key):
    ''' 
        encrypt_blob

        Encrypts a blob using an RSA public key
        Adapted from https://cryptobook.nakov.com/asymmetric-key-ciphers/rsa-encrypt-decrypt-examples
    '''
    #Import the Public Key and use for encryption using PKCS1_OAEP
    rsa_key = RSA.importKey(public_key)
    encryptor = PKCS1_OAEP.new(rsa_key)
    encrypted = encryptor.encrypt(blob)

    # return encrypted file
    return encrypted


def generate_otp():
    with open('/usr/share/dict/british-english') as f:
        words = [word.strip() for word in f]
    return '-'.join(secrets.choice(words) for i in range(8))


def encrypt_file_rsa(public_key, filename): 
    logging.info("Encrypt backup {} with key {}".format(filename,public_key))
    # Use the public key for encryption
    fd = open(public_key, "rb")
    public_key = fd.read()
    fd.close()

    #Our candidate file to be encrypted
    fd = open(filename, "rb")
    unencrypted_blob = fd.read()
    fd.close()

    encrypted_blob = encrypt_blob(unencrypted_blob, public_key)

    # overwrite the encrypted contents to a file
    encrypted_filename = filename + '.rsa'
    fd = open(encrypted_filename, "wb")
    fd.write(encrypted_blob)
    fd.close()

    logger.info("Encrypted {} as {}".format(filename, encrypted_filename))
    return encrypted_filename


def encrypt_file_aes(filename, otp):
    encrypted_filename = filename + '.aes'
    pyAesCrypt.encryptFile(filename, encrypted_filename, otp)
    logger.info("Encrypted {} as {}".format(filename, encrypted_filename))
    return encrypted_filename


def update_node_exporter(work_dir, collector_dir):
    ''' 
        update_node_exporter

        Writes the current epoch to a file for node-exporter. 

        In order to avoid node-exporter picking up a partially written file, the write is atomic
        being written to work_dir and then moved to the collector_dir after

        Required Args:
            work_dir (string)       - A temporary working directory
            collector_dir (string)  - The path node-exporters textcollector is configured to look at
    '''
    logger.info("Writing backup status for node-exporter")
    currentEpoch = int((datetime.now() - datetime(1970,1,1)).total_seconds())
    promData = [
        "# HELP last_artifact_backup epoch of the last successful etcd backup",
        "# TYPE last_artifact_backup counter",
        "last_artifact_backup{{ host=\"{}\" }} {}\n".format(socket.gethostname(), currentEpoch),
    ]
  
    # write prom file atomically
    promfile = open("{}/artifact-backup.prom".format(work_dir), 'w')
    promfile.write("{}\n".format("\n".join(promData)))
    promfile.close()
    shutil.move(
        "{}/artifact-backup.prom".format(work_dir), 
        "{}/artifact-backup.prom".format(collector_dir)
    )


# remove the backup file and any intermediate files created
def cleanup(backup, intermediate_files):
    
    for item in intermediate_files:
        logging.debug("Cleanup requested for {}".format(item))
        if os.path.isfile(item):
            os.remove(item)
        elif os.path.isdir(item):
            shutil.rmtree(item)
        else:
            logging.warn("Asked to cleanup {} but it's neither a file nor a directory".format(item))
    
    backup.remove()


def main():
 
    os.chdir(args.work_dir)

    backup = BackupETCD(
        s3_endpoint=args.s3_endpoint, s3_bucket=args.bucket, bucket_lifecycle_days=args.expire_days, ssl_verify=SSL_VERIFY
    )
    backup.ensure_bucket_created()
    backup.ensure_bucket_lifecycle()

    # list backups in the bucket
    if args.list:
        objectsInBucket = backup.get_remote_object_list()
        if not objectsInBucket:
            logger.info("This bucket appears to be empty")
            return
        for item in objectsInBucket:
            logger.info("Backup Object: {} Size: {}".format(item[0], item[1]) )
        return

    # remove backups from the bucket
    if args.remove:
        s3objects = args.remove.split(",")
        for item in s3objects:
            backup.remove_remote_object(item)
        return

    # remove backups from the bucket
    if args.get:
        s3objects = args.get.split(",")
        for item in s3objects:
            backup.get(remote_key=item, local_file="{}/{}".format(args.work_dir,item))
        return

    # if we get here, we should be performing a backup
    backup_date_time = datetime.now().strftime("%d-%m-%Y-%H.%M.%S")
    hostname = socket.gethostname()

    # Files to be deleted later
    intermediate_files = []

    # Files to be uploaded to S3
    content = []
    try:
        if args.etcd_type == 'Standalone':
            snapshot = backup.create_etcd_snapshot(cacert, cacert=args.etcd_ca, cert=args.etcd_cert, key=args.etcd_key, hostname=hostname)
            content += ['/etc/etcd', snapshot, ]
            # we'll want to bin this once backup completes
            intermediate_files.append(snapshot)
        elif args.etcd_type == 'Openshift4':
            content.append(backup.etcd_openshift_4())

            # okd4 backups go into a directory which will need removing 
            intermediate_files += content
        else:
            # realistically should never get here
            logging.error("Invalid etcd-type version: {}".format(args.etcd_type))
            return


        if args.encrypt:
            # New list of files to encrypt
            encrypt_content = []

            # Generate a one-time passphrase and save it in a file
            otp = generate_otp()
            otpfile = "{}/otp-{}.{}.txt".format(args.work_dir, hostname, backup_date_time)
            with open(otpfile, 'w') as f:
                f.write(otp)
            intermediate_files.append(otpfile)

            # Encrypt the large backup file with AES (fast)
            # loop through content, if it's a dir, glob it
            # encrypt everything one by one
            for c in content:
                if os.path.isfile(c):
                    encrypt_content.append(c)
                    logger.info("Added {} to list of files to encrypt".format(c))
                elif os.path.isdir(c):
                    files = os.listdir(c)
                    for f in files:
                        target = os.path.join(c, f)
                        encrypt_content.append(target)
                        logger.info("Added {} to list of files to encrypt".format(target))

            
            # List of files that have been encrypted
            encrypted_content = []
            for f in encrypt_content:
                encrypted_filename = encrypt_file_aes(f, otp)
                intermediate_files.append(encrypted_filename)
                encrypted_content.append(encrypted_filename)

            # Now encrypt the OTP with RSA (slow)
            encrypted_otpfile = encrypt_file_rsa(args.publickey, otpfile)
            encrypted_content.append(encrypted_otpfile)

            # Now we have a list of encrypted files to back up, make sure these are the
            # only files that get tarred up
            content = encrypted_content

        # tarball the backup content
        backup_filename = "{}/{}.{}.tgz".format(args.work_dir, hostname, backup_date_time)
        backup.tar_backup_content(backup_filename, content)


        # if we failed to backup, moan about it
        if not backup.status:
            logging.error("backup failed, check logs for details")
            raise RuntimeError("Backup failed, check logs")
        else:
            logging.info("get backup size")
            backup.backup_size()
            logging.info("Backup {} was created".format(backup_filename))
    
        # upload and test if that happened
        if backup.upload():
            logging.info("Backup {} was uploaded".format(backup_filename))
            # Prometheus temporarily disabled until we can get it working
            # update_node_exporter(args.work_dir,args.collector_dir)
        # otherwise moan about that
        else:
            logging.error("Uploading backup {} failed, check logs for details".format(backup_filename))
            raise RuntimeError("Backup upload failed, check logs")
    except Exception as e:
         logging.error("Exception caught during backup: {} - {}".format(e, traceback.format_exc()))
    finally:
        cleanup(backup, intermediate_files) 
 


    
if __name__ == "__main__":
 
    # parse out command line arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("--loglevel", required=False, default="INFO", help="Log level, one of INFO,WARN,DEBUG (Default=INFO)")
    parser.add_argument("--list",required=False, help="List existing backups only", action='store_true')
    parser.add_argument("--remove", required=False, help="Provide a comma separated list of backup files to remove")
    parser.add_argument("--get", required=False, help="Get an object from the bucket")
    parser.add_argument("--s3-endpoint", required=False, default="https://s3.gb.iplatform.1and1.org", help="The S3 endpoint (Default=https://s3.gb.iplatform.1and1.org)")
    parser.add_argument("--bucket", required=True, help="The bucket name for backups to be uploaded to")
    parser.add_argument("--expire-days", required=False, default=7, type=int, help="The number of days before backups expire (Default=7)")
    parser.add_argument("--work-dir", required=False, default="/var/tmp", help="Temporary working directory (Default=/var/tmp)")
    parser.add_argument("--collector-dir", required=False, default="/opt/node_exporter", help="Node export collector directory (Default=/opt/node_exporter)")
    parser.add_argument("--encrypt", required=False, help="Encrypt the backup file (Default=False)")
    parser.add_argument("--publickey", required=False, default="/etc/ssh/ssh_host_rsa_key.pub", help="RSA public key to use for encrypting the backup")
    parser.add_argument("--etcd-cert", required=False, default='/etc/etcd/peer.crt')
    parser.add_argument("--etcd-key", required=False, default='/etc/etcd/peer.key')
    parser.add_argument("--etcd-ca", required=False, default='/etc/etcd/ca.crt')
    parser.add_argument("--hostname", required=False, default=socket.gethostname())
    parser.add_argument("--etcd-type", required=False, default='Standalone', choices=["Standalone", "Openshift4"], help="Type of ETCD backup, either standalone or Openshift hosted")

    args = parser.parse_args()

    # setup a rotating logfile handler
    logging.basicConfig(level=args.loglevel)
    logger = logging.getLogger(__name__)
    handler = RotatingFileHandler(LOG_FILE, maxBytes=MAX_LOGSIZE_BYTES, backupCount=MAX_LOG_FILES)
    handler.setFormatter(logging.Formatter("%(asctime)s:%(levelname)s -> %(message)s", datefmt="%d-%m-%Y %H:%M:%S"))
    logger.addHandler(handler)

    logger.debug("Runtime Args: {}".format(args))

    # python2 lacks SNI support which causes us problems, disable SSL verify on 2.x
    if sys.version_info[0] < 3:
        logger.warn("Your python version is less than 3, disabling SSL_VERIFY")
        SSL_VERIFY = False


    main()