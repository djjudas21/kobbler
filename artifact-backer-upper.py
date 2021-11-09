#!/usr/bin/env python
import argparse
import copy
import logging
import os
import random
import shutil
import socket
import sys
import tarfile
import traceback
from datetime import datetime
from logging import StreamHandler
from os.path import basename
from pathlib import Path

import humanize
import pyAesCrypt
import yaml
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from S3Utils import S3Backup
from english_words import english_words_alpha_set
from kubernetes.client import ApiClient, V1Secret

from kubernetes import client, config

LOGGER = None

'''
    NAME: artifact-backer-upper
    AUTHOR: Terry Hurcombe <terry.hurcombe@fasthosts.com>
    DESCRIPTION:

    A python script to invoke etcd backups and upload the resulting archive to an S3 bucket.

    S3 credentials are read from the shared credentials file, see https://boto3.amazonaws.com/v1/documentation/api/latest/guide/configuration.html

    Backup archive lifecycle is managed by S3 BucketLifecycle policy.

    Upon a successful backup and upload, node-exporter is updated to reflect the current epoch. This data is available under the metric last_artifact_backup

    The script utilises a stderr log handler. To increase the loglevel, specify --loglevel
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


def drop_nones_inplace(d: dict) -> dict:
    """Recursively drop Nones in dict d in-place and return original dict"""
    dd = drop_nones(d)
    d.clear()
    d.update(dd)
    return d


def drop_nones(d: dict) -> dict:
    """Recursively drop Nones in dict d and return a new dict"""
    dd = {}
    for k, v in d.items():
        if isinstance(v, dict):
            dd[k] = drop_nones(v)
        elif isinstance(v, (list, set, tuple)):
            # note: Nones in lists are not dropped
            # simply add "if vv is not None" at the end if required
            dd[k] = type(v)(drop_nones(vv) if isinstance(vv, dict) else vv
                            for vv in v)
        elif v is not None:
            dd[k] = v
    return dd


def kube_metadata_filter(resource):
    '''
        Deletes metadata from a kube resource allowing for the returned
        resource to be applied to another cluster without conflict
    '''

    filtered = copy.deepcopy(resource)
    metadata_remove = [
        'uid',
        'ownerReferences',
        'managedFields',
        'resourceVersion'
    ]
    annotations_remove = [
        'kopf.zalando.org/last-handled-configuration',
        'kubectl.kubernetes.io/last-applied-configuration'
    ]

    for md in metadata_remove:
        try:
            del filtered['metadata'][md]
        except KeyError:
            pass
    for annotation in annotations_remove:
        try:
            del filtered['metadata']['annotations'][annotation]
        except:
            pass

    # Drop any keys that have None values
    return drop_nones_inplace(filtered)

def empty_contents(folder):
    for filename in os.listdir(folder):
        file_path = os.path.join(folder, filename)
        try:
            if os.path.isfile(file_path) or os.path.islink(file_path):
                os.unlink(file_path)
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
        except Exception as e:
            print('Failed to delete %s. Reason: %s' % (file_path, e))


def export_to_yaml(item, work_dir):
    if isinstance(item, dict):
        ns_dir = os.path.join(work_dir, item["metadata"]["namespace"], item["kind"])
        resource_name = item["metadata"]["name"]
    else:
        ns_dir = os.path.join(work_dir, item.metadata.namespace, item.kind)
        resource_name = item.metadata.name

    os.makedirs(ns_dir, exist_ok=True)

    # Let kube api serialise our model and sort key case
    serialised_dict = ApiClient().sanitize_for_serialization(item)

    # Filter out unwanted attributes
    filtered_dict = kube_metadata_filter(serialised_dict)

    # Write yaml version of this dict
    filename = os.path.join(ns_dir, f"{resource_name}.yaml")

    with open(filename, "w") as yaml_file:
        yaml.dump(filtered_dict, yaml_file, default_flow_style=False)

    logger.debug(f"Exported {filename}")

    return filename


# create a class that bases off S3Utils.S3Backup,
class BackupArtifacts(S3Backup):
    backup_name: str = 'backup'

    # instantiator, this must take at least the same args as S3Backup
    def __init__(self, backup_name: str, s3_endpoint, s3_bucket, bucket_lifecycle_days, ssl_verify=True):
        self.backup_name = backup_name

        super().__init__(s3_endpoint, s3_bucket, bucket_lifecycle_days, ssl_verify)

    def put(self, local_file):
        """
            override put so we can create a folder per backup name

            Put a local file to the S3 bucket.

            Required Arguments:
                local_file (string) - Path to a local file

            Optional Arguments: NONE

            Returns True if a file was uploaded, False otherwise

        """
        logger = logging.getLogger(__name__)
        try:
            logger.info(f"Uploading {local_file} to s3://{self.s3_bucket}")
            self.client.upload_file(str(local_file), self.s3_bucket, f"{self.backup_name}/{basename(local_file)}")
        except Exception as e:
            logger.error(f"Uploading backup failed: {e}")
            return False

        return True

    @staticmethod
    def __get_kube_api_client(kubeconfig_path: str = None) -> ApiClient:
        # Login using the given kubeconfig
        if kubeconfig_path:
            return config.new_client_from_config(kubeconfig_path)

        # Login using devs local kubeconfig
        user_kubeconfig = Path(os.path.expanduser("~")).joinpath(".kube", "config")
        if user_kubeconfig.exists():
            config.load_kube_config()
            return config.new_client_from_config()

        # Login using the in cluster kubeconfig
        config.load_incluster_config()
        return ApiClient()

    def backup_artifacts(self):
        # Get kube api client for context
        kube_api_client = self.__get_kube_api_client()

        core = client.CoreV1Api(api_client=kube_api_client)
        custom = client.CustomObjectsApi(api_client=kube_api_client)

        # Trash any existing files in backup work_dir
        work_dir = args.work_dir

        logging.info("Backup artifacts, path={}".format(work_dir))

        # Get labelled secrets and cluster CRs in all namespaces
        label = "backup-operator.infrastructure.ionos.com/backup=true"
        try:
            secrets = core.list_secret_for_all_namespaces(watch=False, label_selector=label)
        except:
            secrets = None
        try:
            clusters = custom.list_cluster_custom_object(group="infrastructure.ionos.com", version="v1", plural="clusters", label_selector=label)
        except:
            clusters = None

        # Create empty list to contain exported yaml objects
        exported_objects = []

        # Export all secrets and clusters to yaml objects
        if secrets is not None:
            item: V1Secret
            for item in secrets.items:
                secret = core.read_namespaced_secret(item.metadata.name, item.metadata.namespace)
                filename = export_to_yaml(secret, work_dir)
                if filename is not None:
                    exported_objects.append(filename)
        if clusters is not None:
            cluster: dict
            for cluster in clusters["items"]:
                cluster_to_export = custom.get_namespaced_custom_object(
                    group="infrastructure.ionos.com",
                    version="v1",
                    plural="clusters",
                    name=cluster["metadata"]["name"],
                    namespace=cluster["metadata"]["namespace"]
                )
                filename = export_to_yaml(cluster_to_export, work_dir)
                if filename is not None:
                    exported_objects.append(filename)

        return exported_objects

    def tar_backup_content(self, filename, sources):
        self.filename = filename
        logging.info("tarring backup to {} with content {}".format(
            filename, ",".join(sources)))
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
    # Import the Public Key and use for encryption using PKCS1_OAEP
    rsa_key = RSA.importKey(public_key)
    encryptor = PKCS1_OAEP.new(rsa_key)
    encrypted = encryptor.encrypt(blob)

    # return encrypted file
    return encrypted


def generate_otp():
    return "-".join(random.sample(english_words_alpha_set, 8))


def encrypt_file_rsa(public_key, filename):
    logging.info("Encrypt backup {} with key {}".format(filename, public_key))
    # Use the public key for encryption
    fd = open(public_key, "rb")
    public_key = fd.read()
    fd.close()

    # Our candidate file to be encrypted
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
    currentEpoch = int((datetime.now() - datetime(1970, 1, 1)).total_seconds())
    promData = [
        "# HELP last_artifact_backup epoch of the last successful artifact backup",
        "# TYPE last_artifact_backup counter",
        "last_artifact_backup{{ host=\"{}\" }} {}\n".format(
            socket.gethostname(), currentEpoch),
    ]

    # write prom file atomically
    promfile = open("{}/artifact-backup.prom".format(work_dir), 'w')
    promfile.write("{}\n".format("\n".join(promData)))
    promfile.close()
    shutil.move(
        "{}/artifact-backup.prom".format(work_dir),
        "{}/artifact-backup.prom".format(collector_dir)
    )


def main():

    backup = BackupArtifacts(
        backup_name=args.backup_name,
        s3_endpoint=args.s3_endpoint,
        s3_bucket=args.bucket,
        bucket_lifecycle_days=args.expire_days,
        ssl_verify=SSL_VERIFY
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
            logger.info("Backup Object: {} Size: {}".format(item[0], item[1]))
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
            backup.get(remote_key=item,
                       local_file="{}/{}".format(args.work_dir, item))
        return

    # if we get here, we should be performing a backup
    backup_date_time = datetime.now().strftime("%d-%m-%Y-%H.%M.%S")

    # Files to be deleted later
    intermediate_files = []

    # Files to be uploaded to S3
    content = []
    try:
        content = backup.backup_artifacts()
        # we'll want to bin this once backup completes
        intermediate_files.append(content)

        if args.encrypt:
            # New list of files to encrypt
            encrypt_content = []

            # Generate a one-time passphrase and save it in a file
            otp = generate_otp()
            otp_file = f"{args.work_dir}/otp-{args.backup_name}.{backup_date_time}.txt"
            with open(otp_file, 'w') as f:
                f.write(otp)
            intermediate_files.append(otp_file)

            # Encrypt the large backup file with AES (fast)
            # loop through content, if it's a dir, glob it
            # encrypt everything one by one
            for c in content:
                if os.path.isfile(c):
                    encrypt_content.append(c)
                    logger.info(f"Added {c} to list of files to encrypt")
                elif os.path.isdir(c):
                    files = os.listdir(c)
                    for f in files:
                        target = os.path.join(c, f)
                        encrypt_content.append(target)
                        logger.info(f"Added {target} to list of files to encrypt")

            # List of files that have been encrypted
            encrypted_content = []
            for f in encrypt_content:
                encrypted_filename = encrypt_file_aes(f, otp)
                intermediate_files.append(encrypted_filename)
                encrypted_content.append(encrypted_filename)

            # Now encrypt the OTP with RSA (slow)
            encrypted_otp_file = encrypt_file_rsa(args.publickey, otp_file)
            encrypted_content.append(encrypted_otp_file)

            # Now we have a list of encrypted files to back up, make sure these are the
            # only files that get tarred up
            content = encrypted_content

        # tarball the backup content
        backup_filename = f"{args.work_dir}/{args.backup_name}.{backup_date_time}.tgz"
        backup.tar_backup_content(backup_filename, content)

        # if we failed to backup, moan about it
        if not backup.status:
            logging.error("backup failed, check logs for details")
            raise RuntimeError("Backup failed, check logs")
        else:
            logging.info("get backup size")
            logging.info(f"Backup {backup_filename} of size {humanize.naturalsize(backup.backup_size())} was created")

        # upload and test if that happened
        if backup.upload():
            logging.info("Backup {} was uploaded".format(backup_filename))
            # Prometheus temporarily disabled until we can get it working
            # update_node_exporter(args.work_dir,args.collector_dir)
        # otherwise moan about that
        else:
            logging.error(
                "Uploading backup {} failed, check logs for details".format(backup_filename))
            raise RuntimeError("Backup upload failed, check logs")
    except Exception as e:
        logging.error(
            "Exception caught during backup: {} - {}".format(e, traceback.format_exc()))
    finally:
        empty_contents(args.work_dir)


if __name__ == "__main__":

    # parse out command line arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("--loglevel",
                        required=False,
                        default="INFO",
                        help="Log level, one of INFO,WARN,DEBUG (Default=INFO)"
    )
    parser.add_argument("--list",
                        required=False,
                        help="List existing backups only",
                        action='store_true'
    )
    parser.add_argument("--remove",
                        required=False,
                        help="Provide a comma separated list of backup files to remove"
    )
    parser.add_argument("--get",
                        required=False,
                        help="Get an object from the bucket"
    )
    parser.add_argument("--s3-endpoint",
                        required=False,
                        default=os.getenv("S3_ENDPOINT", "https://s3.gb.iplatform.1and1.org"),
                        help="The S3 endpoint (Default=https://s3.gb.iplatform.1and1.org)"
    )
    parser.add_argument("--bucket",
                        required=True,
                        default = os.getenv("BUCKET_NAME"),
                        help="The bucket name for backups to be uploaded to"
    )
    parser.add_argument("--backup-name",
                        required=False,
                        default=os.getenv("BACKUP_NAME", os.getenv("HOSTNAME", "backup")),
                        help="The name for the backup"
    )
    parser.add_argument("--expire-days",
                        required=False,
                        default=7,
                        type=int,
                        help="The number of days before backups expire (Default=7)"
    )
    parser.add_argument("--work-dir",
                        required=False,
                        default="/var/tmp",
                        help="Temporary working directory (Default=/var/tmp)"
    )
    parser.add_argument("--collector-dir",
                        required=False,
                        default=os.getenv("COLLECTOR_DIR", "/opt/node_exporter"),
                        help="Node export collector directory (Default=/opt/node_exporter)"
    )
    parser.add_argument("--encrypt",
                        required=False,
                        default=os.getenv("ENCRYPT"),
                        help="Encrypt the backup file (Default=False)"
    )
    parser.add_argument("--publickey",
                        required=False,
                        default=os.getenv("PUBLIC_KEY", "/etc/ssh/ssh_host_rsa_key.pub"),
                        help="RSA public key to use for encrypting the backup"
    )

    args = parser.parse_args()

    # setup a rotating logfile handler
    logging.basicConfig(level=args.loglevel)
    logger = logging.getLogger(__name__)
    handler = StreamHandler()
    handler.setFormatter(logging.Formatter(
        "%(asctime)s:%(levelname)s -> %(message)s", datefmt="%d-%m-%Y %H:%M:%S"))
    logger.addHandler(handler)

    logger.debug("Runtime Args: {}".format(args))

    # python2 lacks SNI support which causes us problems, disable SSL verify on 2.x
    if sys.version_info[0] < 3:
        logger.warn("Your python version is less than 3, disabling SSL_VERIFY")
        SSL_VERIFY = False

    main()
