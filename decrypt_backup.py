from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import argparse
import tarfile
import glob
import pyAesCrypt
import shutil
import os

#Our Decryption Function
def decrypt_blob(encrypted_blob, private_key):

    #Import the Private Key and use for decryption using PKCS1_OAEP
    rsakey = RSA.importKey(private_key)
    decryptor = PKCS1_OAEP.new(rsakey)
    decrypted = decryptor.decrypt(encrypted_blob)
    return decrypted

parser = argparse.ArgumentParser()
parser.add_argument('-k', '--key', help="private key for decryption", required=True)
parser.add_argument('-f', '--file', help="backup file to decrypt", required=True)
args = parser.parse_args()

# Untar the backup file to a temp dir
my_tar = tarfile.open(args.file)
# generate tmpdir name
tmpdir = '/tmp/' + os.path.basename(args.file)
# wipe out & recreate tmp dir
shutil.rmtree(tmpdir, ignore_errors=True)
os.mkdir(tmpdir)
my_tar.extractall(tmpdir)
my_tar.close

# Find RSA-encypted AES passphrase file
passphrasefile = glob.glob(tmpdir + '/*.txt.rsa')
fd = open(passphrasefile[0], "rb")
encrypted_blob = fd.read()
fd.close()

# Use the RSA private key for decryption
fd = open(args.key, "r")
private_key = fd.read()
fd.close()

# Decrypt & stringify the AES passphrase
aespassphrase = decrypt_blob(encrypted_blob, private_key)
aespassphrase = str(aespassphrase, 'utf-8')

# Round up all AES-encrypted files
aesfiles = glob.glob(tmpdir + '/*.aes')
for file in aesfiles:
    outfile = file.replace('.aes', '')
    pyAesCrypt.decryptFile(file, outfile, aespassphrase)