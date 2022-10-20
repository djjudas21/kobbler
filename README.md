# Kobbler

Tool to backup Kube Objects, i.e. any resources in your cluster, by exporting them as yaml objects.

## Usage

### `--work-dir`
Temporary working directory

Required: `False`
Default: `/var/tmp/backup`

### `--resource-kinds`
Comma separated list of resource kinds to backup

Required: `False`
Default: `Secret,ConfigMap`
                        
### `--label`
Label to match to when backing up resources, e.g. `kobbler/backup=true`

Required=`False`
Default: `kobbler/backup=true`

### `--namespace`
Namespace to match to when backing up resources, e.g. `default`. Defaults to match all namespaces.

Required=`False`
Default: `None`

### `--gpgkey`
Path to ASCII-formatted GPG key to use to encrypt backed up files

Required: `False`
Default: `None`

### `--upload`
Upload the compressed backup to object storage

Required: `False`
Default: `False`

### `--verifyssl`

Whether to verify SSL cert of S3. Leave undefined to verify using default CA
bundle, set to `False` to disable verification completely, or set the path to
a custom CA bundle.

Required: `False`
Default: `None`

### `--endpoint_url`

URL of S3 storage, if not AWS

Required: `True`
Default: `None`

### `--region`

Region of S3 storage

Required: `True`
Default: `None`

## S3 object storage

Authentication for the S3 object storage is handled by setting the environment variables `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`

## Building the image

```sh
docker build -t <path> .
docker push <path>
```

## Deploying

```sh
kubectl create secret ...
kubectl apply -f cronjob.yaml
```

## Decrypting

Decrypt a GPG-encrypted file by using the GPG private key that belongs with the GPG public key was used for the encryption.

```
gpg --import private.pgp
gpg --output backup.tar.gz --decrypt backup.tar.gz.gpg
```

Then untar

```
tar xzvf backup.tar.gz
```
