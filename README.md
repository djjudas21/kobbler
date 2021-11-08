# Artifact backup

Script to back up cluster artifacts (i.e secrets) from a cluster
to an encrypted tarball and upload to S3.

## Build

```sh
docker build -t reg.1u1.it/okdaas/artifact-backup:tag .
docker push reg.1u1.it/okdaas/artifact-backup:tag
```

## Run

```sh
oc apply kubernetes/cronjob.yaml
```

## Debug

```sh
oc apply kubernetes/pod.yaml
oc exec -it artifact-backup-dev -- sh
```

```
python ./artifact-backer-upper.py --bucket=artifact-backups --s3-endpoint=https://s3-de-central.profitbricks.com --encrypt=True --collector-dir=/var/node_exporter/textfile --publickey=/etc/ssh/id_rsa.pub
```