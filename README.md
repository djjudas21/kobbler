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