#!/usr/bin/env python

"""
This script exports Kubernetes object manifests as YAML files,
tars them up, optionally GPG encrypts them, and optionally
uploads them to an S3 object storage bucket.
"""

import argparse
import copy
import os
import subprocess
import json
import tarfile
import logging
from pathlib import Path
from datetime import datetime
import yaml
import gnupg
import boto3
from botocore.exceptions import ClientError


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
        'resourceVersion',
        'creationTimestamp'
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
        except KeyError:
            pass

    # Drop any keys that have None values
    return drop_nones_inplace(filtered)


def export_to_yaml(object_json, path):
    """
    Take an object from Kubernetes in its derfault
    JSON format, filter out unwanted attributes
    and write it to a YAML file
    """
    # Convert the json to a python dict
    object_dict = json.loads(object_json)

    # Fetch some key attributes we need for the export
    name = object_dict['metadata']['name']
    kind = object_dict['kind'].lower()

    # Filter out unwanted attributes
    filtered_dict = kube_metadata_filter(object_dict)

    # Build path and ensure it exists
    filename = os.path.join(path, f"{kind}-{name}.yaml")
    Path(path).mkdir(parents=True, exist_ok=True)

    # Write object to file in yaml format
    with open(filename, "w") as yaml_file:
        yaml.dump(filtered_dict, yaml_file, default_flow_style=False)

    return filename


def tar_backup_content(filename, content):
    """
    Create a compressed tar file called {filename}
    which contains the contents of directory {content}
    """
    logger.info(f"Creating tar archive {filename} with contents {content}")
    tar = tarfile.open(filename, "w:gz")
    tar.add(content)
    tar.close()
    #logger.info("tarring complete.")
    #self.status = True
    return filename


def backup_artifacts(args):
    """
    This is the core of the operation. This connects to a Kube
    cluster, searches for relevant resources, and exports them
    """
    # Trash any existing files in backup work_dir
    work_dir = os.path.join(args.work_dir, 'yaml')

    # Start a blank list of files in this backup
    files = []

    # Loop over all specified resource kinds and retrieve
    # all objects of each kind which have the relevant label
    for resource_kind in args.resource_kinds.split(sep=','):
        logger.info(f"Searching for resources of kind {resource_kind}")

        # Build argument list to list all matching resources
        arglist = ["kubectl", "get", resource_kind, "-o", "json"]

        if args.namespace:
            arglist.append("-n")
            arglist.append(args.namespace)
        else:
            arglist.append("-A")

        if args.label:
            arglist.append("-l")
            arglist.append(args.label)

        # Run the command
        resources = subprocess.check_output(arglist)

        resources_dict = json.loads(resources) or None

        # resource_dict is a json object containing multiple objects
        for resource in resources_dict['items']:

            # Fetch some key attributes we need for the export
            namespace = resource['metadata']['namespace']
            name = resource['metadata']['name']
            kind = resource['kind'].lower()
            logger.info(f"Exporting {kind} {namespace}/{name}")

            # Fetch the object as json
            if namespace:
                object_json = subprocess.check_output(
                    ["kubectl", "get", kind, "-n", namespace, name, "-o", "json"])
                path = os.path.join(work_dir, namespace)
            else:
                object_json = subprocess.check_output(
                    ["kubectl", "get", kind, name, "-o", "json"])
                path = work_dir

            # Export to yaml
            filename = export_to_yaml(
                object_json=object_json, path=path)
            files.append(filename)

            return files


def create_bucket(s3_client, bucket_name, region):
    """Create an S3 bucket in a specified region

    :param s3_client: Established S3 client
    :param bucket_name: Bucket to create
    :param region: Region in which to create the bucket
    :return: True if bucket created, else False
    """

    # Create bucket
    try:
        location = {'LocationConstraint': region}
        s3_client.create_bucket(Bucket=bucket_name, CreateBucketConfiguration=location)
    except ClientError as e:
        if e.response['Error'].get('Code') not in (
            "BucketAlreadyExists", "BucketAlreadyOwnedByYou"
        ):
            logging.error(e)
            raise
    return True

def set_bucket_policy(s3_client, bucket, days):
    """
    Set a bucket lifecycle policy that removes backups
    older than {days} days
    """

    s3_client.put_bucket_lifecycle_configuration(
        Bucket=bucket,
        LifecycleConfiguration={
            'Rules': [
                {
                    'ID': 'cleanup',
                    'Expiration': {
                        'Days': int(days),
                    },
                    'Status': 'Enabled',
                    'Prefix': ''
                },
            ],
        },
    )


def upload_file(file_name, s3_client, bucket, object_name=None):
    """Upload a file to an S3 bucket

    :param file_name: File to upload
    :param bucket: Bucket to upload to
    :param object_name: S3 object name. If not specified then file_name is used
    :return: True if file was uploaded, else False
    """

    # If S3 object_name was not specified, use file_name
    if object_name is None:
        object_name = os.path.basename(file_name)

    # Upload the file
    try:
        s3_client.upload_file(file_name, bucket, object_name)
    except ClientError as e:
        logger.error(e)
        return False
    return True


if __name__ == "__main__":

    # Read commandline args
    parser = argparse.ArgumentParser()
    parser.add_argument("--work-dir",
                        required=False,
                        default=os.getenv('WORK_DIR', '/tmp'),
                        help="Temporary working directory (Default=/var/tmp)"
                        )
    parser.add_argument("--resource-kinds",
                        required=False,
                        default=os.getenv('RESOURCE_KINDS', "Secret,ConfigMap"),
                        help="Comma separated list of resource kinds (Default=Secret,ConfigMap)"
                        )
    parser.add_argument("--label",
                        required=False,
                        default=os.getenv('LABEL'),
                        help="Label to match on when backing up resources (Default=None)",
                        )
    parser.add_argument("--namespace",
                        required=False,
                        default=os.getenv('NAMESPACE'),
                        help="Namespace to match on when backing up resources (Default=None)",
                        )
    parser.add_argument("--gpgkey",
                        required=False,
                        default=os.getenv('GPGKEY'),
                        help="GPG public key to use to encrypt backed up files",
                        )
    parser.add_argument("--upload",
                        required=False,
                        default=os.getenv('UPLOAD'),
                        help="Upload the compressed backup to object storage",
                        )
    parser.add_argument("--keepfor",
                        required=False,
                        default=os.getenv('KEEPFOR', '30'),
                        help="Number of days to retain backups",
                        )
    parser.add_argument("--verifyssl",
                        required=False,
                        default=os.getenv('VERIFYSSL', None),
                        help="Whether to verify SSL cert of S3",
                        )
    parser.add_argument("--endpoint_url",
                        required=False,
                        default=os.getenv('ENDPOINT', "https://s3-eu-central-2.ionoscloud.com"),
                        help="URL of S3 storage, if not AWS"
                        )
    parser.add_argument("--region",
                        required=False,
                        default=os.getenv('REGION', "eu-central-2"),
                        help="Region of S3 storage"
                        )
    parser.add_argument("--aws_access_key_id",
                        required=False,
                        default=os.getenv('AWS_ACCESS_KEY_ID'),
                        help="S3 access key"
                        )
    parser.add_argument("--aws_secret_access_key",
                        required=False,
                        default=os.getenv('AWS_SECRET_ACCESS_KEY'),
                        help="S3 secret key"
                        )
    parser.add_argument("--loglevel",
                        required=False,
                        default=os.getenv('LOGLEVEL', 'INFO'),
                        help="Log level verbosity"
                        )
    parser.add_argument("--clustername",
                        required=False,
                        default=os.getenv('CLUSTER_NAME', 'default'),
                        help="Friendly name of the cluster"
                        )
    args = parser.parse_args()

    # setup a rotating logfile handler
    logging.basicConfig(level=args.loglevel)
    logger = logging.getLogger(__name__)
    logger.debug(f"Runtime Args: {args}")

    # Get datetime now, to use in filename
    now = datetime.now()
    date_time = now.strftime("%Y-%m-%dT%H:%M:%S")

    # Read list of supported resources from env var, also with a default list
    # The env var should be populated from a configmap with envFrom

    # Connect to cluster

    # Perform backup, encrypting if requested
    files = backup_artifacts(args)

    # If there are files in the backup...
    if files and len(files) > 0:
        # Tar content
        tarfile = tar_backup_content(
            filename=f"{args.work_dir}/backup-{args.clustername}-{date_time}.tar.gz",
            content=f"{args.work_dir}/yaml")

        # Encrypt content if requested
        if args.gpgkey:
            gpg = gnupg.GPG()

            with open(args.gpgkey, 'r') as f:
                key_data = f.read()
                import_result = gpg.import_keys(key_data)

            gpg.trust_keys(import_result.fingerprints, 'TRUST_FULLY')

            if import_result.count == 1:
                fingerprint = import_result.fingerprints[0]

                logger.info(
                    f"Encrypting tar archive {tarfile} for recipient {fingerprint}")
                with open(tarfile, 'rb') as f:
                    status = gpg.encrypt_file(
                        f, recipients=fingerprint,
                        always_trust=True,
                        output=f"{tarfile}.gpg"
                    )
                    if status.ok is False:
                        logger.error(status.status)
                        raise Exception
            else:
                logger.error("Unable to import GPG key")
                raise Exception

        # Upload backup if requested
        if args.upload:
            logger.info("Uploading tar archive to S3")
            # Connect to S3
            boto3.set_stream_logger('boto3.resources', args.loglevel)
            s3_client = boto3.client('s3', endpoint_url=args.endpoint_url,
                                     verify=args.verifyssl,
                                     region_name=args.region,
                                     aws_access_key_id=args.aws_access_key_id,
                                     aws_secret_access_key=args.aws_secret_access_key)
            # build bucket name
            bucket = f"backup-{args.clustername}"

            # create bucket if necessary
            create_bucket(s3_client, bucket, args.region)

            # set bucket policy
            set_bucket_policy(s3_client, bucket, args.keepfor)

            if args.gpgkey:
                # upload gpg'd tarball
                upload_file(f"{tarfile}.gpg", s3_client, bucket)
            else:
                # upload plain tarball
                upload_file(tarfile, s3_client, bucket)
    else:
        logger.info("No artifacts exported")
