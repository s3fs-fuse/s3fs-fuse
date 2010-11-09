#!/bin/bash -e

S3FS=../src/s3fs

S3FS_CREDENTIALS_FILE=~/.passwd-s3fs

TEST_BUCKET_1=${USER}-s3fs-integration-test
TEST_BUCKET_MOUNT_POINT_1=/mnt/s3fs-test

if [ ! -f "$S3FS_CREDENTIALS_FILE" ]
then
	echo "Missing credentials file: $S3FS_CREDENTIALS_FILE"
	exit 1
fi
