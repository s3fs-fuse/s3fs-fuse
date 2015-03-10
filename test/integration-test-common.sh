#!/bin/bash -e

S3FS=../src/s3fs

S3FS_CREDENTIALS_FILE="passwd-s3fs"

TEST_BUCKET_1="s3fs-integration-test"
TEST_BUCKET_MOUNT_POINT_1=${TEST_BUCKET_1}

if [ ! -f "$S3FS_CREDENTIALS_FILE" ]
then
	echo "Missing credentials file: $S3FS_CREDENTIALS_FILE"
	exit 1
fi
chmod 600 "$S3FS_CREDENTIALS_FILE"

S3PROXY_VERSION="1.4.0"
S3PROXY_BINARY="s3proxy-${S3PROXY_VERSION}-20150307.195914-6-jar-with-dependencies.jar"
if [ ! -e "${S3PROXY_BINARY}" ]; then
    wget "https://oss.sonatype.org/content/repositories/snapshots/org/gaul/s3proxy/${S3PROXY_VERSION}-SNAPSHOT/${S3PROXY_BINARY}"
fi
