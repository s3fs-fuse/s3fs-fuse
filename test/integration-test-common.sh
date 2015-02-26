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

S3PROXY_VERSION="1.3.0"
S3PROXY_BINARY="s3proxy-${S3PROXY_VERSION}-jar-with-dependencies.jar"
if [ ! -e "${S3PROXY_BINARY}" ]; then
    wget "http://repo1.maven.org/maven2/org/gaul/s3proxy/${S3PROXY_VERSION}/${S3PROXY_BINARY}"
fi
