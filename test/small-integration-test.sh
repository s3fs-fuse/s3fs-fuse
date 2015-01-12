#!/bin/bash -e

# Require root
REQUIRE_ROOT=require-root.sh
#source $REQUIRE_ROOT

# Mount the bucket
if [ ! -d $TEST_BUCKET_MOUNT_POINT_1 ]
then
	mkdir -p $TEST_BUCKET_MOUNT_POINT_1
fi
$S3FS $TEST_BUCKET_1 $TEST_BUCKET_MOUNT_POINT_1 -o passwd_file=$S3FS_CREDENTIALS_FILE

./integration-test-main.sh $TEST_BUCKET_MOUNT_POINT_1

umount $TEST_BUCKET_MOUNT_POINT_1

echo "All tests complete."
