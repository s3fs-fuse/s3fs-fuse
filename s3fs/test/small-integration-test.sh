#!/bin/bash -e
COMMON=integration-test-common.sh
source $COMMON

# Require root
REQUIRE_ROOT=require-root.sh
source $REQUIRE_ROOT

# Configuration
TEST_TEXT="HELLO WORLD"
TEST_TEXT_FILE=test-s3fs.txt
TEST_TEXT_FILE_LENGTH=15

# Mount the bucket
if [ ! -d $TEST_BUCKET_MOUNT_POINT_1 ]
then
	mkdir -p $TEST_BUCKET_MOUNT_POINT_1
fi
$S3FS $TEST_BUCKET_1 $TEST_BUCKET_MOUNT_POINT_1 -o passwd_file=$S3FS_CREDENTIALS_FILE
CUR_DIR=`pwd`
cd $TEST_BUCKET_MOUNT_POINT_1

# Write a small test file
for x in `seq 1 $TEST_TEXT_FILE_LENGTH`
do
	echo $TEST_TEXT >> $TEST_TEXT_FILE
done

# Verify contents of file
FILE_LENGTH=`wc -l $TEST_TEXT_FILE | awk '{print $1}'`
if [ "$FILE_LENGTH" -ne "$TEST_TEXT_FILE_LENGTH" ]
then
	exit 1
fi

# Delete the test file
rm $TEST_TEXT_FILE

# Unmount the bucket
cd $CUR_DIR
umount $TEST_BUCKET_MOUNT_POINT_1
