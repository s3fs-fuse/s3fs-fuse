#!/bin/bash -e
COMMON=integration-test-common.sh
source $COMMON

# Require root
REQUIRE_ROOT=require-root.sh
source $REQUIRE_ROOT

# Configuration
TEST_TEXT="HELLO WORLD"
TEST_TEXT_FILE=test-s3fs.txt
TEST_DIR=testdir
ALT_TEST_TEXT_FILE=test-s3fs-ALT.txt
TEST_TEXT_FILE_LENGTH=15

# Mount the bucket
if [ ! -d $TEST_BUCKET_MOUNT_POINT_1 ]
then
	mkdir -p $TEST_BUCKET_MOUNT_POINT_1
fi
$S3FS $TEST_BUCKET_1 $TEST_BUCKET_MOUNT_POINT_1 -o passwd_file=$S3FS_CREDENTIALS_FILE
CUR_DIR=`pwd`
cd $TEST_BUCKET_MOUNT_POINT_1

if [ -e $TEST_TEXT_FILE ]
then
  rm -f $TEST_TEXT_FILE
fi

# Write a small test file
for x in `seq 1 $TEST_TEXT_FILE_LENGTH`
do
   echo "echo ${TEST_TEXT} to ${TEST_TEXT_FILE}"
   echo $TEST_TEXT >> $TEST_TEXT_FILE
done

# Verify contents of file
echo "Verifying length of test file"
FILE_LENGTH=`wc -l $TEST_TEXT_FILE | awk '{print $1}'`
if [ "$FILE_LENGTH" -ne "$TEST_TEXT_FILE_LENGTH" ]
then
   echo "error: expected $TEST_TEXT_FILE_LENGTH , got $FILE_LENGTH"
   exit 1
fi

# Delete the test file
rm $TEST_TEXT_FILE
if [ -e $TEST_TEXT_FILE ]
then
   echo "Could not delete file, it still exists"
   exit 1
fi

##########################################################
# Rename test (individual file)
##########################################################
echo "Testing mv file function ..."

# if the rename file exists, delete it
if [ -e $ALT_TEST_TEXT_FILE ]
then
   rm $ALT_TEST_TEXT_FILE
fi

if [ -e $ALT_TEST_TEXT_FILE ]
then
   echo "Could not delete file ${ALT_TEST_TEXT_FILE}, it still exists"
   exit 1
fi

# create the test file again
echo $TEST_TEXT > $TEST_TEXT_FILE
if [ ! -e $TEST_TEXT_FILE ]
then
   echo "Could not create file ${TEST_TEXT_FILE}, it does not exist"
   exit 1
fi

#rename the test file
mv $TEST_TEXT_FILE $ALT_TEST_TEXT_FILE
if [ ! -e $ALT_TEST_TEXT_FILE ]
then
   echo "Could not move file"
   exit 1
fi

# Check the contents of the alt file
ALT_TEXT_LENGTH=`echo $TEST_TEXT | wc -c | awk '{print $1}'`
ALT_FILE_LENGTH=`wc -c $ALT_TEST_TEXT_FILE | awk '{print $1}'`
if [ "$ALT_FILE_LENGTH" -ne "$ALT_TEXT_LENGTH" ]
then
   echo "moved file length is not as expected expected: $ALT_TEXT_LENGTH  got: $ALT_FILE_LENGTH"
   exit 1
fi

# clean up
rm $ALT_TEST_TEXT_FILE

if [ -e $ALT_TEST_TEXT_FILE ]
then
   echo "Could not cleanup file ${ALT_TEST_TEXT_FILE}, it still exists"
   exit 1
fi

##########################################################
# Rename test (individual directory)
##########################################################
echo "Testing mv directory function ..."
if [ -e $TEST_DIR ]; then
   echo "Unexpected, this file/directory exists: ${TEST_DIR}"
   exit 1
fi

mkdir ${TEST_DIR}

if [ ! -d ${TEST_DIR} ]; then
   echo "Directory ${TEST_DIR} was not created"
   exit 1
fi

mv ${TEST_DIR} ${TEST_DIR}_rename

if [ ! -d "${TEST_DIR}_rename" ]; then
   echo "Directory ${TEST_DIR} was not renamed"
   exit 1
fi

rmdir ${TEST_DIR}_rename
if [ -e "${TEST_DIR}_rename" ]; then
   echo "Could not remove the test directory, it still exists: ${TEST_DIR}_rename"
   exit 1
fi

###################################################################
# test redirects > and >>
###################################################################
echo "Testing redirects ..."

echo ABCDEF > $TEST_TEXT_FILE
if [ ! -e $TEST_TEXT_FILE ]
then
   echo "Could not create file ${TEST_TEXT_FILE}, it does not exist"
   exit 1
fi

CONTENT=`cat $TEST_TEXT_FILE`

if [ ${CONTENT} != "ABCDEF" ]; then
   echo "CONTENT read is unexpected, got ${CONTENT}, expected ABCDEF"
   exit 1
fi

echo XYZ > $TEST_TEXT_FILE

CONTENT=`cat $TEST_TEXT_FILE`

if [ ${CONTENT} != "XYZ" ]; then
   echo "CONTENT read is unexpected, got ${CONTENT}, expected XYZ"
   exit 1
fi

echo 123456 >> $TEST_TEXT_FILE

LINE1=`sed -n '1,1p' $TEST_TEXT_FILE`
LINE2=`sed -n '2,2p' $TEST_TEXT_FILE`

if [ ${LINE1} != "XYZ" ]; then
   echo "LINE1 was not as expected, got ${LINE1}, expected XYZ"
   exit 1
fi

if [ ${LINE2} != "123456" ]; then
   echo "LINE2 was not as expected, got ${LINE2}, expected 123456"
   exit 1
fi


# clean up
rm $TEST_TEXT_FILE

if [ -e $TEST_TEXT_FILE ]
then
   echo "Could not cleanup file ${TEST_TEXT_FILE}, it still exists"
   exit 1
fi

#####################################################################
# Simple directory test mkdir/rmdir
#####################################################################
echo "Testing creation/removal of a directory"

if [ -e $TEST_DIR ]; then
   echo "Unexpected, this file/directory exists: ${TEST_DIR}"
   exit 1
fi

mkdir ${TEST_DIR}

if [ ! -d ${TEST_DIR} ]; then
   echo "Directory ${TEST_DIR} was not created"
   exit 1
fi

rmdir ${TEST_DIR}
if [ -e $TEST_DIR ]; then
   echo "Could not remove the test directory, it still exists: ${TEST_DIR}"
   exit 1
fi

##########################################################
# File permissions test (individual file)
##########################################################
echo "Testing chmod file function ..."

# create the test file again
echo $TEST_TEXT > $TEST_TEXT_FILE
if [ ! -e $TEST_TEXT_FILE ]
then
   echo "Could not create file ${TEST_TEXT_FILE}"
   exit 1
fi

ORIGINAL_PERMISSIONS=$(stat --format=%a $TEST_TEXT_FILE)

chmod 777 $TEST_TEXT_FILE;

# if they're the same, we have a problem.
if [ $(stat --format=%a $TEST_TEXT_FILE) == $ORIGINAL_PERMISSIONS ]
then
  echo "Could not modify $TEST_TEXT_FILE permissions"
  exit 1
fi

# clean up
rm $TEST_TEXT_FILE

if [ -e $TEST_TEXT_FILE ]
then
   echo "Could not cleanup file ${TEST_TEXT_FILE}"
   exit 1
fi

##########################################################
# File permissions test (individual file)
##########################################################
echo "Testing chown file function ..."

# create the test file again
echo $TEST_TEXT > $TEST_TEXT_FILE
if [ ! -e $TEST_TEXT_FILE ]
then
   echo "Could not create file ${TEST_TEXT_FILE}"
   exit 1
fi

ORIGINAL_PERMISSIONS=$(stat --format=%u:%g $TEST_TEXT_FILE)

chown 1000:1000 $TEST_TEXT_FILE;

# if they're the same, we have a problem.
if [ $(stat --format=%a $TEST_TEXT_FILE) == $ORIGINAL_PERMISSIONS ]
then
  echo "Could not modify $TEST_TEXT_FILE ownership"
  exit 1
fi

# clean up
rm $TEST_TEXT_FILE

if [ -e $TEST_TEXT_FILE ]
then
   echo "Could not cleanup file ${TEST_TEXT_FILE}"
   exit 1
fi

#####################################################################
# Tests are finished
#####################################################################

# Unmount the bucket
cd $CUR_DIR
umount $TEST_BUCKET_MOUNT_POINT_1

echo "All tests complete."
