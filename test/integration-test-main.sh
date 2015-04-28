#!/bin/bash

set -o xtrace
set -o errexit

COMMON=integration-test-common.sh
source $COMMON

# Configuration
TEST_TEXT="HELLO WORLD"
TEST_TEXT_FILE=test-s3fs.txt
TEST_DIR=testdir
ALT_TEST_TEXT_FILE=test-s3fs-ALT.txt
TEST_TEXT_FILE_LENGTH=15
BIG_FILE=big-file-s3fs.txt
BIG_FILE_LENGTH=$((25 * 1024 * 1024))

function mk_test_file {
    if [ $# == 0 ]; then
        TEXT=$TEST_TEXT
    else
        TEXT=$1
    fi
    echo $TEXT > $TEST_TEXT_FILE
    if [ ! -e $TEST_TEXT_FILE ]
    then
        echo "Could not create file ${TEST_TEXT_FILE}, it does not exist"
        exit 1
    fi
}

function rm_test_file {
    if [ $# == 0 ]; then
        FILE=$TEST_TEXT_FILE
    else
        FILE=$1
    fi
    rm -f $FILE

    if [ -e $FILE ]
    then
        echo "Could not cleanup file ${TEST_TEXT_FILE}"
        exit 1
    fi
}

function mk_test_dir {
    mkdir ${TEST_DIR}

    if [ ! -d ${TEST_DIR} ]; then
        echo "Directory ${TEST_DIR} was not created"
        exit 1
    fi
}

function rm_test_dir {
    rmdir ${TEST_DIR}
    if [ -e $TEST_DIR ]; then
        echo "Could not remove the test directory, it still exists: ${TEST_DIR}"
        exit 1
    fi
}

CUR_DIR=`pwd`
TEST_BUCKET_MOUNT_POINT_1=$1
if [ "$TEST_BUCKET_MOUNT_POINT_1" == "" ]; then
    echo "Mountpoint missing"
    exit 1
fi
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

rm_test_file

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
mk_test_file

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
rm_test_file $ALT_TEST_TEXT_FILE

##########################################################
# Rename test (individual directory)
##########################################################
echo "Testing mv directory function ..."
if [ -e $TEST_DIR ]; then
   echo "Unexpected, this file/directory exists: ${TEST_DIR}"
   exit 1
fi

mk_test_dir

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

mk_test_file ABCDEF

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
rm_test_file

#####################################################################
# Simple directory test mkdir/rmdir
#####################################################################
echo "Testing creation/removal of a directory"

if [ -e $TEST_DIR ]; then
   echo "Unexpected, this file/directory exists: ${TEST_DIR}"
   exit 1
fi

mk_test_dir
rm_test_dir

##########################################################
# File permissions test (individual file)
##########################################################
echo "Testing chmod file function ..."

# create the test file again
mk_test_file

ORIGINAL_PERMISSIONS=$(stat --format=%a $TEST_TEXT_FILE)

chmod 777 $TEST_TEXT_FILE;

# if they're the same, we have a problem.
if [ $(stat --format=%a $TEST_TEXT_FILE) == $ORIGINAL_PERMISSIONS ]
then
  echo "Could not modify $TEST_TEXT_FILE permissions"
  exit 1
fi

# clean up
rm_test_file

##########################################################
# File permissions test (individual file)
##########################################################
echo "Testing chown file function ..."

# create the test file again
mk_test_file

ORIGINAL_PERMISSIONS=$(stat --format=%u:%g $TEST_TEXT_FILE)

chown 1000:1000 $TEST_TEXT_FILE;

# if they're the same, we have a problem.
if [ $(stat --format=%a $TEST_TEXT_FILE) == $ORIGINAL_PERMISSIONS ]
then
  echo "Could not modify $TEST_TEXT_FILE ownership"
  exit 1
fi

# clean up
rm_test_file

##########################################################
# Testing list
##########################################################
echo "Testing list"
mk_test_file
mk_test_dir

file_cnt=$(ls -1 | wc -l)
if [ $file_cnt != 2 ]; then
    echo "Expected 2 file but got $file_cnt"
    exit 1
fi

rm_test_file
rm_test_dir

##########################################################
# Testing rename before close
##########################################################
if false; then
echo "Testing rename before close ..."
$CUR_DIR/rename_before_close $TEST_TEXT_FILE
if [ $? != 0 ]; then
    echo "rename before close failed"
    exit 1
fi

# clean up
rm_test_file
fi

##########################################################
# Testing multi-part upload
##########################################################
echo "Testing multi-part upload ..."
dd if=/dev/urandom of="/tmp/${BIG_FILE}" bs=$BIG_FILE_LENGTH count=1
dd if="/tmp/${BIG_FILE}" of="${BIG_FILE}" bs=$BIG_FILE_LENGTH count=1

# Verify contents of file
echo "Comparing test file"
if ! cmp "/tmp/${BIG_FILE}" "${BIG_FILE}"
then
   exit 1
fi

rm -f "/tmp/${BIG_FILE}"
rm -f "${BIG_FILE}"

#####################################################################
# Tests are finished
#####################################################################

# Unmount the bucket
cd $CUR_DIR
echo "All tests complete."
