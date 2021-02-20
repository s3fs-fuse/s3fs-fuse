#!/bin/bash
#
# s3fs - FUSE-based file system backed by Amazon S3
#
# Copyright 2007-2008 Randy Rizun <rrizun@gmail.com>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#

#### Test utils

set -o errexit
set -o pipefail

# Configuration
TEST_TEXT="HELLO WORLD"
TEST_TEXT_FILE=test-s3fs.txt
TEST_DIR=testdir
ALT_TEST_TEXT_FILE=test-s3fs-ALT.txt
TEST_TEXT_FILE_LENGTH=15
BIG_FILE=big-file-s3fs.txt
TEMP_DIR=${TMPDIR:-"/var/tmp"}
# /dev/urandom can only return 32 MB per block maximum
BIG_FILE_BLOCK_SIZE=$((25 * 1024 * 1024))
BIG_FILE_COUNT=1
# This should be greater than the multipart size
BIG_FILE_LENGTH=$(($BIG_FILE_BLOCK_SIZE * $BIG_FILE_COUNT))
export RUN_DIR

# [NOTE]
# stdbuf, truncate and sed installed on macos do not work as
# expected(not compatible with Linux).
# Therefore, macos installs a brew package such as coreutils
# and uses gnu commands(gstdbuf, gtruncate, gsed).
# Set your PATH appropriately so that you can find these commands.
#
if [ `uname` = "Darwin" ]; then
    export STDBUF_BIN="gstdbuf"
    export TRUNCATE_BIN="gtruncate"
    export SED_BIN="gsed"
else
    export STDBUF_BIN="stdbuf"
    export TRUNCATE_BIN="truncate"
    export SED_BIN="sed"
fi
export SED_BUFFER_FLAG="--unbuffered"

function get_xattr() {
    if [ `uname` = "Darwin" ]; then
        xattr -p "$1" "$2"
    else
        getfattr -n "$1" --only-values "$2"
    fi
}

function set_xattr() {
    if [ `uname` = "Darwin" ]; then
        xattr -w "$1" "$2" "$3"
    else
        setfattr -n "$1" -v "$2" "$3"
    fi
}

function del_xattr() {
    if [ `uname` = "Darwin" ]; then
        xattr -d "$1" "$2"
    else
        setfattr -x "$1" "$2"
    fi
}

function get_size() {
    if [ `uname` = "Darwin" ]; then
        stat -f "%z" "$1"
    else
        stat -c %s "$1"
    fi
}

function check_file_size() {
    FILE_NAME="$1"
    EXPECTED_SIZE="$2"

    # Verify file is zero length via metadata
    size=$(get_size ${FILE_NAME})
    if [ $size -ne $EXPECTED_SIZE ]
    then
        echo "error: expected ${FILE_NAME} to be zero length"
        return 1
    fi

    # Verify file is zero length via data
    size=$(cat ${FILE_NAME} | wc -c)
    if [ $size -ne $EXPECTED_SIZE ]
    then
        echo "error: expected ${FILE_NAME} to be $EXPECTED_SIZE length, got $size"
        return 1
    fi
}

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

    # wait & check
    BASE_TEXT_LENGTH=`echo $TEXT | wc -c | awk '{print $1}'`
    TRY_COUNT=10
    while true; do
        MK_TEXT_LENGTH=`wc -c $TEST_TEXT_FILE | awk '{print $1}'`
        if [ $BASE_TEXT_LENGTH -eq $MK_TEXT_LENGTH ]; then
            break
        fi
        TRY_COUNT=`expr $TRY_COUNT - 1`
        if [ $TRY_COUNT -le 0 ]; then
            echo "Could not create file ${TEST_TEXT_FILE}, that file size is something wrong"
        fi
        sleep 1
    done
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

# Create and cd to a unique directory for this test run
# Sets RUN_DIR to the name of the created directory
function cd_run_dir {
    if [ "$TEST_BUCKET_MOUNT_POINT_1" == "" ]; then
        echo "TEST_BUCKET_MOUNT_POINT_1 variable not set"
        exit 1
    fi
    RUN_DIR=${TEST_BUCKET_MOUNT_POINT_1}/${1}
    mkdir -p ${RUN_DIR}
    cd ${RUN_DIR}
}

function clean_run_dir {
    if [  -d ${RUN_DIR} ]; then
        rm -rf ${RUN_DIR} || echo "Error removing ${RUN_DIR}"
    fi
}

# Resets test suite
function init_suite {
    TEST_LIST=()
    TEST_FAILED_LIST=()
    TEST_PASSED_LIST=()
}

# Report a passing test case
#   report_pass TEST_NAME
function report_pass {
    echo "$1 passed"
    TEST_PASSED_LIST+=($1)
}

# Report a failing test case
#   report_fail TEST_NAME
function report_fail {
    echo "$1 failed"
    TEST_FAILED_LIST+=($1)
}

# Add tests to the suite
#   add_tests TEST_NAME...
function add_tests {
    TEST_LIST+=("$@")
}

# Log test name and description
#    describe [DESCRIPTION]
function describe {
    echo "${FUNCNAME[1]}: \"$*\""
}

# Runs each test in a suite and summarizes results.  The list of
# tests added by add_tests() is called with CWD set to a tmp
# directory in the bucket.  An attempt to clean this directory is
# made after the test run.  
function run_suite {
   orig_dir=$PWD
   key_prefix="testrun-$RANDOM"
   cd_run_dir $key_prefix
   for t in "${TEST_LIST[@]}"; do
       # The following sequence runs tests in a subshell to allow continuation
       # on test failure, but still allowing errexit to be in effect during
       # the test.
       #
       # See:
       #     https://groups.google.com/d/msg/gnu.bash.bug/NCK_0GmIv2M/dkeZ9MFhPOIJ
       # Other ways of trying to capture the return value will also disable
       # errexit in the function due to bash... compliance with POSIX? 
       set +o errexit
       (set -o errexit; $t $key_prefix)
       if [[ $? == 0 ]]; then
           report_pass $t
       else
           report_fail $t
       fi
       set -o errexit
   done
   cd ${orig_dir}
   clean_run_dir

   for t in "${TEST_PASSED_LIST[@]}"; do
       echo "PASS: $t"
   done
   for t in "${TEST_FAILED_LIST[@]}"; do
       echo "FAIL: $t"
   done

   passed=${#TEST_PASSED_LIST[@]} 
   failed=${#TEST_FAILED_LIST[@]} 

   echo "SUMMARY for $0: $passed tests passed.  $failed tests failed."

   if [[ $failed != 0 ]]; then
       return 1
   else
       return 0
   fi
}

function get_ctime() {
    if [ `uname` = "Darwin" ]; then
        stat -f "%c" "$1"
    else
        stat -c "%Z" "$1"
    fi
}

function get_mtime() {
    if [ `uname` = "Darwin" ]; then
        stat -f "%m" "$1"
    else
        stat -c "%Y" "$1"
    fi
}

function get_atime() {
    if [ `uname` = "Darwin" ]; then
        stat -f "%a" "$1"
    else
        stat -c "%X" "$1"
    fi
}

function get_permissions() {
    if [ `uname` = "Darwin" ]; then
        stat -f "%p" "$1"
    else
        stat -c "%a" "$1"
    fi
}

function check_content_type() {
    INFO_STR=`aws_cli s3api head-object --bucket ${TEST_BUCKET_1} --key $1`
    if [[ "${INFO_STR}" != *"$2"* ]]
    then
        echo "moved file content-type is not as expected expected:$2 got:${INFO_STR}"
        exit 1
    fi
}

function get_disk_avail_size() {
    DISK_AVAIL_SIZE=`BLOCKSIZE=$((1024 * 1024)) df $1 | awk '{print $4}' | tail -n 1`
    echo ${DISK_AVAIL_SIZE}
}

function aws_cli() {
    FLAGS=""
    if [ -n "${S3FS_PROFILE}" ]; then
        FLAGS="--profile ${S3FS_PROFILE}"
    fi
    aws $* --endpoint-url "${S3_URL}" --no-verify-ssl $FLAGS
}

function wait_for_port() {
    PORT=$1
    for i in $(seq 30); do
        if exec 3<>"/dev/tcp/127.0.0.1/${PORT}";
        then
            exec 3<&-  # Close for read
            exec 3>&-  # Close for write
            break
        fi
        sleep 1
    done
}

function make_random_string() {
    if [ -n "$1" ]; then
        END_POS=$1
    else
        END_POS=8
    fi
    RANDOM_STR=`cat /dev/urandom | base64 | sed 's#[/|+]##g' | head -1 | cut -c 1-${END_POS}`
    echo "${RANDOM_STR}"
}

#
# Local variables:
# tab-width: 4
# c-basic-offset: 4
# End:
# vim600: expandtab sw=4 ts=4 fdm=marker
# vim<600: expandtab sw=4 ts=4
#
