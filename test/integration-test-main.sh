#!/bin/bash

set -o errexit

source test-utils.sh

function test_append_file {
    describe "Testing append to file ..."
    # Write a small test file
    for x in `seq 1 $TEST_TEXT_FILE_LENGTH`
    do
       echo "echo ${TEST_TEXT} to ${TEST_TEXT_FILE}"
    done > ${TEST_TEXT_FILE}

    # Verify contents of file
    echo "Verifying length of test file"
    FILE_LENGTH=`wc -l $TEST_TEXT_FILE | awk '{print $1}'`
    if [ "$FILE_LENGTH" -ne "$TEST_TEXT_FILE_LENGTH" ]
    then
       echo "error: expected $TEST_TEXT_FILE_LENGTH , got $FILE_LENGTH"
       return 1
    fi

    rm_test_file
}

function test_truncate_file {
    describe "Testing truncate file ..."
    # Write a small test file
    echo "${TEST_TEXT}" > ${TEST_TEXT_FILE}

    # Truncate file to 0 length.  This should trigger open(path, O_RDWR | O_TRUNC...)
    : > ${TEST_TEXT_FILE}

    # Verify file is zero length
    if [ -s ${TEST_TEXT_FILE} ]
    then
        echo "error: expected ${TEST_TEXT_FILE} to be zero length"
        return 1
    fi
    rm_test_file
}

function test_truncate_empty_file {
    echo "Testing truncate empty file ..."
    # Write an empty test file
    touch ${TEST_TEXT_FILE}

    # Truncate the file to 1024 length
    t_size=1024
    truncate ${TEST_TEXT_FILE} -s $t_size

    # Verify file is zero length
    size=$(stat -c %s ${TEST_TEXT_FILE})
    if [ $t_size -ne $size ]
    then
        echo "error: expected ${TEST_TEXT_FILE} to be $t_size length, got $size"
        return 1
    fi
    rm_test_file
}

function test_mv_file {
    describe "Testing mv file function ..."
    # if the rename file exists, delete it
    if [ -e $ALT_TEST_TEXT_FILE ]
    then
       rm $ALT_TEST_TEXT_FILE
    fi

    if [ -e $ALT_TEST_TEXT_FILE ]
    then
       echo "Could not delete file ${ALT_TEST_TEXT_FILE}, it still exists"
       return 1
    fi

    # create the test file again
    mk_test_file

    #rename the test file
    mv $TEST_TEXT_FILE $ALT_TEST_TEXT_FILE
    if [ ! -e $ALT_TEST_TEXT_FILE ]
    then
       echo "Could not move file"
       return 1
    fi

    # Check the contents of the alt file
    ALT_TEXT_LENGTH=`echo $TEST_TEXT | wc -c | awk '{print $1}'`
    ALT_FILE_LENGTH=`wc -c $ALT_TEST_TEXT_FILE | awk '{print $1}'`
    if [ "$ALT_FILE_LENGTH" -ne "$ALT_TEXT_LENGTH" ]
    then
       echo "moved file length is not as expected expected: $ALT_TEXT_LENGTH  got: $ALT_FILE_LENGTH"
       return 1
    fi

    # clean up
    rm_test_file $ALT_TEST_TEXT_FILE
}

function test_mv_directory {
    describe "Testing mv directory function ..."
    if [ -e $TEST_DIR ]; then
       echo "Unexpected, this file/directory exists: ${TEST_DIR}"
       return 1
    fi

    mk_test_dir

    mv ${TEST_DIR} ${TEST_DIR}_rename

    if [ ! -d "${TEST_DIR}_rename" ]; then
       echo "Directory ${TEST_DIR} was not renamed"
       return 1
    fi

    rmdir ${TEST_DIR}_rename
    if [ -e "${TEST_DIR}_rename" ]; then
       echo "Could not remove the test directory, it still exists: ${TEST_DIR}_rename"
       return 1
    fi
}

function test_redirects {
    describe "Testing redirects ..."

    mk_test_file ABCDEF

    CONTENT=`cat $TEST_TEXT_FILE`

    if [ "${CONTENT}" != "ABCDEF" ]; then
       echo "CONTENT read is unexpected, got ${CONTENT}, expected ABCDEF"
       return 1
    fi

    echo XYZ > $TEST_TEXT_FILE

    CONTENT=`cat $TEST_TEXT_FILE`

    if [ ${CONTENT} != "XYZ" ]; then
       echo "CONTENT read is unexpected, got ${CONTENT}, expected XYZ"
       return 1
    fi

    echo 123456 >> $TEST_TEXT_FILE

    LINE1=`sed -n '1,1p' $TEST_TEXT_FILE`
    LINE2=`sed -n '2,2p' $TEST_TEXT_FILE`

    if [ ${LINE1} != "XYZ" ]; then
       echo "LINE1 was not as expected, got ${LINE1}, expected XYZ"
       return 1
    fi

    if [ ${LINE2} != "123456" ]; then
       echo "LINE2 was not as expected, got ${LINE2}, expected 123456"
       return 1
    fi

    # clean up
    rm_test_file
}

function test_mkdir_rmdir {
    describe "Testing creation/removal of a directory"

    if [ -e $TEST_DIR ]; then
       echo "Unexpected, this file/directory exists: ${TEST_DIR}"
       return 1
    fi

    mk_test_dir
    rm_test_dir
}

function test_chmod {
    describe "Testing chmod file function ..."

    # create the test file again
    mk_test_file

    ORIGINAL_PERMISSIONS=$(stat --format=%a $TEST_TEXT_FILE)

    chmod 777 $TEST_TEXT_FILE;

    # if they're the same, we have a problem.
    if [ $(stat --format=%a $TEST_TEXT_FILE) == $ORIGINAL_PERMISSIONS ]
    then
      echo "Could not modify $TEST_TEXT_FILE permissions"
      return 1
    fi

    # clean up
    rm_test_file
}

function test_chown {
    describe "Testing chown file function ..."

    # create the test file again
    mk_test_file

    ORIGINAL_PERMISSIONS=$(stat --format=%u:%g $TEST_TEXT_FILE)

    chown 1000:1000 $TEST_TEXT_FILE;

    # if they're the same, we have a problem.
    if [ $(stat --format=%u:%g $TEST_TEXT_FILE) == $ORIGINAL_PERMISSIONS ]
    then
      echo "Could not modify $TEST_TEXT_FILE ownership"
      return 1
    fi

    # clean up
    rm_test_file
}

function test_list {
    describe "Testing list"
    mk_test_file
    mk_test_dir

    file_cnt=$(ls -1 | wc -l)
    if [ $file_cnt != 2 ]; then
        echo "Expected 2 file but got $file_cnt"
        return 1
    fi

    rm_test_file
    rm_test_dir
}

function test_remove_nonempty_directory {
    describe "Testing removing a non-empty directory"
    mk_test_dir
    touch "${TEST_DIR}/file"
    rmdir "${TEST_DIR}" 2>&1 | grep -q "Directory not empty"
    rm "${TEST_DIR}/file"
    rm_test_dir
}

function test_rename_before_close {
    describe "Testing rename before close ..."
    (
        echo foo
        mv $TEST_TEXT_FILE ${TEST_TEXT_FILE}.new
    ) > $TEST_TEXT_FILE

    if ! cmp <(echo foo) ${TEST_TEXT_FILE}.new; then
        echo "rename before close failed"
        return 1
    fi

    rm_test_file ${TEST_TEXT_FILE}.new
    rm -f ${TEST_TEXT_FILE}
}

function test_multipart_upload {
    describe "Testing multi-part upload ..."
    dd if=/dev/urandom of="/tmp/${BIG_FILE}" bs=$BIG_FILE_LENGTH count=1
    dd if="/tmp/${BIG_FILE}" of="${BIG_FILE}" bs=$BIG_FILE_LENGTH count=1

    # Verify contents of file
    echo "Comparing test file"
    if ! cmp "/tmp/${BIG_FILE}" "${BIG_FILE}"
    then
       return 1
    fi

    rm -f "/tmp/${BIG_FILE}"
    rm_test_file "${BIG_FILE}"
}

function test_multipart_copy {
    describe "Testing multi-part copy ..."
    dd if=/dev/urandom of="/tmp/${BIG_FILE}" bs=$BIG_FILE_LENGTH count=1
    dd if="/tmp/${BIG_FILE}" of="${BIG_FILE}" bs=$BIG_FILE_LENGTH count=1
    mv "${BIG_FILE}" "${BIG_FILE}-copy"

    # Verify contents of file
    echo "Comparing test file"
    if ! cmp "/tmp/${BIG_FILE}" "${BIG_FILE}-copy"
    then
       return 1
    fi

    rm -f "/tmp/${BIG_FILE}"
    rm_test_file "${BIG_FILE}-copy"
}

function test_special_characters {
    describe "Testing special characters ..."

    ls 'special' 2>&1 | grep -q 'No such file or directory'
    ls 'special?' 2>&1 | grep -q 'No such file or directory'
    ls 'special*' 2>&1 | grep -q 'No such file or directory'
    ls 'special~' 2>&1 | grep -q 'No such file or directory'
    ls 'specialµ' 2>&1 | grep -q 'No such file or directory'
}

function test_symlink {
    describe "Testing symlinks ..."

    rm -f $TEST_TEXT_FILE
    rm -f $ALT_TEST_TEXT_FILE
    echo foo > $TEST_TEXT_FILE

    ln -s $TEST_TEXT_FILE $ALT_TEST_TEXT_FILE
    cmp $TEST_TEXT_FILE $ALT_TEST_TEXT_FILE

    rm -f $TEST_TEXT_FILE

    [ -L $ALT_TEST_TEXT_FILE ]
    [ ! -f $ALT_TEST_TEXT_FILE ]
}

function test_extended_attributes {
    command -v setfattr >/dev/null 2>&1 || \
        { echo "Skipping extended attribute tests" ; return; }

    describe "Testing extended attributes ..."

    rm -f $TEST_TEXT_FILE
    touch $TEST_TEXT_FILE

    # set value
    setfattr -n key1 -v value1 $TEST_TEXT_FILE
    getfattr -n key1 --only-values $TEST_TEXT_FILE | grep -q '^value1$'

    # append value
    setfattr -n key2 -v value2 $TEST_TEXT_FILE
    getfattr -n key1 --only-values $TEST_TEXT_FILE | grep -q '^value1$'
    getfattr -n key2 --only-values $TEST_TEXT_FILE | grep -q '^value2$'

    # remove value
    setfattr -x key1 $TEST_TEXT_FILE
    ! getfattr -n key1 --only-values $TEST_TEXT_FILE
    getfattr -n key2 --only-values $TEST_TEXT_FILE | grep -q '^value2$'
}

function test_mtime_file {
    describe "Testing mtime preservation function ..."

    # if the rename file exists, delete it
    if [ -e $ALT_TEST_TEXT_FILE -o -L $ALT_TEST_TEXT_FILE ]
    then
       rm $ALT_TEST_TEXT_FILE
    fi

    if [ -e $ALT_TEST_TEXT_FILE ]
    then
       echo "Could not delete file ${ALT_TEST_TEXT_FILE}, it still exists"
       return 1
    fi

    # create the test file again
    mk_test_file
    sleep 2 # allow for some time to pass to compare the timestamps between test & alt

    #copy the test file with preserve mode
    cp -p $TEST_TEXT_FILE $ALT_TEST_TEXT_FILE
    testmtime=`stat -c %Y $TEST_TEXT_FILE`
    altmtime=`stat -c %Y $ALT_TEST_TEXT_FILE`
    if [ "$testmtime" -ne "$altmtime" ]
    then
       echo "File times do not match:  $testmtime != $altmtime"
       return 1
    fi
}

function test_rm_rf_dir {
   describe "Test that rm -rf will remove directory with contents"
   # Create a dir with some files and directories
   mkdir dir1
   mkdir dir1/dir2
   touch dir1/file1
   touch dir1/dir2/file2

   # Remove the dir with recursive rm
   rm -rf dir1

   if [ -e dir1 ]; then
       echo "rm -rf did not remove $PWD/dir1"
       return 1
   fi
}

function test_write_after_seek_ahead {
   describe "Test writes succeed after a seek ahead"
   dd if=/dev/zero of=testfile seek=1 count=1 bs=1024
   rm testfile
}


function add_all_tests {
    add_tests test_append_file 
    add_tests test_truncate_file 
    add_tests test_truncate_empty_file
    add_tests test_mv_file
    add_tests test_mv_directory
    add_tests test_redirects
    add_tests test_mkdir_rmdir
    add_tests test_chmod
    add_tests test_chown
    add_tests test_list
    add_tests test_remove_nonempty_directory
    # TODO: broken: https://github.com/s3fs-fuse/s3fs-fuse/issues/145
    #add_tests test_rename_before_close
    add_tests test_multipart_upload
    # TODO: test disabled until S3Proxy 1.5.0 is released
    #add_tests test_multipart_copy
    add_tests test_special_characters
    add_tests test_symlink
    add_tests test_extended_attributes
    add_tests test_rm_rf_dir
    add_tests test_write_after_seek_ahead
}

init_suite
add_all_tests
run_suite
