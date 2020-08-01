#!/bin/bash

set -o errexit
set -o pipefail

source test-utils.sh

function test_append_file {
    describe "Testing append to file ..."
    TEST_INPUT="echo ${TEST_TEXT} to ${TEST_TEXT_FILE}"

    # Write a small test file
    for x in `seq 1 $TEST_TEXT_FILE_LENGTH`
    do
        echo $TEST_INPUT
    done > ${TEST_TEXT_FILE}

    check_file_size "${TEST_TEXT_FILE}" $(($TEST_TEXT_FILE_LENGTH * $(echo $TEST_INPUT | wc -c)))

    rm_test_file
}

function test_truncate_file {
    describe "Testing truncate file ..."
    # Write a small test file
    echo "${TEST_TEXT}" > ${TEST_TEXT_FILE}

    # Truncate file to 0 length.  This should trigger open(path, O_RDWR | O_TRUNC...)
    : > ${TEST_TEXT_FILE}

    check_file_size "${TEST_TEXT_FILE}" 0

    rm_test_file
}

function test_truncate_upload {
    describe "Testing truncate file for uploading ..."

    # This file size uses multipart, mix upload when uploading.
    # We will test these cases.

    rm_test_file ${BIG_FILE}

    truncate ${BIG_FILE} -s ${BIG_FILE_LENGTH}

    rm_test_file ${BIG_FILE}
}

function test_truncate_empty_file {
    describe "Testing truncate empty file ..."
    # Write an empty test file
    touch ${TEST_TEXT_FILE}

    # Truncate the file to 1024 length
    t_size=1024
    truncate ${TEST_TEXT_FILE} -s $t_size

    check_file_size "${TEST_TEXT_FILE}" $t_size

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

    # save file length
    ALT_TEXT_LENGTH=`wc -c $TEST_TEXT_FILE | awk '{print $1}'`

    #rename the test file
    mv $TEST_TEXT_FILE $ALT_TEST_TEXT_FILE
    if [ ! -e $ALT_TEST_TEXT_FILE ]
    then
       echo "Could not move file"
       return 1
    fi
    
    #check the renamed file content-type
    if [ -f "/etc/mime.types" ]
    then
      check_content_type "$1/$ALT_TEST_TEXT_FILE" "text/plain"
    fi

    # Check the contents of the alt file
    ALT_FILE_LENGTH=`wc -c $ALT_TEST_TEXT_FILE | awk '{print $1}'`
    if [ "$ALT_FILE_LENGTH" -ne "$ALT_TEXT_LENGTH" ]
    then
       echo "moved file length is not as expected expected: $ALT_TEXT_LENGTH  got: $ALT_FILE_LENGTH"
       return 1
    fi

    # clean up
    rm_test_file $ALT_TEST_TEXT_FILE
}

function test_mv_empty_directory {
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

function test_mv_nonempty_directory {
    describe "Testing mv directory function ..."
    if [ -e $TEST_DIR ]; then
       echo "Unexpected, this file/directory exists: ${TEST_DIR}"
       return 1
    fi

    mk_test_dir

    touch ${TEST_DIR}/file

    mv ${TEST_DIR} ${TEST_DIR}_rename
    if [ ! -d "${TEST_DIR}_rename" ]; then
       echo "Directory ${TEST_DIR} was not renamed"
       return 1
    fi

    rm -r ${TEST_DIR}_rename
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
    describe "Testing creation/removal of a directory ..."

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

    ORIGINAL_PERMISSIONS=$(get_permissions $TEST_TEXT_FILE)

    chmod 777 $TEST_TEXT_FILE;

    # if they're the same, we have a problem.
    CHANGED_PERMISSIONS=$(get_permissions $TEST_TEXT_FILE)
    if [ $CHANGED_PERMISSIONS == $ORIGINAL_PERMISSIONS ]
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

    if [ `uname` = "Darwin" ]; then
        ORIGINAL_PERMISSIONS=$(stat -f "%u:%g" $TEST_TEXT_FILE)
    else
        ORIGINAL_PERMISSIONS=$(stat --format=%u:%g $TEST_TEXT_FILE)
    fi

    # [NOTE]
    # Prevents test interruptions due to permission errors, etc.
    # If the chown command fails, an error will occur with the
    # following judgment statement. So skip the chown command error.
    # '|| true' was added due to a problem with Travis CI and MacOS
    # and ensure_diskfree option.
    #
    chown 1000:1000 $TEST_TEXT_FILE || true

    # if they're the same, we have a problem.
    if [ `uname` = "Darwin" ]; then
        CHANGED_PERMISSIONS=$(stat -f "%u:%g" $TEST_TEXT_FILE)
    else
        CHANGED_PERMISSIONS=$(stat --format=%u:%g $TEST_TEXT_FILE)
    fi
    if [ $CHANGED_PERMISSIONS == $ORIGINAL_PERMISSIONS ]
    then
      if [ $ORIGINAL_PERMISSIONS == "1000:1000" ]
      then
        echo "Could not be strict check because original file permission 1000:1000"
      else
        echo "Could not modify $TEST_TEXT_FILE ownership($ORIGINAL_PERMISSIONS to 1000:1000)"
        return 1
      fi
    fi

    # clean up
    rm_test_file
}

function test_list {
    describe "Testing list ..."
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
    describe "Testing removing a non-empty directory ..."
    mk_test_dir
    touch "${TEST_DIR}/file"
    (
        set +o pipefail
        rmdir "${TEST_DIR}" 2>&1 | grep -q "Directory not empty"
    )
    rm "${TEST_DIR}/file"
    rm_test_dir
}

function test_external_directory_creation {
    describe "Test external directory creation ..."
    OBJECT_NAME="$(basename $PWD)/directory/${TEST_TEXT_FILE}"
    echo "data" | aws_cli s3 cp - "s3://${TEST_BUCKET_1}/${OBJECT_NAME}"
    ls | grep directory
    get_permissions directory | grep ^750$
    ls directory
    cmp <(echo "data") directory/${TEST_TEXT_FILE}
    rm -f directory/${TEST_TEXT_FILE}
}

function test_external_modification {
    describe "Test external modification to an object ..."
    echo "old" > ${TEST_TEXT_FILE}
    OBJECT_NAME="$(basename $PWD)/${TEST_TEXT_FILE}"
    sleep 2
    echo "new new" | aws_cli s3 cp - "s3://${TEST_BUCKET_1}/${OBJECT_NAME}"
    cmp ${TEST_TEXT_FILE} <(echo "new new")
    rm -f ${TEST_TEXT_FILE}
}

function test_read_external_object() {
    describe "create objects via aws CLI and read via s3fs ..."
    OBJECT_NAME="$(basename $PWD)/${TEST_TEXT_FILE}"
    sleep 3
    echo "test" | aws_cli s3 cp - "s3://${TEST_BUCKET_1}/${OBJECT_NAME}"
    cmp ${TEST_TEXT_FILE} <(echo "test")
    rm -f ${TEST_TEXT_FILE}
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

    #check the renamed file content-type
    check_content_type "$1/${BIG_FILE}-copy" "application/octet-stream"

    rm -f "/tmp/${BIG_FILE}"
    rm_test_file "${BIG_FILE}-copy"
}

function test_multipart_mix {
    describe "Testing multi-part mix ..."

    if [ `uname` = "Darwin" ]; then
       cat /dev/null > $BIG_FILE
    fi
    dd if=/dev/urandom of="/tmp/${BIG_FILE}" bs=$BIG_FILE_LENGTH seek=0 count=1
    dd if="/tmp/${BIG_FILE}" of="${BIG_FILE}" bs=$BIG_FILE_LENGTH seek=0 count=1

    # (1) Edit the middle of an existing file
    #     modify directly(seek 7.5MB offset)
    #     In the case of nomultipart and nocopyapi,
    #     it makes no sense, but copying files is because it leaves no cache.
    #
    cp /tmp/${BIG_FILE} /tmp/${BIG_FILE}-mix
    cp ${BIG_FILE} ${BIG_FILE}-mix

    MODIFY_START_BLOCK=$((15*1024*1024/2/4))
    echo -n "0123456789ABCDEF" | dd of="${BIG_FILE}-mix" bs=4 count=4 seek=$MODIFY_START_BLOCK conv=notrunc
    echo -n "0123456789ABCDEF" | dd of="/tmp/${BIG_FILE}-mix" bs=4 count=4 seek=$MODIFY_START_BLOCK conv=notrunc

    # Verify contents of file
    echo "Comparing test file (1)"
    if ! cmp "/tmp/${BIG_FILE}-mix" "${BIG_FILE}-mix"
    then
       return 1
    fi

    # (2) Write to an area larger than the size of the existing file
    #     modify directly(over file end offset)
    #
    cp /tmp/${BIG_FILE} /tmp/${BIG_FILE}-mix
    cp ${BIG_FILE} ${BIG_FILE}-mix

    OVER_FILE_BLOCK_POS=$((26*1024*1024/4))
    echo -n "0123456789ABCDEF" | dd of="${BIG_FILE}-mix" bs=4 count=4 seek=$OVER_FILE_BLOCK_POS conv=notrunc
    echo -n "0123456789ABCDEF" | dd of="/tmp/${BIG_FILE}-mix" bs=4 count=4 seek=$OVER_FILE_BLOCK_POS conv=notrunc

    # Verify contents of file
    echo "Comparing test file (2)"
    if ! cmp "/tmp/${BIG_FILE}-mix" "${BIG_FILE}-mix"
    then
       return 1
    fi

    # (3) Writing from the 0th byte
    #
    cp /tmp/${BIG_FILE} /tmp/${BIG_FILE}-mix
    cp ${BIG_FILE} ${BIG_FILE}-mix

    echo -n "0123456789ABCDEF" | dd of="${BIG_FILE}-mix" bs=4 count=4 seek=0 conv=notrunc
    echo -n "0123456789ABCDEF" | dd of="/tmp/${BIG_FILE}-mix" bs=4 count=4 seek=0 conv=notrunc

    # Verify contents of file
    echo "Comparing test file (3)"
    if ! cmp "/tmp/${BIG_FILE}-mix" "${BIG_FILE}-mix"
    then
       return 1
    fi

    # (4) Write to the area within 5MB from the top
    #     modify directly(seek 1MB offset)
    #
    cp /tmp/${BIG_FILE} /tmp/${BIG_FILE}-mix
    cp ${BIG_FILE} ${BIG_FILE}-mix

    MODIFY_START_BLOCK=$((1*1024*1024))
    echo -n "0123456789ABCDEF" | dd of="${BIG_FILE}-mix" bs=4 count=4 seek=$MODIFY_START_BLOCK conv=notrunc
    echo -n "0123456789ABCDEF" | dd of="/tmp/${BIG_FILE}-mix" bs=4 count=4 seek=$MODIFY_START_BLOCK conv=notrunc

    # Verify contents of file
    echo "Comparing test file (4)"
    if ! cmp "/tmp/${BIG_FILE}-mix" "${BIG_FILE}-mix"
    then
       return 1
    fi

    rm -f "/tmp/${BIG_FILE}"
    rm -f "/tmp/${BIG_FILE}-mix"
    rm_test_file "${BIG_FILE}"
    rm_test_file "${BIG_FILE}-mix"
}

function test_special_characters {
    describe "Testing special characters ..."

    (
        set +o pipefail
        ls 'special' 2>&1 | grep -q 'No such file or directory'
        ls 'special?' 2>&1 | grep -q 'No such file or directory'
        ls 'special*' 2>&1 | grep -q 'No such file or directory'
        ls 'special~' 2>&1 | grep -q 'No such file or directory'
        ls 'specialµ' 2>&1 | grep -q 'No such file or directory'
    )

    mkdir "TOYOTA TRUCK 8.2.2"
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

    rm -f $ALT_TEST_TEXT_FILE
}

function test_extended_attributes {
    describe "Testing extended attributes ..."

    rm -f $TEST_TEXT_FILE
    touch $TEST_TEXT_FILE

    # set value
    set_xattr key1 value1 $TEST_TEXT_FILE
    get_xattr key1 $TEST_TEXT_FILE | grep -q '^value1$'

    # append value
    set_xattr key2 value2 $TEST_TEXT_FILE
    get_xattr key1 $TEST_TEXT_FILE | grep -q '^value1$'
    get_xattr key2 $TEST_TEXT_FILE | grep -q '^value2$'

    # remove value
    del_xattr key1 $TEST_TEXT_FILE
    ! get_xattr key1 $TEST_TEXT_FILE
    get_xattr key2 $TEST_TEXT_FILE | grep -q '^value2$'

    rm_test_file
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
    testmtime=`get_mtime $TEST_TEXT_FILE`
    altmtime=`get_mtime $ALT_TEST_TEXT_FILE`
    if [ "$testmtime" -ne "$altmtime" ]
    then
       echo "File times do not match:  $testmtime != $altmtime"
       return 1
    fi

    rm_test_file
    rm_test_file $ALT_TEST_TEXT_FILE
}

function test_update_time() {
    describe "Testing update time function ..."

    # create the test
    mk_test_file
    ctime=`get_ctime $TEST_TEXT_FILE`
    mtime=`get_mtime $TEST_TEXT_FILE`

    sleep 2
    chmod +x $TEST_TEXT_FILE

    ctime2=`get_ctime $TEST_TEXT_FILE`
    mtime2=`get_mtime $TEST_TEXT_FILE`
    if [ $ctime -eq $ctime2 -o $mtime -ne $mtime2 ]; then
       echo "Expected updated ctime: $ctime != $ctime2 and same mtime: $mtime == $mtime2"
       return 1
    fi

    sleep 2
    chown $UID $TEST_TEXT_FILE

    ctime3=`get_ctime $TEST_TEXT_FILE`
    mtime3=`get_mtime $TEST_TEXT_FILE`
    if [ $ctime2 -eq $ctime3 -o $mtime2 -ne $mtime3 ]; then
       echo "Expected updated ctime: $ctime2 != $ctime3 and same mtime: $mtime2 == $mtime3"
       return 1
    fi

    sleep 2
    set_xattr key value $TEST_TEXT_FILE

    ctime4=`get_ctime $TEST_TEXT_FILE`
    mtime4=`get_mtime $TEST_TEXT_FILE`
    if [ $ctime3 -eq $ctime4 -o $mtime3 -ne $mtime4 ]; then
       echo "Expected updated ctime: $ctime3 != $ctime4 and same mtime: $mtime3 == $mtime4"
       return 1
    fi

    sleep 2
    echo foo >> $TEST_TEXT_FILE

    ctime5=`get_ctime $TEST_TEXT_FILE`
    mtime5=`get_mtime $TEST_TEXT_FILE`
    if [ $ctime4 -eq $ctime5 -o $mtime4 -eq $mtime5 ]; then
       echo "Expected updated ctime: $ctime4 != $ctime5 and updated mtime: $mtime4 != $mtime5"
       return 1
    fi

    rm_test_file
}

function test_rm_rf_dir {
   describe "Test that rm -rf will remove directory with contents ..."
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

function test_copy_file {
   describe "Test simple copy ..."

   dd if=/dev/urandom of=/tmp/simple_file bs=1024 count=1
   cp /tmp/simple_file copied_simple_file
   cmp /tmp/simple_file copied_simple_file

   rm_test_file /tmp/simple_file
   rm_test_file copied_simple_file
}

function test_write_after_seek_ahead {
   describe "Test writes succeed after a seek ahead ..."
   dd if=/dev/zero of=testfile seek=1 count=1 bs=1024
   rm_test_file testfile
}

function test_overwrite_existing_file_range {
    describe "Test overwrite range succeeds ..."
    dd if=<(seq 1000) of=${TEST_TEXT_FILE}
    dd if=/dev/zero of=${TEST_TEXT_FILE} seek=1 count=1 bs=1024 conv=notrunc
    cmp ${TEST_TEXT_FILE} <(
        seq 1000 | head -c 1024
        dd if=/dev/zero count=1 bs=1024
        seq 1000 | tail -c +2049
    )
    rm_test_file
}

function test_concurrency {
    describe "Test concurrent updates to a directory ..."
    for i in `seq 5`; do echo foo > $i; done
    for process in `seq 10`; do
        for i in `seq 5`; do
            file=$(ls `seq 5` | sed -n "$(($RANDOM % 5 + 1))p")
            cat $file >/dev/null || true
            rm -f $file
            echo foo > $file || true
        done &
    done
    wait
    rm -f `seq 5`
}

function test_concurrent_writes {
    describe "Test concurrent updates to a file ..."
    dd if=/dev/urandom of=${TEST_TEXT_FILE} bs=$BIG_FILE_LENGTH count=1
    for process in `seq 10`; do
        dd if=/dev/zero of=${TEST_TEXT_FILE} seek=$(($RANDOM % $BIG_FILE_LENGTH)) count=1 bs=1024 conv=notrunc &
    done
    wait
    rm_test_file
}

function test_open_second_fd {
    describe "read from an open fd ..."
    rm_test_file second_fd_file
    RESULT=$( (echo foo ; wc -c < second_fd_file >&2) 2>& 1>second_fd_file)
    if [ "$RESULT" -ne 4 ]; then
        echo "size mismatch, expected: 4, was: ${RESULT}"
        return 1
    fi
    rm_test_file second_fd_file
}

function test_write_multiple_offsets {
    describe "test writing to multiple offsets ..."
    ../../write_multiple_offsets.py ${TEST_TEXT_FILE} 1024 1 $((16 * 1024 * 1024)) 1 $((18 * 1024 * 1024)) 1
    rm_test_file ${TEST_TEXT_FILE}
}

function test_write_multiple_offsets_backwards {
    describe "test writing to multiple offsets ..."
    ../../write_multiple_offsets.py ${TEST_TEXT_FILE} $((20 * 1024 * 1024 + 1)) 1 $((10 * 1024 * 1024)) 1
    rm_test_file ${TEST_TEXT_FILE}
}

function test_clean_up_cache() {
    describe "Test clean up cache ..."

    dir="many_files"
    count=25
    mkdir -p $dir

    for x in $(seq $count); do
        dd if=/dev/urandom of=$dir/file-$x bs=10485760 count=1
    done

    file_cnt=$(ls $dir | wc -l)
    if [ $file_cnt != $count ]; then
        echo "Expected $count files but got $file_cnt"
        rm -rf $dir
        return 1
    fi
    CACHE_DISK_AVAIL_SIZE=`get_disk_avail_size $CACHE_DIR`
    if [ "$CACHE_DISK_AVAIL_SIZE" -lt "$ENSURE_DISKFREE_SIZE" ];then
        echo "Cache disk avail size:$CACHE_DISK_AVAIL_SIZE less than ensure_diskfree size:$ENSURE_DISKFREE_SIZE"
        rm -rf $dir
        return 1
    fi
    rm -rf $dir
}

function test_content_type() {
    describe "Test Content-Type detection ..."

    DIR_NAME="$(basename $PWD)"

    touch "test.txt"
    CONTENT_TYPE=$(aws_cli s3api head-object --bucket "${TEST_BUCKET_1}" --key "${DIR_NAME}/test.txt" | grep "ContentType")
    if ! echo $CONTENT_TYPE | grep -q "text/plain"; then
        echo "Unexpected Content-Type: $CONTENT_TYPE"
        return 1;
    fi

    touch "test.jpg"
    CONTENT_TYPE=$(aws_cli s3api head-object --bucket "${TEST_BUCKET_1}" --key "${DIR_NAME}/test.jpg" | grep "ContentType")
    if ! echo $CONTENT_TYPE | grep -q "image/jpeg"; then
        echo "Unexpected Content-Type: $CONTENT_TYPE"
        return 1;
    fi

    touch "test.bin"
    CONTENT_TYPE=$(aws_cli s3api head-object --bucket "${TEST_BUCKET_1}" --key "${DIR_NAME}/test.bin" | grep "ContentType")
    if ! echo $CONTENT_TYPE | grep -q "application/octet-stream"; then
        echo "Unexpected Content-Type: $CONTENT_TYPE"
        return 1;
    fi

    mkdir "test.dir"
    CONTENT_TYPE=$(aws_cli s3api head-object --bucket "${TEST_BUCKET_1}" --key "${DIR_NAME}/test.dir/" | grep "ContentType")
    if ! echo $CONTENT_TYPE | grep -q "application/x-directory"; then
        echo "Unexpected Content-Type: $CONTENT_TYPE"
        return 1;
    fi
}

# create more files than -o max_stat_cache_size
function test_truncate_cache() {
    describe "Test make cache files over max cache file size ..."

    for dir in $(seq 2); do
        mkdir $dir
        for file in $(seq 75); do
            touch $dir/$file
        done
        ls $dir
    done
}

function test_cache_file_stat() {
    describe "Test cache file stat ..."

    dd if=/dev/urandom of="${BIG_FILE}" bs=${BIG_FILE_LENGTH} count=1

    #
    # get "testrun-xxx" directory name
    #
    CACHE_TESTRUN_DIR=$(ls -1 ${CACHE_DIR}/${TEST_BUCKET_1}/ 2>/dev/null | grep testrun 2>/dev/null)

    #
    # get cache file inode number
    #
    CACHE_FILE_INODE=$(ls -i ${CACHE_DIR}/${TEST_BUCKET_1}/${CACHE_TESTRUN_DIR}/${BIG_FILE} 2>/dev/null | awk '{print $1}')
    if [ -z ${CACHE_FILE_INODE} ]; then
        echo "Not found cache file or failed to get inode: ${CACHE_DIR}/${TEST_BUCKET_1}/${CACHE_TESTRUN_DIR}/${BIG_FILE}"
        return 1;
    fi

    #
    # get lines from cache stat file
    #
    CACHE_FILE_STAT_LINE_1=$(sed -n 1p ${CACHE_DIR}/.${TEST_BUCKET_1}.stat/${CACHE_TESTRUN_DIR}/${BIG_FILE})
    CACHE_FILE_STAT_LINE_2=$(sed -n 2p ${CACHE_DIR}/.${TEST_BUCKET_1}.stat/${CACHE_TESTRUN_DIR}/${BIG_FILE})
    if [ -z ${CACHE_FILE_STAT_LINE_1} ] || [ -z ${CACHE_FILE_STAT_LINE_2} ]; then
        echo "could not get first or second line from cache file stat: ${CACHE_DIR}/.${TEST_BUCKET_1}.stat/${CACHE_TESTRUN_DIR}/${BIG_FILE}"
        return 1;
    fi

    #
    # compare
    #
    if [ "${CACHE_FILE_STAT_LINE_1}" != "${CACHE_FILE_INODE}:${BIG_FILE_LENGTH}" ]; then
        echo "first line(cache file stat) is different: \"${CACHE_FILE_STAT_LINE_1}\" != \"${CACHE_FILE_INODE}:${BIG_FILE_LENGTH}\""
        return 1;
    fi
    if [ "${CACHE_FILE_STAT_LINE_2}" != "0:${BIG_FILE_LENGTH}:1:0" ]; then
        echo "last line(cache file stat) is different: \"${CACHE_FILE_STAT_LINE_2}\" != \"0:${BIG_FILE_LENGTH}:1:0\""
        return 1;
    fi

    #
    # remove cache files directly
    #
    rm -f ${CACHE_DIR}/${TEST_BUCKET_1}/${CACHE_TESTRUN_DIR}/${BIG_FILE}
    rm -f ${CACHE_DIR}/.${TEST_BUCKET_1}.stat/${CACHE_TESTRUN_DIR}/${BIG_FILE}

    #
    # write a byte into the middle(not the boundary) of the file
    #
    CHECK_UPLOAD_OFFSET=$((10 * 1024 * 1024 + 17))
    dd if=/dev/urandom of="${BIG_FILE}" bs=1 count=1 seek=${CHECK_UPLOAD_OFFSET} conv=notrunc

    #
    # get cache file inode number
    #
    CACHE_FILE_INODE=$(ls -i ${CACHE_DIR}/${TEST_BUCKET_1}/${CACHE_TESTRUN_DIR}/${BIG_FILE} 2>/dev/null | awk '{print $1}')
    if [ -z ${CACHE_FILE_INODE} ]; then
        echo "Not found cache file or failed to get inode: ${CACHE_DIR}/${TEST_BUCKET_1}/${CACHE_TESTRUN_DIR}/${BIG_FILE}"
        return 1;
    fi

    #
    # get lines from cache stat file
    #
    CACHE_FILE_STAT_LINE_1=$(sed -n 1p ${CACHE_DIR}/.${TEST_BUCKET_1}.stat/${CACHE_TESTRUN_DIR}/${BIG_FILE})
    CACHE_FILE_STAT_LINE_E=$(tail -1 ${CACHE_DIR}/.${TEST_BUCKET_1}.stat/${CACHE_TESTRUN_DIR}/${BIG_FILE} 2>/dev/null)
    if [ -z ${CACHE_FILE_STAT_LINE_1} ] || [ -z ${CACHE_FILE_STAT_LINE_E} ]; then
        echo "could not get first or end line from cache file stat: ${CACHE_DIR}/.${TEST_BUCKET_1}.stat/${CACHE_TESTRUN_DIR}/${BIG_FILE}"
        return 1;
    fi

    #
    # check first and cache file length from last line
    #
    # we should check all stat lines, but there are cases where the value
    # differs depending on the processing system etc., then the cache file
    # size is calculated and compared.
    #
    CACHE_LAST_OFFSET=$(echo ${CACHE_FILE_STAT_LINE_E} | cut -d ":" -f1)
    CACHE_LAST_SIZE=$(echo ${CACHE_FILE_STAT_LINE_E} | cut -d ":" -f2)
    CACHE_TOTAL_SIZE=$((${CACHE_LAST_OFFSET} + ${CACHE_LAST_SIZE}))

    if [ "${CACHE_FILE_STAT_LINE_1}" != "${CACHE_FILE_INODE}:${BIG_FILE_LENGTH}" ]; then
        echo "first line(cache file stat) is different: \"${CACHE_FILE_STAT_LINE_1}\" != \"${CACHE_FILE_INODE}:${BIG_FILE_LENGTH}\""
        return 1;
    fi
    if [ ${BIG_FILE_LENGTH} -ne ${CACHE_TOTAL_SIZE} ]; then
        echo "the file size indicated by the cache stat file is different: \"${BIG_FILE_LENGTH}\" != \"${CACHE_TOTAL_SIZE}\""
        return 1;
    fi

    rm_test_file "${BIG_FILE}"
}

function test_upload_sparsefile {
    describe "Testing upload sparse file ..."

    rm_test_file ${BIG_FILE}
    rm -f /tmp/${BIG_FILE}

    #
    # Make all HOLE file
    #
    truncate ${BIG_FILE} -s ${BIG_FILE_LENGTH}

    #
    # Write some bytes to ABOUT middle in the file
    # (Dare to remove the block breaks)
    #
    WRITE_POS=$((${BIG_FILE_LENGTH} / 2 - 128))
    echo -n "0123456789ABCDEF" | dd of="/tmp/${BIG_FILE}" bs=1 count=16 seek=${WRITE_POS} conv=notrunc

    #
    # copy(upload) the file
    #
    cp /tmp/${BIG_FILE} ${BIG_FILE}

    #
    # check
    #
    cmp /tmp/${BIG_FILE} ${BIG_FILE}

    rm_test_file ${BIG_FILE}
    rm -f /tmp/${BIG_FILE}
}

function test_mix_upload_entities() {
    describe "Testing upload sparse files ..."

    #
    # Make test file
    #
    dd if=/dev/urandom of=${BIG_FILE} bs=$BIG_FILE_LENGTH count=1

    #
    # If the cache option is enabled, delete the cache of uploaded files.
    #
    if [ -f ${CACHE_DIR}/${TEST_BUCKET_1}/${BIG_FILE} ]; then
        rm -f ${CACHE_DIR}/${TEST_BUCKET_1}/${BIG_FILE}
    fi
    if [ -f ${CACHE_DIR}/.${TEST_BUCKET_1}.stat/${BIG_FILE} ]; then
        rm -f ${CACHE_DIR}/.${TEST_BUCKET_1}.stat/${BIG_FILE}
    fi

    #
    # Do a partial write to the file.
    #
    echo -n "0123456789ABCDEF" | dd of=${BIG_FILE} bs=1 count=16 seek=0 conv=notrunc
    echo -n "0123456789ABCDEF" | dd of=${BIG_FILE} bs=1 count=16 seek=8192 conv=notrunc
    echo -n "0123456789ABCDEF" | dd of=${BIG_FILE} bs=1 count=16 seek=1073152 conv=notrunc
    echo -n "0123456789ABCDEF" | dd of=${BIG_FILE} bs=1 count=16 seek=26214400 conv=notrunc
    echo -n "0123456789ABCDEF" | dd of=${BIG_FILE} bs=1 count=16 seek=26222592 conv=notrunc

    rm_test_file "${BIG_FILE}"
}

function test_ut_ossfs {
    describe "Testing ossfs python ut..."
    export TEST_BUCKET_MOUNT_POINT=$TEST_BUCKET_MOUNT_POINT_1
    ../../ut_test.py
}

function add_all_tests {
    if ! ps u $S3FS_PID | grep -q ensure_diskfree && ! uname | grep -q Darwin; then
        add_tests test_clean_up_cache
    fi
    add_tests test_append_file
    add_tests test_truncate_file
    add_tests test_truncate_upload
    add_tests test_truncate_empty_file
    add_tests test_mv_file
    add_tests test_mv_empty_directory
    add_tests test_mv_nonempty_directory
    add_tests test_redirects
    add_tests test_mkdir_rmdir
    add_tests test_chmod
    add_tests test_chown
    add_tests test_list
    add_tests test_remove_nonempty_directory
    if ! ps u $S3FS_PID | grep -q notsup_compat_dir; then
        # TODO: investigate why notsup_compat_dir fails
        add_tests test_external_directory_creation
    fi
    add_tests test_external_modification
    add_tests test_read_external_object
    add_tests test_rename_before_close
    add_tests test_multipart_upload
    add_tests test_multipart_copy
    add_tests test_multipart_mix
    add_tests test_special_characters
    add_tests test_symlink
    add_tests test_extended_attributes
    add_tests test_mtime_file
    add_tests test_update_time
    add_tests test_rm_rf_dir
    add_tests test_copy_file
    add_tests test_write_after_seek_ahead
    add_tests test_overwrite_existing_file_range
    add_tests test_concurrency
    add_tests test_concurrent_writes
    add_tests test_open_second_fd
    add_tests test_write_multiple_offsets
    add_tests test_write_multiple_offsets_backwards
    add_tests test_content_type
    add_tests test_truncate_cache
    add_tests test_upload_sparsefile
    add_tests test_mix_upload_entities
    add_tests test_ut_ossfs
    if `ps -ef | grep -v grep | grep s3fs | grep -q use_cache`; then
        add_tests test_cache_file_stat
    fi
}

init_suite
add_all_tests
run_suite
