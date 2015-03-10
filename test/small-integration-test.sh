#!/bin/bash

set -o xtrace
set -o errexit

# Require root
REQUIRE_ROOT=require-root.sh
#source $REQUIRE_ROOT
source integration-test-common.sh

function retry {
    set +o errexit
    N=$1; shift;
    status=0
    for i in $(seq $N); do
        $@
        status=$?
        if [ $status == 0 ]; then
            break
        fi
        sleep 1
    done

    if [ $status != 0 ]; then
        echo "timeout waiting for $@"
    fi
    set -o errexit
    return $status
}

function exit_handler {
    kill $S3PROXY_PID
    retry 30 fusermount -u $TEST_BUCKET_MOUNT_POINT_1
}
trap exit_handler EXIT

stdbuf -oL -eL java -jar "$S3PROXY_BINARY" --properties s3proxy.conf | stdbuf -oL -eL sed -u "s/^/s3proxy: /" &

# wait for S3Proxy to start
for i in $(seq 30);
do
    if exec 3<>"/dev/tcp/localhost/8080";
    then
        exec 3<&-  # Close for read
        exec 3>&-  # Close for write
        break
    fi
    sleep 1
done

S3PROXY_PID=$(netstat -lpnt | grep :8080 | awk '{ print $7 }' | sed -u 's|/java||')

# Mount the bucket
if [ ! -d $TEST_BUCKET_MOUNT_POINT_1 ]
then
	mkdir -p $TEST_BUCKET_MOUNT_POINT_1
fi
stdbuf -oL -eL $S3FS $TEST_BUCKET_1 $TEST_BUCKET_MOUNT_POINT_1 \
    -o createbucket \
    -o passwd_file=$S3FS_CREDENTIALS_FILE \
    -o sigv2 \
    -o url=http://127.0.0.1:8080 \
    -o use_path_request_style -f -o f2 -d -d |& stdbuf -oL -eL sed -u "s/^/s3fs: /" &

retry 30 grep $TEST_BUCKET_MOUNT_POINT_1 /proc/mounts || exit 1

./integration-test-main.sh $TEST_BUCKET_MOUNT_POINT_1

echo "All tests complete."
