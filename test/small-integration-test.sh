#!/bin/bash -e

# Require root
REQUIRE_ROOT=require-root.sh
#source $REQUIRE_ROOT
source integration-test-common.sh

java -jar "$S3PROXY_BINARY" --properties s3proxy.conf &
S3PROXY_PID="$?"

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

# Mount the bucket
if [ ! -d $TEST_BUCKET_MOUNT_POINT_1 ]
then
	mkdir -p $TEST_BUCKET_MOUNT_POINT_1
fi
$S3FS $TEST_BUCKET_1 $TEST_BUCKET_MOUNT_POINT_1 \
    -o createbucket \
    -o passwd_file=$S3FS_CREDENTIALS_FILE \
    -o sigv2 \
    -o url=http://127.0.0.1:8080 \
    -o use_path_request_style

./integration-test-main.sh $TEST_BUCKET_MOUNT_POINT_1

umount $TEST_BUCKET_MOUNT_POINT_1

kill $S3PROXY_PID

echo "All tests complete."
