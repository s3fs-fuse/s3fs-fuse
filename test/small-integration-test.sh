#!/bin/bash

#
# Test s3fs-fuse file system operations with
#

set -o errexit
set -o pipefail

# Require root
REQUIRE_ROOT=require-root.sh
#source $REQUIRE_ROOT

source integration-test-common.sh

CACHE_DIR="/tmp/s3fs-cache"
rm -rf "${CACHE_DIR}"
mkdir "${CACHE_DIR}"

#reserve 200MB for data cache
source test-utils.sh
CACHE_DISK_AVAIL_SIZE=`get_disk_avail_size $CACHE_DIR`
if [ `uname` = "Darwin" ]; then
    # [FIXME]
    # Only on MacOS, there are cases where process or system
    # other than the s3fs cache uses disk space.
    # We can imagine that this is caused by Timemachine, but
    # there is no workaround, so s3fs cache size is set +1gb
    # for error bypass.
    #
    ENSURE_DISKFREE_SIZE=$((CACHE_DISK_AVAIL_SIZE - 1200))
else
    ENSURE_DISKFREE_SIZE=$((CACHE_DISK_AVAIL_SIZE - 200))
fi

export CACHE_DIR
export ENSURE_DISKFREE_SIZE 
FLAGS=(
    "use_cache=${CACHE_DIR} -o ensure_diskfree=${ENSURE_DISKFREE_SIZE}"
    enable_content_md5
    enable_noobj_cache
    nocopyapi
    nomultipart
    notsup_compat_dir
    sigv2
    singlepart_copy_limit=$((10 * 1024))  # limit size to exercise multipart code paths
    #use_sse  # TODO: S3Proxy does not support SSE
)

start_s3proxy

for flag in "${FLAGS[@]}"; do
    echo "testing s3fs flag: $flag"

    start_s3fs -o $flag

    ./integration-test-main.sh

    stop_s3fs
done

stop_s3proxy

echo "$0: tests complete."
