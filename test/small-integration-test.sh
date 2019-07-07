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

FLAGS=(
    enable_content_md5
    nocopyapi
    nomultipart
    notsup_compat_dir
    sigv2
    singlepart_copy_limit=$((10 * 1024))  # limit size to exercise multipart code paths
    use_cache="${CACHE_DIR}"
    #use_sse  # TODO: S3Proxy does not support SSE
)

start_s3proxy

for flag in ${FLAGS[*]}; do
    echo "testing s3fs flag: $flag"

    start_s3fs -o $flag

    ./integration-test-main.sh

    stop_s3fs
done

stop_s3proxy

echo "$0: tests complete."
