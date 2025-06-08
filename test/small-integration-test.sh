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

#
# Test s3fs-fuse file system operations with
#

set -o errexit
set -o pipefail

source integration-test-common.sh

CACHE_DIR="/tmp/s3fs-cache"
rm -rf "${CACHE_DIR}"
mkdir "${CACHE_DIR}"

source test-utils.sh

#reserve 200MB for data cache
FAKE_FREE_DISK_SIZE=200
ENSURE_DISKFREE_SIZE=10

# set up client-side encryption keys
head -c 32 < /dev/urandom > /tmp/ssekey.bin
base64 < /tmp/ssekey.bin > /tmp/ssekey
openssl md5 -binary < /tmp/ssekey.bin | base64 > /tmp/ssekeymd5
chmod 600 /tmp/ssekey /tmp/ssekey.bin /tmp/ssekeymd5

export CACHE_DIR
export ENSURE_DISKFREE_SIZE 
if [ -n "${ALL_TESTS}" ]; then
    FLAGS=(
        # TODO: -o update_parent_dir_stat fails due to XMinioInvalidObjectName
        #"use_cache=${CACHE_DIR} -o ensure_diskfree=${ENSURE_DISKFREE_SIZE} -o fake_diskfree=${FAKE_FREE_DISK_SIZE} -o use_xattr -o update_parent_dir_stat"
        enable_content_md5
        disable_noobj_cache
        "max_stat_cache_size=100"
        nocopyapi
        nomultipart
        sigv2
        sigv4
        "singlepart_copy_limit=10"  # limit size to exercise multipart code paths
        #"use_sse"  # TODO: minio needs additional configuration: https://min.io/docs/minio/linux/administration/server-side-encryption/server-side-encryption-sse-kms.html
        "use_sse=custom:/tmp/ssekey"
        "use_cache=${CACHE_DIR} -o ensure_diskfree=${ENSURE_DISKFREE_SIZE} -o fake_diskfree=${FAKE_FREE_DISK_SIZE} -o streamupload"
    )
else
    FLAGS=(
        sigv4
    )
fi

start_s3proxy

# minio puts its objects in .trash until the scanner runs.  Try to make it run faster.
./mc alias set myminio https://127.0.0.1:8080 local-identity local-credential --insecure
./mc admin config set myminio scanner speed=fastest --insecure

if ! aws_cli s3api head-bucket --bucket "${TEST_BUCKET_1}" --region "${S3_ENDPOINT}"; then
    aws_cli s3 mb "s3://${TEST_BUCKET_1}" --region "${S3_ENDPOINT}"
fi

for flag in "${FLAGS[@]}"; do
    echo "testing s3fs flag: ${flag}"

    # shellcheck disable=SC2086
    start_s3fs -o ${flag}

    ./integration-test-main.sh

    stop_s3fs
done

stop_s3proxy

echo "$0: tests complete."

#
# Local variables:
# tab-width: 4
# c-basic-offset: 4
# End:
# vim600: expandtab sw=4 ts=4 fdm=marker
# vim<600: expandtab sw=4 ts=4
#
