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
        "use_cache=${CACHE_DIR} -o ensure_diskfree=${ENSURE_DISKFREE_SIZE} -o fake_diskfree=${FAKE_FREE_DISK_SIZE} -o use_xattr -o update_parent_dir_stat"
        enable_content_md5
        disable_noobj_cache
        "max_stat_cache_size=100"
        nocopyapi
        nomultipart
        sigv2
        sigv4
        "singlepart_copy_limit=10 -o multipart_copy_size=10"  # limit sizes to exercise multipart copy code paths
        #use_sse  # TODO: S3Proxy does not support SSE
        #use_sse=custom:/tmp/ssekey  # TODO: S3Proxy does not support SSE
        "use_cache=${CACHE_DIR} -o ensure_diskfree=${ENSURE_DISKFREE_SIZE} -o fake_diskfree=${FAKE_FREE_DISK_SIZE} -o streamupload"
        hard_remove  # exercise null-path file handle operations
    )
else
    FLAGS=(
        sigv4
    )
fi

start_s3proxy

if ! s3_head "${TEST_BUCKET_1}"; then
    s3_mb "${TEST_BUCKET_1}"
fi

# Regression test for the bucket check at startup: mounting a bucket
# that does not exist must fail promptly instead of retrying forever.
function test_mount_nonexistent_bucket {
    echo "testing mount of nonexistent bucket"

    local bucket="s3fs-nonexistent-bucket-$$"
    local mountpoint="nonexistent-bucket-mountpoint"
    local logfile="nonexistent-bucket-s3fs.log"

    if [ -n "${PUBLIC}" ]; then
        local AUTH_OPT="-o public_bucket=1"
    elif [ -n "${S3FS_PROFILE}" ]; then
        local AUTH_OPT="-o profile=${S3FS_PROFILE}"
    else
        local AUTH_OPT="-o passwd_file=${S3FS_CREDENTIALS_FILE}"
    fi

    mkdir -p "${mountpoint}"

    # shellcheck disable=SC2086
    CURL_CA_BUNDLE="${S3PROXY_CACERT_FILE}" "${S3FS}" "${bucket}" "${mountpoint}" \
        -o use_path_request_style \
        -o url="${S3_URL}" \
        -o region="${S3_ENDPOINT}" \
        ${AUTH_OPT} \
        -o dbglevel="${DBGLEVEL:=info}" \
        -o retries=3 \
        -f > "${logfile}" 2>&1 &
    local pid=$!

    # s3fs must exit on its own; give it 30 seconds before declaring a hang
    local rc=""
    for _ in $(seq 300); do
        if ! kill -0 "${pid}" 2>/dev/null; then
            rc=0
            wait "${pid}" || rc=$?
            break
        fi
        sleep 0.1
    done

    if [ -z "${rc}" ]; then
        kill -9 "${pid}" 2>/dev/null || true
        fusermount3 -u "${mountpoint}" 2>/dev/null || umount "${mountpoint}" 2>/dev/null || true
        cat "${logfile}"
        echo "s3fs did not exit after mounting nonexistent bucket: ${bucket}"
        return 1
    fi
    if [ "${rc}" -eq 0 ]; then
        cat "${logfile}"
        echo "s3fs unexpectedly succeeded mounting nonexistent bucket: ${bucket}"
        return 1
    fi
    if ! grep -q "Bucket or directory not found" "${logfile}"; then
        cat "${logfile}"
        echo "s3fs did not report a missing bucket: ${bucket}"
        return 1
    fi

    rm -f "${logfile}"
    rmdir "${mountpoint}"
}

test_mount_nonexistent_bucket

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
