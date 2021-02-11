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
    max_stat_cache_size=100
    nocopyapi
    nomultipart
    notsup_compat_dir
    sigv2
    sigv4
    singlepart_copy_limit=10  # limit size to exercise multipart code paths
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

#
# Local variables:
# tab-width: 4
# c-basic-offset: 4
# End:
# vim600: expandtab sw=4 ts=4 fdm=marker
# vim<600: expandtab sw=4 ts=4
#
