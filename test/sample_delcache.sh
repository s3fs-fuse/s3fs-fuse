#!/bin/sh
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
# This is unsupport sample deleting cache files script.
# So s3fs's local cache files(stats and objects) grow up,
# you need to delete these.
# This script deletes these files with total size limit
# by sorted atime of files.
# You can modify this script for your system.
#
# [Usage] script <bucket name> <cache path> <limit size> [-silent]
#

func_usage()
{
    echo ""
    echo "Usage:  $1 <bucket name> <cache path> <limit size> [-silent]"
    echo "        $1 -h"
    echo "Sample: $1 mybucket /tmp/s3fs/cache 1073741824"
    echo ""
    echo "  bucket name = bucket name which specified s3fs option"
    echo "  cache path  = cache directory path which specified by"
    echo "                use_cache s3fs option."
    echo "  limit size  = limit for total cache files size."
    echo "                specify by BYTE"
    echo "  -silent     = silent mode"
    echo ""
}

PRGNAME=$(basename "$0")

if [ "X$1" = "X-h" ] || [ "X$1" = "X-H" ]; then
    func_usage "${PRGNAME}"
    exit 0
fi
if [ "X$1" = "X" ] || [ "X$2" = "X" ] || [ "X$3" = "X" ]; then
    func_usage "${PRGNAME}"
    exit 1
fi

BUCKET="$1"
CDIR="$2"
LIMIT="$3"
SILENT=0
if [ "X$4" = "X-silent" ]; then
    SILENT=1
fi
FILES_CDIR="${CDIR}/${BUCKET}"
STATS_CDIR="${CDIR}/.${BUCKET}.stat"
CURRENT_CACHE_SIZE=$(du -sb "${FILES_CDIR}" | awk '{print $1}')
#
# Check total size
#
if [ "${LIMIT}" -ge "${CURRENT_CACHE_SIZE}" ]; then
    if [ $SILENT -ne 1 ]; then
        echo "${FILES_CDIR} (${CURRENT_CACHE_SIZE}) is below allowed ${LIMIT}"
    fi
    exit 0
fi

#
# Remove loop
#
TMP_ATIME=0
TMP_STATS=""
TMP_CFILE=""
#
# Make file list by sorted access time
#
find "${STATS_CDIR}" -type f -exec stat -c "%X:%n" "{}" \; | sort | while read -r part
do
    echo "Looking at ${part}"
    TMP_ATIME=$(echo "${part}" | cut -d: -f1)
    TMP_STATS=$(echo "${part}" | cut -d: -f2)
    TMP_CFILE=$(echo "${TMP_STATS}" | sed -e "s/\\.${BUCKET}\\.stat/${BUCKET}/")

    if [ "$(stat -c %X "${TMP_STATS}")" -eq "${TMP_ATIME}" ]; then
        if ! rm "${TMP_STATS}" "${TMP_CFILE}" > /dev/null 2>&1; then
            if [ "${SILENT}" -ne 1 ]; then
                echo "ERROR: Could not remove files(${TMP_STATS},${TMP_CFILE})"
            fi
            exit 1
        else
            if [ "${SILENT}" -ne 1 ]; then
                echo "remove file: ${TMP_CFILE}	${TMP_STATS}"
            fi
        fi
    fi
    if [ "${LIMIT}" -ge "$(du -sb "${FILES_CDIR}" | awk '{print $1}')" ]; then
        if [ "${SILENT}" -ne 1 ]; then
            echo "finish removing files"
        fi
        break
    fi
done

if [ "${SILENT}" -ne 1 ]; then
    TOTAL_SIZE=$(du -sb "${FILES_CDIR}" | awk '{print $1}')
    echo "Finish: ${FILES_CDIR} total size is ${TOTAL_SIZE}"
fi

exit 0

#
# Local variables:
# tab-width: 4
# c-basic-offset: 4
# End:
# vim600: expandtab sw=4 ts=4 fdm=marker
# vim<600: expandtab sw=4 ts=4
#
