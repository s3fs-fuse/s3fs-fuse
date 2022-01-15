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

func_usage()
{
    echo ""
    echo "Usage:  $1 [-h] <log file path>"
    echo "        -h                print help"
    echo "        log file path     path for test-suite.log"
    echo ""
}

PRGNAME=$(basename "$0")
SCRIPTDIR=$(dirname "$0")
S3FSDIR=$(cd "${SCRIPTDIR}"/.. || exit 1; pwd)
TOPDIR=$(cd "${S3FSDIR}"/test || exit 1; pwd)
SUITELOG="${TOPDIR}/test-suite.log"
TMP_LINENO_FILE="/tmp/.lineno.tmp"

while [ $# -ne 0 ]; do
    if [ "X$1" = "X" ]; then
        break
    elif [ "X$1" = "X-h" ] || [ "X$1" = "X-H" ] || [ "X$1" = "X--help" ] || [ "X$1" = "X--HELP" ]; then
        func_usage "${PRGNAME}"
        exit 0
    else
        SUITELOG=$1
    fi
    shift
done
if [ ! -f "${SUITELOG}" ]; then
    echo "[ERROR] not found ${SUITELOG} log file."
    exit 1
fi

#
# Extract keyword line numbers and types
#
# 0 : normal line
# 1 : start line for one small test(specified in integration-test-main.sh)
# 2 : passed line of end of one small test(specified in test-utils.sh)
# 3 : failed line of end of one small test(specified in test-utils.sh)
#
grep -n -e 'test_.*: ".*"' -o -e 'test_.* passed' -o -e 'test_.* failed' "${SUITELOG}" 2>/dev/null | sed 's/:test_.*: ".*"/ 1/g' | sed 's/:test_.* passed/ 2/g' | sed 's/:test_.* failed/ 3/g' > "${TMP_LINENO_FILE}"

#
# Loop for printing result
#
prev_line_type=0
prev_line_number=1
while read -r line; do
    # line is "<line number> <line type>"
    #
    # shellcheck disable=SC2206
    number_type=(${line})

    head_line_cnt=$((number_type[0] - 1))
    tail_line_cnt=$((number_type[0] - prev_line_number))

    if [ "${number_type[1]}" -eq 2 ]; then
        echo ""
    fi
    if [ "${prev_line_type}" -eq 1 ]; then
        if [ "${number_type[1]}" -eq 2 ]; then
            # if passed, cut s3fs information messages
            head "-${head_line_cnt}" "${SUITELOG}" | tail "-${tail_line_cnt}" | grep -v -e '[0-9]\+\%' | grep -v -e '^s3fs: ' -a -e '\[INF\]'
        elif [ "${number_type[1]}" -eq 3 ]; then
            # if failed, print all
            head "-${head_line_cnt}" "${SUITELOG}" | tail "-${tail_line_cnt}" | grep -v -e '[0-9]\+\%'
        else
            # there is start keyword but not end keyword, so print all
            head "-${head_line_cnt}" "${SUITELOG}" | tail "-${tail_line_cnt}" | grep -v -e '[0-9]\+\%'
        fi
    elif [ "${prev_line_type}" -eq 2 ] || [ "${prev_line_type}" -eq 3 ]; then
        if [ "${number_type[1]}" -eq 2 ] || [ "${number_type[1]}" -eq 3 ]; then
            # previous is end of chmpx, but this type is end of chmpx without start keyword. then print all
            head "-${head_line_cnt}" "${SUITELOG}" | tail "-${tail_line_cnt}" | grep -v -e '[0-9]\+\%'
        else
            # this area is not from start to end, cut s3fs information messages
            head "-${head_line_cnt}" "${SUITELOG}" | tail "-${tail_line_cnt}" | grep -v -e '[0-9]\+\%' | grep -v -e '^s3fs: ' -a -e '\[INF\]'
        fi
    else
        if [ "${number_type[1]}" -eq 2 ] || [ "${number_type[1]}" -eq 3 ]; then
            # previous is normal, but this type is end of chmpx without start keyword. then print all
            head "-${head_line_cnt}" "${SUITELOG}" | tail "-${tail_line_cnt}" | grep -v -e '[0-9]\+\%'
        else
            # this area is normal, cut s3fs information messages
            head "-${head_line_cnt}" "${SUITELOG}" | tail "-${tail_line_cnt}" | grep -v -e '[0-9]\+\%' | grep -v -e '^s3fs: ' -a -e '\[INF\]'
        fi
    fi
    if [ "${number_type[1]}" -eq 3 ]; then
        echo ""
    fi
    prev_line_type="${number_type[1]}"
    prev_line_number="${number_type[0]}"

done < "${TMP_LINENO_FILE}"

#
# Print rest lines
#
file_line_cnt=$(wc -l "${SUITELOG}" | awk '{print $1}')
tail_line_cnt=$((file_line_cnt - prev_line_number))

if [ "${prev_line_type}" -eq 1 ]; then
    tail "-${tail_line_cnt}" "${SUITELOG}" | grep -v -e '[0-9]\+\%'
else
    tail "-${tail_line_cnt}" "${SUITELOG}" | grep -v -e '[0-9]\+\%' | grep -v -e '^s3fs: ' -a -e '\[INF\]'
fi

#
# Remove temp file
#
rm -f "${TMP_LINENO_FILE}"

exit 0

#
# Local variables:
# tab-width: 4
# c-basic-offset: 4
# End:
# vim600: expandtab sw=4 ts=4 fdm=marker
# vim<600: expandtab sw=4 ts=4
#
