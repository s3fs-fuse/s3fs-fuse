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
# Merge old directory object to new.
# For s3fs after v1.64
#

###
### UsageFunction <program name>
###
UsageFunction()
{
    echo "Usage: $1 [-h] [-y] [-all] <base directory>"
    echo "  -h   print usage"
    echo "  -y   no confirm"
    echo "  -all force all directories"
    echo "       There is no -all option is only to merge for other S3 client."
    echo "       If -all is specified, this shell script merge all directory"
    echo "       for s3fs old version."
    echo ""
}

### Check parameters
WHOAMI=$(whoami)
OWNNAME=$(basename "$0")
AUTOYES="no"
ALLYES="no"
DIRPARAM=""

while [ "$1" != "" ]; do
    if [ "X$1" = "X-help" ] || [ "X$1" = "X-h" ] || [ "X$1" = "X-H" ]; then
        UsageFunction "${OWNNAME}"
        exit 0
    elif [ "X$1" = "X-y" ] || [ "X$1" = "X-Y" ]; then
        AUTOYES="yes"
    elif [ "X$1" = "X-all" ] || [ "X$1" = "X-ALL" ]; then
        ALLYES="yes"
    else
        if [ "X$DIRPARAM" != "X" ]; then
            echo "*** Input error."
            echo ""
            UsageFunction "${OWNNAME}"
            exit 1
        fi
        DIRPARAM=$1
    fi
    shift
done
if [ "X$DIRPARAM" = "X" ]; then
    echo "*** Input error."
    echo ""
    UsageFunction "${OWNNAME}"
    exit 1
fi

if [ "$WHOAMI" != "root" ]; then
    echo ""
    echo "Warning: You run this script by $WHOAMI, should be root."
    echo ""
fi

### Caution
echo "#############################################################################"
echo "[CAUTION]"
echo "This program merges a directory made in s3fs which is older than version 1.64."
echo "And made in other S3 client application."
echo "This program may be have bugs which are not fixed yet."
echo "Please execute this program by responsibility of your own."
echo "#############################################################################"
echo ""

DATE=$(date +'%Y%m%d-%H%M%S')
LOGFILE="${OWNNAME}-${DATE}.log"

echo "Start to merge directory object... [${DIRPARAM}]"
{
	echo "# Start to merge directory object... [${DIRPARAM}]"
	echo "# DATE :        $(date)"
	echo "# BASEDIR :     $(pwd)"
	echo "# TARGET PATH : ${DIRPARAM}"
	echo  ""
} > "${LOGFILE}"

if [ "$AUTOYES" = "yes" ]; then
    echo "(no confirmation)"
else
    echo ""
fi
echo ""

### Get Directory list
DIRLIST=$(find "${DIRPARAM}" -type d -print | grep -v ^\.$)

#
# Main loop
#
for DIR in $DIRLIST; do
    ### Skip "." and ".." directories
    BASENAME=$(basename "${DIR}")
    if [ "${BASENAME}" = "." ] || [ "${BASENAME}" = ".." ]; then
        continue
    fi

    if [ "${ALLYES}" = "no" ]; then
        ### Skip "d---------" directories.
        ### Other clients make directory object "dir/" which don't have
        ### "x-amz-meta-mode" attribute.
        ### Then these directories is "d---------", it is target directory.

        # shellcheck disable=SC2012
        DIRPERMIT=$(ls -ld --time-style=+'%Y%m%d%H%M' "${DIR}" | awk '{print $1}')
        if [ "${DIRPERMIT}" != "d---------" ]; then
            continue
        fi
    fi

    ### Confirm
    ANSWER=""
    if [ "${AUTOYES}" = "yes" ]; then
        ANSWER="y"
    fi
    while [ "X${ANSWER}" != "XY" ] && [ "X${ANSWER}" != "Xy" ] && [ "X${ANSWER}" != "XN" ] && [ "X${ANSWER}" != "Xn" ]; do
        printf "%s" "Do you merge ${DIR} ? (y/n): "
        read -r ANSWER
    done
    if [ "X${ANSWER}" != "XY" ] && [ "X${ANSWER}" != "Xy" ]; then
        continue
    fi

    ### Do
    # shellcheck disable=SC2012
    CHOWN=$(ls -ld --time-style=+'%Y%m%d%H%M' "${DIR}" | awk '{print $3":"$4" "$7}')
    # shellcheck disable=SC2012
    CHMOD=$(ls -ld --time-style=+'%Y%m%d%H%M' "${DIR}" | awk '{print $7}')
    # shellcheck disable=SC2012
    TOUCH=$(ls -ld --time-style=+'%Y%m%d%H%M' "${DIR}" | awk '{print $6" "$7}')

    printf "%s" "*** Merge ${DIR} :	"
    printf "%s" "	${DIR} :		" >> "${LOGFILE}"

    chmod 755 "${CHMOD}" > /dev/null 2>&1
    RESULT=$?
    if [ "${RESULT}" -ne 0 ]; then
        echo "Failed(chmod)"
        echo "Failed(chmod)" >> "${LOGFILE}"
        continue
    fi
    chown "${CHOWN}" > /dev/null 2>&1
    RESULT=$?
    if [ "${RESULT}" -ne 0 ]; then
        echo "Failed(chown)"
        echo "Failed(chown)" >> "${LOGFILE}"
        continue
    fi
    touch -t "${TOUCH}" > /dev/null 2>&1
    RESULT=$?
    if [ "${RESULT}" -ne 0 ]; then
        echo "Failed(touch)"
        echo "Failed(touch)" >> "${LOGFILE}"
        continue
    fi
    echo "Succeed"
    echo "Succeed" >> "${LOGFILE}"
done

echo ""
echo "" >> "${LOGFILE}"
echo "Finished."
echo "# Finished : $(date)" >> "${LOGFILE}"

#
# Local variables:
# tab-width: 4
# c-basic-offset: 4
# End:
# vim600: expandtab sw=4 ts=4 fdm=marker
# vim<600: expandtab sw=4 ts=4
#
