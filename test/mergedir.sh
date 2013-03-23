#!/bin/sh
#
# Merge old directory object to new.
# For s3fs after v1.64
#

###
### UsageFunction <program name>
###
UsageFuntion()
{
    echo "Usage: $1 [-h] [-y] [-all] <base directory>"
    echo "  -h   print usage"
    echo "  -y   no confirm"
    echo "  -all force all directoris"
    echo "       There is no -all option is only to merge for other S3 client."
    echo "       If -all is specified, this shell script merge all directory"
    echo "       for s3fs old version."
    echo ""
}

### Check parameters
WHOAMI=`whoami`
OWNNAME=`basename $0`
AUTOYES="no"
ALLYES="no"
DIRPARAM=""

while [ "$1" != "" ]; do
    if [ "X$1" = "X-help" -o "X$1" = "X-h" -o "X$1" = "X-H" ]; then
        UsageFuntion $OWNNAME
        exit 0
    elif [ "X$1" = "X-y" -o "X$1" = "X-Y" ]; then
        AUTOYES="yes"
    elif [ "X$1" = "X-all" -o "X$1" = "X-ALL" ]; then
        ALLYES="yes"
    else
        if [ "X$DIRPARAM" != "X" ]; then
            echo "*** Input error."
            echo ""
            UsageFuntion $OWNNAME
            exit 1
        fi
        DIRPARAM=$1
    fi
    shift
done
if [ "X$DIRPARAM" = "X" ]; then
    echo "*** Input error."
    echo ""
    UsageFuntion $OWNNAME
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
echo "And made in other S3 client appilication."
echo "This program may be have bugs which are not fixed yet."
echo "Please execute this program by responsibility of your own."
echo "#############################################################################"
echo ""

DATE=`date +'%Y%m%d-%H%M%S'`
LOGFILE="$OWNNAME-$DATE.log"

echo -n "Start to merge directory object... [$DIRPARAM]"
echo "# Start to merge directory object... [$DIRPARAM]" >> $LOGFILE
echo -n "# DATE :        " >> $LOGFILE
echo `date` >> $LOGFILE
echo -n "# BASEDIR :     " >> $LOGFILE
echo `pwd` >> $LOGFILE
echo -n "# TARGET PATH : " >> $LOGFILE
echo $DIRPARAM >> $LOGFILE
echo  "" >> $LOGFILE

if [ "$AUTOYES" = "yes" ]; then
    echo "(no confirmation)"
else
    echo ""
fi
echo ""

### Get Directory list
DIRLIST=`find $DIRPARAM -type d -print | grep -v ^\.$`

#
# Main loop
#
for DIR in $DIRLIST; do
    ### Skip "." and ".." directories
    BASENAME=`basename $DIR`
    if [ "$BASENAME" = "." -o "$BASENAME" = ".." ]; then
        continue
    fi

    if [ "$ALLYES" = "no" ]; then
        ### Skip "d---------" directories.
        ### Other clients make directory object "dir/" which don't have
        ### "x-amz-meta-mode" attribyte.
        ### Then these directories is "d---------", it is target directory.
        DIRPERMIT=`ls -ld --time-style=+'%Y%m%d%H%M' $DIR | awk '{print $1}'`
        if [ "$DIRPERMIT" != "d---------" ]; then
            continue
        fi
    fi

    ### Comfirm
    ANSWER=""
    if [ "$AUTOYES" = "yes" ]; then
        ANSWER="y"
    fi
    while [ "X$ANSWER" != "XY" -a "X$ANSWER" != "Xy" -a "X$ANSWER" != "XN" -a "X$ANSWER" != "Xn" ]; do
        echo -n "Do you merge $DIR? (y/n): "
        read ANSWER
    done
    if [ "X$ANSWER" != "XY" -a "X$ANSWER" != "Xy" ]; then
        continue
    fi

    ### Do
    CHOWN=`ls -ld --time-style=+'%Y%m%d%H%M' $DIR | awk '{print $3":"$4" "$7}'`
    CHMOD=`ls -ld --time-style=+'%Y%m%d%H%M' $DIR | awk '{print $7}'`
    TOUCH=`ls -ld --time-style=+'%Y%m%d%H%M' $DIR | awk '{print $6" "$7}'`

    echo -n "*** Merge $DIR :	"
    echo -n "	$DIR :		" >> $LOGFILE

    chmod 755 $CHMOD > /dev/null 2>&1
    RESULT=$?
    if [ $RESULT -ne 0 ]; then
        echo "Failed(chmod)"
        echo "Failed(chmod)" >> $LOGFILE
        continue
    fi
    chown $CHOWN > /dev/null 2>&1
    RESULT=$?
    if [ $RESULT -ne 0 ]; then
        echo "Failed(chown)"
        echo "Failed(chown)" >> $LOGFILE
        continue
    fi
    touch -t $TOUCH > /dev/null 2>&1
    RESULT=$?
    if [ $RESULT -ne 0 ]; then
        echo "Failed(touch)"
        echo "Failed(touch)" >> $LOGFILE
        continue
    fi
    echo "Succeed"
    echo "Succeed" >> $LOGFILE
done

echo ""
echo "" >> $LOGFILE
echo "Finished."
echo -n "# Finished : " >> $LOGFILE
echo `date` >> $LOGFILE

#
# END
#
