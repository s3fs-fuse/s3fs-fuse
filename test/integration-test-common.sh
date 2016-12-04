#!/bin/bash

#
# Common code for starting an s3fs-fuse mountpoint and an S3Proxy instance 
# to run tests against S3Proxy locally.
#
# To run against an Amazon S3 or other S3 provider, specify the following 
# environment variables:
#
# S3FS_CREDENTIALS_FILE=keyfile      s3fs format key file
# TEST_BUCKET_1=bucketname           Name of bucket to use 
# S3PROXY_BINARY=""                  Specify empty string to skip S3Proxy start
# S3_URL="http://s3.amazonaws.com"   Specify Amazon AWS as the S3 provider 
#
# Example of running against Amazon S3 using a bucket named "bucket:
#
# S3FS_CREDENTIALS_FILE=keyfile TEST_BUCKET_1=bucket S3PROXY_BINARY="" S3_URL="http://s3.amazonaws.com" ./small-integration-test.sh
#
# To change the s3fs-fuse debug level:
#
#    DBGLEVEL=debug ./small-integration-test.sh
# 
# To stop and wait after the mount point is up for manual interaction. This allows you to
# explore the mounted file system exactly as it would have been started for the test case
#
#    INTERACT=1 DBGLEVEL=debug ./small-integration-test.sh
#
# Run all of the tests from the makefile
#
#    S3FS_CREDENTIALS_FILE=keyfile TEST_BUCKET_1=bucket S3PROXY_BINARY="" S3_URL="http://s3.amazonaws.com" make check
#
# Run the tests with request auth turned off in both S3Proxy and s3fs-fuse.  This can be
# useful for poking around with plain old curl
#
#    PUBLIC=1 INTERACT=1 ./small-integration-test.sh 
#
# A valgrind tool can be specified
# eg: VALGRIND="--tool=memcheck --leak-check=full" ./small-integration-test.sh

set -o errexit
S3FS=../src/s3fs

# Allow these defaulted values to be overridden
: ${S3_URL:="http://127.0.0.1:8080"}
: ${S3FS_CREDENTIALS_FILE:="passwd-s3fs"}
: ${TEST_BUCKET_1:="s3fs-integration-test"}

export TEST_BUCKET_1
export S3_URL
export TEST_SCRIPT_DIR=`pwd`
export TEST_BUCKET_MOUNT_POINT_1=${TEST_BUCKET_1}

S3PROXY_VERSION="1.5.1"
S3PROXY_BINARY=${S3PROXY_BINARY-"s3proxy-${S3PROXY_VERSION}"}

if [ ! -f "$S3FS_CREDENTIALS_FILE" ]
then
	echo "Missing credentials file: $S3FS_CREDENTIALS_FILE"
	exit 1
fi
chmod 600 "$S3FS_CREDENTIALS_FILE"

if [ ! -d $TEST_BUCKET_MOUNT_POINT_1 ]
then
	mkdir -p $TEST_BUCKET_MOUNT_POINT_1
fi

# This function execute the function parameters $1 times
# before giving up, with 1 second delays.
function retry {
    set +o errexit
    N=$1; shift;
    status=0
    for i in $(seq $N); do
        echo "Trying: $@"
        $@
        status=$?
        if [ $status == 0 ]; then
            break
        fi
        sleep 1
        echo "Retrying: $@"
    done

    if [ $status != 0 ]; then
        echo "timeout waiting for $@"
    fi
    set -o errexit
    return $status
}

# Proxy is not started if S3PROXY_BINARY is an empty string
# PUBLIC unset: use s3proxy.conf
# PUBLIC=1:     use s3proxy-noauth.conf (no request signing)
# 
function start_s3proxy {
    if [ -n "${PUBLIC}" ]; then
        S3PROXY_CONFIG="s3proxy-noauth.conf"
    else
        S3PROXY_CONFIG="s3proxy.conf"
    fi

    if [ -n "${S3PROXY_BINARY}" ]
    then
        if [ ! -e "${S3PROXY_BINARY}" ]; then
            wget "https://github.com/andrewgaul/s3proxy/releases/download/s3proxy-${S3PROXY_VERSION}/s3proxy" \
                --quiet -O "${S3PROXY_BINARY}"
            chmod +x "${S3PROXY_BINARY}"
        fi

        stdbuf -oL -eL java -jar "$S3PROXY_BINARY" --properties $S3PROXY_CONFIG | stdbuf -oL -eL sed -u "s/^/s3proxy: /" &

        # wait for S3Proxy to start
        for i in $(seq 30);
        do
            if exec 3<>"/dev/tcp/127.0.0.1/8080";
            then
                exec 3<&-  # Close for read
                exec 3>&-  # Close for write
                break
            fi
            sleep 1
        done

        S3PROXY_PID=$(netstat -lpnt | grep :8080 | awk '{ print $7 }' | sed -u 's|/java||')
    fi
}

function stop_s3proxy {
    if [ -n "${S3PROXY_PID}" ]
    then
        kill $S3PROXY_PID
        wait $S3PROXY_PID
    fi
}

# Mount the bucket, function arguments passed to s3fs in addition to
# a set of common arguments.  
function start_s3fs {

    # Public bucket if PUBLIC is set
    if [ -n "${PUBLIC}" ]; then
        AUTH_OPT="-o public_bucket=1"
    else
        AUTH_OPT="-o passwd_file=${S3FS_CREDENTIALS_FILE}"
    fi

    # If VALGRIND is set, pass it as options to valgrind.
    # start valgrind-listener in another shell. 
    # eg: VALGRIND="--tool=memcheck --leak-check=full" ./small-integration-test.sh
    # Start valgind-listener (default port is 1500)
    if [ -n "${VALGRIND}" ]; then
        VALGRIND_EXEC="valgrind ${VALGRIND} --log-socket=127.0.1.1"
    fi

    # Common s3fs options:
    #
    # TODO: Allow all these options to be overriden with env variables
    #
    # use_path_request_style
    #     The test env doesn't have virtual hosts
    # createbucket
    #     S3Proxy always starts with no buckets, this tests the s3fs-fuse
    #     automatic bucket creation path.
    # $AUTH_OPT
    #     Will be either "-o public_bucket=1" 
    #                     or 
    #     "-o passwd_file=${S3FS_CREDENTIALS_FILE}"
    # dbglevel
    #     error by default.  override with DBGLEVEL env variable
    # -f
    #     Keep s3fs in foreground instead of daemonizing
    #

    # subshell with set -x to log exact invocation of s3fs-fuse
    (
        set -x 
        stdbuf -oL -eL \
            ${VALGRIND_EXEC} ${S3FS} \
            $TEST_BUCKET_1 \
            $TEST_BUCKET_MOUNT_POINT_1 \
            -o use_path_request_style \
            -o url=${S3_URL} \
            -o createbucket \
            ${AUTH_OPT} \
            -o dbglevel=${DBGLEVEL:=info} \
            -f \
            ${@} \
        |& stdbuf -oL -eL sed -u "s/^/s3fs: /" &
    )

    retry 5 grep -q $TEST_BUCKET_MOUNT_POINT_1 /proc/mounts || exit 1

    # Quick way to start system up for manual testing with options under test
    if [[ -n ${INTERACT} ]]; then
        echo "Mountpoint $TEST_BUCKET_MOUNT_POINT_1  is ready"
        echo "control-C to quit"
        sleep infinity
        exit 0
    fi
}

function stop_s3fs {
    # Retry in case file system is in use
    if grep -q $TEST_BUCKET_MOUNT_POINT_1 /proc/mounts; then 
        retry 10 grep -q $TEST_BUCKET_MOUNT_POINT_1 /proc/mounts && fusermount -u $TEST_BUCKET_MOUNT_POINT_1
    fi
}

# trap handlers do not stack.  If a test sets its own, the new handler should call common_exit_handler
function common_exit_handler {
    stop_s3proxy
    stop_s3fs
}
trap common_exit_handler EXIT
