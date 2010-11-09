#!/bin/bash -e

if [[ $EUID -ne 0 ]]
then
	echo "This test script must be run as root" 1>&2
	exit 1
fi
