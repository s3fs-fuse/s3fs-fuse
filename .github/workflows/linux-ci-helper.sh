#!/bin/sh
#
# s3fs - FUSE-based file system backed by Amazon S3
#
# Copyright(C) 2007 Takeshi Nakatani <ggtakec.com>
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

# [NOTE]
# Since bash is not present in some Runner containers, this script
# runs in sh.
# pipefail etc. are not native variables of sh. It exists in bash's
# sh compatibility mode, but doesn't work in sh compatibility mode
# of ash such as alpine.
# However, it's not fatal that pipefail doesn't work for this script.
#
set -o errexit
set -o nounset
#set -o pipefail

#-----------------------------------------------------------
# Common variables
#-----------------------------------------------------------
PRGNAME=$(basename "$0")

echo "${PRGNAME} [INFO] Start Linux helper for installing packages."

#-----------------------------------------------------------
# Parameter check
#-----------------------------------------------------------
#
# Usage: ${PRGNAME} "OS:VERSION"
#
if [ $# -ne 1 ]; then
    echo "${PRGNAME} [ERROR] No container name options specified."
fi

#-----------------------------------------------------------
# Container OS variables
#-----------------------------------------------------------
CONTAINER_FULLNAME=$1
# shellcheck disable=SC2034
CONTAINER_OSNAME=$(echo "${CONTAINER_FULLNAME}" | sed 's/:/ /g' | awk '{print $1}')
# shellcheck disable=SC2034
CONTAINER_OSVERSION=$(echo "${CONTAINER_FULLNAME}" | sed 's/:/ /g' | awk '{print $2}')

#-----------------------------------------------------------
# Common variables for awscli2
#-----------------------------------------------------------
AWSCLI_URI="https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip"
AWSCLI_ZIP_FILE="awscliv2.zip"

#-----------------------------------------------------------
# Parameters for configure(set environments)
#-----------------------------------------------------------
CXXFLAGS="-O -DS3FS_PTHREAD_ERRORCHECK=1"
CONFIGURE_OPTIONS="--prefix=/usr --with-openssl"

#-----------------------------------------------------------
# OS dependent variables
#-----------------------------------------------------------
#
# Default values
#
PACKAGE_ENABLE_REPO_OPTIONS=""
PACKAGE_INSTALL_ADDITIONAL_OPTIONS=""
SHELLCHECK_DIRECT_INSTALL=0
AWSCLI_DIRECT_INSTALL=1

if [ "${CONTAINER_FULLNAME}" = "ubuntu:23.10" ]; then
    PACKAGE_MANAGER_BIN="apt-get"
    PACKAGE_UPDATE_OPTIONS="update -y -qq"
    PACKAGE_INSTALL_OPTIONS="install -y"

    INSTALL_PACKAGES="autoconf autotools-dev clang-tidy openjdk-21-jre-headless fuse jq libfuse-dev libcurl4-openssl-dev libxml2-dev locales-all mime-support libtool pkg-config libssl-dev attr curl python3-pip unzip"
    INSTALL_CHECKER_PKGS="cppcheck shellcheck"
    INSTALL_CHECKER_PKG_OPTIONS=""

elif [ "${CONTAINER_FULLNAME}" = "ubuntu:22.04" ]; then
    PACKAGE_MANAGER_BIN="apt-get"
    PACKAGE_UPDATE_OPTIONS="update -y -qq"
    PACKAGE_INSTALL_OPTIONS="install -y"

    INSTALL_PACKAGES="autoconf autotools-dev clang-tidy openjdk-17-jre-headless fuse jq libfuse-dev libcurl4-openssl-dev libxml2-dev locales-all mime-support libtool pkg-config libssl-dev attr curl python3-pip unzip"
    INSTALL_CHECKER_PKGS="cppcheck shellcheck"
    INSTALL_CHECKER_PKG_OPTIONS=""

elif [ "${CONTAINER_FULLNAME}" = "ubuntu:20.04" ]; then
    PACKAGE_MANAGER_BIN="apt-get"
    PACKAGE_UPDATE_OPTIONS="update -y -qq"
    PACKAGE_INSTALL_OPTIONS="install -y"

    INSTALL_PACKAGES="autoconf autotools-dev clang-tidy openjdk-17-jre-headless fuse jq libfuse-dev libcurl4-openssl-dev libxml2-dev locales-all mime-support libtool pkg-config libssl-dev attr curl python3-pip unzip"
    INSTALL_CHECKER_PKGS="cppcheck shellcheck"
    INSTALL_CHECKER_PKG_OPTIONS=""

elif [ "${CONTAINER_FULLNAME}" = "debian:bookworm" ]; then
    PACKAGE_MANAGER_BIN="apt-get"
    PACKAGE_UPDATE_OPTIONS="update -y -qq"
    PACKAGE_INSTALL_OPTIONS="install -y"

    INSTALL_PACKAGES="autoconf autotools-dev clang-tidy openjdk-17-jre-headless fuse jq libfuse-dev libcurl4-openssl-dev libxml2-dev locales-all mime-support libtool pkg-config libssl-dev attr curl procps python3-pip unzip"
    INSTALL_CHECKER_PKGS="cppcheck shellcheck"
    INSTALL_CHECKER_PKG_OPTIONS=""

elif [ "${CONTAINER_FULLNAME}" = "debian:bullseye" ]; then
    PACKAGE_MANAGER_BIN="apt-get"
    PACKAGE_UPDATE_OPTIONS="update -y -qq"
    PACKAGE_INSTALL_OPTIONS="install -y"

    INSTALL_PACKAGES="autoconf autotools-dev clang-tidy openjdk-17-jre-headless fuse jq libfuse-dev libcurl4-openssl-dev libxml2-dev locales-all mime-support libtool pkg-config libssl-dev attr curl procps python3-pip unzip"
    INSTALL_CHECKER_PKGS="cppcheck shellcheck"
    INSTALL_CHECKER_PKG_OPTIONS=""

elif [ "${CONTAINER_FULLNAME}" = "debian:buster" ]; then
    PACKAGE_MANAGER_BIN="apt-get"
    PACKAGE_UPDATE_OPTIONS="update -y -qq"
    PACKAGE_INSTALL_OPTIONS="install -y"

    INSTALL_PACKAGES="autoconf autotools-dev clang-tidy default-jre-headless fuse jq libfuse-dev libcurl4-openssl-dev libxml2-dev locales-all mime-support libtool pkg-config libssl-dev attr curl procps python3-pip unzip"
    INSTALL_CHECKER_PKGS="cppcheck shellcheck"
    INSTALL_CHECKER_PKG_OPTIONS=""

elif [ "${CONTAINER_FULLNAME}" = "rockylinux:9" ]; then
    PACKAGE_MANAGER_BIN="dnf"
    PACKAGE_UPDATE_OPTIONS="update -y -qq"
    PACKAGE_INSTALL_OPTIONS="install -y"
    PACKAGE_ENABLE_REPO_OPTIONS="--enablerepo=crb"

    # [NOTE]
    # Rocky Linux 9 (or CentOS Stream 9) images may have curl installation issues that
    # conflict with the curl-minimal package.
    #
    PACKAGE_INSTALL_ADDITIONAL_OPTIONS="--allowerasing"

    INSTALL_PACKAGES="clang-tools-extra curl-devel fuse fuse-devel gcc libstdc++-devel gcc-c++ glibc-langpack-en java-17-openjdk-headless jq libxml2-devel mailcap git automake make openssl openssl-devel attr diffutils curl python3 procps unzip xz https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm"
    INSTALL_CHECKER_PKGS="cppcheck"
    INSTALL_CHECKER_PKG_OPTIONS="--enablerepo=epel"

    # [NOTE]
    # For RockyLinux, ShellCheck is downloaded from the github archive and installed.
    #
    SHELLCHECK_DIRECT_INSTALL=1

elif [ "${CONTAINER_FULLNAME}" = "rockylinux:8" ]; then
    PACKAGE_MANAGER_BIN="dnf"
    PACKAGE_UPDATE_OPTIONS="update -y -qq"
    PACKAGE_INSTALL_OPTIONS="install -y"

    INSTALL_PACKAGES="clang-tools-extra curl-devel fuse fuse-devel gcc libstdc++-devel gcc-c++ glibc-langpack-en java-17-openjdk-headless jq libxml2-devel mailcap git automake make openssl openssl-devel attr diffutils curl python3 unzip"
    INSTALL_CHECKER_PKGS="cppcheck"
    INSTALL_CHECKER_PKG_OPTIONS="--enablerepo=powertools"

    # [NOTE]
    # For RockyLinux, ShellCheck is downloaded from the github archive and installed.
    #
    SHELLCHECK_DIRECT_INSTALL=1

elif [ "${CONTAINER_FULLNAME}" = "centos:centos7" ]; then
    PACKAGE_MANAGER_BIN="yum"
    PACKAGE_UPDATE_OPTIONS="update -y"
    PACKAGE_INSTALL_OPTIONS="install -y"

    # [NOTE]
    # ShellCheck version(0.3.8) is too low to check.
    # And in this version, it cannot be passed due to following error.
    # "shellcheck: ./test/integration-test-main.sh: hGetContents: invalid argument (invalid byte sequence)"
    #
    INSTALL_PACKAGES="curl-devel fuse fuse-devel gcc libstdc++-devel llvm-toolset-7-clang-tools-extra gcc-c++ glibc-langpack-en java-11-openjdk-headless libxml2-devel mailcap git automake make openssl openssl-devel attr curl python3 epel-release unzip"
    INSTALL_CHECKER_PKGS="cppcheck jq"
    INSTALL_CHECKER_PKG_OPTIONS="--enablerepo=epel"

elif [ "${CONTAINER_FULLNAME}" = "fedora:39" ]; then
    PACKAGE_MANAGER_BIN="dnf"
    PACKAGE_UPDATE_OPTIONS="update -y -qq"
    PACKAGE_INSTALL_OPTIONS="install -y"

    INSTALL_PACKAGES="clang-tools-extra curl-devel fuse fuse-devel gcc libstdc++-devel gcc-c++ glibc-langpack-en java-latest-openjdk-headless jq libxml2-devel mailcap git automake make openssl openssl-devel curl attr diffutils procps python3-pip unzip"
    INSTALL_CHECKER_PKGS="cppcheck ShellCheck"
    INSTALL_CHECKER_PKG_OPTIONS=""

elif [ "${CONTAINER_FULLNAME}" = "fedora:38" ]; then
    PACKAGE_MANAGER_BIN="dnf"
    PACKAGE_UPDATE_OPTIONS="update -y -qq"
    PACKAGE_INSTALL_OPTIONS="install -y"

    INSTALL_PACKAGES="clang-tools-extra curl-devel fuse fuse-devel gcc libstdc++-devel gcc-c++ glibc-langpack-en java-latest-openjdk-headless jq libxml2-devel mailcap git automake make openssl openssl-devel curl attr diffutils procps python3-pip unzip"
    INSTALL_CHECKER_PKGS="cppcheck ShellCheck"
    INSTALL_CHECKER_PKG_OPTIONS=""

elif [ "${CONTAINER_FULLNAME}" = "opensuse/leap:15" ]; then
    PACKAGE_MANAGER_BIN="zypper"
    PACKAGE_UPDATE_OPTIONS="refresh"
    PACKAGE_INSTALL_OPTIONS="install -y"

    INSTALL_PACKAGES="automake clang-tools curl-devel fuse fuse-devel gcc-c++ java-17-openjdk-headless jq libxml2-devel make openssl openssl-devel python3-pip curl attr ShellCheck unzip"
    INSTALL_CHECKER_PKGS="cppcheck ShellCheck"
    INSTALL_CHECKER_PKG_OPTIONS=""

elif [ "${CONTAINER_FULLNAME}" = "alpine:3.19" ]; then
    PACKAGE_MANAGER_BIN="apk"
    PACKAGE_UPDATE_OPTIONS="update --no-progress"
    PACKAGE_INSTALL_OPTIONS="add --no-progress --no-cache"

    INSTALL_PACKAGES="bash clang-extra-tools curl g++ make automake autoconf libtool git curl-dev fuse-dev jq libxml2-dev openssl coreutils procps attr sed mailcap openjdk17 aws-cli"
    INSTALL_CHECKER_PKGS="cppcheck shellcheck"
    INSTALL_CHECKER_PKG_OPTIONS=""

    AWSCLI_DIRECT_INSTALL=0

else
    echo "No container configured for: ${CONTAINER_FULLNAME}"
    exit 1
fi

#-----------------------------------------------------------
# Install
#-----------------------------------------------------------
#
# Update packages (ex. apt-get update -y -qq)
#
echo "${PRGNAME} [INFO] Updates."
/bin/sh -c "${PACKAGE_MANAGER_BIN} ${PACKAGE_UPDATE_OPTIONS}"

#
# Install packages ( with cppcheck )
#
echo "${PRGNAME} [INFO] Install packages."
/bin/sh -c "${PACKAGE_MANAGER_BIN} ${PACKAGE_ENABLE_REPO_OPTIONS} ${PACKAGE_INSTALL_OPTIONS} ${PACKAGE_INSTALL_ADDITIONAL_OPTIONS} ${INSTALL_PACKAGES}"

echo "${PRGNAME} [INFO] Install cppcheck package."
/bin/sh -c "${PACKAGE_MANAGER_BIN} ${INSTALL_CHECKER_PKG_OPTIONS} ${PACKAGE_INSTALL_OPTIONS} ${INSTALL_CHECKER_PKGS}"

#
# Install ShellCheck manually
#
if [ "${SHELLCHECK_DIRECT_INSTALL}" -eq 1 ]; then
    echo "${PRGNAME} [INFO] Install shellcheck package from github archive."

    if ! LATEST_SHELLCHECK_DOWNLOAD_URL=$(curl --silent --show-error https://api.github.com/repos/koalaman/shellcheck/releases/latest | jq -r '.assets[].browser_download_url | select(contains("linux.x86_64"))'); then
        echo "Could not get shellcheck package url"
        exit 1
    fi
    if ! curl -s -S -L -o /tmp/shellcheck.tar.xz "${LATEST_SHELLCHECK_DOWNLOAD_URL}"; then
        echo "Failed to download shellcheck package from ${LATEST_SHELLCHECK_DOWNLOAD_URL}"
        exit 1
    fi
    if ! tar -C /usr/bin/ -xf /tmp/shellcheck.tar.xz --no-anchored 'shellcheck' --strip=1; then
        echo "Failed to extract and install shellcheck."
        rm -f /tmp/shellcheck.tar.xz
        exit 1
    fi
    rm -f /tmp/shellcheck.tar.xz
fi

# Check Java version
java -version

#
# Install awscli
#
if [ "${AWSCLI_DIRECT_INSTALL}" -eq 1 ]; then
    echo "${PRGNAME} [INFO] Install awscli2 package."

    CURRENT_DIR=$(pwd)
    cd /tmp || exit 1

    curl "${AWSCLI_URI}" -o "${AWSCLI_ZIP_FILE}"
    unzip  "${AWSCLI_ZIP_FILE}"
    ./aws/install

    cd "${CURRENT_DIR}" || exit 1
fi

#-----------------------------------------------------------
# Set environment for configure
#-----------------------------------------------------------
echo "${PRGNAME} [INFO] Set environment for configure options"

echo "CXXFLAGS=${CXXFLAGS}"                   >> "${GITHUB_ENV}"
echo "CONFIGURE_OPTIONS=${CONFIGURE_OPTIONS}" >> "${GITHUB_ENV}"

echo "${PRGNAME} [INFO] Finish Linux helper for installing packages."

exit 0

#
# Local variables:
# tab-width: 4
# c-basic-offset: 4
# End:
# vim600: expandtab sw=4 ts=4 fdm=marker
# vim<600: expandtab sw=4 ts=4
#
