#!/bin/bash
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
CONTAINER_OSNAME=$(echo "${CONTAINER_FULLNAME}" | cut -d: -f1)
# shellcheck disable=SC2034
CONTAINER_OSVERSION=$(echo "${CONTAINER_FULLNAME}" | cut -d: -f2)

CURL_DIRECT_VERSION="v8.11.0"
CURL_DIRECT_URL="https://github.com/moparisthebest/static-curl/releases/download/${CURL_DIRECT_VERSION}/curl-$(uname -m | sed -e s/x86_64/amd64/)"
CURL_HASH_X86_64="d18aa1f4e03b50b649491ca2c401cd8c5e89e72be91ff758952ad2ab5a83135d"
CURL_HASH_AARCH64="1b050abd1669f9a2ac29b34eb022cdeafb271dce5a4fb57d8ef8fadff6d7be1f"

#-----------------------------------------------------------
# Parameters for configure(set environments)
#-----------------------------------------------------------
CXX="g++"
CXXFLAGS="-O"
LDFLAGS=""
CONFIGURE_OPTIONS="--prefix=/usr --with-openssl"

#-----------------------------------------------------------
# OS dependent variables
#-----------------------------------------------------------
#
# Default values
#
PACKAGE_ENABLE_REPO_OPTIONS=""
PACKAGE_INSTALL_ADDITIONAL_OPTIONS=""
CURL_DIRECT_INSTALL=0

if [ "${CONTAINER_FULLNAME}" = "ubuntu:25.10" ] ||
   [ "${CONTAINER_FULLNAME}" = "ubuntu:24.04" ]; then
    PACKAGE_MANAGER_BIN="apt-get"
    PACKAGE_UPDATE_OPTIONS="update -y -qq"
    PACKAGE_INSTALL_OPTIONS="install -y"

    INSTALL_PACKAGES=(
        attr
        autoconf
        autotools-dev
        build-essential
        curl
        fuse
        g++
        git
        jq
        libcurl4-openssl-dev
        libfuse-dev
        libssl-dev
        libtool
        libxml2-dev
        locales-all
        mailcap
        openjdk-21-jre-headless
        pkg-config
    )

elif [ "${CONTAINER_FULLNAME}" = "ubuntu:22.04" ]; then
    PACKAGE_MANAGER_BIN="apt-get"
    PACKAGE_UPDATE_OPTIONS="update -y -qq"
    PACKAGE_INSTALL_OPTIONS="install -y"

    INSTALL_PACKAGES=(
        attr
        autoconf
        autotools-dev
        build-essential
        curl
        fuse
        g++
        git
        jq
        libcurl4-openssl-dev
        libfuse-dev
        libssl-dev
        libtool
        libxml2-dev
        locales-all
        mime-support
        openjdk-21-jre-headless
        pkg-config
    )

    CURL_DIRECT_INSTALL=1

elif [ "${CONTAINER_FULLNAME}" = "debian:trixie" ]; then
    PACKAGE_MANAGER_BIN="apt-get"
    PACKAGE_UPDATE_OPTIONS="update -y -qq"
    PACKAGE_INSTALL_OPTIONS="install -y"

    INSTALL_PACKAGES=(
        attr
        autoconf
        autotools-dev
        build-essential
        curl
        fuse
        g++
        git
        jq
        libcurl4-openssl-dev
        libfuse-dev
        libssl-dev
        libtool
        libxml2-dev
        locales-all
        mailcap
        openjdk-21-jre-headless
        pkg-config
        procps
    )

elif [ "${CONTAINER_FULLNAME}" = "debian:bookworm" ] ||
     [ "${CONTAINER_FULLNAME}" = "debian:bullseye" ]; then
    PACKAGE_MANAGER_BIN="apt-get"
    PACKAGE_UPDATE_OPTIONS="update -y -qq"
    PACKAGE_INSTALL_OPTIONS="install -y"

    INSTALL_PACKAGES=(
        attr
        autoconf
        autotools-dev
        build-essential
        curl
        fuse
        g++
        git
        jq
        libcurl4-openssl-dev
        libfuse-dev
        libssl-dev
        libtool
        libxml2-dev
        locales-all
        mime-support
        openjdk-17-jre-headless
        pkg-config
        procps
    )

    CURL_DIRECT_INSTALL=1

elif [ "${CONTAINER_FULLNAME}" = "rockylinux/rockylinux:10" ] ||
     [ "${CONTAINER_FULLNAME}" = "rockylinux/rockylinux:9" ]; then
    PACKAGE_MANAGER_BIN="dnf"
    PACKAGE_UPDATE_OPTIONS="update -y -qq"
    PACKAGE_INSTALL_OPTIONS="install -y"
    PACKAGE_ENABLE_REPO_OPTIONS="--enablerepo=crb"

    # [NOTE]
    # Rocky Linux 9/10 (or CentOS Stream 9/10) images may have curl installation issues that
    # conflict with the curl-minimal package.
    #
    PACKAGE_INSTALL_ADDITIONAL_OPTIONS="--allowerasing"

    INSTALL_PACKAGES=(
        attr
        automake
        curl
        curl-devel
        diffutils
        fuse
        fuse-devel
        gcc
        gcc-c++
        git
        glibc-langpack-en
        java-21-openjdk-headless
        jq
        libstdc++-devel
        libxml2-devel
        mailcap
        make
        openssl
        openssl-devel
        perl-Test-Harness
        procps
        xz
    )

    CURL_DIRECT_INSTALL=1

elif [ "${CONTAINER_FULLNAME}" = "rockylinux/rockylinux:8" ]; then
    PACKAGE_MANAGER_BIN="dnf"
    PACKAGE_UPDATE_OPTIONS="update -y -qq"
    PACKAGE_INSTALL_OPTIONS="install -y"

    INSTALL_PACKAGES=(
        attr
        automake
        curl
        curl-devel
        diffutils
        fuse
        fuse-devel
        gcc
        gcc-c++
        git
        glibc-langpack-en
        java-21-openjdk-headless
        jq
        libstdc++-devel
        libxml2-devel
        mailcap
        make
        openssl
        openssl-devel
        perl-Test-Harness
    )

    CURL_DIRECT_INSTALL=1

elif [ "${CONTAINER_FULLNAME}" = "fedora:43" ] ||
     [ "${CONTAINER_FULLNAME}" = "fedora:42" ]; then
    PACKAGE_MANAGER_BIN="dnf"
    PACKAGE_UPDATE_OPTIONS="update -y -qq"
    PACKAGE_INSTALL_OPTIONS="install -y"

    INSTALL_PACKAGES=(
        attr
        automake
        curl
        curl-devel
        diffutils
        fuse
        fuse-devel
        gawk
        gcc
        gcc-c++
        git
        glibc-langpack-en
        java-latest-openjdk-headless
        jq
        libstdc++-devel
        libxml2-devel
        mailcap
        make
        openssl
        openssl-devel
        perl-Test-Harness
        procps
    )

elif [ "${CONTAINER_FULLNAME}" = "opensuse/leap:15" ]; then
    PACKAGE_MANAGER_BIN="zypper"
    PACKAGE_UPDATE_OPTIONS="refresh"
    PACKAGE_INSTALL_OPTIONS="install -y"

    INSTALL_PACKAGES=(
        attr
        automake
        curl
        curl-devel
        fuse
        fuse-devel
        gcc-c++
        java-21-openjdk-headless
        jq
        libxml2-devel
        make
        openssl
        openssl-devel
        procps
        python3
    )

elif [ "${CONTAINER_FULLNAME}" = "alpine:3.22" ]; then
    PACKAGE_MANAGER_BIN="apk"
    PACKAGE_UPDATE_OPTIONS="update --no-progress"
    PACKAGE_INSTALL_OPTIONS="add --no-progress --no-cache"

    INSTALL_PACKAGES=(
        attr
        autoconf
        automake
        coreutils
        curl
        curl-dev
        fuse-dev
        g++
        git
        jq
        libtool
        libxml2-dev
        mailcap
        make
        openjdk21
        openssl
        perl-test-harness-utils
        procps
        sed
    )

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
# Install packages
#
echo "${PRGNAME} [INFO] Install packages."
/bin/sh -c "${PACKAGE_MANAGER_BIN} ${PACKAGE_ENABLE_REPO_OPTIONS} ${PACKAGE_INSTALL_OPTIONS} ${PACKAGE_INSTALL_ADDITIONAL_OPTIONS} ${INSTALL_PACKAGES[*]}"

# Check Java version
java -version

# Install newer curl for older distributions
if [ "${CURL_DIRECT_INSTALL}" -eq 1 ]; then
    echo "${PRGNAME} [INFO] Install newer curl package."

    curl --fail --location --silent --output "/tmp/curl" "${CURL_DIRECT_URL}"
    case "$(uname -m)" in
        x86_64)  curl_hash="$CURL_HASH_X86_64" ;;
        aarch64) curl_hash="$CURL_HASH_AARCH64" ;;
        *)       exit 1 ;;
    esac
    echo "$curl_hash" "/tmp/curl" | sha256sum --check
    mv "/tmp/curl" "/usr/local/bin/curl"
    chmod +x "/usr/local/bin/curl"

    # Rocky Linux 8 and 9 have a different certificate path
    if [ ! -f /etc/ssl/certs/ca-certificates.crt ]; then
        ln -s /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/certs/ca-certificates.crt
    fi
fi

# Check curl version
curl --version

#-----------------------------------------------------------
# Set environment for configure
#-----------------------------------------------------------
echo "${PRGNAME} [INFO] Set environment for configure options"

cat << EOF >> "${GITHUB_ENV}"
CXX=${CXX}
CXXFLAGS=${CXXFLAGS}
LDFLAGS=${LDFLAGS}
CONFIGURE_OPTIONS=${CONFIGURE_OPTIONS}
EOF

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
