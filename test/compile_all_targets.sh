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

set -o errexit
set -o nounset
set -o pipefail

COMMON_FLAGS='-O -Wall -Werror'

make clean
CXXFLAGS="$COMMON_FLAGS" ./configure --with-gnutls
make --jobs "$(nproc)"

make clean
CXXFLAGS="$COMMON_FLAGS" ./configure --with-gnutls --with-nettle
make --jobs "$(nproc)"

make clean
CXXFLAGS="$COMMON_FLAGS" ./configure --with-nss
make --jobs "$(nproc)"

make clean
CXXFLAGS="$COMMON_FLAGS" ./configure --with-openssl
make --jobs "$(nproc)"

make clean
CXXFLAGS="$COMMON_FLAGS -std=c++23" ./configure
make --jobs "$(nproc)"

make clean
CXXFLAGS="$COMMON_FLAGS -m32" ./configure
make --jobs "$(nproc)"

make clean
CXX=clang++ CXXFLAGS="$COMMON_FLAGS -Wshorten-64-to-32" ./configure
make --jobs "$(nproc)"

#
# Local variables:
# tab-width: 4
# c-basic-offset: 4
# End:
# vim600: expandtab sw=4 ts=4 fdm=marker
# vim<600: expandtab sw=4 ts=4
#
