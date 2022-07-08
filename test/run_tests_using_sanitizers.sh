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

# Disable preprocessor warnings from _FORTIFY_SOURCE and -O0
COMMON_FLAGS="-g -O0 -Wno-cpp"

# run tests with libstc++ debug mode, https://gcc.gnu.org/onlinedocs/libstdc++/manual/debug_mode.html
make clean
./configure CXXFLAGS="$COMMON_FLAGS -D_GLIBCXX_DEBUG"
make
make check -C test/

# run tests under AddressSanitizer, https://clang.llvm.org/docs/AddressSanitizer.html
make clean
./configure CXX=clang++ CXXFLAGS="$COMMON_FLAGS -fsanitize=address -fsanitize-address-use-after-scope"
make
ASAN_OPTIONS='detect_leaks=1,detect_stack_use_after_return=1' make check -C test/

# run tests under MemorySanitizer, https://clang.llvm.org/docs/MemorySanitizer.html
# TODO: this requires a custom libc++
#make clean
#./configure CXX=clang++ CXXFLAGS="$COMMON_FLAGS -fsanitize=memory"
#make
#make check -C test/

# run tests under ThreadSanitizer, https://clang.llvm.org/docs/ThreadSanitizer.html
make clean
./configure CXX=clang++ CXXFLAGS="$COMMON_FLAGS -fsanitize=thread"
make
TSAN_OPTIONS='halt_on_error=1' make check -C test/

# run tests under UndefinedBehaviorSanitizer, https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html
make clean
./configure CXX=clang++ CXXFLAGS="$COMMON_FLAGS -fsanitize=undefined,implicit-conversion,local-bounds,unsigned-integer-overflow"
make
make check -C test/

# run tests with Valgrind
make clean
./configure CXXFLAGS="$COMMON_FLAGS"
make
RETRIES=100 VALGRIND="--leak-check=full" make check -C test/

#
# Local variables:
# tab-width: 4
# c-basic-offset: 4
# End:
# vim600: expandtab sw=4 ts=4 fdm=marker
# vim<600: expandtab sw=4 ts=4
#
