#!/bin/bash

set -o errexit
set -o nounset
set -o pipefail

# run tests with libstc++ debug mode, https://gcc.gnu.org/onlinedocs/libstdc++/manual/debug_mode.html
make clean
./configure CXXFLAGS='-D_GLIBCXX_DEBUG -g'
make
DBGLEVEL=debug make check -C test/

# run tests under AddressSanitizer, https://clang.llvm.org/docs/AddressSanitizer.html
make clean
./configure CXX=clang++ CXXFLAGS='-fsanitize=address -fsanitize-address-use-after-scope -g'
make
ASAN_OPTIONS='detect_stack_use_after_return=1' make check -C test/

# run tests under ThreadSanitizer, https://clang.llvm.org/docs/ThreadSanitizer.html
make clean
./configure CXX=clang++ CXXFLAGS='-fsanitize=thread -g'
make
TSAN_OPTIONS='halt_on_error=1' make check -C test/

# run tests under Valgrind
make clean
./configure CXXFLAGS='-O1 -g'
make
RETRIES=200 VALGRIND='--error-exitcode=1 --leak-check=full' make check -C test/
