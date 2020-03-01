#!/usr/bin/env python3

# TODO: parse argv so that test script can issue multiple (offset, size) pairs

import os
import sys

filename = sys.argv[1]
data = bytes('a', 'utf-8')

fd = os.open(filename, os.O_CREAT | os.O_TRUNC | os.O_WRONLY)
try:
    os.pwrite(fd, data, 20 * 1024 * 1024 + 1)
    os.pwrite(fd, data, 10 * 1024 * 1024)
finally:
    os.close(fd)

stat = os.lstat(filename)
assert stat.st_size == 20 * 1024 * 1024 + 2
