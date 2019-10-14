#!/usr/bin/env python3

import os
import sys

filename = sys.argv[1]
data = bytes('a', 'utf-8')

fd = os.open(filename, os.O_CREAT | os.O_TRUNC | os.O_WRONLY)
try:
    os.pwrite(fd, data, 1024)
    os.pwrite(fd, data, 16 * 1024 * 1024)
    os.pwrite(fd, data, 18 * 1024 * 1024)
finally:
    os.close(fd)

stat = os.lstat(filename)
assert stat.st_size == 18 * 1024 * 1024 + 1
