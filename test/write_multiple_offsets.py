#!/usr/bin/env python2

import os
import sys

if len(sys.argv) < 4 or len(sys.argv) % 2 != 0:
    sys.exit("Usage: %s OUTFILE OFFSET_1 SIZE_1 [OFFSET_N SIZE_N]...")

filename = sys.argv[1]

fd = os.open(filename, os.O_CREAT | os.O_TRUNC | os.O_WRONLY)
try:
    for i in range(2, len(sys.argv), 2):
        data = "a" * int(sys.argv[i+1])
        os.lseek(fd, int(sys.argv[i]), os.SEEK_SET)
        os.write(fd, data)
finally:
    os.close(fd)
