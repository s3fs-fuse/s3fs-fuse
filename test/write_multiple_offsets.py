#!/usr/bin/env python3

import os
import sys

if len(sys.argv) < 4 or len(sys.argv) % 2 != 0:
    sys.exit("Usage: %s OUTFILE OFFSET_1 SIZE_1 [OFFSET_N SIZE_N]...")

filename = sys.argv[1]

fd = os.open(filename, os.O_CREAT | os.O_TRUNC | os.O_WRONLY)
try:
    for i in range(2, len(sys.argv), 2):
        data = bytes("a" * int(sys.argv[i+1]), 'utf-8')
        os.pwrite(fd, data, int(sys.argv[i]))
finally:
    os.close(fd)
