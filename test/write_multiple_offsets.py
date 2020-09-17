#!/usr/bin/env python2
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

# 
# Local variables:
# tab-width: 4
# c-basic-offset: 4
# End:
# vim600: expandtab sw=4 ts=4 fdm=marker
# vim<600: expandtab sw=4 ts=4
# 
