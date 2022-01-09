#!/usr/bin/env python3
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
import unittest
import random
import sys
import time

class OssfsUnitTest(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def random_string(self, len):
        char_set = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g']
        list = []
        for i in range(0, len):
            list.append(random.choice(char_set))
        return "".join(list)

    def test_read_file(self):
        filename = "%s" % (self.random_string(10))
        print(filename)

        f = open(filename, 'w')
        data = self.random_string(1000)
        f.write(data)
        f.close()

        f = open(filename, 'r')
        data = f.read(100)
        self.assertEqual(len(data), 100)
        data = f.read(100)
        self.assertEqual(len(data), 100)
        f.close()

        os.remove(filename)

    def test_rename_file(self):
        filename1 = "%s" % (self.random_string(10))
        filename2 = "%s" % (self.random_string(10))
        print(filename1, filename2)

        f = open(filename1, 'w+')
        data1 = self.random_string(1000)
        f.write(data1)

        os.rename(filename1, filename2)

        f.seek(0, 0)
        data2 = f.read()
        f.close()

        self.assertEqual(len(data1), len(data2))
        self.assertEqual(data1, data2)

        os.remove(filename2)

    def test_rename_file2(self):
        filename1 = "%s" % (self.random_string(10))
        filename2 = "%s" % (self.random_string(10))
        print(filename1, filename2)

        f = open(filename1, 'w')
        data1 = self.random_string(1000)
        f.write(data1)
        f.close()

        os.rename(filename1, filename2)

        f = open(filename2, 'r')
        f.seek(0, 0)
        data2 = f.read()
        f.close()

        self.assertEqual(len(data1), len(data2))
        self.assertEqual(data1, data2)

        os.remove(filename2)

    def test_truncate_open_file(self):
        filename = "%s" % (self.random_string(10))
        fd = os.open(filename, os.O_CREAT|os.O_RDWR)
        try:
            os.write(fd, b'a' * 42)
            self.assertEqual(os.fstat(fd).st_size, 42)
            os.ftruncate(fd, 100)
            self.assertEqual(os.fstat(fd).st_size, 100)
        finally:
            os.close(fd)
        self.assertEqual(100, os.stat(filename).st_size)

        os.remove(filename)

if __name__ == '__main__':
    unittest.main()

# 
# Local variables:
# tab-width: 4
# c-basic-offset: 4
# End:
# vim600: expandtab sw=4 ts=4 fdm=marker
# vim<600: expandtab sw=4 ts=4
# 
