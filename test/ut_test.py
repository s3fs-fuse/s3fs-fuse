#!/usr/bin/env python2

import os
import unittest
import ConfigParser
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
        print filename

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

    def test_rename_file(self):
        filename1 = "%s" % (self.random_string(10))
        filename2 = "%s" % (self.random_string(10))
        print filename1, filename2

        f = open(filename1, 'w+')
        data1 = self.random_string(1000)
        f.write(data1)

        os.rename(filename1, filename2)

        f.seek(0, 0)
        data2 = f.read()
        f.close()

        self.assertEqual(len(data1), len(data2))
        self.assertEqual(data1, data2)

    def test_rename_file2(self):
        filename1 = "%s" % (self.random_string(10))
        filename2 = "%s" % (self.random_string(10))
        print filename1, filename2

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


if __name__ == '__main__':
    unittest.main()

