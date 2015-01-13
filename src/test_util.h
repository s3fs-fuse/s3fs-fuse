/*
 * s3fs - FUSE-based file system backed by Amazon S3
 *
 * Copyright 2014 Andrew Gaul <andrew@gaul.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <cstdlib>
#include <iostream>

template <typename T> void assert_equals(const T &x, const T &y, const char *file, int line)
{
  if (x != y) {
    std::cerr << x << " != " << y << " at " << file << ":" << line << std::endl;
    std::exit(1);
  }
}

#define ASSERT_EQUALS(x, y) \
  assert_equals((x), (y), __FILE__, __LINE__)

