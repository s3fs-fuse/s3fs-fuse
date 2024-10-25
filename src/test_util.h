/*
 * s3fs - FUSE-based file system backed by Amazon S3
 *
 * Copyright(C) 2014 Andrew Gaul <andrew@gaul.org>
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

#ifndef S3FS_TEST_UTIL_H_
#define S3FS_TEST_UTIL_H_

#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <string>

#include "string_util.h"

template <typename T> inline void assert_equals(const T &x, const T &y, const char *file, int line)
{
    if (x != y) {
        std::cerr << x << " != " << y << " at " << file << ":" << line << std::endl;
        std::cerr << std::endl;
        abort();
    }
}

template <> inline void assert_equals(const std::string &x, const std::string &y, const char *file, int line)
{
    if (x != y) {
        std::cerr << x << " != " << y << " at " << file << ":" << line << std::endl;
        std::cerr << s3fs_hex_lower(reinterpret_cast<const unsigned char *>(x.c_str()), x.size()) << std::endl;
        std::cerr << s3fs_hex_lower(reinterpret_cast<const unsigned char *>(y.c_str()), y.size()) << std::endl;
        abort();
    }
}


template <typename T> inline void assert_nequals(const T &x, const T &y, const char *file, int line)
{
    if (x == y) {
        std::cerr << x << " == " << y << " at " << file << ":" << line << std::endl;
        abort();
    }
}

template <> inline void assert_nequals(const std::string &x, const std::string &y, const char *file, int line)
{
    if (x == y) {
        std::cerr << x << " == " << y << " at " << file << ":" << line << std::endl;
        std::cerr << s3fs_hex_lower(reinterpret_cast<const unsigned char *>(x.c_str()), x.size()) << std::endl;
        std::cerr << s3fs_hex_lower(reinterpret_cast<const unsigned char *>(y.c_str()), y.size()) << std::endl;
        abort();
    }
}

inline void assert_strequals(const char *x, const char *y, const char *file, int line)
{
  if(x == nullptr && y == nullptr){
      return;
  // cppcheck-suppress nullPointerRedundantCheck
  } else if(x == nullptr || y == nullptr || strcmp(x, y) != 0){
      std::cerr << (x ? x : "null") << " != " << (y ? y : "null") << " at " << file << ":" << line << std::endl;
      abort();
  }
}

inline void assert_bufequals(const char *x, size_t len1, const char *y, size_t len2, const char *file, int line)
{
    if(x == nullptr && y == nullptr){
        return;
    // cppcheck-suppress nullPointerRedundantCheck
    } else if(x == nullptr || y == nullptr || len1 != len2 || memcmp(x, y, len1) != 0){
        std::cerr << (x ? std::string(x, len1) : "null") << " != " << (y ? std::string(y, len2) : "null") << " at " << file << ":" << line << std::endl;
        abort();
    }
}

#define ASSERT_TRUE(x)          assert_equals((x), true, __FILE__, __LINE__)
#define ASSERT_FALSE(x)         assert_equals((x), false, __FILE__, __LINE__)
#define ASSERT_EQUALS(x, y)     assert_equals((x), (y), __FILE__, __LINE__)
#define ASSERT_NEQUALS(x, y)    assert_nequals((x), (y), __FILE__, __LINE__)
#define ASSERT_STREQUALS(x, y)  assert_strequals((x), (y), __FILE__, __LINE__)
#define ASSERT_BUFEQUALS(x, len1, y, len2) assert_bufequals((x), (len1), (y), (len2), __FILE__, __LINE__)

#endif // S3FS_TEST_UTIL_H_

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
