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

#include <limits>
#include <stdint.h>
#include <string>

#include "string_util.h"
#include "test_util.h"

void test_trim()
{
  ASSERT_EQUALS(std::string("1234"), trim("  1234  "));
  ASSERT_EQUALS(std::string("1234"), trim("1234  "));
  ASSERT_EQUALS(std::string("1234"), trim("  1234"));
  ASSERT_EQUALS(std::string("1234"), trim("1234"));

  ASSERT_EQUALS(std::string("1234  "), trim_left("  1234  "));
  ASSERT_EQUALS(std::string("1234  "), trim_left("1234  "));
  ASSERT_EQUALS(std::string("1234"), trim_left("  1234"));
  ASSERT_EQUALS(std::string("1234"), trim_left("1234"));

  ASSERT_EQUALS(std::string("  1234"), trim_right("  1234  "));
  ASSERT_EQUALS(std::string("1234"), trim_right("1234  "));
  ASSERT_EQUALS(std::string("  1234"), trim_right("  1234"));
  ASSERT_EQUALS(std::string("1234"), trim_right("1234"));

  ASSERT_EQUALS(std::string("0"), str(0));
  ASSERT_EQUALS(std::string("1"), str(1));
  ASSERT_EQUALS(std::string("-1"), str(-1));
  ASSERT_EQUALS(std::string("9223372036854775807"), str(std::numeric_limits<int64_t>::max()));
  ASSERT_EQUALS(std::string("-9223372036854775808"), str(std::numeric_limits<int64_t>::min()));
  ASSERT_EQUALS(std::string("0"), str(std::numeric_limits<uint64_t>::min()));
  ASSERT_EQUALS(std::string("18446744073709551615"), str(std::numeric_limits<uint64_t>::max()));
}

void test_base64()
{
  size_t len;
  ASSERT_STREQUALS(s3fs_base64(NULL, 0), NULL);
  ASSERT_STREQUALS(reinterpret_cast<const char *>(s3fs_decode64(NULL, &len)), NULL);
  ASSERT_STREQUALS(s3fs_base64(reinterpret_cast<const unsigned char *>(""), 0), NULL);
  ASSERT_STREQUALS(reinterpret_cast<const char *>(s3fs_decode64("", &len)), NULL);

  ASSERT_STREQUALS(s3fs_base64(reinterpret_cast<const unsigned char *>("1"), 1), "MQ==");
  ASSERT_STREQUALS(reinterpret_cast<const char *>(s3fs_decode64("MQ==", &len)), "1");
  ASSERT_EQUALS(len, static_cast<size_t>(1));
  ASSERT_STREQUALS(s3fs_base64(reinterpret_cast<const unsigned char *>("12"), 2), "MTI=");
  ASSERT_STREQUALS(reinterpret_cast<const char *>(s3fs_decode64("MTI=", &len)), "12");
  ASSERT_EQUALS(len, static_cast<size_t>(2));
  ASSERT_STREQUALS(s3fs_base64(reinterpret_cast<const unsigned char *>("123"), 3), "MTIz");
  ASSERT_STREQUALS(reinterpret_cast<const char *>(s3fs_decode64("MTIz", &len)), "123");
  ASSERT_EQUALS(len, static_cast<size_t>(3));
  ASSERT_STREQUALS(s3fs_base64(reinterpret_cast<const unsigned char *>("1234"), 4), "MTIzNA==");
  ASSERT_STREQUALS(reinterpret_cast<const char *>(s3fs_decode64("MTIzNA==", &len)), "1234");
  ASSERT_EQUALS(len, static_cast<size_t>(4));

  // TODO: invalid input
}

void test_strtoofft()
{
  ASSERT_EQUALS(s3fs_strtoofft("0"), static_cast<off_t>(0L));
  ASSERT_EQUALS(s3fs_strtoofft("9"), static_cast<off_t>(9L));
  ASSERT_EQUALS(s3fs_strtoofft("A"), static_cast<off_t>(0L));
  ASSERT_EQUALS(s3fs_strtoofft("A", /*is_base_16=*/ true), static_cast<off_t>(10L));
  ASSERT_EQUALS(s3fs_strtoofft("F", /*is_base_16=*/ true), static_cast<off_t>(15L));
  ASSERT_EQUALS(s3fs_strtoofft("a", /*is_base_16=*/ true), static_cast<off_t>(10L));
  ASSERT_EQUALS(s3fs_strtoofft("f", /*is_base_16=*/ true), static_cast<off_t>(15L));
  ASSERT_EQUALS(s3fs_strtoofft("deadbeef", /*is_base_16=*/ true), static_cast<off_t>(3735928559L));
}

void test_wtf8_encoding()
{
  std::string ascii("normal string");
  std::string utf8("Hyld\xc3\xbdpi \xc3\xbej\xc3\xb3\xc3\xb0""f\xc3\xa9lagsins vex \xc3\xbar k\xc3\xa6rkomnu b\xc3\xb6li \xc3\xad \xc3\xa1st");
  std::string cp1252("Hyld\xfdpi \xfej\xf3\xf0""f\xe9lagsins vex \xfar k\xe6rkomnu b\xf6li \xed \xe1st");
  std::string broken = utf8;
  broken[14] = 0x97;
  std::string mixed = ascii + utf8 + cp1252;

  ASSERT_EQUALS(s3fs_wtf8_encode(ascii), ascii);
  ASSERT_EQUALS(s3fs_wtf8_decode(ascii), ascii);
  ASSERT_EQUALS(s3fs_wtf8_encode(utf8), utf8);
  ASSERT_EQUALS(s3fs_wtf8_decode(utf8), utf8);

  ASSERT_NEQUALS(s3fs_wtf8_encode(cp1252), cp1252);
  ASSERT_EQUALS(s3fs_wtf8_decode(s3fs_wtf8_encode(cp1252)), cp1252);

  ASSERT_NEQUALS(s3fs_wtf8_encode(broken), broken);
  ASSERT_EQUALS(s3fs_wtf8_decode(s3fs_wtf8_encode(broken)), broken);

  ASSERT_NEQUALS(s3fs_wtf8_encode(mixed), mixed);
  ASSERT_EQUALS(s3fs_wtf8_decode(s3fs_wtf8_encode(mixed)), mixed);
}

int main(int argc, char *argv[])
{
  test_trim();
  test_base64();
  test_strtoofft();
  test_wtf8_encoding();
  return 0;
}
