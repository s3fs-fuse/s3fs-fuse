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

#include <string>

#include "string_util.h"
#include "test_util.h"

int main(int argc, char *argv[])
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

  return 0;
}
