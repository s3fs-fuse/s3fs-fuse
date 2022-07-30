/*
 * s3fs - FUSE-based file system backed by Amazon S3
 *
 * Copyright(C) 2021 Andrew Gaul <andrew@gaul.org>
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

#include "fdcache_page.h"
#include "fdcache_stat.h"
#include "test_util.h"

bool CacheFileStat::Open() { return false; }

void test_compress()
{
  PageList list;
  ASSERT_EQUALS(off_t(0), list.Size());

  list.Init(42, /*is_loaded=*/ false, /*is_modified=*/ false);
  ASSERT_EQUALS(off_t(42), list.Size());
  ASSERT_FALSE(list.IsPageLoaded(0, 1));

  list.SetPageLoadedStatus(0, 1, /*pstatus=*/ PageList::PAGE_LOADED);
  ASSERT_TRUE(list.IsPageLoaded(0, 1));
  ASSERT_FALSE(list.IsPageLoaded(0, 2));

  off_t start = 0;
  off_t size = 0;
  ASSERT_TRUE(list.FindUnloadedPage(0, start, size));
  ASSERT_EQUALS(off_t(1), start);
  ASSERT_EQUALS(off_t(41), size);

  // test adding subsequent page then compressing
  list.SetPageLoadedStatus(1, 3, /*pstatus=*/ PageList::PAGE_LOADED);
  list.Compress();
  ASSERT_TRUE(list.IsPageLoaded(0, 3));

  ASSERT_TRUE(list.FindUnloadedPage(0, start, size));
  ASSERT_EQUALS(off_t(4), start);
  ASSERT_EQUALS(off_t(38), size);

  // test adding non-contiguous page then compressing
  list.SetPageLoadedStatus(5, 1, /*pstatus=*/ PageList::PAGE_LOADED);
  list.Compress();

  ASSERT_TRUE(list.FindUnloadedPage(0, start, size));
  ASSERT_EQUALS(off_t(4), start);
  ASSERT_EQUALS(off_t(1), size);
  list.Dump();
  printf("\n");

  // test adding page between two pages then compressing
  list.SetPageLoadedStatus(4, 1, /*pstatus=*/ PageList::PAGE_LOADED);
  list.Compress();

  list.Dump();
  ASSERT_TRUE(list.FindUnloadedPage(0, start, size));
  ASSERT_EQUALS(off_t(6), start);
  ASSERT_EQUALS(off_t(36), size);
}

int main(int argc, char *argv[])
{
  test_compress();
  return 0;
}
