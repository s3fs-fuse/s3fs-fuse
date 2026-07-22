/*
 * s3fs - FUSE-based file system backed by Amazon S3
 *
 * Copyright(C) 2026 Andrew Gaul <andrew@gaul.org>
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

#include "s3objlist.h"
#include "test_util.h"

void test_hasname()
{
    S3ObjList list;

    ASSERT_TRUE(list.insert("file1"));
    ASSERT_TRUE(list.insert("sub", nullptr, true));

    // names are found with and without a terminating slash
    ASSERT_TRUE(list.HasName("file1"));
    ASSERT_TRUE(list.HasName("file1/"));
    ASSERT_TRUE(list.HasName("sub"));
    ASSERT_TRUE(list.HasName("sub/"));

    ASSERT_FALSE(list.HasName("missing"));
    ASSERT_FALSE(list.HasName("missing/"));
    ASSERT_FALSE(list.HasName("/"));
    ASSERT_FALSE(list.HasName(""));
}

void test_remove()
{
    S3ObjList list;

    // remove a file by the name with a terminating slash
    ASSERT_TRUE(list.insert("file1"));
    ASSERT_TRUE(list.Remove("file1/"));
    ASSERT_FALSE(list.HasName("file1"));

    // a directory is stored under both "sub/" and the normalized name
    // "sub", and removing it must erase both
    ASSERT_TRUE(list.insert("sub", nullptr, true));
    ASSERT_TRUE(list.Remove("sub/"));
    ASSERT_FALSE(list.HasName("sub"));
    ASSERT_FALSE(list.HasName("sub/"));

    ASSERT_FALSE(list.Remove(""));
    ASSERT_TRUE(list.IsEmpty());
}

int main(int argc, const char *argv[])
{
    test_hasname();
    test_remove();

    return 0;
}

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
