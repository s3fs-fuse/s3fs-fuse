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

#include <sys/stat.h>

#include <memory>
#include <string>

#include "cache_node.h"
#include "metaheader.h"
#include "s3objlist.h"
#include "test_util.h"
#include "types.h"

static struct stat make_dir_stat()
{
    struct stat st = {};
    st.st_mode  = S_IFDIR | 0755;
    st.st_nlink = 2;
    return st;
}

static struct stat make_file_stat()
{
    struct stat st = {};
    st.st_mode  = S_IFREG | 0644;
    st.st_nlink = 1;
    return st;
}

//
// A CommonPrefixes entry in a listing proves only that keys exist under
// "subdir/".  It must not be typed as a legacy no-slash directory
// object("subdir"), otherwise readdir stamps that wrong sub-type into the
// stat cache and every later metadata update rebuilds the directory
// object instead of copying it.
//
static void test_common_prefix_type()
{
    S3ObjList list;
    ASSERT_TRUE(list.insert("subdir", nullptr, /*is_dir=*/ true, -1, nullptr));

    s3obj_type_map_t typemap;
    ASSERT_TRUE(list.GetNameMap(typemap, /*OnlyNormalized=*/ true, /*CutSlash=*/ false));
    auto iter = typemap.find("subdir/");
    ASSERT_TRUE(typemap.cend() != iter);
    ASSERT_EQUALS(static_cast<int>(objtype_t::DIR_NORMAL), static_cast<int>(iter->second));
}

//
// Directory objects can change their physical representation while the
// path stays a directory(ex. replacing a legacy "dir" object with "dir/").
// Re-adding a cached directory with a new sub-type must update the node,
// otherwise a stale sub-type can never heal.
//
static void test_dir_subtype_heal()
{
    DirStatCache root("/");
    struct stat  st   = make_dir_stat();
    headers_t    meta;
    meta["Content-Type"]       = "application/x-directory";
    meta["x-amz-meta-foreign"] = "keepme";

    ASSERT_TRUE(root.Add("/dir/", &st, &meta, objtype_t::DIR_NOT_TERMINATE_SLASH, false));
    std::shared_ptr<StatCacheNode> node = root.Find("/dir/");
    ASSERT_TRUE(nullptr != node);
    ASSERT_EQUALS(static_cast<int>(objtype_t::DIR_NOT_TERMINATE_SLASH), static_cast<int>(node->GetType()));

    // Update to the modern "dir/" representation.
    ASSERT_TRUE(root.Add("/dir/", &st, &meta, objtype_t::DIR_NORMAL, false));
    node = root.Find("/dir/");
    ASSERT_TRUE(nullptr != node);
    ASSERT_EQUALS(static_cast<int>(objtype_t::DIR_NORMAL), static_cast<int>(node->GetType()));

    // The stat and meta survive the sub-type update.
    struct stat getst = {};
    headers_t   getmeta;
    ASSERT_TRUE(node->Get(getmeta, getst));
    ASSERT_TRUE(S_ISDIR(getst.st_mode));
    ASSERT_TRUE(getmeta.cend() != getmeta.find("x-amz-meta-foreign"));

    // The object was deleted externally and only the path remains.
    ASSERT_TRUE(root.Add("/dir/", &st, &meta, objtype_t::DIR_NOT_EXIST_OBJECT, false));
    node = root.Find("/dir/");
    ASSERT_TRUE(nullptr != node);
    ASSERT_EQUALS(static_cast<int>(objtype_t::DIR_NOT_EXIST_OBJECT), static_cast<int>(node->GetType()));

    // Re-adding with the same sub-type keeps the node untouched.
    ASSERT_TRUE(root.Add("/dir/", &st, &meta, objtype_t::DIR_NOT_EXIST_OBJECT, false));
    node = root.Find("/dir/");
    ASSERT_TRUE(nullptr != node);
    ASSERT_EQUALS(static_cast<int>(objtype_t::DIR_NOT_EXIST_OBJECT), static_cast<int>(node->GetType()));
}

//
// The same heal must work for a directory nested below the top level,
// where the parent recursion ends in the direct-child branch.
//
static void test_nested_dir_subtype_heal()
{
    DirStatCache root("/");
    struct stat  st = make_dir_stat();

    ASSERT_TRUE(root.Add("/dir/", &st, nullptr, objtype_t::DIR_NORMAL, false));
    ASSERT_TRUE(root.Add("/dir/sub/", &st, nullptr, objtype_t::DIR_NOT_TERMINATE_SLASH, false));
    std::shared_ptr<StatCacheNode> node = root.Find("/dir/sub/");
    ASSERT_TRUE(nullptr != node);
    ASSERT_EQUALS(static_cast<int>(objtype_t::DIR_NOT_TERMINATE_SLASH), static_cast<int>(node->GetType()));

    ASSERT_TRUE(root.Add("/dir/sub/", &st, nullptr, objtype_t::DIR_NORMAL, false));
    node = root.Find("/dir/sub/");
    ASSERT_TRUE(nullptr != node);
    ASSERT_EQUALS(static_cast<int>(objtype_t::DIR_NORMAL), static_cast<int>(node->GetType()));
}

//
// Non-directory nodes are not affected by the directory sub-type update.
//
static void test_file_type_unchanged()
{
    DirStatCache root("/");
    struct stat  st = make_file_stat();

    ASSERT_TRUE(root.Add("/file", &st, nullptr, objtype_t::FILE, false));
    std::shared_ptr<StatCacheNode> node = root.Find("/file");
    ASSERT_TRUE(nullptr != node);
    ASSERT_EQUALS(static_cast<int>(objtype_t::FILE), static_cast<int>(node->GetType()));

    ASSERT_TRUE(root.Add("/file", &st, nullptr, objtype_t::FILE, false));
    node = root.Find("/file");
    ASSERT_TRUE(nullptr != node);
    ASSERT_EQUALS(static_cast<int>(objtype_t::FILE), static_cast<int>(node->GetType()));
}

int main(int argc, const char *argv[])
{
    test_common_prefix_type();
    test_dir_subtype_heal();
    test_nested_dir_subtype_heal();
    test_file_type_unchanged();
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
