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

//--------------------------------------------------------------------
// Common data
//--------------------------------------------------------------------
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

static struct stat make_symlink_stat()
{
    struct stat st = {};
    st.st_mode  = S_IFLNK | 0777;
    st.st_nlink = 1;
    return st;
}

//
// Directory and file names for each object type
//
static constexpr char builtin_file[]                 = "file";
static constexpr char builtin_symlink[]              = "symlink";
static constexpr char builtin_dir_norm[]             = "dirnorm/";
static constexpr char builtin_dir_noslash[]          = "dirnoslash/";
static constexpr char builtin_dir_folder[]           = "dirfolder/";
static constexpr char builtin_dir_notexist[]         = "dirnotexist/";
static constexpr char builtin_negative[]             = "negative";

static constexpr char builtin_s3obj_file[]           = "file";
static constexpr char builtin_s3obj_symlink[]        = "symlink";
static constexpr char builtin_s3obj_dir_norm[]       = "dirnorm/";
static constexpr char builtin_s3obj_dir_noslash[]    = "dirnoslash";
static constexpr char builtin_s3obj_dir_folder[]     = "dirfolder_$folder$";
static constexpr char builtin_s3obj_dir_notexist[]   = "dirnotexist/";

static constexpr char builtin_dir_norm_noslash[]     = "dirnorm";
static constexpr char builtin_dir_noslash_noslash[]  = "dirnoslash";
static constexpr char builtin_dir_folder_noslash[]   = "dirfolder";
static constexpr char builtin_dir_notexist_noslash[] = "dirnotexist";

//
// The value of Common Prefixes for an S3Object
//
static constexpr const char* builtin_s3obj_common_prefix[] = {
    "dirnorm",
    "dirnoslash",
    "dirfolder_$folder$",
    "dirnotexist"
};

//
// Utility function : Register objects of all types into the cache
//
// Insert the following object hierarchy into the cache:
//    <parent(directory)>
//      +-- "file"                      Regular file
//      +-- "symlink"                   Symbolic Link file
//      +-- "dirnorm/"                  Directory terminated with "/"
//      +-- "dirnoslash"                Directory not terminated with "/"
//      +-- "dirfolder_$folder$"        Directory with the "_$folder$" suffix
//      +-- "dirnotexist/"              Non-existent directory object
//
static void add_all_type_child_nodes(const std::string& parent, const std::shared_ptr<DirStatCache>& root, bool files, bool negative)
{
    struct stat  st_dir     = make_dir_stat();
    struct stat  st_file    = make_file_stat();
    struct stat  st_symlink = make_symlink_stat();

    headers_t    meta_dir;
    meta_dir["Content-Type"]            = "application/x-directory";
    meta_dir["x-amz-meta-creationtype"] = "builtin";

    headers_t    meta_file;
    meta_file["Content-Type"]            = "text/plain";
    meta_file["x-amz-meta-creationtype"] = "builtin";

    std::string  strparent = parent.empty() ? "/" : parent;
    if('/' != strparent.back()){
        strparent += '/';
    }

    if(files){
        ASSERT_TRUE(root->Add(strparent + builtin_file,     &st_file,    &meta_file, objtype_t::FILE,                    false));
        ASSERT_TRUE(root->Add(strparent + builtin_symlink,  &st_symlink, &meta_file, objtype_t::SYMLINK,                 false));
    }
    ASSERT_TRUE(root->Add(strparent + builtin_dir_norm,     &st_dir,     &meta_dir,  objtype_t::DIR_NORMAL,              false));
    ASSERT_TRUE(root->Add(strparent + builtin_dir_noslash,  &st_dir,     &meta_dir,  objtype_t::DIR_NOT_TERMINATE_SLASH, false));
    ASSERT_TRUE(root->Add(strparent + builtin_dir_folder,   &st_dir,     &meta_dir,  objtype_t::DIR_FOLDER_SUFFIX,       false));
    ASSERT_TRUE(root->Add(strparent + builtin_dir_notexist, &st_dir,     nullptr,    objtype_t::DIR_NOT_EXIST_OBJECT,    false));
    if(negative){
        ASSERT_TRUE(root->Add(strparent + builtin_negative, nullptr,     nullptr,    objtype_t::NEGATIVE,                false));
    }

    S3ObjList s3obj;
    if(files){
        ASSERT_TRUE(s3obj.insert(builtin_s3obj_file,     nullptr, false, -1, nullptr));
        ASSERT_TRUE(s3obj.insert(builtin_s3obj_symlink,  nullptr, false, -1, nullptr));
    }
    ASSERT_TRUE(s3obj.insert(builtin_s3obj_dir_norm,     nullptr, true,  -1, nullptr));
    ASSERT_TRUE(s3obj.insert(builtin_s3obj_dir_noslash,  nullptr, true,  -1, nullptr));
    ASSERT_TRUE(s3obj.insert(builtin_s3obj_dir_folder,   nullptr, true,  -1, nullptr));
    ASSERT_TRUE(s3obj.insert(builtin_s3obj_dir_notexist, nullptr, true,  -1, nullptr));

    for(const char* prefix : builtin_s3obj_common_prefix){
        s3obj.AddCommonPrefix(prefix);
    }
    ASSERT_TRUE(root->AddS3ObjList(strparent, s3obj));
}

//
// Utility function : Add, Get, and Remove objects of all types
//
// Use the add_all_type_child_nodes() function to perform additions.
// Test the Add, Get, and Remove operations on the objects registered via this function.
//
static void all_type_add_get_remove(const std::string& parent, const std::shared_ptr<DirStatCache>& root)
{
    std::string  strparent = parent.empty() ? "/" : parent;
    if('/' != strparent.back()){
        strparent += '/';
    }

    //---------------------------------
    // ADD TEST
    //---------------------------------
    // set all type object under parent
    add_all_type_child_nodes(strparent, root, true, true);

    headers_t        meta;
    struct stat      st;
    S3ObjList        s3obj;
    s3obj_type_map_t s3obj_typemap;

    //---------------------------------
    // GET TEST
    //---------------------------------
    // file type
    auto pnode = root->Find(strparent + builtin_file, nullptr);
    ASSERT_TRUE(nullptr != pnode);
    ASSERT_EQUALS(static_cast<int>(objtype_t::FILE), static_cast<int>(pnode->GetType()));
    ASSERT_TRUE(pnode->Get(meta, st));
    ASSERT_TRUE(pnode->Get() == (strparent + builtin_file));
    ASSERT_TRUE(S_ISREG(st.st_mode));
    auto meta_iter = meta.find("x-amz-meta-creationtype");
    ASSERT_TRUE(meta.cend() != meta_iter);
    ASSERT_TRUE(meta_iter->second == "builtin");
    meta_iter = meta.find("Content-Type");
    ASSERT_TRUE(meta.cend() != meta_iter);
    ASSERT_TRUE(meta_iter->second == "text/plain");

    // symlink type
    pnode = root->Find(strparent + builtin_symlink, nullptr);
    ASSERT_TRUE(nullptr != pnode);
    ASSERT_EQUALS(static_cast<int>(objtype_t::SYMLINK), static_cast<int>(pnode->GetType()));
    ASSERT_TRUE(pnode->Get(meta, st));
    ASSERT_TRUE(pnode->Get() == (strparent + builtin_symlink));
    ASSERT_TRUE(S_ISLNK(st.st_mode));
    meta_iter = meta.find("x-amz-meta-creationtype");
    ASSERT_TRUE(meta.cend() != meta_iter);
    ASSERT_TRUE(meta_iter->second == "builtin");
    meta_iter = meta.find("Content-Type");
    ASSERT_TRUE(meta.cend() != meta_iter);
    ASSERT_TRUE(meta_iter->second == "text/plain");

    // normal directory type (dir name with "/")
    pnode = root->Find(strparent + builtin_dir_norm, nullptr);
    ASSERT_TRUE(nullptr != pnode);
    ASSERT_EQUALS(static_cast<int>(objtype_t::DIR_NORMAL), static_cast<int>(pnode->GetType()));
    ASSERT_TRUE(pnode->Get(meta, st));
    ASSERT_TRUE(pnode->Get() == (strparent + builtin_dir_norm));
    ASSERT_TRUE(S_ISDIR(st.st_mode));
    meta_iter = meta.find("x-amz-meta-creationtype");
    ASSERT_TRUE(meta.cend() != meta_iter);
    ASSERT_TRUE(meta_iter->second == "builtin");
    meta_iter = meta.find("Content-Type");
    ASSERT_TRUE(meta.cend() != meta_iter);
    ASSERT_TRUE(meta_iter->second == "application/x-directory");

    // normal directory type (dir name without "/")
    pnode = root->Find(strparent + builtin_dir_norm_noslash, nullptr);
    ASSERT_TRUE(nullptr != pnode);
    ASSERT_EQUALS(static_cast<int>(objtype_t::DIR_NORMAL), static_cast<int>(pnode->GetType()));
    ASSERT_TRUE(pnode->Get(meta, st));
    ASSERT_TRUE(pnode->Get() == (strparent + builtin_dir_norm));
    ASSERT_TRUE(S_ISDIR(st.st_mode));
    meta_iter = meta.find("x-amz-meta-creationtype");
    ASSERT_TRUE(meta.cend() != meta_iter);
    ASSERT_TRUE(meta_iter->second == "builtin");
    meta_iter = meta.find("Content-Type");
    ASSERT_TRUE(meta.cend() != meta_iter);
    ASSERT_TRUE(meta_iter->second == "application/x-directory");

    // no slash directory type (dir name with "/")
    pnode = root->Find(strparent + builtin_dir_noslash, nullptr);
    ASSERT_TRUE(nullptr != pnode);
    ASSERT_EQUALS(static_cast<int>(objtype_t::DIR_NOT_TERMINATE_SLASH), static_cast<int>(pnode->GetType()));
    ASSERT_TRUE(pnode->Get(meta, st));
    ASSERT_TRUE(pnode->Get() == (strparent + builtin_dir_noslash));
    ASSERT_TRUE(S_ISDIR(st.st_mode));
    meta_iter = meta.find("x-amz-meta-creationtype");
    ASSERT_TRUE(meta.cend() != meta_iter);
    ASSERT_TRUE(meta_iter->second == "builtin");
    meta_iter = meta.find("Content-Type");
    ASSERT_TRUE(meta.cend() != meta_iter);
    ASSERT_TRUE(meta_iter->second == "application/x-directory");

    // no slash directory type (dir name without "/")
    pnode = root->Find(strparent + builtin_dir_noslash_noslash, nullptr);
    ASSERT_TRUE(nullptr != pnode);
    ASSERT_EQUALS(static_cast<int>(objtype_t::DIR_NOT_TERMINATE_SLASH), static_cast<int>(pnode->GetType()));
    ASSERT_TRUE(pnode->Get(meta, st));
    ASSERT_TRUE(pnode->Get() == (strparent + builtin_dir_noslash));
    ASSERT_TRUE(S_ISDIR(st.st_mode));
    meta_iter = meta.find("x-amz-meta-creationtype");
    ASSERT_TRUE(meta.cend() != meta_iter);
    ASSERT_TRUE(meta_iter->second == "builtin");
    meta_iter = meta.find("Content-Type");
    ASSERT_TRUE(meta.cend() != meta_iter);
    ASSERT_TRUE(meta_iter->second == "application/x-directory");

    // _$folder$ suffix directory type (dir name with "/")
    pnode = root->Find(strparent + builtin_dir_folder, nullptr);
    ASSERT_TRUE(nullptr != pnode);
    ASSERT_EQUALS(static_cast<int>(objtype_t::DIR_FOLDER_SUFFIX), static_cast<int>(pnode->GetType()));
    ASSERT_TRUE(pnode->Get(meta, st));
    ASSERT_TRUE(pnode->Get() == (strparent + builtin_dir_folder));
    ASSERT_TRUE(S_ISDIR(st.st_mode));
    meta_iter = meta.find("x-amz-meta-creationtype");
    ASSERT_TRUE(meta.cend() != meta_iter);
    ASSERT_TRUE(meta_iter->second == "builtin");
    meta_iter = meta.find("Content-Type");
    ASSERT_TRUE(meta.cend() != meta_iter);
    ASSERT_TRUE(meta_iter->second == "application/x-directory");

    // _$folder$ suffix directory type (dir name without "/")
    pnode = root->Find(strparent + builtin_dir_folder_noslash, nullptr);
    ASSERT_TRUE(nullptr != pnode);
    ASSERT_EQUALS(static_cast<int>(objtype_t::DIR_FOLDER_SUFFIX), static_cast<int>(pnode->GetType()));
    ASSERT_TRUE(pnode->Get(meta, st));
    ASSERT_TRUE(pnode->Get() == (strparent + builtin_dir_folder));
    ASSERT_TRUE(S_ISDIR(st.st_mode));
    meta_iter = meta.find("x-amz-meta-creationtype");
    ASSERT_TRUE(meta.cend() != meta_iter);
    ASSERT_TRUE(meta_iter->second == "builtin");
    meta_iter = meta.find("Content-Type");
    ASSERT_TRUE(meta.cend() != meta_iter);
    ASSERT_TRUE(meta_iter->second == "application/x-directory");

    // not exist directory type (dir name with "/")
    pnode = root->Find(strparent + builtin_dir_notexist, nullptr);
    ASSERT_TRUE(nullptr != pnode);
    ASSERT_EQUALS(static_cast<int>(objtype_t::DIR_NOT_EXIST_OBJECT), static_cast<int>(pnode->GetType()));
    ASSERT_TRUE(pnode->Get(st));
    ASSERT_FALSE(pnode->Get(meta));
    ASSERT_TRUE(S_ISDIR(st.st_mode));
    ASSERT_TRUE(pnode->Get() == (strparent + builtin_dir_notexist));

    // not exist directory type (dir name without "/")
    pnode = root->Find(strparent + builtin_dir_notexist_noslash, nullptr);
    ASSERT_TRUE(nullptr != pnode);
    ASSERT_EQUALS(static_cast<int>(objtype_t::DIR_NOT_EXIST_OBJECT), static_cast<int>(pnode->GetType()));
    ASSERT_TRUE(pnode->Get(st));
    ASSERT_FALSE(pnode->Get(meta));
    ASSERT_TRUE(S_ISDIR(st.st_mode));
    ASSERT_TRUE(pnode->Get() == (strparent + builtin_dir_notexist));

    // negative type
    pnode = root->Find(strparent + builtin_negative, nullptr);
    ASSERT_TRUE(nullptr != pnode);
    ASSERT_EQUALS(static_cast<int>(objtype_t::NEGATIVE), static_cast<int>(pnode->GetType()));

    // check S3Object
    pnode = root->Find(strparent, nullptr);
    ASSERT_TRUE(nullptr != pnode);
    ASSERT_TRUE(pnode->GetS3ObjList(s3obj));
    ASSERT_TRUE(s3obj.GetNameMap(s3obj_typemap, /*OnlyNormalized=*/ true, /*CutSlash=*/ false));
    ASSERT_TRUE(s3obj_typemap.size() == 6);
    for(const auto& typemap : s3obj_typemap){
        if(typemap.first == builtin_file){
            ASSERT_EQUALS(static_cast<int>(objtype_t::UNKNOWN), static_cast<int>(typemap.second));
        }else if(typemap.first == builtin_symlink){
            ASSERT_EQUALS(static_cast<int>(objtype_t::UNKNOWN), static_cast<int>(typemap.second));
        }else if(typemap.first == builtin_dir_norm){
            ASSERT_EQUALS(static_cast<int>(objtype_t::DIR_NORMAL), static_cast<int>(typemap.second));
        }else if(typemap.first == builtin_dir_noslash){
            // [NOTE]
            // When a NameMap is created from an S3Object, DIR_NOT_TERMINATE_SLASH
            // may be converted to DIR_NORMAL, which applies in this case.
            // For details, refer to the comments in S3ObjList::insert.
            //
            ASSERT_EQUALS(static_cast<int>(objtype_t::DIR_NORMAL), static_cast<int>(typemap.second));
        }else if(typemap.first == builtin_dir_folder){
            ASSERT_EQUALS(static_cast<int>(objtype_t::DIR_FOLDER_SUFFIX), static_cast<int>(typemap.second));
        }else if(typemap.first == builtin_dir_notexist){
            // [NOTE]
            // Similar to the DIR_NOT_TERMINATE_SLASH case, it receives DIR_NORMAL.
            //
            ASSERT_EQUALS(static_cast<int>(objtype_t::DIR_NORMAL), static_cast<int>(typemap.second));
        }else{
            ASSERT_FALSE(true);     // fail
        }
    }
    auto common_prefix = s3obj.GetCommonPrefixes();
    ASSERT_TRUE(common_prefix.size() == 4);
    for(const auto& strprefix : common_prefix){
        bool found = false;
        for(const char* prefix : builtin_s3obj_common_prefix){
            if(strprefix == prefix){
                found = true;
            }
        }
        ASSERT_TRUE(found);
    }

    //---------------------------------
    // REMOVE TEST
    //---------------------------------
    // file type
    ASSERT_TRUE(root->RemoveChild(strparent + builtin_file));
    pnode = root->Find(strparent + builtin_file, nullptr);
    ASSERT_TRUE(nullptr == pnode);

    // symlink type
    ASSERT_TRUE(root->RemoveChild(strparent + builtin_symlink));
    pnode = root->Find(strparent + builtin_symlink, nullptr);
    ASSERT_TRUE(nullptr == pnode);

    // normal directory type (dir name with "/")
    ASSERT_TRUE(root->RemoveChild(strparent + builtin_dir_norm));
    pnode = root->Find(strparent + builtin_dir_norm, nullptr);
    ASSERT_TRUE(nullptr == pnode);

    // normal directory type (dir name without "/")
    ASSERT_TRUE(root->RemoveChild(strparent + builtin_dir_norm_noslash));      // already remove it
    pnode = root->Find(strparent + builtin_dir_norm_noslash, nullptr);
    ASSERT_TRUE(nullptr == pnode);

    // no slash directory type (dir name with "/")
    ASSERT_TRUE(root->RemoveChild(strparent + builtin_dir_noslash));
    pnode = root->Find(strparent + builtin_dir_noslash, nullptr);
    ASSERT_TRUE(nullptr == pnode);

    // no slash directory type (dir name without "/")
    ASSERT_TRUE(root->RemoveChild(strparent + builtin_dir_noslash_noslash));   // already remove it
    pnode = root->Find(strparent + builtin_dir_noslash_noslash, nullptr);
    ASSERT_TRUE(nullptr == pnode);

    // _$folder$ suffix directory type (dir name with "/")
    ASSERT_TRUE(root->RemoveChild(strparent + builtin_dir_folder));
    pnode = root->Find(strparent + builtin_dir_folder, nullptr);
    ASSERT_TRUE(nullptr == pnode);

    // _$folder$ suffix directory type (dir name without "/")
    ASSERT_TRUE(root->RemoveChild(strparent + builtin_dir_folder_noslash));    // already remove it
    pnode = root->Find(strparent + builtin_dir_folder_noslash, nullptr);
    ASSERT_TRUE(nullptr == pnode);

    // not exist directory type (dir name with "/")
    ASSERT_TRUE(root->RemoveChild(strparent + builtin_dir_notexist));
    pnode = root->Find(strparent + builtin_dir_notexist, nullptr);
    ASSERT_TRUE(nullptr == pnode);

    // not exist directory type (dir name without "/")
    ASSERT_TRUE(root->RemoveChild(strparent + builtin_dir_notexist_noslash));  // already remove it
    pnode = root->Find(strparent + builtin_dir_notexist_noslash, nullptr);
    ASSERT_TRUE(nullptr == pnode);

    // negative type
    ASSERT_TRUE(root->RemoveChild(strparent + builtin_negative));
    pnode = root->Find(strparent + builtin_negative, nullptr);
    ASSERT_TRUE(nullptr == pnode);

    // S3Object
    pnode = root->Find(strparent, nullptr);
    ASSERT_TRUE(nullptr != pnode);
    ASSERT_TRUE(pnode->GetS3ObjList(s3obj));
    s3obj_typemap.clear();
    ASSERT_TRUE(s3obj.GetNameMap(s3obj_typemap, /*OnlyNormalized=*/ false, /*CutSlash=*/ false));
    ASSERT_TRUE(s3obj_typemap.empty());
    common_prefix = s3obj.GetCommonPrefixes();
    ASSERT_TRUE(common_prefix.empty());
}

//--------------------------------------------------------------------
// Simple positive testing
//--------------------------------------------------------------------
//
// Test Level 1 directory : Add / Get / Remove (simple positive)
//
// Directory and file hierarchy:
//    "/"
//      +-- "file"                      Regular file
//      +-- "symlink"                   Symbolic Link file
//      +-- "dirnorm/"                  Directory terminated with "/"
//      +-- "dirnoslash"                Directory not terminated with "/"
//      +-- "dirfolder_$folder$"        Directory with the "_$folder$" suffix
//      +-- "dirnotexist/"              Non-existent directory object
//
static void test_positive_level1_add_get_remove()
{
    std::string                   parent("/");
    std::shared_ptr<DirStatCache> root(std::make_shared<DirStatCache>("/"));

    all_type_add_get_remove(parent, root);
}

//
// Test Level 2 directory : Add / Get / Remove (simple positive)
//
// Directory and file hierarchy:
//    "/"
//      +-- "file"
//      +-- "symlink"
//      +-- "dirnorm/"
//          +-- "file"
//          +-- "symlink"
//          +-- "dirnorm/"
//          +-- "dirnoslash"
//          +-- "dirfolder_$folder$"
//          +-- "dirnotexist/"
//      +-- "dirnoslash"
//          +-- "file"
//          +-- "symlink"
//          +-- "dirnorm/"
//          +-- "dirnoslash"
//          +-- "dirfolder_$folder$"
//          +-- "dirnotexist/"
//      +-- "dirfolder_$folder$"
//          +-- "file"
//          +-- "symlink"
//          +-- "dirnorm/"
//          +-- "dirnoslash"
//          +-- "dirfolder_$folder$"
//          +-- "dirnotexist/"
//      +-- "dirnotexist/"
//          +-- "file"
//          +-- "symlink"
//          +-- "dirnorm/"
//          +-- "dirnoslash"
//          +-- "dirfolder_$folder$"
//          +-- "dirnotexist/"
//
static void test_positive_level2_add_get_remove()
{
    std::string                   parent("/");
    std::shared_ptr<DirStatCache> root(std::make_shared<DirStatCache>("/"));

    // add level 1 directories
    add_all_type_child_nodes(parent, root, false, false);

    // test level 2 under normal type directory
    all_type_add_get_remove(parent + builtin_dir_norm, root);

    // test level 2 under no slash type directory
    all_type_add_get_remove(parent + builtin_dir_noslash, root);

    // test level 2 under folder type directory
    all_type_add_get_remove(parent + builtin_dir_folder, root);

    // test level 2 under not exist type directory
    all_type_add_get_remove(parent + builtin_dir_notexist, root);
}

//--------------------------------------------------------------------
// Remove directory which has child(ren)
//--------------------------------------------------------------------
//
// Remove non-empty directories of each type
//
static void test_remove_not_empty_directory()
{
    std::string                   parent("/");
    std::shared_ptr<DirStatCache> root(std::make_shared<DirStatCache>("/"));

    // Add all directory
    add_all_type_child_nodes(parent, root, false, false);

    struct stat  st_file = make_file_stat();
    headers_t    meta_file;
    meta_file["Content-Type"]            = "text/plain";
    meta_file["x-amz-meta-creationtype"] = "builtin";
    ASSERT_TRUE(root->Add(parent + builtin_dir_norm     + builtin_file, &st_file, &meta_file, objtype_t::FILE, false));
    ASSERT_TRUE(root->Add(parent + builtin_dir_noslash  + builtin_file, &st_file, &meta_file, objtype_t::FILE, false));
    ASSERT_TRUE(root->Add(parent + builtin_dir_folder   + builtin_file, &st_file, &meta_file, objtype_t::FILE, false));
    ASSERT_TRUE(root->Add(parent + builtin_dir_notexist + builtin_file, &st_file, &meta_file, objtype_t::FILE, false));

    S3ObjList    s3obj;
    ASSERT_TRUE(s3obj.insert(builtin_s3obj_file, nullptr, false, -1, nullptr));
    s3obj.AddCommonPrefix(builtin_s3obj_file);
    ASSERT_TRUE(root->AddS3ObjList(parent + builtin_dir_norm,     s3obj));
    ASSERT_TRUE(root->AddS3ObjList(parent + builtin_dir_noslash,  s3obj));
    ASSERT_TRUE(root->AddS3ObjList(parent + builtin_dir_folder,   s3obj));
    ASSERT_TRUE(root->AddS3ObjList(parent + builtin_dir_notexist, s3obj));

    //
    // Remove directory
    //
    ASSERT_TRUE(root->RemoveChild(parent + builtin_dir_norm));
    auto pnode = root->Find(parent + builtin_dir_norm, nullptr);
    ASSERT_TRUE(nullptr != pnode);

    ASSERT_TRUE(root->RemoveChild(parent + builtin_dir_noslash));
    pnode = root->Find(parent + builtin_dir_noslash, nullptr);
    ASSERT_TRUE(nullptr != pnode);

    ASSERT_TRUE(root->RemoveChild(parent + builtin_dir_folder));
    pnode = root->Find(parent + builtin_dir_folder, nullptr);
    ASSERT_TRUE(nullptr != pnode);

    ASSERT_TRUE(root->RemoveChild(parent + builtin_dir_notexist));
    pnode = root->Find(parent + builtin_dir_notexist, nullptr);
    ASSERT_TRUE(nullptr != pnode);

    //
    // Get file under removed directory
    //
    headers_t   meta;
    struct stat st;

    pnode = root->Find(parent + builtin_dir_norm + builtin_file, nullptr);
    ASSERT_TRUE(nullptr != pnode);
    ASSERT_EQUALS(static_cast<int>(objtype_t::FILE), static_cast<int>(pnode->GetType()));
    ASSERT_TRUE(pnode->Get(meta, st));
    ASSERT_TRUE(pnode->Get() == (parent + builtin_dir_norm + builtin_file));
    ASSERT_TRUE(S_ISREG(st.st_mode));
    auto meta_iter = meta.find("x-amz-meta-creationtype");
    ASSERT_TRUE(meta.cend() != meta_iter);
    ASSERT_TRUE(meta_iter->second == "builtin");
    meta_iter = meta.find("Content-Type");
    ASSERT_TRUE(meta.cend() != meta_iter);
    ASSERT_TRUE(meta_iter->second == "text/plain");

    pnode = root->Find(parent + builtin_dir_noslash + builtin_file, nullptr);
    ASSERT_TRUE(nullptr != pnode);
    ASSERT_EQUALS(static_cast<int>(objtype_t::FILE), static_cast<int>(pnode->GetType()));
    ASSERT_TRUE(pnode->Get(meta, st));
    ASSERT_TRUE(pnode->Get() == (parent + builtin_dir_noslash + builtin_file));
    ASSERT_TRUE(S_ISREG(st.st_mode));
    meta_iter = meta.find("x-amz-meta-creationtype");
    ASSERT_TRUE(meta.cend() != meta_iter);
    ASSERT_TRUE(meta_iter->second == "builtin");
    meta_iter = meta.find("Content-Type");
    ASSERT_TRUE(meta.cend() != meta_iter);
    ASSERT_TRUE(meta_iter->second == "text/plain");

    pnode = root->Find(parent + builtin_dir_folder + builtin_file, nullptr);
    ASSERT_TRUE(nullptr != pnode);
    ASSERT_EQUALS(static_cast<int>(objtype_t::FILE), static_cast<int>(pnode->GetType()));
    ASSERT_TRUE(pnode->Get(meta, st));
    ASSERT_TRUE(pnode->Get() == (parent + builtin_dir_folder + builtin_file));
    ASSERT_TRUE(S_ISREG(st.st_mode));
    meta_iter = meta.find("x-amz-meta-creationtype");
    ASSERT_TRUE(meta.cend() != meta_iter);
    ASSERT_TRUE(meta_iter->second == "builtin");
    meta_iter = meta.find("Content-Type");
    ASSERT_TRUE(meta.cend() != meta_iter);
    ASSERT_TRUE(meta_iter->second == "text/plain");

    pnode = root->Find(parent + builtin_dir_notexist + builtin_file, nullptr);
    ASSERT_TRUE(nullptr != pnode);
    ASSERT_EQUALS(static_cast<int>(objtype_t::FILE), static_cast<int>(pnode->GetType()));
    ASSERT_TRUE(pnode->Get(meta, st));
    ASSERT_TRUE(pnode->Get() == (parent + builtin_dir_notexist + builtin_file));
    ASSERT_TRUE(S_ISREG(st.st_mode));
    meta_iter = meta.find("x-amz-meta-creationtype");
    ASSERT_TRUE(meta.cend() != meta_iter);
    ASSERT_TRUE(meta_iter->second == "builtin");
    meta_iter = meta.find("Content-Type");
    ASSERT_TRUE(meta.cend() != meta_iter);
    ASSERT_TRUE(meta_iter->second == "text/plain");
}

//--------------------------------------------------------------------
// Expired caches
//--------------------------------------------------------------------
//
// Test all object type with expired validity periods
//
static void test_get_expired_caches()
{
    std::string                   parent("/");
    std::shared_ptr<DirStatCache> root(std::make_shared<DirStatCache>("/"));

    // Add all type
    add_all_type_child_nodes(parent, root, true, true);

    // Add files under level1 directory
    struct stat  st_file = make_file_stat();
    headers_t    meta_file;
    meta_file["Content-Type"]            = "text/plain";
    meta_file["x-amz-meta-creationtype"] = "builtin";
    ASSERT_TRUE(root->Add(parent + builtin_dir_norm     + builtin_file, &st_file, &meta_file, objtype_t::FILE, false));
    ASSERT_TRUE(root->Add(parent + builtin_dir_noslash  + builtin_file, &st_file, &meta_file, objtype_t::FILE, false));
    ASSERT_TRUE(root->Add(parent + builtin_dir_folder   + builtin_file, &st_file, &meta_file, objtype_t::FILE, false));
    ASSERT_TRUE(root->Add(parent + builtin_dir_notexist + builtin_file, &st_file, &meta_file, objtype_t::FILE, false));

    S3ObjList    s3obj;
    ASSERT_TRUE(s3obj.insert(builtin_s3obj_file, nullptr, false, -1, nullptr));
    s3obj.AddCommonPrefix(builtin_s3obj_file);
    ASSERT_TRUE(root->AddS3ObjList(parent + builtin_dir_norm,     s3obj));
    ASSERT_TRUE(root->AddS3ObjList(parent + builtin_dir_noslash,  s3obj));
    ASSERT_TRUE(root->AddS3ObjList(parent + builtin_dir_folder,   s3obj));
    ASSERT_TRUE(root->AddS3ObjList(parent + builtin_dir_notexist, s3obj));

    //
    // Set expire time = -1
    //
    // [NOTE]
    // Setting this value to less than 0 will effectively invalidate all
    // cache entries.
    //
    bool   org_enable   = StatCacheNode::IsEnableExpireTime();
    time_t org_expire   = StatCacheNode::SetExpireTime(-1);

    //
    // Get level1 files
    //
    auto pnode = root->Find(parent + builtin_file, nullptr);
    ASSERT_TRUE(nullptr == pnode);

    pnode = root->Find(parent + builtin_symlink, nullptr);
    ASSERT_TRUE(nullptr == pnode);

    //
    // Get level2 files
    //
    pnode = root->Find(parent + builtin_dir_norm + builtin_file, nullptr);
    ASSERT_TRUE(nullptr == pnode);

    pnode = root->Find(parent + builtin_dir_noslash + builtin_file, nullptr);
    ASSERT_TRUE(nullptr == pnode);

    pnode = root->Find(parent + builtin_dir_folder + builtin_file, nullptr);
    ASSERT_TRUE(nullptr == pnode);

    pnode = root->Find(parent + builtin_dir_notexist + builtin_file, nullptr);
    ASSERT_TRUE(nullptr == pnode);

    //
    // Get level1 directories
    //
    pnode = root->Find(parent + builtin_dir_norm, nullptr);
    ASSERT_TRUE(nullptr == pnode);

    pnode = root->Find(parent + builtin_dir_noslash, nullptr);
    ASSERT_TRUE(nullptr == pnode);

    pnode = root->Find(parent + builtin_dir_folder, nullptr);
    ASSERT_TRUE(nullptr == pnode);

    pnode = root->Find(parent + builtin_dir_notexist, nullptr);
    ASSERT_TRUE(nullptr == pnode);

    //
    // Get level1 negative
    //
    pnode = root->Find(parent + builtin_negative, nullptr);
    ASSERT_TRUE(nullptr == pnode);

    //
    // Get parent s3objlist
    //
    S3ObjList list;
    ASSERT_FALSE(root->GetS3ObjList(list));

    // Restore expire time
    if(org_enable){
        // [NOTE]
        // Since the "interval type" getter methods, we assume it remains
        // in its default state up to this point in the test and therefore
        // treat it as a fixed value.
        //
        StatCacheNode::SetExpireTime(org_expire, false);
    }else{
        StatCacheNode::UnsetExpireTime();
    }
}

//--------------------------------------------------------------------
// Test Notruncate
//--------------------------------------------------------------------
//
// Test the scenario : Where the notruncate setting is applied to a leaf
//                     file cache and the directory's expiration time
//                     has passed.
//
static void test_get_notruncate_expired_caches()
{
    std::string                   parent("/");
    std::shared_ptr<DirStatCache> root(std::make_shared<DirStatCache>("/"));

    // Add all type
    add_all_type_child_nodes(parent, root, true, true);

    // Add files under level1 directory
    struct stat  st_file = make_file_stat();
    headers_t    meta_file;
    meta_file["Content-Type"]            = "text/plain";
    meta_file["x-amz-meta-creationtype"] = "builtin";
    ASSERT_TRUE(root->Add(parent + builtin_dir_norm     + builtin_file, &st_file, &meta_file, objtype_t::FILE, false));
    ASSERT_TRUE(root->Add(parent + builtin_dir_noslash  + builtin_file, &st_file, &meta_file, objtype_t::FILE, false));
    ASSERT_TRUE(root->Add(parent + builtin_dir_folder   + builtin_file, &st_file, &meta_file, objtype_t::FILE, false));
    ASSERT_TRUE(root->Add(parent + builtin_dir_notexist + builtin_file, &st_file, &meta_file, objtype_t::FILE, false));

    S3ObjList    s3obj;
    ASSERT_TRUE(s3obj.insert(builtin_s3obj_file, nullptr, false, -1, nullptr));
    s3obj.AddCommonPrefix(builtin_s3obj_file);
    ASSERT_TRUE(root->AddS3ObjList(parent + builtin_dir_norm,     s3obj));
    ASSERT_TRUE(root->AddS3ObjList(parent + builtin_dir_noslash,  s3obj));
    ASSERT_TRUE(root->AddS3ObjList(parent + builtin_dir_folder,   s3obj));
    ASSERT_TRUE(root->AddS3ObjList(parent + builtin_dir_notexist, s3obj));

    //
    // Set notruncate for the terminal files
    //
    auto pnode = root->Find(parent + builtin_file, nullptr);
    ASSERT_TRUE(nullptr != pnode);
    ASSERT_TRUE(pnode->Update(true));

    pnode = root->Find(parent + builtin_symlink, nullptr);
    ASSERT_TRUE(nullptr != pnode);
    ASSERT_TRUE(pnode->Update(true));

    pnode = root->Find(parent + builtin_dir_norm + builtin_file, nullptr);
    ASSERT_TRUE(nullptr != pnode);
    ASSERT_TRUE(pnode->Update(true));

    pnode = root->Find(parent + builtin_dir_noslash + builtin_file, nullptr);
    ASSERT_TRUE(nullptr != pnode);
    ASSERT_TRUE(pnode->Update(true));

    pnode = root->Find(parent + builtin_dir_folder + builtin_file, nullptr);
    ASSERT_TRUE(nullptr != pnode);
    ASSERT_TRUE(pnode->Update(true));

    pnode = root->Find(parent + builtin_dir_notexist + builtin_file, nullptr);
    ASSERT_TRUE(nullptr != pnode);
    ASSERT_TRUE(pnode->Update(true));

    //
    // Set expire time = -1
    //
    // [NOTE]
    // Setting this value to less than 0 will effectively invalidate all
    // cache entries.
    //
    bool   org_enable   = StatCacheNode::IsEnableExpireTime();
    time_t org_expire = StatCacheNode::SetExpireTime(-1);

    //
    // Get level1 files
    //
    headers_t   meta;
    struct stat st;

    pnode = root->Find(parent + builtin_file, nullptr);
    ASSERT_TRUE(nullptr != pnode);
    ASSERT_EQUALS(static_cast<int>(objtype_t::FILE), static_cast<int>(pnode->GetType()));
    ASSERT_TRUE(pnode->Get(meta, st));
    ASSERT_TRUE(pnode->Get() == (parent + builtin_file));
    ASSERT_TRUE(S_ISREG(st.st_mode));
    auto meta_iter = meta.find("x-amz-meta-creationtype");
    ASSERT_TRUE(meta.cend() != meta_iter);
    ASSERT_TRUE(meta_iter->second == "builtin");
    meta_iter = meta.find("Content-Type");
    ASSERT_TRUE(meta.cend() != meta_iter);
    ASSERT_TRUE(meta_iter->second == "text/plain");

    pnode = root->Find(parent + builtin_symlink, nullptr);
    ASSERT_TRUE(nullptr != pnode);
    ASSERT_EQUALS(static_cast<int>(objtype_t::SYMLINK), static_cast<int>(pnode->GetType()));
    ASSERT_TRUE(pnode->Get(meta, st));
    ASSERT_TRUE(pnode->Get() == (parent + builtin_symlink));
    ASSERT_TRUE(S_ISLNK(st.st_mode));
    meta_iter = meta.find("x-amz-meta-creationtype");
    ASSERT_TRUE(meta.cend() != meta_iter);
    ASSERT_TRUE(meta_iter->second == "builtin");
    meta_iter = meta.find("Content-Type");
    ASSERT_TRUE(meta.cend() != meta_iter);
    ASSERT_TRUE(meta_iter->second == "text/plain");

    //
    // Get level2 files
    //
    pnode = root->Find(parent + builtin_dir_norm + builtin_file, nullptr);
    ASSERT_TRUE(nullptr != pnode);
    ASSERT_EQUALS(static_cast<int>(objtype_t::FILE), static_cast<int>(pnode->GetType()));
    ASSERT_TRUE(pnode->Get(meta, st));
    ASSERT_TRUE(pnode->Get() == (parent + builtin_dir_norm + builtin_file));
    ASSERT_TRUE(S_ISREG(st.st_mode));
    meta_iter = meta.find("x-amz-meta-creationtype");
    ASSERT_TRUE(meta.cend() != meta_iter);
    ASSERT_TRUE(meta_iter->second == "builtin");
    meta_iter = meta.find("Content-Type");
    ASSERT_TRUE(meta.cend() != meta_iter);
    ASSERT_TRUE(meta_iter->second == "text/plain");

    pnode = root->Find(parent + builtin_dir_noslash + builtin_file, nullptr);
    ASSERT_TRUE(nullptr != pnode);
    ASSERT_EQUALS(static_cast<int>(objtype_t::FILE), static_cast<int>(pnode->GetType()));
    ASSERT_TRUE(pnode->Get(meta, st));
    ASSERT_TRUE(pnode->Get() == (parent + builtin_dir_noslash + builtin_file));
    ASSERT_TRUE(S_ISREG(st.st_mode));
    meta_iter = meta.find("x-amz-meta-creationtype");
    ASSERT_TRUE(meta.cend() != meta_iter);
    ASSERT_TRUE(meta_iter->second == "builtin");
    meta_iter = meta.find("Content-Type");
    ASSERT_TRUE(meta.cend() != meta_iter);
    ASSERT_TRUE(meta_iter->second == "text/plain");

    pnode = root->Find(parent + builtin_dir_folder + builtin_file, nullptr);
    ASSERT_TRUE(nullptr != pnode);
    ASSERT_EQUALS(static_cast<int>(objtype_t::FILE), static_cast<int>(pnode->GetType()));
    ASSERT_TRUE(pnode->Get(meta, st));
    ASSERT_TRUE(pnode->Get() == (parent + builtin_dir_folder + builtin_file));
    ASSERT_TRUE(S_ISREG(st.st_mode));
    meta_iter = meta.find("x-amz-meta-creationtype");
    ASSERT_TRUE(meta.cend() != meta_iter);
    ASSERT_TRUE(meta_iter->second == "builtin");
    meta_iter = meta.find("Content-Type");
    ASSERT_TRUE(meta.cend() != meta_iter);
    ASSERT_TRUE(meta_iter->second == "text/plain");

    pnode = root->Find(parent + builtin_dir_notexist + builtin_file, nullptr);
    ASSERT_TRUE(nullptr != pnode);
    ASSERT_EQUALS(static_cast<int>(objtype_t::FILE), static_cast<int>(pnode->GetType()));
    ASSERT_TRUE(pnode->Get(meta, st));
    ASSERT_TRUE(pnode->Get() == (parent + builtin_dir_notexist + builtin_file));
    ASSERT_TRUE(S_ISREG(st.st_mode));
    meta_iter = meta.find("x-amz-meta-creationtype");
    ASSERT_TRUE(meta.cend() != meta_iter);
    ASSERT_TRUE(meta_iter->second == "builtin");
    meta_iter = meta.find("Content-Type");
    ASSERT_TRUE(meta.cend() != meta_iter);
    ASSERT_TRUE(meta_iter->second == "text/plain");

    //
    // Get level1 directories
    //
    pnode = root->Find(parent + builtin_dir_norm, nullptr);
    ASSERT_TRUE(nullptr == pnode);

    pnode = root->Find(parent + builtin_dir_noslash, nullptr);
    ASSERT_TRUE(nullptr == pnode);

    pnode = root->Find(parent + builtin_dir_folder, nullptr);
    ASSERT_TRUE(nullptr == pnode);

    pnode = root->Find(parent + builtin_dir_notexist, nullptr);
    ASSERT_TRUE(nullptr == pnode);

    //
    // Get level1 negative
    //
    pnode = root->Find(parent + builtin_negative, nullptr);
    ASSERT_TRUE(nullptr == pnode);

    // Restore expire time
    if(org_enable){
        // [NOTE]
        // Since the "interval type" getter methods, we assume it remains
        // in its default state up to this point in the test and therefore
        // treat it as a fixed value.
        //
        StatCacheNode::SetExpireTime(org_expire, false);
    }else{
        StatCacheNode::UnsetExpireTime();
    }
}

//--------------------------------------------------------------------
// Common Prefixes in S3Object
//--------------------------------------------------------------------
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

//--------------------------------------------------------------------
// Directory objects
//--------------------------------------------------------------------
//
// Directory objects can change their physical representation while the
// path stays a directory(ex. replacing a legacy "dir" object with "dir/").
// Re-adding a cached directory with a new sub-type must update the node,
// otherwise a stale sub-type can never heal.
//
static void test_dir_subtype_heal()
{
    std::shared_ptr<DirStatCache> root(std::make_shared<DirStatCache>("/"));
    struct stat  st = make_dir_stat();
    headers_t    meta;
    meta["Content-Type"]       = "application/x-directory";
    meta["x-amz-meta-foreign"] = "keepme";

    ASSERT_TRUE(root->Add("/dir/", &st, &meta, objtype_t::DIR_NOT_TERMINATE_SLASH, false));
    std::shared_ptr<StatCacheNode> node = root->Find("/dir/");
    ASSERT_TRUE(nullptr != node);
    ASSERT_EQUALS(static_cast<int>(objtype_t::DIR_NOT_TERMINATE_SLASH), static_cast<int>(node->GetType()));

    // Update to the modern "dir/" representation.
    ASSERT_TRUE(root->Add("/dir/", &st, &meta, objtype_t::DIR_NORMAL, false));
    node = root->Find("/dir/");
    ASSERT_TRUE(nullptr != node);
    ASSERT_EQUALS(static_cast<int>(objtype_t::DIR_NORMAL), static_cast<int>(node->GetType()));

    // The stat and meta survive the sub-type update.
    struct stat getst = {};
    headers_t   getmeta;
    ASSERT_TRUE(node->Get(getmeta, getst));
    ASSERT_TRUE(S_ISDIR(getst.st_mode));
    ASSERT_TRUE(getmeta.cend() != getmeta.find("x-amz-meta-foreign"));

    // The object was deleted externally and only the path remains.
    ASSERT_TRUE(root->Add("/dir/", &st, &meta, objtype_t::DIR_NOT_EXIST_OBJECT, false));
    node = root->Find("/dir/");
    ASSERT_TRUE(nullptr != node);
    ASSERT_EQUALS(static_cast<int>(objtype_t::DIR_NOT_EXIST_OBJECT), static_cast<int>(node->GetType()));

    // Re-adding with the same sub-type keeps the node untouched.
    ASSERT_TRUE(root->Add("/dir/", &st, &meta, objtype_t::DIR_NOT_EXIST_OBJECT, false));
    node = root->Find("/dir/");
    ASSERT_TRUE(nullptr != node);
    ASSERT_EQUALS(static_cast<int>(objtype_t::DIR_NOT_EXIST_OBJECT), static_cast<int>(node->GetType()));
}

//
// The same heal must work for a directory nested below the top level,
// where the parent recursion ends in the direct-child branch.
//
static void test_nested_dir_subtype_heal()
{
    std::shared_ptr<DirStatCache> root(std::make_shared<DirStatCache>("/"));
    struct stat  st = make_dir_stat();

    ASSERT_TRUE(root->Add("/dir/", &st, nullptr, objtype_t::DIR_NORMAL, false));
    ASSERT_TRUE(root->Add("/dir/sub/", &st, nullptr, objtype_t::DIR_NOT_TERMINATE_SLASH, false));
    std::shared_ptr<StatCacheNode> node = root->Find("/dir/sub/");
    ASSERT_TRUE(nullptr != node);
    ASSERT_EQUALS(static_cast<int>(objtype_t::DIR_NOT_TERMINATE_SLASH), static_cast<int>(node->GetType()));

    ASSERT_TRUE(root->Add("/dir/sub/", &st, nullptr, objtype_t::DIR_NORMAL, false));
    node = root->Find("/dir/sub/");
    ASSERT_TRUE(nullptr != node);
    ASSERT_EQUALS(static_cast<int>(objtype_t::DIR_NORMAL), static_cast<int>(node->GetType()));
}

//
// Non-directory nodes are not affected by the directory sub-type update.
//
static void test_file_type_unchanged()
{
    std::shared_ptr<DirStatCache> root(std::make_shared<DirStatCache>("/"));
    struct stat  st = make_file_stat();

    ASSERT_TRUE(root->Add("/file", &st, nullptr, objtype_t::FILE, false));
    std::shared_ptr<StatCacheNode> node = root->Find("/file");
    ASSERT_TRUE(nullptr != node);
    ASSERT_EQUALS(static_cast<int>(objtype_t::FILE), static_cast<int>(node->GetType()));

    ASSERT_TRUE(root->Add("/file", &st, nullptr, objtype_t::FILE, false));
    node = root->Find("/file");
    ASSERT_TRUE(nullptr != node);
    ASSERT_EQUALS(static_cast<int>(objtype_t::FILE), static_cast<int>(node->GetType()));
}

//--------------------------------------------------------------------
// Main
//--------------------------------------------------------------------
int main(int argc, const char *argv[])
{
    test_common_prefix_type();
    test_dir_subtype_heal();
    test_nested_dir_subtype_heal();
    test_file_type_unchanged();
    test_positive_level1_add_get_remove();
    test_positive_level2_add_get_remove();
    test_remove_not_empty_directory();
    test_get_expired_caches();
    test_get_notruncate_expired_caches();
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
