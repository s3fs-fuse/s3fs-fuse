/*
 * s3fs - FUSE-based file system backed by Amazon S3
 *
 * Copyright(C) 2007 Randy Rizun <rrizun@gmail.com>
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

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <limits>
#include <memory>
#include <mutex>
#include <string>
#include <unistd.h>
#include <utility>
#include <dirent.h>  // NOLINT(misc-include-cleaner)
#include <sys/types.h>
#include <getopt.h>  // NOLINT(misc-include-cleaner)

#include "common.h"
#include "s3fs.h"  // NOLINT(misc-include-cleaner)
#include "s3fs_logger.h"
#include "metaheader.h"
#include "fdcache.h"
#include "fdcache_auto.h"
#include "fdcache_stat.h"
#include "curl.h"
#include "curl_share.h"
#include "curl_util.h"
#include "s3objlist.h"
#include "cache.h"
#include "addhead.h"
#include "sighandlers.h"
#include "s3fs_xml.h"
#include "string_util.h"
#include "s3fs_auth.h"
#include "s3fs_cred.h"
#include "s3fs_help.h"
#include "s3fs_util.h"
#include "s3fs_threadreqs.h"
#include "mpu_util.h"
#include "threadpoolman.h"

//-------------------------------------------------------------------
// Symbols
//-------------------------------------------------------------------
#ifndef ENOATTR
#define ENOATTR                   ENODATA
#endif

#if FUSE_USE_VERSION >= 30
#define FUSE3_FILE_INFO_ARG , struct fuse_file_info* info
#else
#define FUSE3_FILE_INFO_ARG
#endif

//-------------------------------------------------------------------
// Static variables
//-------------------------------------------------------------------
static uid_t mp_uid               = 0;    // owner of mount point(only not specified uid opt)
static gid_t mp_gid               = 0;    // group of mount point(only not specified gid opt)
static mode_t mp_mode             = 0;    // mode of mount point
static mode_t mp_umask            = 0;    // umask for mount point
static bool is_mp_umask           = false;// default does not set.
static std::string mountpoint;
static std::unique_ptr<S3fsCred> ps3fscred; // using only in this file
static std::string mimetype_file;
static bool nocopyapi             = false;
static bool norenameapi           = false;
#if FUSE_USE_VERSION < 30
static bool nonempty              = false;
#endif
static bool allow_other           = false;
static uid_t s3fs_uid             = 0;
static gid_t s3fs_gid             = 0;
static mode_t s3fs_umask          = 0;
static bool is_s3fs_uid           = false;// default does not set.
static bool is_s3fs_gid           = false;// default does not set.
static bool is_s3fs_umask         = false;// default does not set.
static bool is_remove_cache       = false;
static bool is_use_xattr          = false;
static off_t multipart_threshold  = 25 * 1024 * 1024;
static int64_t singlepart_copy_limit = 512 * 1024 * 1024;
static bool is_region_specified   = false;
static int s3fs_init_deferred_exit_status = 0;
static bool support_compat_dir    = false;// default does not support compatibility directory type
static int max_keys_list_object   = 1000;// default is 1000
static off_t max_dirty_data       = 5LL * 1024LL * 1024LL * 1024LL;
static bool use_wtf8              = false;
static off_t fake_diskfree_size   = -1; // default is not set(-1)
static bool update_parent_dir_stat= false;  // default not updating parent directory stats
static fsblkcnt_t bucket_block_count;                       // advertised block count of the bucket
static unsigned long s3fs_block_size = 16 * 1024 * 1024;    // s3fs block size is 16MB

//-------------------------------------------------------------------
// Static functions : prototype
//-------------------------------------------------------------------
static int chk_dir_object_type(const char* path, std::string& normpath, std::string& curpath, headers_t* pmeta = nullptr, objtype_t* pObjType = nullptr);
static int remove_old_type_dir(const std::string& path, objtype_t ObjType);
static int get_object_attribute(const char* path, struct stat* pstbuf, headers_t* pmeta = nullptr, bool overcheck = true, objtype_t* pObjType = nullptr, bool notruncate = false);
static int check_object_access(const char* path, int mask, struct stat* pstbuf);
static int check_object_owner(const char* path, struct stat* pstbuf);
static int check_parent_object_access(const char* path, int mask);
static int get_local_fent(AutoFdEntity& autoent, FdEntity **entity, const char* path, int flags = O_RDONLY, bool is_load = false);
static int readdir_multi_head(const std::string& strpath, const S3ObjList& head, void* buf, fuse_fill_dir_t filler);
static int list_bucket(const char* path, S3ObjList& head, const char* delimiter, bool check_content_only = false);
static int directory_empty(const char* path);
static int rename_large_object(const char* from, const char* to);
static int create_file_object(const char* path, mode_t mode, uid_t uid, gid_t gid, struct stat* pstbuf = nullptr);
static int create_directory_object(const char* path, mode_t mode, const struct timespec& ts_atime, const struct timespec& ts_mtime, const struct timespec& ts_ctime, uid_t uid, gid_t gid, const char* pxattrvalue, struct stat* pstbuf = nullptr);
static int rename_object(const char* from, const char* to, bool update_ctime);
static int rename_object_nocopy(const char* from, const char* to, bool update_ctime);
static int clone_directory_object(const char* from, const char* to, bool update_ctime, const char* pxattrvalue);
static int rename_directory(const char* from, const char* to);
static int update_mctime_parent_directory(const char* _path);
static int remote_mountpath_exists(const char* path, bool compat_dir);
static bool get_meta_xattr_value(const char* path, std::string& rawvalue);
static bool get_parent_meta_xattr_value(const char* path, std::string& rawvalue);
static bool get_xattr_posix_key_value(const char* path, std::string& xattrvalue, bool default_key);
static bool build_inherited_xattr_value(const char* path, std::string& xattrvalue);
static bool parse_xattr_keyval(const std::string& xattrpair, std::string& key, std::string* pval);
static size_t parse_xattrs(const std::string& strxattrs, xattrs_t& xattrs);
static std::string raw_build_xattrs(const xattrs_t& xattrs);
static std::string build_xattrs(const xattrs_t& xattrs);
static int s3fs_check_service();
static bool set_mountpoint_attribute(struct stat& mpst);
static int set_bucket(const std::string& arg);
static int my_fuse_opt_proc(void* data, const char* arg, int key, struct fuse_args* outargs);
static fsblkcnt_t parse_bucket_size(std::string max_size);
static bool is_cmd_exists(const std::string& command);
static int print_umount_message(const std::string& mp, bool force) __attribute__ ((unused));

//-------------------------------------------------------------------
// fuse interface functions
//-------------------------------------------------------------------
static int s3fs_getattr(const char* path, struct stat* stbuf FUSE3_FILE_INFO_ARG);
static int s3fs_readlink(const char* path, char* buf, size_t size);
static int s3fs_mknod(const char* path, mode_t mode, dev_t rdev);
static int s3fs_mkdir(const char* path, mode_t mode);
static int s3fs_unlink(const char* path);
static int s3fs_rmdir(const char* path);
static int s3fs_symlink(const char* from, const char* to);
#if FUSE_USE_VERSION >= 30
static int s3fs_rename(const char* from, const char* to, unsigned int flags);
#else
static int s3fs_rename(const char* from, const char* to);
#endif
static int s3fs_link(const char* from, const char* to);
static int s3fs_chmod(const char* path, mode_t mode FUSE3_FILE_INFO_ARG);
static int s3fs_chmod_nocopy(const char* path, mode_t mode FUSE3_FILE_INFO_ARG);
static int s3fs_chown(const char* path, uid_t uid, gid_t gid FUSE3_FILE_INFO_ARG);
static int s3fs_chown_nocopy(const char* path, uid_t uid, gid_t gid FUSE3_FILE_INFO_ARG);
static int s3fs_utimens(const char* path, const struct timespec ts[2] FUSE3_FILE_INFO_ARG);
static int s3fs_utimens_nocopy(const char* path, const struct timespec ts[2] FUSE3_FILE_INFO_ARG);
static int s3fs_truncate(const char* path, off_t size FUSE3_FILE_INFO_ARG);
static int s3fs_create(const char* path, mode_t mode, struct fuse_file_info* fi);
static int s3fs_open(const char* path, struct fuse_file_info* fi);
static int s3fs_read(const char* path, char* buf, size_t size, off_t offset, struct fuse_file_info* fi);
static int s3fs_write(const char* path, const char* buf, size_t size, off_t offset, struct fuse_file_info* fi);
static int s3fs_statfs(const char* path, struct statvfs* stbuf);
static int s3fs_flush(const char* path, struct fuse_file_info* fi);
static int s3fs_fsync(const char* path, int datasync, struct fuse_file_info* fi);
static int s3fs_release(const char* path, struct fuse_file_info* fi);
static int s3fs_opendir(const char* path, struct fuse_file_info* fi);
#if FUSE_USE_VERSION >= 30
static int s3fs_readdir(const char* path, void* buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info* info, enum fuse_readdir_flags);
#else
static int s3fs_readdir(const char* path, void* buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info* info);
#endif
static int s3fs_access(const char* path, int mask);
#if FUSE_USE_VERSION >= 30
static void* s3fs_init(struct fuse_conn_info* conn, fuse_config* config);
#else
static void* s3fs_init(struct fuse_conn_info* conn);
#endif
static void s3fs_destroy(void*);
#ifdef __APPLE__
static int s3fs_setxattr(const char* path, const char* name, const char* value, size_t size, int flags, uint32_t position);
static int s3fs_getxattr(const char* path, const char* name, char* value, size_t size, uint32_t position);
#else
static int s3fs_setxattr(const char* path, const char* name, const char* value, size_t size, int flags);
static int s3fs_getxattr(const char* path, const char* name, char* value, size_t size);
#endif
static int s3fs_listxattr(const char* path, char* list, size_t size);
static int s3fs_removexattr(const char* path, const char* name);

//-------------------------------------------------------------------
// Classes
//-------------------------------------------------------------------
//
// A flag indicating whether the mount point has a stat
//
// [NOTE]
// The flag is accessed from child threads, so std::atomic is used for exclusive control of flags.
static std::atomic<bool> has_mp_stat;

//-------------------------------------------------------------------
// Functions
//-------------------------------------------------------------------
static constexpr bool IS_CREATE_MP_STAT(const char* path)
{
    // [NOTE] has_mp_stat is set in get_object_attribute()
    return (path != nullptr && 0 == strcmp(path, "/") && !has_mp_stat);
}

// [Detail]
// This function is complicated for checking directory object type.
// Arguments is used for deleting cache/path, and remake directory object.
// Please see the codes which calls this function.
//
// path:      target path
// normpath:  normalized path for making/putting/getting after checking
// curpath:   current object name for deleting after checking
// pmeta:     headers map
// pObjType:  object type(only directory)
//
static int chk_dir_object_type(const char* path, std::string& normpath, std::string& curpath, headers_t* pmeta, objtype_t* pObjType)
{
    objtype_t tmpObjType = objtype_t::UNKNOWN;
    int       result     = -1;
    pObjType             = pObjType ? pObjType : &tmpObjType;

    // Normalize new path.
    normpath = path;
    if('/' != *normpath.rbegin()){
        std::string::size_type Pos;
        if(std::string::npos != (Pos = normpath.find("_$folder$", 0))){
            normpath.erase(Pos);
        }
        normpath += "/";
    }

    // Always check "dir/" at first.
    if(0 == (result = get_object_attribute(normpath.c_str(), nullptr, pmeta, false, pObjType))){
        // Found "dir/" object
        if(objtype_t::DIR_NOT_TERMINATE_SLASH == *pObjType){
            curpath = normpath;
            curpath.erase(normpath.length() - 1);
        }else if(objtype_t::DIR_FOLDER_SUFFIX == *pObjType){
            curpath = normpath;
            curpath.erase(normpath.length() - 1);
            curpath += "_$folder$";
        }else if(objtype_t::DIR_NOT_EXIST_OBJECT == *pObjType){
            curpath  = "";
        }else{  // objtype_t::DIR_NORMAL
            curpath = normpath;
        }
    }
    return result;
}

static int remove_old_type_dir(const std::string& path, objtype_t ObjType)
{
    if(NEED_RMDIR_OBJ(ObjType)){
        int result;
        if(0 != (result = delete_request(path))){
            return result;
        }
        // succeed removing or not found the directory, then remove stat cache as well
        StatCache::getStatCacheData()->DelStat(path);
    }else{
        // nothing to do
    }
    return 0;
}

//
// Get object attributes with stat cache.
// This function is base for s3fs_getattr().
//
// [NOTICE]
// Checking order is changed following list because of reducing the number of the requests.
// 1) "dir"
// 2) "dir/"
// 3) "dir_$folder$"
//
// Special two case of the mount point directory:
//  [Case 1] the mount point is the root of the bucket:
//           1) "/"
//
//  [Case 2] the mount point is a directory path(ex. foo) below the bucket:
//           1) "foo"
//           2) "foo/"
//           3) "foo_$folder$"
//
static int get_object_attribute(const char* path, struct stat* pstbuf, headers_t* pmeta, bool overcheck, objtype_t* pObjType, bool notruncate)
{
    int          result               = -1;
    std::string  strpath;
    struct stat  tmpstbuf             = {};
    headers_t    tmpHead;
    objtype_t    tmpObjType           = objtype_t::UNKNOWN;
    bool         need_meta            = (nullptr != pmeta); // required for stat cache checking
    bool         is_mountpoint        = false;              // path is the mount point
    bool         is_bucket_mountpoint = false;              // path is the mount point which is the bucket root
    std::string::size_type Pos;

    //
    // Initialize variables in this function
    //
    if(!path || '\0' == path[0]){
        return -ENOENT;
    }
    strpath   = path;
    pmeta     = pmeta ? pmeta : &tmpHead;
    pstbuf    = pstbuf ? pstbuf : &tmpstbuf;
    *pstbuf   = {};
    pObjType  = (pObjType ? pObjType : &tmpObjType);
    *pObjType = objtype_t::UNKNOWN;

    S3FS_PRN_DBG("[path=%s, overcheck=%s, objtype=%s, notruncate=%s]", path, overcheck ? "yes" : "no", STR_OBJTYPE(*pObjType).c_str(), notruncate ? "yes" : "no");

    //
    // Check mount point
    //
    if("/" == strpath || "." == strpath){
        is_mountpoint = true;
        if(mount_prefix.empty()){
            is_bucket_mountpoint = true;
        }
        // default stat for mount point if the directory stat file is not existed.
        pstbuf->st_mode  = mp_mode;
        pstbuf->st_uid   = is_s3fs_uid ? s3fs_uid : mp_uid;
        pstbuf->st_gid   = is_s3fs_gid ? s3fs_gid : mp_gid;
    }

    //
    // Set object type by path
    //
    // [NOTE]
    // With "support_compat_dir" and "overcheck", if the path has a "_$folder$" suffix,
    // it will be searched as "dir/".
    //
    if(std::string::npos != strpath.find("_$folder$", 0)){
        *pObjType = objtype_t::DIR_FOLDER_SUFFIX;
    }else if('/' == *strpath.rbegin()){
        *pObjType = objtype_t::DIR_NORMAL;
    }else{      // '/' != *strpath.rbegin()
        *pObjType = objtype_t::UNKNOWN;
    }

    //
    // Check compatible directory
    //
    if(support_compat_dir && overcheck && std::string::npos != (Pos = strpath.find("_$folder$", 0))){
        strpath.erase(Pos);
        strpath += "/";
    }

    //
    // Check Stat Cache
    //
    // [NOTE]
    // For mount points("/"), the Stat cache key name is "/".
    //
    // [MEMO]
    // If pmeta is specified when calling this function, and the stat
    // cache only has a stat structure and no meta information, a HEAD
    // request will occur in subsequent processing.
    // In other words, if pmeta is nullptr and the stat cache has a stat
    // structure, no HEAD request will occur, even if it does not have
    // meta information.
    //
    if(StatCache::getStatCacheData()->GetStat(strpath, pstbuf, (need_meta ? pmeta : nullptr), pObjType)){
        return 0;
    }else{
        // [NOTE]
        // In the case of a Negative Cache, GetStat() returns false and
        // objtype_t::NEGATIVE is set.
        //
        if(objtype_t::NEGATIVE == *pObjType){
            // When not hit cache and the reason is negative cache.
            return -ENOENT;
        }
    }

    //
    // Get "path" object headers
    //
    // set query(head request) path
    if(is_bucket_mountpoint){
        // [NOTE]
        // This is a special process for mount point
        // The path is "/" for mount points.
        // If the bucket mounted at a mount point, we try to find "/" object under
        // the bucket for mount point's stat.
        // In this case, we will send the request "HEAD // HTTP /1.1" to S3 server.
        //
        // If the directory under the bucket is mounted, it will be sent
        // "HEAD /<directories ...>/ HTTP/1.1", so we do not need to change path at
        // here.
        //
        strpath = "//";         // strpath is "//"
    }else{
        strpath = path;
    }

    // get headers
    result = head_request(strpath, *pmeta);

    // if not found target path object, do over checking
    if(-EPERM == result){
        // [NOTE]
        // In case of a permission error, it exists in directory
        // file list but inaccessible. So there is a problem that
        // it will send a HEAD request every time, because it is
        // not registered in the Stats cache.
        // Therefore, even if the file has a permission error, it
        // should be registered in the Stats cache. However, if
        // the response without modifying is registered in the
        // cache, the file permission will be 0644(umask dependent)
        // because the meta header does not exist.
        // Thus, set the mode of 0000 here in the meta header so
        // that s3fs can print a permission error when the file
        // is actually accessed.
        // It is better not to set meta header other than mode,
        // so do not do it.
        //
        (*pmeta)["x-amz-meta-mode"] = "0";

        *pObjType = objtype_t::FILE;       // Since can't access the object, set as a file.

    }else if(0 != result){
        if(overcheck && !is_bucket_mountpoint){
            // when support_compat_dir is disabled, strpath maybe have "_$folder$".
            if('/' != *strpath.rbegin() && std::string::npos == strpath.find("_$folder$", 0)){
                // now path is "object", do check "object/" for over checking
                strpath += "/";

                // re-get headers
                if(0 == (result = head_request(strpath, *pmeta))){
                    // found "dir/"
                    *pObjType = objtype_t::DIR_NORMAL;
                }
            }
            if(support_compat_dir && 0 != result){
                // now path is "object/", do check "object_$folder$" for over checking
                strpath.erase(strpath.length() - 1);
                strpath += "_$folder$";

                // re-get headers
                result = head_request(strpath, *pmeta);

                // cppcheck-suppress unmatchedSuppression
                // cppcheck-suppress knownConditionTrueFalse
                if(0 == result){
                    // found "object_$folder$"
                    *pObjType = objtype_t::DIR_FOLDER_SUFFIX;
                }else{
                    // cut "_$folder$" for over checking "no dir object" after here
                    if(std::string::npos != (Pos = strpath.find("_$folder$", 0))){
                        strpath.erase(Pos);
                    }
                }
            }
        }
        if(0 != result && std::string::npos == strpath.find("_$folder$", 0)){
            // now path is "object" or "object/", do check "no dir object" which is not object but has only children.
            //
            // [NOTE]
            // If the path is mount point and there is no Stat information file for it, we need this process.
            //
            if('/' == *strpath.rbegin()){
                strpath.erase(strpath.length() - 1);
            }
            if(-ENOTEMPTY == directory_empty(strpath.c_str())){
                // found "non-existed directory object".
                strpath  += "/";
                *pObjType = objtype_t::DIR_NOT_EXIST_OBJECT;
                result    = 0;
            }
        }

    }else{
        if(is_reg_fmt(*pmeta)){
            *pObjType = objtype_t::FILE;
        }else if(is_symlink_fmt(*pmeta)){
            *pObjType = objtype_t::SYMLINK;
        }else if(is_dir_fmt(*pmeta)){
            if('/' != *strpath.rbegin() && std::string::npos == strpath.find("_$folder$", 0)){
                // check to send a head request for "dir/"
                //
                // [NOTE][FIXME]
                // Some backends, a Head request to a "dir" path will succeed when only the
                // "dir/" object exists(s3proxy is one of them).
                // When detected as "dir" in this way, the directory type is no longer accurate,
                // so the Head request must be re-examined as "dir/".
                // In this case, the AWS S3 server fails to detect "dir". So in most cases, this
                // process should have little impact on performance. (Currently, s3fs-fuse tests
                // are affected by this process.)
                //
                std::string recheckPath = strpath + "/";
                headers_t   recheckHead;
                if(0 == head_request(recheckPath, recheckHead)){
                    if(is_dir_fmt(recheckHead)){
                        strpath   = recheckPath;
                        *pmeta    = recheckHead;
                    }else{
                        S3FS_PRN_ERR("Both objects \"%s\" and \"%s\" were found, but \"%s\" is a directory and \"%s\" is not a directory. \"%s\" will be ignored.", strpath.c_str(), recheckPath.c_str(), strpath.c_str(), recheckPath.c_str(), recheckPath.c_str());
                    }
                }
                if('/' != *strpath.rbegin() && is_need_check_obj_detail(*pmeta)){
                    // check a case of that "object" does not have attribute and "object" is possible to be directory.
                    if(-ENOTEMPTY == directory_empty(strpath.c_str())){
                        // found "non-existed directory object".
                        strpath  += "/";
                        *pObjType = objtype_t::DIR_NOT_EXIST_OBJECT;
                    }
                }
            }
        }
    }

    // set headers for mount point from default stat
    if(is_mountpoint){
        // [NOTE]
        // This assumes the case where, in a HEAD request to a mount point,
        // the "/" object (path = "//") does not exist, but a 200 error is
        // received instead of a 404 error.
        // In this case, the expected key is not present in the meta header,
        // but other keys may be present and the header may not be empty.
        // Therefore, here we check for the presence of keys that are assumed
        // to be required, and forcibly clear the header if they are missing.
        // Probably, this can occur with AWS-compatible storage.
        //
        if(0 != result                                      ||
           pmeta->empty()                                   ||
           pmeta->cend() == pmeta->find("Content-Type")     ||
           pmeta->cend() == pmeta->find("x-amz-meta-uid")   ||
           pmeta->cend() == pmeta->find("x-amz-meta-gid")   ||
           pmeta->cend() == pmeta->find("x-amz-meta-mode")  ||
           pmeta->cend() == pmeta->find("x-amz-meta-atime") ||
           pmeta->cend() == pmeta->find("x-amz-meta-ctime") ||
           pmeta->cend() == pmeta->find("x-amz-meta-mtime") )
        {
            has_mp_stat = false;
            *pObjType   = objtype_t::DIR_NOT_EXIST_OBJECT;
            result      = 0;

            // [NOTE]
            // If mount point and no stat information file, create header
            // information from the default stat.
            //
            pmeta->clear();
            (*pmeta)["Content-Type"]     = S3fsCurl::LookupMimeType(strpath);
            (*pmeta)["x-amz-meta-uid"]   = std::to_string(pstbuf->st_uid);
            (*pmeta)["x-amz-meta-gid"]   = std::to_string(pstbuf->st_gid);
            (*pmeta)["x-amz-meta-mode"]  = std::to_string(pstbuf->st_mode);
            (*pmeta)["x-amz-meta-atime"] = std::to_string(pstbuf->st_atime);
            (*pmeta)["x-amz-meta-ctime"] = std::to_string(pstbuf->st_ctime);
            (*pmeta)["x-amz-meta-mtime"] = std::to_string(pstbuf->st_mtime);
        }else{
            has_mp_stat = true;
            *pObjType   = objtype_t::DIR_NORMAL;
        }
    }

    // [NOTE]
    // If the file is listed but not allowed access, put it in
    // the positive cache instead of the negative cache.
    //
    // When mount points, the following error does not occur.
    //
    if(0 != result && -EPERM != result){
        // finally, "path" object did not find. Add no object cache.
        *pObjType = objtype_t::NEGATIVE;

        // reset original
        strpath = path;
        if(std::string::npos != (Pos = strpath.find("_$folder$", 0))){
            // if path has "_$folder$", need to cut it.
            strpath.erase(Pos);
            strpath += "/";
        }
        StatCache::getStatCacheData()->AddNegativeStat(strpath);
        return result;
    }

    //
    // Set the object type if UNKNOWN( -> FILE / SYMLINK / DIR_NOT_TERMINATE_SLASH)
    //
    if(objtype_t::UNKNOWN == *pObjType){
        if(is_dir_fmt(*pmeta)){
            // The directory judged here is of type "dir" or "dir/".
            if('/' == *strpath.rbegin()){
                *pObjType = objtype_t::DIR_NORMAL;
            }else{
                *pObjType = objtype_t::DIR_NOT_TERMINATE_SLASH;
            }
        }else if(is_symlink_fmt(*pmeta)){
            *pObjType = objtype_t::SYMLINK;
        }else{  // is_reg_fmt(*pmeta)
            *pObjType = objtype_t::FILE;
        }
    }

    // Set cache key(path)
    //
    if(is_bucket_mountpoint){
        strpath = "/";
    }else if(std::string::npos != (Pos = strpath.find("_$folder$", 0))){
        // if path has "_$folder$", need to cut it.
        strpath.erase(Pos);
        strpath += "/";
    }

    // Set stat structure
    if(!convert_header_to_stat(strpath, *pmeta, *pstbuf, (objtype_t::DIR_NOT_EXIST_OBJECT == *pObjType))){
        S3FS_PRN_ERR("failed convert headers to stat[path=%s]", strpath.c_str());
        return -ENOENT;
    }

    // Set into cache
    //
    // [NOTE]
    // When notruncate is true, the stats is always cached.
    // This cached stats is only removed by DelStat().
    // This is necessary for the case to access the attribute of opened file.
    // (ex. getxattr() is called while writing to the opened file.)
    //
    if(!StatCache::getStatCacheData()->AddStat(strpath, *pstbuf, *pmeta, *pObjType, notruncate)){
        S3FS_PRN_ERR("failed adding stat cache [path=%s]", strpath.c_str());
        return -ENOENT;
    }

    return 0;
}

//
// Check the object uid and gid for write/read/execute.
// The param "mask" is as same as access() function.
// If there is not a target file, this function returns -ENOENT.
// If the target file can be accessed, the result always is 0.
//
// path:   the target object path
// mask:   bit field(F_OK, R_OK, W_OK, X_OK) like access().
// stat:   nullptr or the pointer of struct stat.
//
static int check_object_access(const char* path, int mask, struct stat* pstbuf)
{
    int result;
    struct stat st;
    struct stat* pst = (pstbuf ? pstbuf : &st);
    struct fuse_context* pcxt;

    S3FS_PRN_DBG("[path=%s]", path);

    if(nullptr == (pcxt = fuse_get_context())){
        return -EIO;
    }
    S3FS_PRN_DBG("[pid=%u,uid=%u,gid=%u]", (unsigned int)(pcxt->pid), (unsigned int)(pcxt->uid), (unsigned int)(pcxt->gid));

    if(0 != (result = get_object_attribute(path, pst))){
        // If there is not the target file(object), result is -ENOENT.
        return result;
    }
    if(0 == pcxt->uid){
        // root is allowed all accessing.
        return 0;
    }
    if(is_s3fs_uid && s3fs_uid == pcxt->uid){
        // "uid" user is allowed all accessing.
        return 0;
    }
    if(F_OK == mask){
        // if there is a file, always return allowed.
        return 0;
    }

    // for "uid", "gid" option
    uid_t  obj_uid = (is_s3fs_uid ? s3fs_uid : pst->st_uid);
    gid_t  obj_gid = (is_s3fs_gid ? s3fs_gid : pst->st_gid);

    // compare file mode and uid/gid + mask.
    mode_t mode;
    mode_t base_mask = S_IRWXO;
    if(is_s3fs_umask){
        // If umask is set, all object attributes set ~umask.
        mode = ((S_IRWXU | S_IRWXG | S_IRWXO) & ~s3fs_umask);
    }else{
        mode = pst->st_mode;
    }
    if(pcxt->uid == obj_uid){
        base_mask |= S_IRWXU;
    }
    if(pcxt->gid == obj_gid){
        base_mask |= S_IRWXG;
    } else if(1 == is_uid_include_group(pcxt->uid, obj_gid)){
        base_mask |= S_IRWXG;
    }
    mode &= base_mask;

    if(X_OK == (mask & X_OK)){
        if(0 == (mode & (S_IXUSR | S_IXGRP | S_IXOTH))){
            return -EACCES;
        }
    }
    if(W_OK == (mask & W_OK)){
        if(0 == (mode & (S_IWUSR | S_IWGRP | S_IWOTH))){
            return -EACCES;
        }
    }
    if(R_OK == (mask & R_OK)){
        if(0 == (mode & (S_IRUSR | S_IRGRP | S_IROTH))){
            return -EACCES;
        }
    }
    if(0 == mode){
        return -EACCES;
    }
    return 0;
}

static int check_object_owner(const char* path, struct stat* pstbuf)
{
    int result;
    struct stat st;
    struct stat* pst = (pstbuf ? pstbuf : &st);
    const struct fuse_context* pcxt;

    S3FS_PRN_DBG("[path=%s]", path);

    if(nullptr == (pcxt = fuse_get_context())){
        return -EIO;
    }
    if(0 != (result = get_object_attribute(path, pst))){
        // If there is not the target file(object), result is -ENOENT.
        return result;
    }
    // check owner
    if(0 == pcxt->uid){
        // root is allowed all accessing.
        return 0;
    }
    if(is_s3fs_uid && s3fs_uid == pcxt->uid){
        // "uid" user is allowed all accessing.
        return 0;
    }
    if(pcxt->uid == pst->st_uid){
        return 0;
    }
    return -EPERM;
}

//
// Check accessing the parent directories of the object by uid and gid.
//
static int check_parent_object_access(const char* path, int mask)
{
    std::string parent;
    int result;

    S3FS_PRN_DBG("[path=%s]", path);

    if(0 == strcmp(path, "/") || 0 == strcmp(path, ".")){
        // path is mount point.
        return 0;
    }
    if(X_OK == (mask & X_OK)){
        for(parent = mydirname(path); !parent.empty(); parent = mydirname(parent)){
            if(parent == "."){
                parent = "/";
            }
            if(0 != (result = check_object_access(parent.c_str(), X_OK, nullptr))){
                return result;
            }
            if(parent == "/" || parent == "."){
                break;
            }
        }
    }
    mask = (mask & ~X_OK);
    if(0 != mask){
        parent = mydirname(path);
        if(parent == "."){
            parent = "/";
        }
        if(0 != (result = check_object_access(parent.c_str(), mask, nullptr))){
            return result;
        }
    }
    return 0;
}

//
// ssevalue is MD5 for SSE-C type, or KMS id for SSE-KMS
//
bool get_object_sse_type(const char* path, sse_type_t& ssetype, std::string& ssevalue)
{
    if(!path){
        return false;
    }

    headers_t meta;
    if(0 != get_object_attribute(path, nullptr, &meta)){
        S3FS_PRN_ERR("Failed to get object(%s) headers", path);
        return false;
    }

    ssetype = sse_type_t::SSE_DISABLE;
    ssevalue.clear();
    for(auto iter = meta.cbegin(); iter != meta.cend(); ++iter){
        auto key = CaseInsensitiveStringView(iter->first);
        auto value = CaseInsensitiveStringView(iter->second);
        if(key == "x-amz-server-side-encryption" && value == "AES256"){
            ssetype  = sse_type_t::SSE_S3;
        }else if(key == "x-amz-server-side-encryption-aws-kms-key-id"){
            ssetype  = sse_type_t::SSE_KMS;
            ssevalue = (*iter).second;
        }else if(key == "x-amz-server-side-encryption-customer-key-md5"){
            ssetype  = sse_type_t::SSE_C;
            ssevalue = (*iter).second;
        }
    }
    return true;
}

static int get_local_fent(AutoFdEntity& autoent, FdEntity **entity, const char* path, int flags, bool is_load)
{
    int         result;
    struct stat stobj;
    FdEntity*   ent;
    headers_t   meta;
    FileTimes   ts_times;       // default: all timespecs are UTIME_OMIT

    S3FS_PRN_INFO2("[path=%s]", path);

    if(0 != (result = get_object_attribute(path, &stobj, &meta))){
        return result;
    }

    // open
    if(S_ISREG(stobj.st_mode) || S_ISLNK(stobj.st_mode)){
        ts_times.SetAll(stobj);
    }
    bool   force_tmpfile = S_ISREG(stobj.st_mode) ? false : true;

    if(nullptr == (ent = autoent.Open(path, &meta, stobj.st_size, ts_times, flags, force_tmpfile, true, false))){
        S3FS_PRN_ERR("Could not open file. errno(%d)", errno);
        return -EIO;
    }
    // load
    if(is_load && !ent->LoadAll(autoent.GetPseudoFd())){
        S3FS_PRN_ERR("Could not load file. errno(%d)", errno);
        autoent.Close();
        return -EIO;
    }
    *entity = ent;
    return 0;
}

//
// create or update s3 meta
// @return fuse return code
//
int put_headers(const char* path, const headers_t& meta, bool is_copy, bool use_st_size)
{
    int         result;
    off_t       size;
    std::string strpath;

    S3FS_PRN_INFO2("[path=%s]", path);

    if(0 == strcmp(path, "/") && mount_prefix.empty()){
        strpath = "//";     // for the mount point that is bucket root, change "/" to "//".
    }else{
        strpath = path;
    }

    // files larger than 5GB must be modified via the multipart interface
    // call use_st_size as false when the file does not exist(ex. rename object)
    if(use_st_size && '/' != *strpath.rbegin()){     // directory object("dir/") is always 0(Content-Length = 0)
        struct stat buf;
        if(0 != (result = get_object_attribute(path, &buf))){
          return result;
        }
        size = buf.st_size;
    }else{
        size = get_size(meta);
    }

    if(!nocopyapi && !nomultipart && size >= multipart_threshold){
        if(0 != (result = multipart_put_head_request(strpath, strpath, size, meta))){
            return result;
        }
    }else{
        // send put head request
        if(0 != (result = put_head_request(strpath, meta, is_copy))){
            return result;
        }
    }
    return 0;
}

static int s3fs_getattr(const char* _path, struct stat* stbuf FUSE3_FILE_INFO_ARG)
{
    WTF8_ENCODE(path)
    int result;

#ifdef __APPLE__
    FUSE_CTX_DBG("[path=%s]", path);
#else
    FUSE_CTX_INFO("[path=%s]", path);
#endif

    // check parent directory attribute.
    if(0 != (result = check_parent_object_access(path, X_OK))){
        return result;
    }
    if(0 != (result = check_object_access(path, F_OK, stbuf))){
        return result;
    }
    // If has already opened fd, the st_size should be instead.
    // (See: Issue 241)
    if(stbuf){
        AutoFdEntity autoent;
        const FdEntity*  ent;
        if(nullptr != (ent = autoent.OpenExistFdEntity(path))){
            struct stat tmpstbuf;
            if(ent->GetStats(tmpstbuf)){
                stbuf->st_size = tmpstbuf.st_size;
            }
        }
        if(0 == strcmp(path, "/")){
            stbuf->st_size = 4096;
        }
        stbuf->st_blksize = 4096;
        stbuf->st_blocks  = get_blocks(stbuf->st_size);

        S3FS_PRN_DBG("[path=%s] uid=%u, gid=%u, mode=%04o", path, (unsigned int)(stbuf->st_uid), (unsigned int)(stbuf->st_gid), stbuf->st_mode);
    }

    return result;
}

static int s3fs_readlink(const char* _path, char* buf, size_t size)
{
    if(!_path || !buf || 0 == size){
        return 0;
    }
    WTF8_ENCODE(path)
    std::string strPath = path;
    std::string strValue;
    objtype_t   ObjType = objtype_t::UNKNOWN;
    struct stat stbuf   = {};

    FUSE_CTX_INFO("[path=%s]", strPath.c_str());

    const struct fuse_context* pcxt;
    if(nullptr == (pcxt = fuse_get_context())){
        return -EIO;
    }

    // check if there is a valid cache
    bool found_cache = false;
    if(StatCache::getStatCacheData()->GetStat(strPath, &stbuf, nullptr, &ObjType)){
        if(IS_SYMLINK_OBJ(ObjType)){
            // found symlink stat cache
            found_cache = true;
        }else{
            // found stat cache, but it is not symlink type.
            StatCache::getStatCacheData()->DelStat(strPath);
        }
    }

    // get symlink path
    if(!found_cache || !StatCache::getStatCacheData()->GetSymlink(strPath, strValue)){
        // could not get symlink path from stat cache, so read symlink path from file.
        ssize_t ressize = 0;
        {
            AutoFdEntity autoent;
            FdEntity*    ent;
            int          result;
            if(0 != (result = get_local_fent(autoent, &ent, strPath.c_str(), O_RDONLY))){
                S3FS_PRN_ERR("could not get fent(file=%s)", strPath.c_str());
                return result;
            }

            // Get size
            off_t readsize;
            if(!ent->GetSize(readsize)){
                S3FS_PRN_ERR("could not get file size(file=%s)", strPath.c_str());
                return -EIO;
            }
            if(static_cast<off_t>(size) <= readsize){
                readsize = size - 1;
            }

            // Read
            if(0 > (ressize = ent->Read(autoent.GetPseudoFd(), buf, 0, readsize))){
                S3FS_PRN_ERR("could not read file(file=%s, ressize=%zd)", strPath.c_str(), ressize);
                return static_cast<int>(ressize);
            }
            buf[ressize] = '\0';

            // check buf if it has space words.
            strValue = trim(buf);

            // decode wtf8. This will always be shorter
            if(use_wtf8){
                strValue = s3fs_wtf8_decode(strValue);
            }
        }

        // make meta and stat
        headers_t meta;
        bool      add_cache = true;
        if(!found_cache){
            // make headers for symlink
            std::string strnow       = s3fs_str_realtime();
            meta["Content-Type"]     = "application/octet-stream";  // Static
            meta["Content-Length"]   = std::to_string(ressize);     // length
            meta["x-amz-meta-mode"]  = std::to_string(S_IFLNK | S_IRWXU | S_IRWXG | S_IRWXO);
            meta["x-amz-meta-atime"] = strnow;
            meta["x-amz-meta-ctime"] = strnow;
            meta["x-amz-meta-mtime"] = strnow;
            meta["x-amz-meta-uid"]   = std::to_string(pcxt->uid);
            meta["x-amz-meta-gid"]   = std::to_string(pcxt->gid);

            if(!convert_header_to_stat(strPath, meta, stbuf, false)){
                S3FS_PRN_ERR("failed convert headers to stat[path=%s], but continue...", strPath.c_str());
                add_cache = false;
            }
        }

        // add symbolic link cache
        if(add_cache){
            if(!StatCache::getStatCacheData()->AddSymlink(strPath, stbuf, meta, strValue)){
                S3FS_PRN_ERR("failed to add symbolic link cache for %s, but continue...", strPath.c_str());
            }
        }
    }

    // copy result
    strncpy(buf, strValue.c_str(), size - 1);
    buf[size - 1] = '\0';

    return 0;
}

// Common function for creation of a plain object
//
// [NOTE]
// Currently this is only called by s3fs_mknod.
//
static int create_file_object(const char* path, mode_t mode, uid_t uid, gid_t gid, struct stat* pstbuf)
{
    S3FS_PRN_INFO2("[path=%s][mode=%04o]", path, mode);

    std::string strnow = s3fs_str_realtime();
    headers_t   meta;
    meta["Content-Type"]     = S3fsCurl::LookupMimeType(path);
    meta["x-amz-meta-uid"]   = std::to_string(uid);
    meta["x-amz-meta-gid"]   = std::to_string(gid);
    meta["x-amz-meta-mode"]  = std::to_string(mode);
    meta["x-amz-meta-atime"] = strnow;
    meta["x-amz-meta-ctime"] = strnow;
    meta["x-amz-meta-mtime"] = strnow;

    int result;
    if(0 != (result = put_request(SAFESTRPTR(path), meta, -1, true/* ahbe */))){
        return result;
    }

    if(pstbuf){
        if(!convert_header_to_stat(std::string(path), meta, *pstbuf)){
            S3FS_PRN_ERR("failed convert headers to stat[path=%s]", path);
            return -EIO;
        }
    }
    return 0;
}

static int s3fs_mknod(const char *_path, mode_t mode, dev_t rdev)
{
    WTF8_ENCODE(path)
    int       result;
    struct fuse_context* pcxt;
    struct stat stbuf;

    FUSE_CTX_INFO("[path=%s][mode=%04o][dev=%llu]", path, mode, (unsigned long long)rdev);

    if(nullptr == (pcxt = fuse_get_context())){
        return -EIO;
    }

    if(0 != (result = create_file_object(path, mode, pcxt->uid, pcxt->gid, &stbuf))){
        S3FS_PRN_ERR("could not create object for special file(result=%d)", result);
        return result;
    }

    // Add only stat structure to stat cache
    if(!StatCache::getStatCacheData()->AddStat(std::string(path), stbuf, objtype_t::FILE)){
        S3FS_PRN_ERR("succeed to mknod the file(%s), but could not add stat cache.", path);
    }

    // update parent directory timestamp
    int update_result;
    if(0 != (update_result = update_mctime_parent_directory(path))){
        S3FS_PRN_ERR("succeed to mknod the file(%s), but could not update timestamp of its parent directory(result=%d).", path, update_result);
    }

    return result;
}

static int s3fs_create(const char* _path, mode_t mode, struct fuse_file_info* fi)
{
    WTF8_ENCODE(path)
    std::string  strpath = path;
    int          result;
    const struct fuse_context* pcxt;

    FUSE_CTX_INFO("[path=%s][mode=%04o][flags=0x%x]", strpath.c_str(), mode, fi->flags);

    if(nullptr == (pcxt = fuse_get_context())){
        return -EIO;
    }

    // check parent directory attribute.
    if(0 != (result = check_parent_object_access(strpath.c_str(), X_OK))){
        return result;
    }
    result = check_object_access(strpath.c_str(), W_OK, nullptr);
    if(-ENOENT == result){
        if(0 != (result = check_parent_object_access(strpath.c_str(), W_OK))){
            return result;
        }
    }else if(0 != result){
        return result;
    }

    // Set meta headers
    std::string strnow = s3fs_str_realtime();
    headers_t   meta;
    meta["Content-Length"] = "0";
    meta["x-amz-meta-uid"]   = std::to_string(pcxt->uid);
    meta["x-amz-meta-gid"]   = std::to_string(pcxt->gid);
    meta["x-amz-meta-mode"]  = std::to_string(mode);
    meta["x-amz-meta-atime"] = strnow;
    meta["x-amz-meta-mtime"] = strnow;
    meta["x-amz-meta-ctime"] = strnow;

    std::string xattrvalue;
    if(build_inherited_xattr_value(strpath.c_str(), xattrvalue)){
        S3FS_PRN_DBG("Set xattrs = %s", urlDecode(xattrvalue).c_str());
        meta["x-amz-meta-xattr"] = xattrvalue;
    }

    // Set stat structure
    struct stat stbuf = {};
    if(!convert_header_to_stat(strpath, meta, stbuf, false)){
        S3FS_PRN_ERR("failed convert headers to stat[path=%s]", strpath.c_str());
        return -EIO;
    }

    // [NOTE] set no_truncate flag
    // At this point, the file has not been created(uploaded) and
    // the data is only present in the Stats cache.
    // The Stats cache should not be deleted automatically by
    // timeout. If this stats is deleted, s3fs will try to get it
    // from the server with a Head request and will get an
    // unexpected error because the result object does not exist.
    //
    if(!StatCache::getStatCacheData()->AddStat(std::string(path), stbuf, meta, objtype_t::FILE, true)){     // [NOTICE] notruncate = true
        return -EIO;
    }

    AutoFdEntity autoent;
    FdEntity*    ent;
    int          error = 0;
    FileTimes    ts_times;
    if(nullptr == (ent = autoent.Open(strpath.c_str(), &meta, 0, ts_times, fi->flags, false, true, false, &error))){
        // remove from cache
        StatCache::getStatCacheData()->DelStat(strpath);
        return error;
    }
    ent->MarkDirtyNewFile();
    fi->fh = autoent.Detach();       // KEEP fdentity open;

    return 0;
}

static int create_directory_object(const char* path, mode_t mode, const struct timespec& ts_atime, const struct timespec& ts_mtime, const struct timespec& ts_ctime, uid_t uid, gid_t gid, const char* pxattrvalue, struct stat* pstbuf)
{
    S3FS_PRN_INFO1("[path=%s][mode=%04o][atime=%s][mtime=%s][ctime=%s][uid=%u][gid=%u]", path, mode, str(ts_atime).c_str(), str(ts_mtime).c_str(), str(ts_ctime).c_str(), (unsigned int)uid, (unsigned int)gid);

    if(!path || '\0' == path[0]){
        return -EINVAL;
    }
    std::string tpath = path;
    if('/' != *tpath.rbegin()){
        tpath += "/";
    }else if("/" == tpath && mount_prefix.empty()){
        tpath = "//";       // for the mount point that is bucket root, change "/" to "//".
    }

    headers_t meta;
    meta["x-amz-meta-uid"]   = std::to_string(uid);
    meta["x-amz-meta-gid"]   = std::to_string(gid);
    meta["x-amz-meta-mode"]  = std::to_string(mode);
    meta["x-amz-meta-atime"] = str(ts_atime);
    meta["x-amz-meta-mtime"] = str(ts_mtime);
    meta["x-amz-meta-ctime"] = str(ts_ctime);

    if(pxattrvalue){
        S3FS_PRN_DBG("Set xattrs = %s", urlDecode(pxattrvalue).c_str());
        meta["x-amz-meta-xattr"] = pxattrvalue;
    }

    int result;
    if(0 != (result = put_request(tpath, meta, -1, false/* ahbe */))){
        return result;
    }

    if(pstbuf){
        if(!convert_header_to_stat(tpath, meta, *pstbuf, true)){    // There is no need to worry if the tpath is "//"
            S3FS_PRN_ERR("failed convert headers to stat[path=%s]", path);
            return -EIO;
        }
    }
    return 0;
}

static int s3fs_mkdir(const char* _path, mode_t mode)
{
    WTF8_ENCODE(path)
    int result;
    struct fuse_context* pcxt;
    struct stat stbuf;

    FUSE_CTX_INFO("[path=%s][mode=%04o]", path, mode);

    if(nullptr == (pcxt = fuse_get_context())){
        return -EIO;
    }

    // keep stat cache without checking expiration
    //
    // [FIXME]
    // The process to prevent cache expiration needs to be revised.
    // The following process will be pending until this is completed.
    //PreventStatCacheExpire nocacheexpire;

    // check parent directory attribute.
    if(0 != (result = check_parent_object_access(path, W_OK | X_OK))){
        return result;
    }
    if(-ENOENT != (result = check_object_access(path, F_OK, nullptr))){
        if(0 == result){
            result = -EEXIST;
        }
        return result;
    }

    std::string xattrvalue;
    const char* pxattrvalue;
    if(get_parent_meta_xattr_value(path, xattrvalue)){
        pxattrvalue = xattrvalue.c_str();
    }else{
        pxattrvalue = nullptr;
    }

    struct timespec now;
    s3fs_realtime(now);
    result = create_directory_object(path, mode, now, now, now, pcxt->uid, pcxt->gid, pxattrvalue, &stbuf);

    // Add only stat structure to stat cache
    if(!StatCache::getStatCacheData()->AddStat(std::string(path), stbuf, objtype_t::DIR_NORMAL)){
        S3FS_PRN_ERR("succeed to create the directory(%s), but could not add stat cache.", path);
    }

    // update parent directory timestamp
    int update_result;
    if(0 != (update_result = update_mctime_parent_directory(path))){
        S3FS_PRN_ERR("succeed to create the directory(%s), but could not update timestamp of its parent directory(result=%d).", path, update_result);
    }

    return result;
}

static int s3fs_unlink(const char* _path)
{
    WTF8_ENCODE(path)
    std::string strPath = path;
    int         result;

    FUSE_CTX_INFO("[path=%s]", strPath.c_str());

    if(0 != (result = check_parent_object_access(strPath.c_str(), W_OK | X_OK))){
        return result;
    }

    if(0 != (result = delete_request(strPath))){
        return result;
    }

    // remove file cache and stat cache
    StatCache::getStatCacheData()->DelStat(strPath);
    FdManager::DeleteCacheFile(strPath.c_str());

    // update parent directory timestamp
    int update_result;
    if(0 != (update_result = update_mctime_parent_directory(strPath.c_str()))){
        S3FS_PRN_ERR("succeed to remove the file(%s), but could not update timestamp of its parent directory(result=%d).", strPath.c_str(), update_result);
    }

    return result;
}

static int directory_empty(const char* path)
{
    int       result = 0;
    S3ObjList head;

    // check s3objlist in cache
    if(!StatCache::getStatCacheData()->GetS3ObjList(path, head)){
        if((result = list_bucket(path, head, "/", true)) != 0){
            S3FS_PRN_ERR("list_bucket returns error.");
            return result;
        }
        if(!head.IsEmpty()){
            if(!StatCache::getStatCacheData()->AddS3ObjList(path, head)){
                S3FS_PRN_WARN("failed to add s3objlist for %s, but continue...", path);
            }
            result = -ENOTEMPTY;
        }
    }else{
        if(!head.IsEmpty()){
            result = -ENOTEMPTY;
        }
    }
    return result;
}

static int s3fs_rmdir(const char* _path)
{
    WTF8_ENCODE(path)
    int         result;
    std::string strpath;
    struct stat stbuf;
    objtype_t   ObjType;

    FUSE_CTX_INFO("[path=%s]", path);

    // keep stat cache without checking expiration
    //
    // [FIXME]
    // The process to prevent cache expiration needs to be revised.
    // The following process will be pending until this is completed.
    //PreventStatCacheExpire nocacheexpire;

    if(0 != (result = check_parent_object_access(path, W_OK | X_OK))){
        return result;
    }

    // directory must be empty
    if(directory_empty(path) != 0){
        return -ENOTEMPTY;
    }

    strpath = path;
    if('/' != *strpath.rbegin()){
        strpath += "/";
    }

    // delete request
    result = delete_request(strpath);

    // remove stat cache
    StatCache::getStatCacheData()->DelStat(strpath);

    // double check for old version(before 1.63)
    // The old version makes "dir" object, newer version makes "dir/".
    // A case, there is only "dir", the first removing object is "dir/".
    // Then "dir/" is not exists, but curl_delete returns 0.
    // So need to check "dir" and should be removed it.
    if('/' == *strpath.rbegin()){
        strpath.erase(strpath.length() - 1);
    }
    if(0 == get_object_attribute(strpath.c_str(), &stbuf, nullptr, false, &ObjType)){
        if(IS_DIR_OBJ(ObjType)){
            // Found "dir" object.
            if(objtype_t::DIR_NORMAL == ObjType){
                // delete request
                strpath += "/";
                result = delete_request(strpath);

                // remove stat cache
                StatCache::getStatCacheData()->DelStat(strpath);

            }else if(objtype_t::DIR_NOT_TERMINATE_SLASH == ObjType){
                // delete request
                result = delete_request(strpath);

                // remove stat cache
                strpath += "/";
                StatCache::getStatCacheData()->DelStat(strpath);

            }else if(objtype_t::DIR_FOLDER_SUFFIX == ObjType){
                // delete request
                std::string strtmp = strpath + "_$folder$";
                result = delete_request(strtmp);

                // remove stat cache
                strpath += "/";
                StatCache::getStatCacheData()->DelStat(strpath);

            }else if(objtype_t::DIR_NOT_EXIST_OBJECT == ObjType){
                // the directory to be deleted does not exist
                result = 0;

                // remove stat cache
                strpath += "/";
                StatCache::getStatCacheData()->DelStat(strpath);
            }
        }
    }

    // update parent directory timestamp
    int update_result;
    if(0 != (update_result = update_mctime_parent_directory(path))){
        S3FS_PRN_ERR("succeed to remove the directory(%s), but could not update timestamp of its parent directory(result=%d).", path, update_result);
    }

    return result;
}

static int s3fs_symlink(const char* _from, const char* _to)
{
    WTF8_ENCODE(from)
    WTF8_ENCODE(to)
    std::string                strFrom = trim(from);;
    std::string                strTo   = trim(to);
    int                        result;
    const struct fuse_context* pcxt;

    FUSE_CTX_INFO("[from=%s][to=%s]", strFrom.c_str(), strTo.c_str());

    if(nullptr == (pcxt = fuse_get_context())){
        return -EIO;
    }
    if(0 != (result = check_parent_object_access(strTo.c_str(), W_OK | X_OK))){
        return result;
    }
    if(-ENOENT != (result = check_object_access(strTo.c_str(), F_OK, nullptr))){
        if(0 == result){
            result = -EEXIST;
        }
        return result;
    }

    std::string strnow = s3fs_str_realtime();
    headers_t   headers;
    headers["Content-Type"]     = "application/octet-stream"; // Static
    headers["x-amz-meta-mode"]  = std::to_string(S_IFLNK | S_IRWXU | S_IRWXG | S_IRWXO);
    headers["x-amz-meta-atime"] = strnow;
    headers["x-amz-meta-ctime"] = strnow;
    headers["x-amz-meta-mtime"] = strnow;
    headers["x-amz-meta-uid"]   = std::to_string(pcxt->uid);
    headers["x-amz-meta-gid"]   = std::to_string(pcxt->gid);

    // [NOTE]
    // Symbolic links do not set xattrs.

    // open tmpfile
    {   // scope for AutoFdEntity
        AutoFdEntity autoent;
        FdEntity*    ent;
        FileTimes    ts_times;      // Default: all time values are set UTIME_OMIT
        if(nullptr == (ent = autoent.Open(strTo.c_str(), &headers, 0, ts_times, O_RDWR, true, true, false))){
            S3FS_PRN_ERR("could not open tmpfile(errno=%d)", errno);
            return -errno;
        }

        // write(without space words)
        auto from_size = static_cast<ssize_t>(strFrom.length());
        ssize_t ressize;
        if(from_size != (ressize = ent->Write(autoent.GetPseudoFd(), strFrom.c_str(), 0, from_size))){
            if(ressize < 0){
                S3FS_PRN_ERR("could not write tmpfile(errno=%d)", static_cast<int>(ressize));
                return static_cast<int>(ressize);
            }else{
                S3FS_PRN_ERR("could not write tmpfile %zd byte(errno=%d)", ressize, errno);
                return (0 == errno ? -EIO : -errno);
            }
        }

        // set length
        headers["Content-Length"] = std::to_string(ressize);

        // upload
        if(0 != (result = ent->Flush(autoent.GetPseudoFd(), true))){
            S3FS_PRN_WARN("could not upload tmpfile(result=%d)", result);
        }
    }

    // make stat and add cache
    struct stat stbuf;
    if(!convert_header_to_stat(strTo, headers, stbuf, false)){
        S3FS_PRN_ERR("failed convert headers to stat[path=%s], but continue...", strTo.c_str());
    }else{
        // add symbolic link cache
        if(!StatCache::getStatCacheData()->AddSymlink(strTo, stbuf, headers, strFrom)){
          S3FS_PRN_ERR("failed to add symbolic link cache for %s(->%s), but continue...", strTo.c_str(), strFrom.c_str());
        }
    }

    // update parent directory timestamp
    int update_result;
    if(0 != (update_result = update_mctime_parent_directory(strTo.c_str()))){
        S3FS_PRN_ERR("succeed to create symbolic link(%s), but could not update timestamp of its parent directory(result=%d).", strTo.c_str(), update_result);
    }

    return result;
}

static int rename_object(const char* from, const char* to, bool update_ctime)
{
    int         result;
    headers_t   meta;
    struct stat stbuf;

    S3FS_PRN_INFO1("[from=%s][to=%s]", from , to);

    if(0 != (result = check_parent_object_access(to, W_OK | X_OK))){
        // not permit writing "to" object parent dir.
        return result;
    }
    if(0 != (result = check_parent_object_access(from, W_OK | X_OK))){
        // not permit removing "from" object parent dir.
        return result;
    }
    if(0 != (result = get_object_attribute(from, &stbuf, &meta))){
        return result;
    }

    std::string strSourcePath        = (mount_prefix.empty() && 0 == strcmp("/", from)) ? "//" : from;

    if(update_ctime){
        meta["x-amz-meta-ctime"]     = s3fs_str_realtime();
    }
    meta["x-amz-copy-source"]        = urlEncodePath(service_path + S3fsCred::GetBucket() + get_realpath(strSourcePath.c_str()));
    meta["Content-Type"]             = S3fsCurl::LookupMimeType(to);
    meta["x-amz-metadata-directive"] = "REPLACE";

    std::string xattrvalue;
    if(get_meta_xattr_value(from, xattrvalue)){
        S3FS_PRN_DBG("Set xattrs = %s", urlDecode(xattrvalue).c_str());
        meta["x-amz-meta-xattr"] = xattrvalue;
    }

    // [NOTE]
    // If it has a cache, open it first and leave it open until rename.
    // The cache is renamed after put_header, because it must be open
    // at the time of renaming.
    {
        // update time
        AutoFdEntity autoent;
        FdEntity*    ent;
        if(nullptr == (ent = autoent.OpenExistFdEntity(from))){
            // no opened fd

            // get mtime/ctime/atime from meta
            struct timespec mtime = get_mtime(meta);
            struct timespec ctime = get_ctime(meta);
            struct timespec atime = get_atime(meta);

            if(FdManager::IsCacheDir()){
                // create cache file if be needed
                //
                // [NOTE]
                // Do not specify "UTIME_OMIT" for ts_time parameter.
                // This is because if the cache file does not exist, the pagelist for it
                // will be recreated, but the entire file area indicated by this pagelist
                // will be in the "modified" state.
                // This does not affect the rename process, but the cache information in
                // the "modified" state remains, making it impossible to read the file correctly.
                //
                FileTimes ts_times;
                ts_times.SetAll(ctime, atime, mtime, false);

                ent = autoent.Open(from, &meta, stbuf.st_size, ts_times, O_RDONLY, false, true, false);
            }
            if(ent){
                if(0 != (result = ent->SetMtime(mtime)) || 0 != (result = ent->SetCtime(ctime)) || 0 != (result = ent->SetAtime(atime))){
                    S3FS_PRN_ERR("could not set mtime/ctime/atime to file(%s): result=%d", from, result);
                    return result;
                }
            }
        }
    }

    // copy
    if(0 != (result = put_headers(to, meta, true, /* use_st_size= */ false))){
        return result;
    }

    // rename
    FdManager::get()->Rename(from, to);

    // Remove file
    result = s3fs_unlink(from);

    // Add only stat structure to stat cache
    std::string strTo = to;

    stbuf = {};
    if(convert_header_to_stat(strTo, meta, stbuf)){
        objtype_t ObjType = derive_object_type(strTo, meta, objtype_t::FILE);
        if(!StatCache::getStatCacheData()->AddStat(strTo, stbuf, ObjType)){
            S3FS_PRN_ERR("succeed to rename %s to %s, but could not add stat cache. So remove stat cache.", from, to);
            StatCache::getStatCacheData()->DelStat(strTo);
        }
    }else{
        S3FS_PRN_ERR("failed convert headers to stat[path=%s]. So remove stat cache.", to);
        StatCache::getStatCacheData()->DelStat(strTo);
    }

    return result;
}

static int rename_object_nocopy(const char* from, const char* to, bool update_ctime)
{
    int result;

    FUSE_CTX_INFO1("[from=%s][to=%s]", from , to);

    if(0 != (result = check_parent_object_access(to, W_OK | X_OK))){
        // not permit writing "to" object parent dir.
        return result;
    }
    if(0 != (result = check_parent_object_access(from, W_OK | X_OK))){
        // not permit removing "from" object parent dir.
        return result;
    }

    // open & load
    {   // scope for AutoFdEntity
        AutoFdEntity autoent;
        FdEntity*    ent;
        if(0 != (result = get_local_fent(autoent, &ent, from, O_RDWR, true))){
            S3FS_PRN_ERR("could not open and read file(%s)", from);
            return result;
        }

        // Set header
        if(!ent->SetContentType(to)){
            S3FS_PRN_ERR("could not set content-type for %s", to);
            return -EIO;
        }

        // update ctime
        if(update_ctime){
            struct timespec ts;
            s3fs_realtime(ts);
            ent->SetCtime(ts);
        }

        // upload
        if(0 != (result = ent->RowFlush(autoent.GetPseudoFd(), to, true))){
            S3FS_PRN_ERR("could not upload file(%s): result=%d", to, result);
            return result;
        }
    }
    FdManager::get()->Rename(from, to);

    // Remove file
    result = s3fs_unlink(from);

    // [NOTE]
    // Not have a copy API (nocopy), the stat cache will be removed.
    //
    StatCache::getStatCacheData()->DelStat(to);

    return result;
}

static int rename_large_object(const char* from, const char* to)
{
    int         result;
    struct stat stbuf;
    headers_t   meta;

    S3FS_PRN_INFO1("[from=%s][to=%s]", from , to);

    if(0 != (result = check_parent_object_access(to, W_OK | X_OK))){
        // not permit writing "to" object parent dir.
        return result;
    }
    if(0 != (result = check_parent_object_access(from, W_OK | X_OK))){
        // not permit removing "from" object parent dir.
        return result;
    }
    if(0 != (result = get_object_attribute(from, &stbuf, &meta, false))){
        return result;
    }

    if(0 != (result = multipart_put_head_request(from, to, stbuf.st_size, meta))){
        return result;
    }

    // Rename cache file
    FdManager::get()->Rename(from, to);

    // Remove file
    result = s3fs_unlink(from);

    // Add only stat structure to stat cache
    stbuf = {};
    if(convert_header_to_stat(std::string(to), meta, stbuf)){
        objtype_t ObjType = derive_object_type(std::string(to), meta, objtype_t::FILE);
        if(!StatCache::getStatCacheData()->AddStat(std::string(to), stbuf, ObjType)){
            S3FS_PRN_ERR("succeed to rename %s to %s, but could not add stat cache. So remove stat cache.", from, to);
            StatCache::getStatCacheData()->DelStat(std::string(to));
        }
    }else{
        S3FS_PRN_ERR("failed convert headers to stat[path=%s]. So remove stat cache.", to);
        StatCache::getStatCacheData()->DelStat(std::string(to));
    }

    return result;
}

static int clone_directory_object(const char* from, const char* to, bool update_ctime, const char* pxattrvalue)
{
    int result = -1;
    struct stat stbuf;
    struct stat newbuf;

    S3FS_PRN_INFO1("[from=%s][to=%s]", from, to);

    // get target's attributes
    if(0 != (result = get_object_attribute(from, &stbuf))){
        return result;
    }

    struct timespec ts_atime;
    struct timespec ts_mtime;
    struct timespec ts_ctime;
    set_stat_to_timespec(stbuf, stat_time_type::ATIME, ts_atime);
    set_stat_to_timespec(stbuf, stat_time_type::MTIME, ts_mtime);
    if(update_ctime){
        s3fs_realtime(ts_ctime);
    }else{
        set_stat_to_timespec(stbuf, stat_time_type::CTIME, ts_ctime);
    }
    result = create_directory_object(to, stbuf.st_mode, ts_atime, ts_mtime, ts_ctime, stbuf.st_uid, stbuf.st_gid, pxattrvalue, &newbuf);

    // Add only stat structure to stat cache
    if(!StatCache::getStatCacheData()->AddStat(std::string(to), newbuf, objtype_t::DIR_NORMAL)){
        S3FS_PRN_ERR("succeed to rename %s to %s directory, but could not add stat cache. So remove stat cache.", from, to);
        StatCache::getStatCacheData()->DelStat(std::string(to));
    }

    return result;
}

static int rename_directory(const char* from, const char* to)
{
    S3ObjList    head;
    s3obj_list_t headlist;
    std::string  strfrom  = from ? from : "";   // from is without "/".
    std::string  strto    = to ? to : "";       // to is without "/" too.
    std::string  basepath = strfrom + "/";
    std::string  normpath;                      // normalized path for "from name"(not used)
    objtype_t    ObjType;
    bool         normdir; 
    struct stat  stbuf;
    int          result;
    bool         is_dir;
    std::vector<mvnode> mvnodes;

    S3FS_PRN_INFO1("[from=%s][to=%s]", from, to);

    //
    // Initiate and Add base directory into mvnode struct.
    //
    strto += "/";
    if(0 == chk_dir_object_type(strfrom.c_str(), normpath, strfrom, nullptr, &ObjType) && IS_DIR_OBJ(ObjType)){
        if(objtype_t::DIR_NOT_EXIST_OBJECT != ObjType){
            normdir = false;
        }else{
            normdir = true;
            strfrom = from;               // from directory is not removed, but from directory attr is needed.
        }
        mvnodes.emplace_back(strfrom, strto, true, normdir);
    }else{
        // Something wrong about "from" directory.
    }

    //
    // get a list of all the objects
    //
    // No delimiter is specified, the result(head) is all object keys.
    // (CommonPrefixes is empty, but all object is listed in Key.)
    //
    if(!StatCache::getStatCacheData()->GetS3ObjList(basepath, head)){
        // get a list of all the objects
        if(0 != (result = list_bucket(basepath.c_str(), head, nullptr))){
            S3FS_PRN_ERR("list_bucket returns error.");
            return result;
        }
        if(!StatCache::getStatCacheData()->AddS3ObjList(basepath, head)){
            S3FS_PRN_WARN("failed to add s3objlist for %s, but continue...", basepath.c_str());
        }
    }
    head.GetNameList(headlist);                                             // get name without "/".

    // [NOTE]
    // If there are leaf paths that only exist in the Stat Cache,
    // they will be merged here.
    // This means that for newly created file, the Stat Cache(NoTruncate)
    // will exist before the actual file is uploaded.
    //
    if(!StatCache::getStatCacheData()->GetChildStatList(basepath, headlist)){
        S3FS_PRN_ERR("failed get child leaf list[path=%s], but continue...", basepath.c_str());
    }

    // add hierarchized dir.
    S3ObjList::MakeHierarchizedList(headlist, false);

    s3obj_list_t::const_iterator liter;
    for(liter = headlist.cbegin(); headlist.cend() != liter; ++liter){
        // make "from" and "to" object name.
        std::string from_name = basepath + (*liter);
        std::string to_name   = strto + (*liter);
        std::string etag      = head.GetETag((*liter).c_str());

        // Check subdirectory.
        if(!StatCache::getStatCacheData()->GetStat(from_name, &stbuf, etag.c_str())){    // Check ETag
            // try to get stat directly(and cached it)
            if(0 != get_object_attribute(from_name.c_str(), &stbuf, nullptr)){
                S3FS_PRN_WARN("failed to get %s object attribute.", from_name.c_str());
                continue;
            }
        }
        if(S_ISDIR(stbuf.st_mode)){
            is_dir = true;
            if(0 != chk_dir_object_type(from_name.c_str(), normpath, from_name, nullptr, &ObjType) || !IS_DIR_OBJ(ObjType)){
                S3FS_PRN_WARN("failed to get %s%s object directory type.", basepath.c_str(), (*liter).c_str());
                continue;
            }
            if(objtype_t::DIR_NOT_EXIST_OBJECT != ObjType){
                normdir = false;
            }else{
                normdir = true;
                from_name = basepath + (*liter);  // from directory is not removed, but from directory attr is needed.
            }
        }else{
            is_dir  = false;
            normdir = false;
        }
        
        // push this one onto the stack
        mvnodes.emplace_back(from_name, to_name, is_dir, normdir);
    }

    std::sort(mvnodes.begin(), mvnodes.end(), [](const mvnode& a, const mvnode& b) { return a.old_path < b.old_path; });

    //
    // rename
    //
    // rename directory objects.
    for(auto mn_cur = mvnodes.cbegin(); mn_cur != mvnodes.cend(); ++mn_cur){
        if(mn_cur->is_dir && !mn_cur->old_path.empty()){
            std::string xattrvalue;
            const char* pxattrvalue;
            if(get_meta_xattr_value(mn_cur->old_path.c_str(), xattrvalue)){
                pxattrvalue = xattrvalue.c_str();
            }else{
                pxattrvalue = nullptr;
            }

            // [NOTE]
            // The ctime is updated only for the top (from) directory.
            // Other than that, it will not be updated.
            //
            if(0 != (result = clone_directory_object(mn_cur->old_path.c_str(), mn_cur->new_path.c_str(), (strfrom == mn_cur->old_path), pxattrvalue))){
                S3FS_PRN_ERR("clone_directory_object returned an error(%d)", result);
                return result;
            }
        }
    }

    // iterate over the list - copy the files with rename_object
    // does a safe copy - copies first and then deletes old
    for(auto mn_cur = mvnodes.cbegin(); mn_cur != mvnodes.cend(); ++mn_cur){
        if(!mn_cur->is_dir){
            if(!nocopyapi && !norenameapi){
                result = rename_object(mn_cur->old_path.c_str(), mn_cur->new_path.c_str(), false);          // keep ctime
            }else{
                result = rename_object_nocopy(mn_cur->old_path.c_str(), mn_cur->new_path.c_str(), false);   // keep ctime
            }
            if(0 != result){
                S3FS_PRN_ERR("rename_object returned an error(%d)", result);
                return result;
            }
        }
    }

    // Iterate over old the directories, bottoms up and remove
    for(auto mn_cur = mvnodes.rbegin(); mn_cur != mvnodes.rend(); ++mn_cur){
        if(mn_cur->is_dir && !mn_cur->old_path.empty()){
            if(!(mn_cur->is_normdir)){
                if(0 != (result = s3fs_rmdir(mn_cur->old_path.c_str()))){
                    S3FS_PRN_ERR("s3fs_rmdir returned an error(%d)", result);
                    return result;
                }
            }else{
                // remove stat cache
                StatCache::getStatCacheData()->DelStat(mn_cur->old_path);
            }
        }
    }

    return 0;
}

#if FUSE_USE_VERSION >= 30
static int s3fs_rename(const char* _from, const char* _to, unsigned int flags)
#else
static int s3fs_rename(const char* _from, const char* _to)
#endif
{
    WTF8_ENCODE(from)
    WTF8_ENCODE(to)
    struct stat buf;
    int result;

    FUSE_CTX_INFO("[from=%s][to=%s]", from, to);

    if(0 != (result = check_parent_object_access(to, W_OK | X_OK))){
        // not permit writing "to" object parent dir.
        return result;
    }
    if(0 != (result = check_parent_object_access(from, W_OK | X_OK))){
        // not permit removing "from" object parent dir.
        return result;
    }
    if(0 != (result = get_object_attribute(from, &buf, nullptr))){
        return result;
    }
    if(0 != (result = directory_empty(to))){
        return result;
    }

    // flush pending writes if file is open
    {   // scope for AutoFdEntity
        AutoFdEntity autoent;
        FdEntity*    ent;
        if(nullptr != (ent = autoent.OpenExistFdEntity(from, O_RDWR))){
            if(0 != (result = ent->Flush(autoent.GetPseudoFd(), true))){
                S3FS_PRN_ERR("could not upload file(%s): result=%d", to, result);
                return result;
            }
            // remove stat cache
            StatCache::getStatCacheData()->DelStat(from);
        }
    }

    // files larger than 5GB must be modified via the multipart interface
    if(S_ISDIR(buf.st_mode)){
        result = rename_directory(from, to);
    }else if(!nomultipart && buf.st_size >= singlepart_copy_limit){
        result = rename_large_object(from, to);
    }else{
        if(!nocopyapi && !norenameapi){
            result = rename_object(from, to, true);             // update ctime
        }else{
            result = rename_object_nocopy(from, to, true);      // update ctime
        }
    }

    // update parent directory timestamp
    //
    // [NOTE]
    // already updated timestamp for original path in above functions.
    //
    int update_result;
    if(0 != (update_result = update_mctime_parent_directory(to))){
        S3FS_PRN_ERR("succeed to create the file/directory(%s), but could not update timestamp of its parent directory(result=%d).", to, update_result);
    }

    return result;
}

static int s3fs_link(const char* _from, const char* _to)
{
    WTF8_ENCODE(from)
    WTF8_ENCODE(to)
    FUSE_CTX_INFO("[from=%s][to=%s]", from, to);
    return -ENOTSUP;
}

static int s3fs_chmod(const char* _path, mode_t mode FUSE3_FILE_INFO_ARG)
{
    WTF8_ENCODE(path)
    int         result;
    std::string curpath;
    std::string normpath;
    headers_t   meta;
    struct stat stbuf;
    struct stat newstbuf;
    objtype_t   ObjType = objtype_t::UNKNOWN;

    FUSE_CTX_INFO("[path=%s][mode=%04o]", path, mode);

    if(0 != (result = check_parent_object_access(path, X_OK))){
        return result;
    }
    if(0 != (result = check_object_owner(path, &stbuf))){
        return result;
    }

    if(S_ISDIR(stbuf.st_mode)){
        result = chk_dir_object_type(path, normpath, curpath, &meta, &ObjType);
    }else{
        curpath  = path;
        normpath = curpath;
        result   = get_object_attribute(curpath.c_str(), nullptr, &meta);
    }
    if(0 != result){
        return result;
    }

    if(S_ISDIR(stbuf.st_mode) && (NEED_REPLACEDIR_OBJ(ObjType) || IS_CREATE_MP_STAT(normpath.c_str()))){
        std::string xattrvalue;
        const char* pxattrvalue;
        if(get_meta_xattr_value(curpath.c_str(), xattrvalue)){
            pxattrvalue = xattrvalue.c_str();
        }else{
            pxattrvalue = nullptr;
        }
        if(NEED_REPLACEDIR_OBJ(ObjType)){
            // Should rebuild directory object(except new type)
            // Need to remove old dir("dir" etc) and make new dir("dir/")

            // At first, remove directory old object
            if(0 != (result = remove_old_type_dir(curpath, ObjType))){
                return result;
            }
        }

        // Make new directory object("dir/")
        struct timespec ts_atime;
        struct timespec ts_mtime;
        struct timespec ts_ctime;
        set_stat_to_timespec(stbuf, stat_time_type::ATIME, ts_atime);
        set_stat_to_timespec(stbuf, stat_time_type::MTIME, ts_mtime);
        s3fs_realtime(ts_ctime);

        if(0 != (result = create_directory_object(normpath.c_str(), mode, ts_atime, ts_mtime, ts_ctime, stbuf.st_uid, stbuf.st_gid, pxattrvalue, &newstbuf))){
            return result;
        }

        // Add only stat structure to stat cache
        if(!StatCache::getStatCacheData()->AddStat(normpath, newstbuf, objtype_t::DIR_NORMAL)){
            S3FS_PRN_ERR("succeed to change mode for directory(%s), but could not add stat cache. So remove stat cache.", normpath.c_str());
            StatCache::getStatCacheData()->DelStat(normpath);
        }
    }else{
        // normal object or directory object of newer version
        std::string strSourcePath              = (mount_prefix.empty() && "/" == curpath) ? "//" : curpath;
        headers_t   updatemeta;
        updatemeta["x-amz-meta-ctime"]         = s3fs_str_realtime();
        updatemeta["x-amz-meta-mode"]          = std::to_string(mode);
        updatemeta["x-amz-copy-source"]        = urlEncodePath(service_path + S3fsCred::GetBucket() + get_realpath(strSourcePath.c_str()));
        updatemeta["x-amz-metadata-directive"] = "REPLACE";

        // check opened file handle.
        //
        // If the file starts uploading by multipart when the disk capacity is insufficient,
        // we need to put these header after finishing upload.
        // Or if the file is only open, we must update to FdEntity's internal meta.
        //
        AutoFdEntity autoent;
        FdEntity*    ent;
        bool         need_put_header = true;
        if(nullptr != (ent = autoent.OpenExistFdEntity(curpath.c_str()))){
            if(ent->MergeOrgMeta(updatemeta)){
                // meta is changed, but now uploading.
                // then the meta is pending and accumulated to be put after the upload is complete.
                S3FS_PRN_INFO("meta pending until upload is complete");
                need_put_header = false;

                // get current entity's meta headers
                if(!ent->GetOrgMeta(meta)){
                    S3FS_PRN_ERR("failed get original meta from fd entity object");
                    return -EIO;
                }

                // set stat structure
                if(!convert_header_to_stat(normpath, meta, stbuf, false)){
                    S3FS_PRN_ERR("failed convert headers to stat[path=%s]", normpath.c_str());
                    return -EIO;
                }

                // update cache(if exists)
                if(!StatCache::getStatCacheData()->UpdateStat(curpath, stbuf, meta)){
                    // maybe cache is not found, so add new cache

                    // check object type(if UNKNOWN, to symbolic link or file)
                    if(is_symlink_fmt(meta)){
                        ObjType = objtype_t::SYMLINK;
                    }else if(is_reg_fmt(meta)){
                        ObjType = objtype_t::FILE;
                    }
                    if(!StatCache::getStatCacheData()->AddStat(curpath, stbuf, meta, ObjType, true)){     // [NOTICE] notruncate = true
                        S3FS_PRN_ERR("failed add new stat cache [path=%s]", curpath.c_str());
                        return -EIO;
                    }
                }
            }
        }
        if(need_put_header){
            // not found opened file.
            merge_headers(meta, updatemeta, true);

            // upload meta directly.
            if(0 != (result = put_headers(curpath.c_str(), meta, true))){
                return result;
            }

            // Add only stat structure to stat cache
            if(convert_header_to_stat(curpath, meta, newstbuf)){
                ObjType = derive_object_type(curpath, meta, objtype_t::FILE);
                if(!StatCache::getStatCacheData()->AddStat(curpath, newstbuf, ObjType)){
                    S3FS_PRN_ERR("succeed to change mode for %s, but could not add stat cache. So remove stat cache.", curpath.c_str());
                    StatCache::getStatCacheData()->DelStat(curpath);
                }
            }else{
                S3FS_PRN_ERR("failed convert headers to stat[path=%s]. So remove stat cache.", curpath.c_str());
                StatCache::getStatCacheData()->DelStat(curpath);
            }
        }
    }

    return 0;
}

static int s3fs_chmod_nocopy(const char* _path, mode_t mode FUSE3_FILE_INFO_ARG)
{
    WTF8_ENCODE(path)
    int         result;
    std::string curpath;
    std::string normpath;
    struct stat stbuf;
    struct stat newstbuf;
    objtype_t   ObjType = objtype_t::UNKNOWN;

    FUSE_CTX_INFO1("[path=%s][mode=%04o]", path, mode);

    if(0 != (result = check_parent_object_access(path, X_OK))){
        return result;
    }
    if(0 != (result = check_object_owner(path, &stbuf))){
        return result;
    }

    // Get attributes
    if(S_ISDIR(stbuf.st_mode)){
        result = chk_dir_object_type(path, normpath, curpath, nullptr, &ObjType);
    }else{
        curpath  = path;
        normpath = curpath;
        result   = get_object_attribute(curpath.c_str(), nullptr, nullptr);
    }
    if(0 != result){
        return result;
    }

    if(S_ISDIR(stbuf.st_mode)){
        std::string xattrvalue;
        const char* pxattrvalue;
        if(get_meta_xattr_value(curpath.c_str(), xattrvalue)){
            pxattrvalue = xattrvalue.c_str();
        }else{
            pxattrvalue = nullptr;
        }

        if(NEED_REPLACEDIR_OBJ(ObjType)){
            // Should rebuild all directory object
            // Need to remove old dir("dir" etc) and make new dir("dir/")

            // At first, remove directory old object
            if(0 != (result = remove_old_type_dir(curpath, ObjType))){
                return result;
            }
        }

        // Make new directory object("dir/")
        struct timespec ts_atime;
        struct timespec ts_mtime;
        struct timespec ts_ctime;
        set_stat_to_timespec(stbuf, stat_time_type::ATIME, ts_atime);
        set_stat_to_timespec(stbuf, stat_time_type::MTIME, ts_mtime);
        s3fs_realtime(ts_ctime);

        if(0 != (result = create_directory_object(normpath.c_str(), mode, ts_atime, ts_mtime, ts_ctime, stbuf.st_uid, stbuf.st_gid, pxattrvalue, &newstbuf))){
            return result;
        }

        // Add only stat structure to stat cache
        if(!StatCache::getStatCacheData()->AddStat(normpath, newstbuf, objtype_t::DIR_NORMAL)){
            S3FS_PRN_ERR("succeed to change mode for directory(%s), but could not add stat cache. So remove stat cache.", normpath.c_str());
            StatCache::getStatCacheData()->DelStat(normpath);
        }
    }else{
        // normal object or directory object of newer version

        // open & load
        AutoFdEntity autoent;
        FdEntity*    ent;
        if(0 != (result = get_local_fent(autoent, &ent, curpath.c_str(), O_RDWR, true))){
            S3FS_PRN_ERR("could not open and read file(%s)", curpath.c_str());
            return result;
        }

        struct timespec ts;
        s3fs_realtime(ts);
        ent->SetCtime(ts);

        // Change file mode
        ent->SetMode(mode);

        // upload
        if(0 != (result = ent->Flush(autoent.GetPseudoFd(), true))){
            S3FS_PRN_ERR("could not upload file(%s): result=%d", curpath.c_str(), result);
            return result;
        }

        // [NOTE]
        // Not have a copy API (nocopy), the stat cache will be removed.
        //
        StatCache::getStatCacheData()->DelStat(normpath);
    }
  
    return result;
}

static int s3fs_chown(const char* _path, uid_t uid, gid_t gid FUSE3_FILE_INFO_ARG)
{
    WTF8_ENCODE(path)
    int         result;
    std::string curpath;
    std::string normpath;
    headers_t   meta;
    struct stat stbuf;
    struct stat newstbuf;
    objtype_t   ObjType = objtype_t::UNKNOWN;

    FUSE_CTX_INFO("[path=%s][uid=%u][gid=%u]", path, (unsigned int)uid, (unsigned int)gid);

    if(0 != (result = check_parent_object_access(path, X_OK))){
        return result;
    }
    if(0 != (result = check_object_owner(path, &stbuf))){
        return result;
    }
    if(static_cast<uid_t>(-1) == uid){
        uid = stbuf.st_uid;
    }
    if(static_cast<gid_t>(-1) == gid){
        gid = stbuf.st_gid;
    }

    if(S_ISDIR(stbuf.st_mode)){
        result = chk_dir_object_type(path, normpath, curpath, &meta, &ObjType);
    }else{
        curpath  = path;
        normpath = curpath;
        result   = get_object_attribute(curpath.c_str(), nullptr, &meta);
    }
    if(0 != result){
        return result;
    }

    if(S_ISDIR(stbuf.st_mode) && (NEED_REPLACEDIR_OBJ(ObjType) || IS_CREATE_MP_STAT(normpath.c_str()))){
        std::string xattrvalue;
        const char* pxattrvalue;
        if(get_meta_xattr_value(curpath.c_str(), xattrvalue)){
            pxattrvalue = xattrvalue.c_str();
        }else{
            pxattrvalue = nullptr;
        }
        if(NEED_REPLACEDIR_OBJ(ObjType)){
            // Should rebuild directory object(except new type)
            // Need to remove old dir("dir" etc) and make new dir("dir/")

            // At first, remove directory old object
            if(0 != (result = remove_old_type_dir(curpath, ObjType))){
                return result;
            }
        }

        // Make new directory object("dir/")
        struct timespec ts_atime;
        struct timespec ts_mtime;
        struct timespec ts_ctime;
        set_stat_to_timespec(stbuf, stat_time_type::ATIME, ts_atime);
        set_stat_to_timespec(stbuf, stat_time_type::MTIME, ts_mtime);
        s3fs_realtime(ts_ctime);

        if(0 != (result = create_directory_object(normpath.c_str(), stbuf.st_mode, ts_atime, ts_mtime, ts_ctime, uid, gid, pxattrvalue, &newstbuf))){
            return result;
        }

        // Add only stat structure to stat cache
        if(!StatCache::getStatCacheData()->AddStat(normpath, newstbuf, objtype_t::DIR_NORMAL)){
            S3FS_PRN_ERR("succeed to chown for directory(%s), but could not add stat cache. So remove stat cache.", normpath.c_str());
            StatCache::getStatCacheData()->DelStat(normpath);
        }
    }else{
        std::string strSourcePath              = (mount_prefix.empty() && "/" == curpath) ? "//" : curpath;
        headers_t   updatemeta;
        updatemeta["x-amz-meta-ctime"]         = s3fs_str_realtime();
        updatemeta["x-amz-meta-uid"]           = std::to_string(uid);
        updatemeta["x-amz-meta-gid"]           = std::to_string(gid);
        updatemeta["x-amz-copy-source"]        = urlEncodePath(service_path + S3fsCred::GetBucket() + get_realpath(strSourcePath.c_str()));
        updatemeta["x-amz-metadata-directive"] = "REPLACE";

        // check opened file handle.
        //
        // If the file starts uploading by multipart when the disk capacity is insufficient,
        // we need to put these header after finishing upload.
        // Or if the file is only open, we must update to FdEntity's internal meta.
        //
        AutoFdEntity autoent;
        FdEntity*    ent;
        bool         need_put_header = true;
        if(nullptr != (ent = autoent.OpenExistFdEntity(curpath.c_str()))){
            if(ent->MergeOrgMeta(updatemeta)){
                // meta is changed, but now uploading.
                // then the meta is pending and accumulated to be put after the upload is complete.
                S3FS_PRN_INFO("meta pending until upload is complete");
                need_put_header = false;

                // get current entity's meta headers
                if(!ent->GetOrgMeta(meta)){
                    S3FS_PRN_ERR("failed get original meta from fd entity object");
                    return -EIO;
                }

                // set stat structure
                if(!convert_header_to_stat(normpath, meta, stbuf, false)){
                    S3FS_PRN_ERR("failed convert headers to stat[path=%s]", normpath.c_str());
                    return -EIO;
                }

                // update cache(if exists)
                if(!StatCache::getStatCacheData()->UpdateStat(curpath, stbuf, meta)){
                    // maybe cache is not found, so add new cache

                    // check object type(if UNKNOWN, to symbolic link or file)
                    if(is_symlink_fmt(meta)){
                        ObjType = objtype_t::SYMLINK;
                    }else if(is_reg_fmt(meta)){
                        ObjType = objtype_t::FILE;
                    }
                    if(!StatCache::getStatCacheData()->AddStat(curpath, stbuf, meta, ObjType, true)){     // [NOTICE] notruncate = true
                        S3FS_PRN_ERR("failed add new stat cache [path=%s]", curpath.c_str());
                        return -EIO;
                    }
                }
            }
        }
        if(need_put_header){
            // not found opened file.
            merge_headers(meta, updatemeta, true);

            // upload meta directly.
            if(0 != (result = put_headers(curpath.c_str(), meta, true))){
                return result;
            }

            // Add only stat structure to stat cache
            if(convert_header_to_stat(curpath, meta, newstbuf)){
                ObjType = derive_object_type(curpath, meta, objtype_t::FILE);
                if(!StatCache::getStatCacheData()->AddStat(curpath, newstbuf, ObjType)){
                    S3FS_PRN_ERR("succeed to chown for %s, but could not add stat cache. So remove stat cache.", curpath.c_str());
                    StatCache::getStatCacheData()->DelStat(curpath);
                }
            }else{
                S3FS_PRN_ERR("failed convert headers to stat[path=%s]. So remove stat cache.", curpath.c_str());
                StatCache::getStatCacheData()->DelStat(curpath);
            }
        }
    }

    return 0;
}

static int s3fs_chown_nocopy(const char* _path, uid_t uid, gid_t gid FUSE3_FILE_INFO_ARG)
{
    WTF8_ENCODE(path)
    int         result;
    std::string curpath;
    std::string normpath;
    struct stat stbuf;
    struct stat newstbuf;
    objtype_t   ObjType = objtype_t::UNKNOWN;

    FUSE_CTX_INFO1("[path=%s][uid=%u][gid=%u]", path, (unsigned int)uid, (unsigned int)gid);

    if(0 != (result = check_parent_object_access(path, X_OK))){
        return result;
    }
    if(0 != (result = check_object_owner(path, &stbuf))){
        return result;
    }
    if(static_cast<uid_t>(-1) == uid){
        uid = stbuf.st_uid;
    }
    if(static_cast<gid_t>(-1) == gid){
        gid = stbuf.st_gid;
    }

    // Get attributes
    if(S_ISDIR(stbuf.st_mode)){
        result = chk_dir_object_type(path, normpath, curpath, nullptr, &ObjType);
    }else{
        curpath  = path;
        normpath = curpath;
        result   = get_object_attribute(curpath.c_str(), nullptr, nullptr);
    }
    if(0 != result){
        return result;
    }

    if(S_ISDIR(stbuf.st_mode)){
        std::string xattrvalue;
        const char* pxattrvalue;
        if(get_meta_xattr_value(curpath.c_str(), xattrvalue)){
            pxattrvalue = xattrvalue.c_str();
        }else{
            pxattrvalue = nullptr;
        }

        if(NEED_REPLACEDIR_OBJ(ObjType)){
            // Should rebuild all directory object
            // Need to remove old dir("dir" etc) and make new dir("dir/")

            // At first, remove directory old object
            if(0 != (result = remove_old_type_dir(curpath, ObjType))){
                return result;
            }
        }

        // Make new directory object("dir/")
        struct timespec ts_atime;
        struct timespec ts_mtime;
        struct timespec ts_ctime;
        set_stat_to_timespec(stbuf, stat_time_type::ATIME, ts_atime);
        set_stat_to_timespec(stbuf, stat_time_type::MTIME, ts_mtime);
        s3fs_realtime(ts_ctime);

        if(0 != (result = create_directory_object(normpath.c_str(), stbuf.st_mode, ts_atime, ts_mtime, ts_ctime, uid, gid, pxattrvalue, &newstbuf))){
            return result;
        }

        // Add only stat structure to stat cache
        if(!StatCache::getStatCacheData()->AddStat(normpath, newstbuf, objtype_t::DIR_NORMAL)){
            S3FS_PRN_ERR("succeed to chown for directory(%s), but could not add stat cache. So remove stat cache.", normpath.c_str());
            StatCache::getStatCacheData()->DelStat(normpath);
        }
    }else{
        // normal object or directory object of newer version

        // open & load
        AutoFdEntity autoent;
        FdEntity*    ent;
        if(0 != (result = get_local_fent(autoent, &ent, curpath.c_str(), O_RDWR, true))){
            S3FS_PRN_ERR("could not open and read file(%s)", curpath.c_str());
            return result;
        }

        struct timespec ts;
        s3fs_realtime(ts);
        ent->SetCtime(ts);

        // Change owner
        ent->SetUId(uid);
        ent->SetGId(gid);
  
        // upload
        if(0 != (result = ent->Flush(autoent.GetPseudoFd(), true))){
            S3FS_PRN_ERR("could not upload file(%s): result=%d", curpath.c_str(), result);
            return result;
        }

        // [NOTE]
        // Not have a copy API (nocopy), the stat cache will be removed.
        //
        StatCache::getStatCacheData()->DelStat(normpath);
    }
  
    return result;
}

static timespec handle_utimens_special_values(timespec ts, timespec now, timespec orig)
{
    if(ts.tv_nsec == UTIME_NOW){
        return now;
    }else if(ts.tv_nsec == UTIME_OMIT){
        return orig;
    }else{
        return ts;
    }
}

static int update_mctime_parent_directory(const char* _path)
{
    if(!update_parent_dir_stat){
        // Disable updating parent directory stat.
        S3FS_PRN_DBG("Updating parent directory stats is disabled");
        return 0;
    }

    WTF8_ENCODE(path)
    int             result;
    std::string     parentpath;     // parent directory path
    std::string     curpath;        // current directory object path("dir" or "dir/" or "xxx_$folder$", etc)
    std::string     normpath;       // normalized directory path(ex. "dir/")
    headers_t       meta;
    struct stat     stbuf;
    struct stat newstbuf;
    struct timespec mctime;
    struct timespec atime;
    objtype_t       ObjType = objtype_t::UNKNOWN;

    S3FS_PRN_INFO2("[path=%s]", path);

    // get parent directory path
    parentpath = mydirname(path);

    // check & get directory type
    if(0 != (result = chk_dir_object_type(parentpath.c_str(), normpath, curpath, &meta, &ObjType))){
        return result;
    }

    // get directory stat
    //
    // [NOTE]
    // It is assumed that this function is called after the operation on
    // the file is completed, so there is no need to check the permissions
    // on the parent directory.
    //
    if(0 != (result = get_object_attribute(parentpath.c_str(), &stbuf))){
        // If there is not the target file(object), result is -ENOENT.
        return result;
    }
    if(!S_ISDIR(stbuf.st_mode)){
        S3FS_PRN_ERR("path(%s) is not parent directory.", parentpath.c_str());
        return -EIO;
    }

    // make atime/mtime/ctime for updating
    s3fs_realtime(mctime);
    set_stat_to_timespec(stbuf, stat_time_type::ATIME, atime);

    if(0 == atime.tv_sec && 0 == atime.tv_nsec){
        atime = mctime;
    }

    if(nocopyapi || NEED_REPLACEDIR_OBJ(ObjType) || IS_CREATE_MP_STAT(parentpath.c_str())){
        // Should rebuild directory object(except new type)
        // Need to remove old dir("dir" etc) and make new dir("dir/")
        std::string xattrvalue;
        const char* pxattrvalue;
        if(get_meta_xattr_value(parentpath.c_str(), xattrvalue)){
            pxattrvalue = xattrvalue.c_str();
        }else{
            pxattrvalue = nullptr;
        }

        // At first, remove directory old object
        if(!curpath.empty()){
            if(0 != (result = remove_old_type_dir(curpath, ObjType))){
                return result;
            }
        }

        // Make new directory object("dir/")
        if(0 != (result = create_directory_object(normpath.c_str(), stbuf.st_mode, atime, mctime, mctime, stbuf.st_uid, stbuf.st_gid, pxattrvalue, &newstbuf))){
            return result;
        }

        // Add only stat structure to stat cache
        if(!StatCache::getStatCacheData()->AddStat(normpath, newstbuf, objtype_t::DIR_NORMAL)){
            S3FS_PRN_ERR("succeed to change mctime for parent(%s), but could not add stat cache. So remove stat cache.", normpath.c_str());
            StatCache::getStatCacheData()->DelStat(normpath);
        }
    }else{
        std::string strSourcePath              = (mount_prefix.empty() && "/" == curpath) ? "//" : curpath;
        headers_t   updatemeta;
        updatemeta["x-amz-meta-mtime"]         = str(mctime);
        updatemeta["x-amz-meta-ctime"]         = str(mctime);
        updatemeta["x-amz-meta-atime"]         = str(atime);
        updatemeta["x-amz-copy-source"]        = urlEncodePath(service_path + S3fsCred::GetBucket() + get_realpath(strSourcePath.c_str()));
        updatemeta["x-amz-metadata-directive"] = "REPLACE";

        merge_headers(meta, updatemeta, true);

        // upload meta for parent directory.
        if(0 != (result = put_headers(curpath.c_str(), meta, true))){
            return result;
        }

        if(convert_header_to_stat(curpath, meta, newstbuf)){
            ObjType = derive_object_type(curpath, meta, objtype_t::DIR_NORMAL);
            if(!StatCache::getStatCacheData()->AddStat(curpath, newstbuf, ObjType)){
                S3FS_PRN_ERR("succeed to change mctime for parent(%s), but could not add stat cache. So remove stat cache.", curpath.c_str());
                StatCache::getStatCacheData()->DelStat(curpath);
            }
        }else{
            S3FS_PRN_ERR("failed convert headers to stat[path=%s]. So remove stat cache.", curpath.c_str());
            StatCache::getStatCacheData()->DelStat(curpath);
        }
    }

    return 0;
}

static int s3fs_utimens(const char* _path, const struct timespec ts[2] FUSE3_FILE_INFO_ARG)
{
    WTF8_ENCODE(path)
    int         result;
    std::string curpath;
    std::string normpath;
    headers_t   meta;
    struct stat stbuf;
    struct stat newstbuf;
    objtype_t   ObjType = objtype_t::UNKNOWN;

    FUSE_CTX_INFO("[path=%s][mtime=%s][ctime/atime=%s]", path, str(ts[1]).c_str(), str(ts[0]).c_str());

    if(0 != (result = check_parent_object_access(path, X_OK))){
        return result;
    }
    if(0 != (result = check_object_access(path, W_OK, &stbuf))){
        if(0 != check_object_owner(path, &stbuf)){
            return result;
        }
    }

    struct timespec now;
    struct timespec ts_atime;
    struct timespec ts_ctime;
    struct timespec ts_mtime;

    s3fs_realtime(now);
    set_stat_to_timespec(stbuf, stat_time_type::ATIME, ts_atime);
    set_stat_to_timespec(stbuf, stat_time_type::CTIME, ts_ctime);
    set_stat_to_timespec(stbuf, stat_time_type::MTIME, ts_mtime);

    struct timespec atime = handle_utimens_special_values(ts[0], now, ts_atime);
    struct timespec ctime = handle_utimens_special_values(ts[0], now, ts_ctime);
    struct timespec mtime = handle_utimens_special_values(ts[1], now, ts_mtime);

    if(S_ISDIR(stbuf.st_mode)){
        result = chk_dir_object_type(path, normpath, curpath, &meta, &ObjType);
    }else{
        curpath  = path;
        normpath = curpath;
        result   = get_object_attribute(curpath.c_str(), nullptr, &meta);
    }
    if(0 != result){
        return result;
    }

    if(S_ISDIR(stbuf.st_mode) && (NEED_REPLACEDIR_OBJ(ObjType) || IS_CREATE_MP_STAT(normpath.c_str()))){
        std::string xattrvalue;
        const char* pxattrvalue;
        if(get_meta_xattr_value(curpath.c_str(), xattrvalue)){
            pxattrvalue = xattrvalue.c_str();
        }else{
            pxattrvalue = nullptr;
        }
        if(NEED_REPLACEDIR_OBJ(ObjType)){
            // Should rebuild directory object(except new type)
            // Need to remove old dir("dir" etc) and make new dir("dir/")

            // At first, remove directory old object
            if(0 != (result = remove_old_type_dir(curpath, ObjType))){
                return result;
            }
        }

        // Make new directory object("dir/")
        if(0 != (result = create_directory_object(normpath.c_str(), stbuf.st_mode, atime, mtime, ctime, stbuf.st_uid, stbuf.st_gid, pxattrvalue, &newstbuf))){
            return result;
        }

        // Add only stat structure to stat cache
        if(!StatCache::getStatCacheData()->AddStat(normpath, newstbuf, objtype_t::DIR_NORMAL)){
            S3FS_PRN_ERR("succeed to set utimens directory(%s), but could not add stat cache. So remove stat cache.", normpath.c_str());
            StatCache::getStatCacheData()->DelStat(normpath);
        }
    }else{
        std::string strSourcePath              = (mount_prefix.empty() && "/" == curpath) ? "//" : curpath;
        headers_t   updatemeta;
        updatemeta["x-amz-meta-mtime"]         = str(mtime);
        updatemeta["x-amz-meta-ctime"]         = str(ctime);
        updatemeta["x-amz-meta-atime"]         = str(atime);
        updatemeta["x-amz-copy-source"]        = urlEncodePath(service_path + S3fsCred::GetBucket() + get_realpath(strSourcePath.c_str()));
        updatemeta["x-amz-metadata-directive"] = "REPLACE";

        // check opened file handle.
        //
        // If the file starts uploading by multipart when the disk capacity is insufficient,
        // we need to put these header after finishing upload.
        // Or if the file is only open, we must update to FdEntity's internal meta.
        //
        AutoFdEntity autoent;
        FdEntity*    ent;
        bool         need_put_header = true;
        if(nullptr != (ent = autoent.OpenExistFdEntity(curpath.c_str()))){
            if(ent->MergeOrgMeta(updatemeta)){
                // meta is changed, but now uploading.
                // then the meta is pending and accumulated to be put after the upload is complete.
                S3FS_PRN_INFO("meta pending until upload is complete");
                need_put_header = false;

                // get current entity's meta headers
                if(!ent->GetOrgMeta(meta)){
                    S3FS_PRN_ERR("failed get original meta from fd entity object");
                    return -EIO;
                }

                // set stat structure
                if(!convert_header_to_stat(normpath, meta, stbuf, false)){
                    S3FS_PRN_ERR("failed convert headers to stat[path=%s]", normpath.c_str());
                    return -EIO;
                }

                // update cache(if exists)
                if(!StatCache::getStatCacheData()->UpdateStat(curpath, stbuf, meta)){
                    // maybe cache is not found, so add new cache

                    // check object type(if UNKNOWN, to symbolic link or file)
                    if(is_symlink_fmt(meta)){
                        ObjType = objtype_t::SYMLINK;
                    }else if(is_reg_fmt(meta)){
                        ObjType = objtype_t::FILE;
                    }
                    if(!StatCache::getStatCacheData()->AddStat(curpath, stbuf, meta, ObjType, true)){     // [NOTICE] notruncate = true
                        S3FS_PRN_ERR("failed add new stat cache [path=%s]", curpath.c_str());
                        return -EIO;
                    }
                }

            }else{
                S3FS_PRN_INFO("meta is not pending, but need to keep current mtime.");
            }
        }
        if(need_put_header){
            // not found opened file.
            merge_headers(meta, updatemeta, true);

            // upload meta directly.
            if(0 != (result = put_headers(curpath.c_str(), meta, true))){
                return result;
            }

            // Add only stat structure to stat cache
            if(convert_header_to_stat(curpath, meta, newstbuf)){
                ObjType = derive_object_type(curpath, meta, objtype_t::FILE);
                if(!StatCache::getStatCacheData()->AddStat(curpath, newstbuf, ObjType)){
                    S3FS_PRN_ERR("succeed to set utimens for %s, but could not add stat cache. So remove stat cache.", curpath.c_str());
                    StatCache::getStatCacheData()->DelStat(curpath);
                }
            }else{
                S3FS_PRN_ERR("failed convert headers to stat[path=%s]. So remove stat cache.", curpath.c_str());
                StatCache::getStatCacheData()->DelStat(curpath);
            }
        }
    }

    return 0;
}

static int s3fs_utimens_nocopy(const char* _path, const struct timespec ts[2] FUSE3_FILE_INFO_ARG)
{
    WTF8_ENCODE(path)
    int         result;
    std::string curpath;
    std::string normpath;
    struct stat stbuf;
    struct stat newstbuf;
    objtype_t   ObjType = objtype_t::UNKNOWN;

    FUSE_CTX_INFO1("[path=%s][mtime=%s][atime/ctime=%s]", path, str(ts[1]).c_str(), str(ts[0]).c_str());

    if(0 != (result = check_parent_object_access(path, X_OK))){
        return result;
    }
    if(0 != (result = check_object_access(path, W_OK, &stbuf))){
        if(0 != check_object_owner(path, &stbuf)){
            return result;
        }
    }

    struct timespec now;
    struct timespec ts_atime;
    struct timespec ts_ctime;
    struct timespec ts_mtime;

    s3fs_realtime(now);
    set_stat_to_timespec(stbuf, stat_time_type::ATIME, ts_atime);
    set_stat_to_timespec(stbuf, stat_time_type::CTIME, ts_ctime);
    set_stat_to_timespec(stbuf, stat_time_type::MTIME, ts_mtime);

    struct timespec atime = handle_utimens_special_values(ts[0], now, ts_atime);
    struct timespec ctime = handle_utimens_special_values(ts[0], now, ts_ctime);
    struct timespec mtime = handle_utimens_special_values(ts[1], now, ts_mtime);

    // Get attributes
    if(S_ISDIR(stbuf.st_mode)){
        result = chk_dir_object_type(path, normpath, curpath, nullptr, &ObjType);
    }else{
        curpath  = path;
        normpath = curpath;
        result   = get_object_attribute(curpath.c_str(), nullptr, nullptr);
    }
    if(0 != result){
        return result;
    }

    if(S_ISDIR(stbuf.st_mode)){
        std::string xattrvalue;
        const char* pxattrvalue;
        if(get_meta_xattr_value(curpath.c_str(), xattrvalue)){
            pxattrvalue = xattrvalue.c_str();
        }else{
            pxattrvalue = nullptr;
        }

        if(NEED_REPLACEDIR_OBJ(ObjType)){
            // Should rebuild all directory object
            // Need to remove old dir("dir" etc) and make new dir("dir/")

            // At first, remove directory old object
            if(0 != (result = remove_old_type_dir(curpath, ObjType))){
                return result;
            }
        }

        // Make new directory object("dir/")
        if(0 != (result = create_directory_object(normpath.c_str(), stbuf.st_mode, atime, mtime, ctime, stbuf.st_uid, stbuf.st_gid, pxattrvalue, &newstbuf))){
            return result;
        }

        // Add only stat structure to stat cache
        if(!StatCache::getStatCacheData()->AddStat(normpath, newstbuf, objtype_t::DIR_NORMAL)){
            S3FS_PRN_ERR("succeed to set utimens directory(%s), but could not add stat cache. So remove stat cache.", normpath.c_str());
            StatCache::getStatCacheData()->DelStat(normpath);
        }
    }else{
        // normal object or directory object of newer version

        // open & load
        AutoFdEntity autoent;
        FdEntity*    ent;
        if(0 != (result = get_local_fent(autoent, &ent, curpath.c_str(), O_RDWR, true))){
            S3FS_PRN_ERR("could not open and read file(%s)", curpath.c_str());
            return result;
        }

        // set mtime/ctime/atime
        if(0 != (result = ent->SetMtime(mtime)) || 0 != (result = ent->SetCtime(ctime)) || 0 != (result = ent->SetAtime(atime))){
            S3FS_PRN_ERR("could not set mtime/ctime/atime to file(%s): result=%d", curpath.c_str(), result);
            return result;
        }

        // upload
        if(0 != (result = ent->Flush(autoent.GetPseudoFd(), true))){
            S3FS_PRN_ERR("could not upload file(%s): result=%d", curpath.c_str(), result);
            return result;
        }

        // [NOTE]
        // Not have a copy API (nocopy), the stat cache will be removed.
        //
        StatCache::getStatCacheData()->DelStat(normpath);
    }

    return result;
}

static int s3fs_truncate(const char* _path, off_t size FUSE3_FILE_INFO_ARG)
{
    WTF8_ENCODE(path)
    int          result;
    headers_t    meta;
    AutoFdEntity autoent;
    FdEntity*    ent = nullptr;

    FUSE_CTX_INFO("[path=%s][size=%lld]", path, static_cast<long long>(size));

    size = std::max<off_t>(size, 0);

    if(0 != (result = check_parent_object_access(path, X_OK))){
        return result;
    }
    if(0 != (result = check_object_access(path, W_OK, nullptr))){
        return result;
    }

    // Get file information
    if(0 == (result = get_object_attribute(path, nullptr, &meta))){
        // File exists

        // [NOTE]
        // If the file exists, the file has already been opened by FUSE before
        // truncate is called. Then the call below will change the file size.
        // (When an already open file is changed the file size, FUSE will not
        // reopen it.)
        // The Flush is called before this file is closed, so there is no need
        // to do it here.
        //
        // [NOTICE]
        // FdManager::Open() ignores changes that reduce the file size for the
        // file you are editing. However, if user opens only once, edit it,
        // and then shrink the file, it should be done.
        // When this function is called, the file is already open by FUSE or
        // some other operation. Therefore, if the number of open files is 1,
        // no edits other than that fd will be made, and the files will be
        // shrunk using ignore_modify flag even while editing.
        // See the comments when merging this code for FUSE2 limitations.
        // (In FUSE3, it will be possible to handle it reliably using fuse_file_info.)
        //
        bool ignore_modify;
        if(1 < FdManager::GetOpenFdCount(path)){
            ignore_modify = false;
        }else{
            ignore_modify = true;
        }

        FileTimes ts_times;     // Default: all time values are set UTIME_OMIT
        if(nullptr == (ent = autoent.Open(path, &meta, size, ts_times, O_RDWR, false, true, ignore_modify))){
            S3FS_PRN_ERR("could not open file(%s): errno=%d(ent is null(%p))", path, errno, ent);   // [NOTE] read ent to avoid errors with cppcheck etc
            return -EIO;
        }

#ifdef __APPLE__
        // [NOTE]
        // Only for macos, this truncate calls to "size=0" do not reflect size.
        // The cause is unknown now, but it can be avoided by flushing the file.
        //
        if(0 == size){
            if(0 != (result = ent->Flush(autoent.GetPseudoFd(), true))){
                S3FS_PRN_ERR("could not upload file(%s): result=%d", path, result);
                return result;
            }
            StatCache::getStatCacheData()->DelStat(path);
        }
#endif

    }else{
        // Not found -> Make tmpfile(with size)
        const struct fuse_context* pcxt;
        if(nullptr == (pcxt = fuse_get_context())){
            return -EIO;
        }

        std::string strnow       = s3fs_str_realtime();
        meta["Content-Type"]     = "application/octet-stream"; // Static
        meta["x-amz-meta-mode"]  = std::to_string(S_IFLNK | S_IRWXU | S_IRWXG | S_IRWXO);
        meta["x-amz-meta-ctime"] = strnow;
        meta["x-amz-meta-mtime"] = strnow;
        meta["x-amz-meta-uid"]   = std::to_string(pcxt->uid);
        meta["x-amz-meta-gid"]   = std::to_string(pcxt->gid);

        FileTimes ts_times;     // Default: all time values are set UTIME_OMIT
        if(nullptr == (ent = autoent.Open(path, &meta, size, ts_times, O_RDWR, true, true, false))){
            S3FS_PRN_ERR("could not open file(%s): errno=%d", path, errno);
            return -EIO;
        }
        if(0 != (result = ent->Flush(autoent.GetPseudoFd(), true))){
            S3FS_PRN_ERR("could not upload file(%s): result=%d", path, result);
            return result;
        }
        StatCache::getStatCacheData()->DelStat(path);
    }

    return result;
}

static int s3fs_open(const char* _path, struct fuse_file_info* fi)
{
    WTF8_ENCODE(path)
    int result;
    struct stat st;
    bool needs_flush = false;

    FUSE_CTX_INFO("[path=%s][flags=0x%x]", path, fi->flags);

    if ((fi->flags & O_ACCMODE) == O_RDONLY && fi->flags & O_TRUNC) {
        return -EACCES;
    }

    // [NOTE]
    // Delete the Stats cache only if the file is not open.
    // If the file is open, the stats cache will not be deleted as
    // there are cases where the object does not exist on the server
    // and only the Stats cache exists.
    //
    if(StatCache::getStatCacheData()->HasStat(path)){
        if(!FdManager::HasOpenEntityFd(path)){
            // remove stat cache
            StatCache::getStatCacheData()->DelStat(path);
        }
    }

    int mask = (O_RDONLY != (fi->flags & O_ACCMODE) ? W_OK : R_OK);
    if(0 != (result = check_parent_object_access(path, X_OK))){
        return result;
    }

    result = check_object_access(path, mask, &st);
    if(-ENOENT == result){
        if(0 != (result = check_parent_object_access(path, W_OK))){
            return result;
        }
    }else if(0 != result){
        return result;
    }

    AutoFdEntity autoent;
    FdEntity*    ent;
    headers_t    meta;

    if(static_cast<unsigned int>(fi->flags) & O_TRUNC){
        if(0 != st.st_size){
            st.st_size = 0;
            needs_flush = true;
        }
    }else{
        // [NOTE]
        // If the file has already been opened and edited, the file size in
        // the edited state is given priority.
        // This prevents the file size from being reset to its original size
        // if you keep the file open, shrink its size, and then read the file
        // from another process while it has not yet been flushed.
        //
        if(nullptr != (ent = autoent.OpenExistFdEntity(path)) && ent->IsModified()){
            // sets the file size being edited.
            if(!ent->GetSize(st.st_size)){
                return -EIO;
            }
        }
    }

    if(0 != (result = get_object_attribute(path, nullptr, &meta, true, nullptr, true))){    // no truncate cache
        return result;
    }

    FileTimes ts_times;     // Default: all time values are set UTIME_OMIT
    ts_times.SetAll(st);
    if(nullptr == (ent = autoent.Open(path, &meta, st.st_size, ts_times, fi->flags, false, true, false))){
        // remove stat cache
        StatCache::getStatCacheData()->DelStat(path);
        return -EIO;
    }

    if (needs_flush){
        struct timespec ts_now;
        s3fs_realtime(ts_now);
        if(0 != (result = ent->SetCtime(ts_now)) || 0 != (result = ent->SetMtime(ts_now))){
            S3FS_PRN_ERR("could not set mtime and ctime to file(%s): result=%d", path, result);
            return result;
        }

        if(0 != (result = ent->RowFlush(autoent.GetPseudoFd(), path, true))){
            S3FS_PRN_ERR("could not upload file(%s): result=%d", path, result);

            // remove stat cache
            StatCache::getStatCacheData()->DelStat(path);
            return result;
        }
    }
    fi->fh = autoent.Detach();       // KEEP fdentity open;

    return 0;
}

static int s3fs_read(const char* _path, char* buf, size_t size, off_t offset, struct fuse_file_info* fi)
{
    WTF8_ENCODE(path)
    ssize_t res;

    FUSE_CTX_DBG("[path=%s][size=%zu][offset=%lld][pseudo_fd=%llu]", path, size, static_cast<long long>(offset), (unsigned long long)(fi->fh));

    AutoFdEntity autoent;
    FdEntity*    ent;
    if(nullptr == (ent = autoent.GetExistFdEntity(path, static_cast<int>(fi->fh)))){
        S3FS_PRN_ERR("could not find opened pseudo_fd(=%llu) for path(%s)", (unsigned long long)(fi->fh), path);
        return -EIO;
    }

    // check real file size
    off_t realsize = 0;
    if(!ent->GetSize(realsize) || 0 == realsize){
        S3FS_PRN_DBG("file size is 0, so break to read.");
        return 0;
    }

    if(0 > (res = ent->Read(static_cast<int>(fi->fh), buf, offset, size, false))){
        S3FS_PRN_WARN("failed to read file(%s). result=%zd", path, res);
    }

    return static_cast<int>(res);
}

static int s3fs_write(const char* _path, const char* buf, size_t size, off_t offset, struct fuse_file_info* fi)
{
    WTF8_ENCODE(path)
    ssize_t res;

    FUSE_CTX_DBG("[path=%s][size=%zu][offset=%lld][pseudo_fd=%llu]", path, size, static_cast<long long int>(offset), (unsigned long long)(fi->fh));

    AutoFdEntity autoent;
    FdEntity*    ent;
    if(nullptr == (ent = autoent.GetExistFdEntity(path, static_cast<int>(fi->fh)))){
        S3FS_PRN_ERR("could not find opened pseudo_fd(%llu) for path(%s)", (unsigned long long)(fi->fh), path);
        return -EIO;
    }

    if(0 > (res = ent->Write(static_cast<int>(fi->fh), buf, offset, size))){
        S3FS_PRN_WARN("failed to write file(%s). result=%zd", path, res);
    }

    int    result;
    struct timespec ts_now;
    s3fs_realtime(ts_now);
    if(0 != (result = ent->SetCtime(ts_now)) || 0 != (result = ent->SetMtime(ts_now))){
        S3FS_PRN_ERR("could not set mtime and ctime to file(%s): result=%d", path, result);
        return result;
    }

    if(max_dirty_data != -1 && ent->BytesModified() >= max_dirty_data){
        int flushres;
        if(0 != (flushres = ent->RowFlush(static_cast<int>(fi->fh), path, true))){
            S3FS_PRN_ERR("could not upload file(%s): result=%d", path, flushres);

            // remove stat cache
            StatCache::getStatCacheData()->DelStat(path);
            return flushres;
        }
        // Punch a hole in the file to recover disk space.
        if(!ent->PunchHole()){
            S3FS_PRN_WARN("could not punching HOLEs to a cache file, but continue.");
        }
    }

    return static_cast<int>(res);
}

static int s3fs_statfs(const char* _path, struct statvfs* stbuf)
{
    // WTF8_ENCODE(path)
    stbuf->f_bsize   = s3fs_block_size;
    stbuf->f_namemax = NAME_MAX;

#ifdef __MSYS__
    // WinFsp resolves the free space from f_bfree * f_frsize, and the total space from f_blocks * f_frsize (in bytes).
    stbuf->f_blocks = bucket_block_count;
    stbuf->f_frsize = stbuf->f_bsize;
    stbuf->f_bfree  = stbuf->f_blocks;
#elif defined(__APPLE__)
    stbuf->f_blocks = bucket_block_count;
    stbuf->f_frsize = stbuf->f_bsize;
    stbuf->f_bfree  = stbuf->f_blocks;
    stbuf->f_files  = UINT32_MAX;
    stbuf->f_ffree  = UINT32_MAX;
    stbuf->f_favail = UINT32_MAX;
#else
    stbuf->f_frsize = stbuf->f_bsize;
    stbuf->f_blocks = bucket_block_count;
    stbuf->f_bfree  = stbuf->f_blocks;
#endif
    stbuf->f_bavail = stbuf->f_blocks;

    return 0;
}

static int s3fs_flush(const char* _path, struct fuse_file_info* fi)
{
    WTF8_ENCODE(path)
    int result;

    FUSE_CTX_INFO("[path=%s][pseudo_fd=%llu]", path, (unsigned long long)(fi->fh));

    int mask = (O_RDONLY != (fi->flags & O_ACCMODE) ? W_OK : R_OK);
    if(0 != (result = check_parent_object_access(path, X_OK))){
        return result;
    }
    result = check_object_access(path, mask, nullptr);
    if(-ENOENT == result){
        if(0 != (result = check_parent_object_access(path, W_OK))){
            return result;
        }
    }else if(0 != result){
        return result;
    }

    AutoFdEntity autoent;
    FdEntity*    ent;
    if(nullptr != (ent = autoent.GetExistFdEntity(path, static_cast<int>(fi->fh)))){
        bool is_new_file = ent->IsDirtyNewFile();

        if(0 == (result = ent->Flush(static_cast<int>(fi->fh), false))){
            // [NOTE]
            // If there is any meta information that needs to be updated, update it now.
            // If waiting until s3fs_release is called, problems may occur if reading the
            // meta information of the target path during that period.
            // (This case is found in macos + nomultipart mode)
            //
            if(0 != (result = ent->UploadPending(static_cast<int>(fi->fh)))){
                S3FS_PRN_ERR("could not upload pending data(meta, etc) for pseudo_fd(%llu) / path(%s) by result=%d, but continue...", (unsigned long long)(fi->fh), path, result);
                return result;
            }
        }

        //
        // Cache only stat structures to stat cache
        //
        std::string strpath = path;
        struct stat stbuf   = {};
        if(!nocopyapi && ent->GetStatsFromMeta(stbuf) && StatCache::getStatCacheData()->AddStat(strpath, stbuf, objtype_t::FILE)){
            S3FS_PRN_DBG("Updated stats(without meta) cache(path=%s) from internal meta header in fdentity.", path);
        }else{
            S3FS_PRN_DBG("Could not cache only stat structures, so the stat cache(path=%s) will be deleted.", path);
            StatCache::getStatCacheData()->DelStat(strpath);
        }

        if(is_new_file){
            // update parent directory timestamp
            int update_result;
            if(0 != (update_result = update_mctime_parent_directory(path))){
                S3FS_PRN_ERR("succeed to create the file(%s), but could not update timestamp of its parent directory(result=%d).", path, update_result);
            }
        }
    }

    return result;
}

// [NOTICE]
// Assumption is a valid fd.
//
static int s3fs_fsync(const char* _path, int datasync, struct fuse_file_info* fi)
{
    WTF8_ENCODE(path)
    int result = 0;

    FUSE_CTX_INFO("[path=%s][datasync=%d][pseudo_fd=%llu]", path, datasync, (unsigned long long)(fi->fh));

    AutoFdEntity autoent;
    FdEntity*    ent;
    if(nullptr != (ent = autoent.GetExistFdEntity(path, static_cast<int>(fi->fh)))){
        bool is_new_file = ent->IsDirtyNewFile();

        result = ent->Flush(static_cast<int>(fi->fh), false);

        if(0 != datasync){
            // [NOTE]
            // The metadata are not updated when fdatasync is called.
            // Instead of it, these metadata are pended and set the dirty flag here.
            // Setting this flag allows metadata to be updated even if there is no
            // content update between the fdatasync call and the flush call.
            //
            ent->MarkDirtyMetadata();
        }

        if(is_new_file){
            // update parent directory timestamp
            int update_result;
            if(0 != (update_result = update_mctime_parent_directory(path))){
                S3FS_PRN_ERR("succeed to create the file(%s), but could not update timestamp of its parent directory(result=%d).", path, update_result);
            }
        }
    }

    // Issue 320: Delete stat cache entry because st_size may have changed.
    StatCache::getStatCacheData()->DelStat(path);

    return result;
}

static int s3fs_release(const char* _path, struct fuse_file_info* fi)
{
    WTF8_ENCODE(path)
    FUSE_CTX_INFO("[path=%s][pseudo_fd=%llu]", path, (unsigned long long)(fi->fh));

    {   // scope for AutoFdEntity
        AutoFdEntity autoent;

        // [NOTE]
        // The pseudo fd stored in fi->fh is attached to AutoFdEntry so that it can be
        // destroyed here.
        //
        FdEntity* ent;
        if(nullptr == (ent = autoent.Attach(path, static_cast<int>(fi->fh)))){
            S3FS_PRN_ERR("could not find pseudo_fd(%llu) for path(%s)", (unsigned long long)(fi->fh), path);
            return -EIO;
        }

        // [NOTE]
        // There are cases when s3fs_flush is not called and s3fs_release is called.
        // (There have been reported cases where it is not called when exported as NFS.)
        // Therefore, Flush() is called here to try to upload the data.
        // Flush() will only perform an upload if the file has been updated.
        //
        int result;
        if(ent->IsModified()){
            if(0 != (result = ent->Flush(static_cast<int>(fi->fh), false))){
                S3FS_PRN_ERR("failed to upload file contents for pseudo_fd(%llu) / path(%s) by result(%d)", (unsigned long long)(fi->fh), path, result);
                return result;
            }
        }

        // [NOTE]
        // All opened file's stats is cached with no truncate flag.
        // Thus we unset it here.
        //
        std::string strpath = path;
        StatCache::getStatCacheData()->ClearNoTruncateFlag(strpath);

        // [NOTICE]
        // At first, we remove stats cache.
        // Because fuse does not wait for response from "release" function. :-(
        // And fuse runs next command before this function returns.
        // Thus we call updating or deleting stats function ASAP.
        //
        if((fi->flags & O_RDWR) || (fi->flags & O_WRONLY)){
            //
            // Cache only stat structures to stat cache
            //
            struct stat stbuf = {};
            if(!nocopyapi && ent->GetStatsFromMeta(stbuf) && StatCache::getStatCacheData()->AddStat(strpath, stbuf, objtype_t::FILE)){
                S3FS_PRN_DBG("Updated stats(without meta) cache(path=%s) from internal meta header in fdentity.", path);
            }else{
                S3FS_PRN_DBG("Could not cache only stat structures, so the stat cache(path=%s) will be deleted.", path);
                StatCache::getStatCacheData()->DelStat(strpath);
            }
        }

        bool is_new_file = ent->IsDirtyNewFile();

        if(ent->HaveUploadPending()){
            if(0 != (result = ent->UploadPending(static_cast<int>(fi->fh)))){
                S3FS_PRN_ERR("could not upload pending data(meta, etc) for pseudo_fd(%llu) / path(%s)", (unsigned long long)(fi->fh), path);
                return result;
            }

            // If updated, cache only stat structures to stat cache again.
            struct stat stbuf = {};
            if(!nocopyapi && ent->GetStatsFromMeta(stbuf) && StatCache::getStatCacheData()->AddStat(strpath, stbuf, objtype_t::FILE)){
                S3FS_PRN_DBG("Updated stats(without meta) cache(path=%s) from internal meta header in fdentity.", path);
            }else{
                S3FS_PRN_ERR("Could not get current stats(path=%s) from internal meta header in fdentity. So remove stat cache.", path);
                StatCache::getStatCacheData()->DelStat(strpath);
            }
        }

        if(is_new_file){
            // update parent directory timestamp
            int update_result;
            if(0 != (update_result = update_mctime_parent_directory(path))){
                S3FS_PRN_ERR("succeed to create the file(%s), but could not update timestamp of its parent directory(result=%d).", path, update_result);
            }
        }
    }

    // check - for debug
    if(S3fsLog::IsS3fsLogDbg()){
        if(FdManager::HasOpenEntityFd(path)){
            S3FS_PRN_DBG("file(%s) is still opened(another pseudo fd is opened).", path);
        }
    }

    return 0;
}

static int s3fs_opendir(const char* _path, struct fuse_file_info* fi)
{
    WTF8_ENCODE(path)
    int result;
    int mask = (O_RDONLY != (fi->flags & O_ACCMODE) ? W_OK : R_OK);

    FUSE_CTX_INFO("[path=%s][flags=0x%x]", path, fi->flags);

    if(0 == (result = check_object_access(path, mask, nullptr))){
        result = check_parent_object_access(path, X_OK);
    }

    return result;
}

// [NOTE]
// strpath must end with '/'.
//
static int readdir_multi_head(const std::string& strpath, const S3ObjList& head, void* buf, fuse_fill_dir_t filler)
{
    S3FS_PRN_INFO1("[path=%s][head=<%s>][filler=%p]", strpath.c_str(), head.IsEmpty() ? "empty" : "not empty", filler);

    // Make base path list.
    s3obj_type_map_t headmap;
    head.GetNameMap(headmap, true, false);                                          // get name with "/".

    // [NOTE]
    // If there are leaf paths that only exist in the Stat Cache,
    // they will be merged here.
    // This means that for newly created file, the Stat Cache(NoTruncate)
    // will exist before the actual file is uploaded.
    //
    if(!StatCache::getStatCacheData()->GetChildStatMap(strpath, headmap)){
        S3FS_PRN_ERR("failed get child leaf list[path=%s], but continue...", strpath.c_str());
    }

    // Initialize SyncFiller object
    SyncFiller syncfiller(buf, filler);

    // common variables
    Semaphore    multi_head_sem(0);
    int          req_count  = 0;
    int          req_result = 0;
    int          retrycount = 0;
    std::mutex   thparam_lock;
    s3obj_list_t notfound_list;

    // Make single head request(with max).
    for(auto iter = headmap.cbegin(); headmap.cend() != iter; ++iter){
        std::string disppath = strpath + iter->first;
        std::string etag     = head.GetETag(iter->first.c_str());
        struct stat st;

        // [NOTE]
        // If there is a cache hit, file stat is filled by filler at here.
        //
        if(StatCache::getStatCacheData()->GetStat(disppath, &st, etag.c_str())){
            std::string bpath = mybasename(disppath);
            if(use_wtf8){
                bpath = s3fs_wtf8_decode(bpath);
            }
            syncfiller.Fill(bpath, &st, 0);
            continue;
        }

        // set one head request
        int result;
        if(0 != (result = multi_head_request(disppath, syncfiller, thparam_lock, retrycount, notfound_list, use_wtf8, iter->second, req_result, multi_head_sem))){
            return result;
        }
        ++req_count;
    }

    // wait for finish all requests
    while(req_count > 0){
        multi_head_sem.acquire();
        --req_count;
    }

    // print messages
    if(0 != req_result){
        S3FS_PRN_DBG("Some head requests returned error, first error is %d.", req_result);
    }

    // [NOTE]
    // Objects that could not be found by HEAD request may exist only
    // as a path, so search for objects under that path.(a case of no dir object)
    //
    if(!support_compat_dir){
        syncfiller.SufficiencyFill(head.GetCommonPrefixes());
    }
    if(support_compat_dir && !notfound_list.empty()){      // [NOTE] not need to lock to access this here.
        // dummy header
        mode_t dirmask = umask(0);      // macos does not have getumask()
        umask(dirmask);

        headers_t   dummy_header;
        dummy_header["Content-Type"]     = "application/x-directory";          // directory
        dummy_header["x-amz-meta-uid"]   = std::to_string(is_s3fs_uid ? s3fs_uid : geteuid());
        dummy_header["x-amz-meta-gid"]   = std::to_string(is_s3fs_gid ? s3fs_gid : getegid());
        dummy_header["x-amz-meta-mode"]  = std::to_string(S_IFDIR | (~dirmask & (S_IRWXU | S_IRWXG | S_IRWXO)));
        dummy_header["x-amz-meta-atime"] = "0";
        dummy_header["x-amz-meta-ctime"] = "0";
        dummy_header["x-amz-meta-mtime"] = "0";

        for(auto reiter = notfound_list.cbegin(); reiter != notfound_list.cend(); ++reiter){
            int dir_result;
            const std::string& dirpath = *reiter;
            if(-ENOTEMPTY == (dir_result = directory_empty(dirpath.c_str()))){
                // Found objects under the path, so the path is directory.
                std::string bpath = mybasename(dirpath);
                if(use_wtf8){
                    bpath = s3fs_wtf8_decode(bpath);
                }

                // Set stat structure
                struct stat st;
                if(!convert_header_to_stat(dirpath, dummy_header, st, true)){       // forcedir=true
                    S3FS_PRN_ERR("failed convert headers to stat[path=%s], so fill empty stat.", dirpath.c_str());
                    syncfiller.Fill(bpath, nullptr, 0);
                }else{
                    // Add stat cache
                    if(StatCache::getStatCacheData()->AddStat(dirpath, st, dummy_header, objtype_t::DIR_NOT_EXIST_OBJECT, false)){
                        S3FS_PRN_ERR("failed adding stat cache [path=%s], so fill empty stat.", dirpath.c_str());
                        syncfiller.Fill(bpath, nullptr, 0);
                    }else{
                        syncfiller.Fill(bpath, &st, 0);
                    }
                }
            }else{
                S3FS_PRN_WARN("%s object does not have any object under it(errno=%d),", reiter->c_str(), dir_result);
            }
        }
    }
    return 0;
}

#if FUSE_USE_VERSION >= 30
static int s3fs_readdir(const char* _path, void* buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info* info, enum fuse_readdir_flags)
#else
static int s3fs_readdir(const char* _path, void* buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info* info)
#endif
{
    WTF8_ENCODE(path)
    S3ObjList head;
    int result;

    FUSE_CTX_INFO("[path=%s]", path);

    if(0 != (result = check_object_access(path, R_OK, nullptr))){
        return result;
    }

    // check s3objlist in cache
    if(!StatCache::getStatCacheData()->GetS3ObjList(path, head)){
        // get a list of all the objects
        if((result = list_bucket(path, head, "/")) != 0){
            S3FS_PRN_ERR("list_bucket returns error(%d).", result);
            return result;
        }

        if(!StatCache::getStatCacheData()->AddS3ObjList(path, head)){
            S3FS_PRN_WARN("failed to add s3objlist for %s, but continue...", path);
        }
    }

    // force to add "." and ".." name.
#if FUSE_USE_VERSION >= 30
    filler(buf, ".", nullptr, 0, S3FS_FUSE_FILL_DIR_DEFAULTS);
    filler(buf, "..", nullptr, 0, S3FS_FUSE_FILL_DIR_DEFAULTS);
#else
    filler(buf, ".", nullptr, 0);
    filler(buf, "..", nullptr, 0);
#endif
    if(head.IsEmpty()){
        return 0;
    }

    // Send multi head request for stats caching.
    std::string strpath = path;
    if(strcmp(path, "/") != 0){
        strpath += "/";
    }
    if(0 != (result = readdir_multi_head(strpath, head, buf, filler))){
        S3FS_PRN_ERR("readdir_multi_head returns error(%d).", result);
    }

    return result;
}

static int list_bucket(const char* path, S3ObjList& head, const char* delimiter, bool check_content_only)
{
    std::string s3_realpath;
    std::string query_delimiter;
    std::string query_prefix;
    std::string query_maxkey;
    std::string next_continuation_token;
    std::string next_marker;
    bool truncated = true;

    S3FS_PRN_INFO1("[path=%s]", path);

    if(delimiter && 0 < strlen(delimiter)){
        query_delimiter += "delimiter=";
        query_delimiter += delimiter;
        query_delimiter += "&";
    }

    query_prefix += "&prefix=";
    s3_realpath = get_realpath(path);
    if(s3_realpath.empty() || '/' != *s3_realpath.rbegin()){
        // last word must be "/"
        query_prefix += urlEncodePath(s3_realpath.substr(1) + "/");
    }else{
        query_prefix += urlEncodePath(s3_realpath.substr(1));
    }
    if (check_content_only){
        // Just need to know if there are child objects in dir
        // For dir with children, expect "dir/" and "dir/child"
        query_maxkey += "max-keys=2";
    }else{
        query_maxkey += "max-keys=" + std::to_string(max_keys_list_object);
    }

    while(truncated){
        int         result;
        std::string each_query;
        std::string responseBody;

        // append parameters to query in alphabetical order
        if(!next_continuation_token.empty()){
            each_query             += "continuation-token=" + urlEncodePath(next_continuation_token) + "&";
            next_continuation_token = "";
        }
        each_query += query_delimiter;
        if(S3fsCurl::IsListObjectsV2()){
            each_query += "list-type=2&";
        }
        if(!next_marker.empty()){
            each_query += "marker=" + urlEncodePath(next_marker) + "&";
            next_marker = "";
        }
        each_query += query_maxkey;
        each_query += query_prefix;

        // send request
        if(0 != (result = list_bucket_request(SAFESTRPTR(path), each_query, responseBody))){
            return result;
        }

        // [NOTE]
        // CR code(\r) is replaced with LF(\n) by xmlReadMemory() function.
        // To prevent that, only CR code is encoded by following function.
        // The encoded CR code is decoded with append_objects_from_xml(_ex).
        //
        std::string encbody = get_encoded_cr_code(responseBody.c_str());

        // [NOTE]
        // If encbody is empty, xmlReadMemory will output the message
        // ":1: parser error : Document is empty" to stderr.
        // Make sure encbody is not empty beforehand.
        //
        if(encbody.empty()){
            S3FS_PRN_ERR("The data length passed to xmlReadMemory is 0.");
            return -EIO;
        }

        // xmlDocPtr
        s3fsXmlBufferParserError parserError;
        parserError.SetXmlParseError();

        std::unique_ptr<xmlDoc, decltype(&xmlFreeDoc)> doc(xmlReadMemory(encbody.c_str(), static_cast<int>(encbody.size()), "", nullptr, 0), xmlFreeDoc);
        if(nullptr == doc){
            if(parserError.IsXmlParseError()){
                S3FS_PRN_ERR("xmlReadMemory returns with error: %s", parserError.GetXmlParseError().c_str());
            }else{
                S3FS_PRN_ERR("xmlReadMemory returns with error.");
            }
            return -EIO;
        }
        if(0 != append_objects_from_xml(path, doc.get(), head)){
            S3FS_PRN_ERR("append_objects_from_xml returns with error.");
            return -EIO;
        }
        if(true == (truncated = is_truncated(doc.get()))){
            auto tmpch = get_next_continuation_token(doc.get());
            if(nullptr != tmpch){
                next_continuation_token = reinterpret_cast<const char*>(tmpch.get());
            }else if(nullptr != (tmpch = get_next_marker(doc.get()))){
                next_marker = reinterpret_cast<const char*>(tmpch.get());
            }

            if(next_continuation_token.empty() && next_marker.empty()){
                // If did not specify "delimiter", s3 did not return "NextMarker".
                // On this case, can use last name for next marker.
                //
                std::string lastname;
                if(!head.GetLastName(lastname)){
                    S3FS_PRN_WARN("Could not find next marker, thus break loop.");
                    truncated = false;
                }else{
                    next_marker = s3_realpath.substr(1);
                    if(s3_realpath.empty() || '/' != *s3_realpath.rbegin()){
                        next_marker += "/";
                    }
                    next_marker += lastname;
                }
            }
        }

        if(check_content_only){
            break;
        }
    }

    return 0;
}

static int remote_mountpath_exists(const char* path, bool compat_dir)
{
    struct stat stbuf;
    int result;

    S3FS_PRN_INFO1("[path=%s]", path);

    // getattr will prefix the path with the remote mountpoint
    if(0 != (result = get_object_attribute(path, &stbuf, nullptr))){
        return result;
    }

    // [NOTE]
    // If there is no mount point(directory object) that s3fs can recognize,
    // an error will occur.
    // A mount point with a directory path(ex. "<bucket>/<directory>...")
    // requires that directory object.
    // If the directory or object is created by a client other than s3fs,
    // s3fs may not be able to recognize it. If you specify such a directory
    // as a mount point, you can avoid the error by starting with "compat_dir"
    // specified.
    //
    if(!compat_dir && !has_mp_stat){
        return -ENOENT;
    }
    return 0;
}

static bool get_meta_xattr_value(const char* path, std::string& rawvalue)
{
    if(!path || '\0' == path[0]){
        S3FS_PRN_ERR("path is empty.");
        return false;
    }
    S3FS_PRN_DBG("[path=%s]", path);

    rawvalue.clear();

    headers_t meta;
    if(0 != get_object_attribute(path, nullptr, &meta)){
        S3FS_PRN_ERR("Failed to get object(%s) headers", path);
        return false;
    }

    headers_t::const_iterator iter;
    if(meta.cend() == (iter = meta.find("x-amz-meta-xattr"))){
        return false;
    }
    rawvalue = iter->second;
    return true;
}

static bool get_parent_meta_xattr_value(const char* path, std::string& rawvalue)
{
    if(0 == strcmp(path, "/") || 0 == strcmp(path, ".")){
        // path is mount point, thus does not have parent.
        return false;
    }

    std::string parent = mydirname(path);
    if(parent.empty()){
        S3FS_PRN_ERR("Could not get parent path for %s.", path);
        return false;
    }
    return get_meta_xattr_value(parent.c_str(), rawvalue);
}

static bool get_xattr_posix_key_value(const char* path, std::string& xattrvalue, bool default_key)
{
    xattrvalue.clear();

    std::string rawvalue;
    if(!get_meta_xattr_value(path, rawvalue)){
        return false;
    }

    xattrs_t xattrs;
    if(0 == parse_xattrs(rawvalue, xattrs)){
        return false;
    }

    std::string targetkey;
    if(default_key){
        targetkey = "system.posix_acl_default";
    }else{
        targetkey = "system.posix_acl_access";
    }

    xattrs_t::iterator iter;
    if(xattrs.cend() == (iter = xattrs.find(targetkey))){
        return false;
    }

    // convert value by base64
    xattrvalue = s3fs_base64(reinterpret_cast<const unsigned char*>(iter->second.c_str()), iter->second.length());

    return true;
}

// [NOTE]
// Converts and returns the POSIX ACL default(system.posix_acl_default) value of
// the parent directory as a POSIX ACL(system.posix_acl_access) value.
// Returns false if the parent directory has no POSIX ACL defaults.
//
static bool build_inherited_xattr_value(const char* path, std::string& xattrvalue)
{
    S3FS_PRN_DBG("[path=%s]", path);

    xattrvalue.clear();

    if(0 == strcmp(path, "/") || 0 == strcmp(path, ".")){
        // path is mount point, thus does not have parent.
        return false;
    }

    std::string parent = mydirname(path);
    if(parent.empty()){
        S3FS_PRN_ERR("Could not get parent path for %s.", path);
        return false;
    }

    // get parent's "system.posix_acl_default" value(base64'd).
    std::string parent_default_value;
    if(!get_xattr_posix_key_value(parent.c_str(), parent_default_value, true)){
        return false;
    }

    // build "system.posix_acl_access" from parent's default value
    std::string raw_xattr_value;
    raw_xattr_value  = "{\"system.posix_acl_access\":\"";
    raw_xattr_value += parent_default_value;
    raw_xattr_value += "\"}";

    xattrvalue = urlEncodePath(raw_xattr_value);
    return true;
}

static bool parse_xattr_keyval(const std::string& xattrpair, std::string& key, std::string* pval)
{
    // parse key and value
    size_t pos;
    std::string tmpval;
    if(std::string::npos == (pos = xattrpair.find_first_of(':'))){
        S3FS_PRN_ERR("one of xattr pair(%s) is wrong format.", xattrpair.c_str());
        return false;
    }
    key    = xattrpair.substr(0, pos);
    tmpval = xattrpair.substr(pos + 1);

    if(!takeout_str_dquart(key) || !takeout_str_dquart(tmpval)){
        S3FS_PRN_ERR("one of xattr pair(%s) is wrong format.", xattrpair.c_str());
        return false;
    }

    *pval = s3fs_decode64(tmpval.c_str(), tmpval.size());

    return true;
}

static size_t parse_xattrs(const std::string& strxattrs, xattrs_t& xattrs)
{
    xattrs.clear();

    // decode
    std::string jsonxattrs = urlDecode(strxattrs);

    // get from "{" to "}"
    std::string restxattrs;
    {
        size_t startpos;
        size_t endpos = std::string::npos;
        if(std::string::npos != (startpos = jsonxattrs.find_first_of('{'))){
            endpos = jsonxattrs.find_last_of('}');
        }
        if(startpos == std::string::npos || endpos == std::string::npos || endpos <= startpos){
            S3FS_PRN_WARN("xattr header(%s) is not json format.", jsonxattrs.c_str());
            return 0;
        }
        restxattrs = jsonxattrs.substr(startpos + 1, endpos - (startpos + 1));
    }

    // parse each key:val
    for(size_t pair_nextpos = restxattrs.find_first_of(','); !restxattrs.empty(); restxattrs = (pair_nextpos != std::string::npos ? restxattrs.substr(pair_nextpos + 1) : ""), pair_nextpos = restxattrs.find_first_of(',')){
        std::string pair = pair_nextpos != std::string::npos ? restxattrs.substr(0, pair_nextpos) : restxattrs;
        std::string key;
        std::string val;
        if(!parse_xattr_keyval(pair, key, &val)){
            // something format error, so skip this.
            continue;
        }
        xattrs[key] = val;
    }
    return xattrs.size();
}

static std::string raw_build_xattrs(const xattrs_t& xattrs)
{
    std::string strxattrs;
    bool        is_set = false;
    for(auto iter = xattrs.cbegin(); iter != xattrs.cend(); ++iter){
        if(is_set){
            strxattrs += ',';
        }else{
            is_set    = true;
            strxattrs = "{";
        }
        strxattrs += '\"';
        strxattrs += iter->first;
        strxattrs += "\":\"";
        strxattrs += s3fs_base64(reinterpret_cast<const unsigned char*>(iter->second.c_str()), iter->second.length());
        strxattrs += '\"';
    }
    if(is_set){
        strxattrs += "}";
    }
    return strxattrs;
}

static std::string build_xattrs(const xattrs_t& xattrs)
{
    std::string strxattrs = raw_build_xattrs(xattrs);
    if(strxattrs.empty()){
        strxattrs = "{}";
    }
    strxattrs = urlEncodePath(strxattrs);

    return strxattrs;
}

static int set_xattrs_to_header(headers_t& meta, const char* name, const char* value, size_t size, int flags)
{
    std::string strxattrs;
    xattrs_t xattrs;

    headers_t::iterator iter;
    if(meta.cend() == (iter = meta.find("x-amz-meta-xattr"))){
#ifdef XATTR_REPLACE
        if(XATTR_REPLACE == (flags & XATTR_REPLACE)){
            // there is no xattr header but flags is replace, so failure.
            return -ENOATTR;
        }
#endif
    }else{
#ifdef XATTR_CREATE
        if(XATTR_CREATE == (flags & XATTR_CREATE)){
            // found xattr header but flags is only creating, so failure.
            return -EEXIST;
        }
#endif
      strxattrs = iter->second;
    }

    // get map as xattrs_t
    parse_xattrs(strxattrs, xattrs);

    // add name(do not care overwrite and empty name/value)
    xattrs[name] = std::string(value, size);

    // build new strxattrs(not encoded) and set it to headers_t
    meta["x-amz-meta-xattr"] = build_xattrs(xattrs);

    S3FS_PRN_DBG("Set xattrs(after adding %s key) = %s", name, raw_build_xattrs(xattrs).c_str());

    return 0;
}

#ifdef __APPLE__
static int s3fs_setxattr(const char* _path, const char* name, const char* value, size_t size, int flags, uint32_t position)
#else
static int s3fs_setxattr(const char* _path, const char* name, const char* value, size_t size, int flags)
#endif
{
    if(!value && 0 < size){
        S3FS_PRN_ERR("Wrong parameter: value(%p), size(%zu)", value, size);
        return 0;
    }

#ifdef __APPLE__
    if(position != 0){
        // No resource fork support
        return -EINVAL;
    }
#endif

    WTF8_ENCODE(path)
    int         result;
    std::string curpath;
    std::string normpath;
    headers_t   meta;
    struct stat stbuf;
    struct stat newstbuf;
    objtype_t   ObjType = objtype_t::UNKNOWN;

    FUSE_CTX_INFO("[path=%s][name=%s][value=%p][size=%zu][flags=0x%x]", path, name, value, size, flags);

    if(0 != (result = check_parent_object_access(path, X_OK))){
        return result;
    }
    if(0 != (result = check_object_owner(path, &stbuf))){
        return result;
    }

    if(S_ISDIR(stbuf.st_mode)){
        result = chk_dir_object_type(path, normpath, curpath, &meta, &ObjType);
    }else{
        curpath  = path;
        normpath = curpath;
        result   = get_object_attribute(curpath.c_str(), nullptr, &meta);
    }
    if(0 != result){
        return result;
    }

    if(S_ISDIR(stbuf.st_mode) && (NEED_REPLACEDIR_OBJ(ObjType) || IS_CREATE_MP_STAT(normpath.c_str()))){
        if(NEED_REPLACEDIR_OBJ(ObjType)){
            // Should rebuild directory object(except new type)
            // Need to remove old dir("dir" etc) and make new dir("dir/")

            // At first, remove directory old object
            if(0 != (result = remove_old_type_dir(curpath, ObjType))){
                return result;
            }
        }

        // Make new directory object("dir/")
        struct timespec ts_atime;
        struct timespec ts_mtime;
        struct timespec ts_ctime;
        set_stat_to_timespec(stbuf, stat_time_type::ATIME, ts_atime);
        set_stat_to_timespec(stbuf, stat_time_type::MTIME, ts_mtime);
        set_stat_to_timespec(stbuf, stat_time_type::CTIME, ts_ctime);

        if(0 != (result = create_directory_object(normpath.c_str(), stbuf.st_mode, ts_atime, ts_mtime, ts_ctime, stbuf.st_uid, stbuf.st_gid, nullptr, &newstbuf))){
            return result;
        }

        // Add only stat structure to stat cache
        if(!StatCache::getStatCacheData()->AddStat(normpath, newstbuf, objtype_t::DIR_NORMAL)){
            S3FS_PRN_ERR("succeed to set xattrs directory(%s), but could not add stat cache. So remove stat cache.", normpath.c_str());
            StatCache::getStatCacheData()->DelStat(normpath);
        }

        // need to set xattr header for directory.
        curpath  = normpath;
    }

    // set xattr all object
    std::string strSourcePath              = (mount_prefix.empty() && "/" == curpath) ? "//" : curpath;
    headers_t   updatemeta;
    updatemeta["x-amz-meta-ctime"]         = s3fs_str_realtime();
    updatemeta["x-amz-copy-source"]        = urlEncodePath(service_path + S3fsCred::GetBucket() + get_realpath(strSourcePath.c_str()));
    updatemeta["x-amz-metadata-directive"] = "REPLACE";

    // check opened file handle.
    //
    // If the file starts uploading by multipart when the disk capacity is insufficient,
    // we need to put these header after finishing upload.
    // Or if the file is only open, we must update to FdEntity's internal meta.
    //
    AutoFdEntity autoent;
    FdEntity*    ent;
    bool         need_put_header = true;
    if(nullptr != (ent = autoent.OpenExistFdEntity(curpath.c_str()))){
        // get xattr and make new xattr
        std::string strxattr;
        if(ent->GetXattr(strxattr)){
            updatemeta["x-amz-meta-xattr"] = strxattr;
        }else{
            // [NOTE]
            // Set an empty xattr.
            // This requires the key to be present in order to add xattr.
            ent->SetXattr(strxattr);
        }
        // cppcheck-suppress unmatchedSuppression
        // cppcheck-suppress knownConditionTrueFalse
        if(0 != (result = set_xattrs_to_header(updatemeta, name, value, size, flags))){
            return result;
        }

        if(ent->MergeOrgMeta(updatemeta)){
            // meta is changed, but now uploading.
            // then the meta is pending and accumulated to be put after the upload is complete.
            S3FS_PRN_INFO("meta pending until upload is complete");
            need_put_header = false;

            // get current entity's meta headers
            if(!ent->GetOrgMeta(meta)){
                S3FS_PRN_ERR("failed get original meta from fd entity object");
                return -EIO;
            }

            // set stat structure
            if(!convert_header_to_stat(curpath, meta, stbuf, false)){
                S3FS_PRN_ERR("failed convert headers to stat[path=%s]", curpath.c_str());
                return -EIO;
            }

            // update cache(if exists)
            if(!StatCache::getStatCacheData()->UpdateStat(curpath, stbuf, meta)){
                // maybe cache is not found, so add new cache

                // check object type(if UNKNOWN, to symbolic link or file)
                if(is_symlink_fmt(meta)){
                    ObjType = objtype_t::SYMLINK;
                }else if(is_reg_fmt(meta)){
                    ObjType = objtype_t::FILE;
                }
                if(!StatCache::getStatCacheData()->AddStat(curpath, stbuf, meta, ObjType, true)){     // [NOTICE] notruncate = true
                    S3FS_PRN_ERR("failed add new stat cache [path=%s]", curpath.c_str());
                    return -EIO;
                }
            }
        }
    }
    if(need_put_header){
        // not found opened file.
        // cppcheck-suppress unmatchedSuppression
        // cppcheck-suppress knownConditionTrueFalse
        if(0 != (result = set_xattrs_to_header(meta, name, value, size, flags))){
            return result;
        }
        merge_headers(meta, updatemeta, true);

        // upload meta directly.
        if(0 != (result = put_headers(curpath.c_str(), meta, true))){
            return result;
        }

        // Add only stat structure to stat cache
        if(convert_header_to_stat(curpath, meta, newstbuf)){
            ObjType = derive_object_type(curpath, meta, objtype_t::FILE);
            if(!StatCache::getStatCacheData()->AddStat(curpath, newstbuf, ObjType)){
                S3FS_PRN_ERR("succeed to set xattrs for %s, but could not add stat cache. So remove stat cache.", curpath.c_str());
                StatCache::getStatCacheData()->DelStat(curpath);
            }
        }else{
            S3FS_PRN_ERR("failed convert headers to stat[path=%s]. So remove stat cache.", curpath.c_str());
            StatCache::getStatCacheData()->DelStat(curpath);
        }
    }
    return 0;
}

#ifdef __APPLE__
static int s3fs_getxattr(const char* path, const char* name, char* value, size_t size, uint32_t position)
#else
static int s3fs_getxattr(const char* path, const char* name, char* value, size_t size)
#endif
{
    FUSE_CTX_DBG("[path=%s][name=%s][value=%p][size=%zu]", path, name, value, size);

    if(!path || !name){
        return -EIO;
    }

#ifdef __APPLE__
    if (position != 0) {
        // No resource fork support
        return -EINVAL;
    }
#endif

    int       result;
    headers_t meta;
    xattrs_t  xattrs;

    // check parent directory attribute.
    if(0 != (result = check_parent_object_access(path, X_OK))){
        return result;
    }

    // get headers
    if(0 != (result = get_object_attribute(path, nullptr, &meta))){
        return result;
    }

    // get xattrs
    auto hiter = meta.find("x-amz-meta-xattr");
    if(meta.cend() == hiter){
        // object does not have xattrs
        return -ENOATTR;
    }
    const auto& strxattrs = hiter->second;

    parse_xattrs(strxattrs, xattrs);

    // search name
    std::string strname = name;
    auto xiter = xattrs.find(strname);
    if(xattrs.cend() == xiter){
        // not found name in xattrs
        return -ENOATTR;
    }

    // decode
    size_t      length = xiter->second.length();
    const char* pvalue = xiter->second.c_str();

    if(0 < size){
        if(size < length){
            // over buffer size
            return -ERANGE;
        }
        if(pvalue){
            memcpy(value, pvalue, length);
        }
    }

    return static_cast<int>(length);
}

static int s3fs_listxattr(const char* path, char* list, size_t size)
{
    S3FS_PRN_INFO("[path=%s][list=%p][size=%zu]", path, list, size);

    if(!path){
        return -EIO;
    }

    int       result;
    headers_t meta;
    xattrs_t  xattrs;

    // check parent directory attribute.
    if(0 != (result = check_parent_object_access(path, X_OK))){
        return result;
    }

    // get headers
    if(0 != (result = get_object_attribute(path, nullptr, &meta))){
        return result;
    }

    // get xattrs
    headers_t::iterator iter;
    if(meta.cend() == (iter = meta.find("x-amz-meta-xattr"))){
        // object does not have xattrs
        return 0;
    }
    const auto& strxattrs = iter->second;

    parse_xattrs(strxattrs, xattrs);

    S3FS_PRN_DBG("Get xattrs = %s", raw_build_xattrs(xattrs).c_str());

    // calculate total name length
    size_t total = 0;
    for(auto xiter = xattrs.cbegin(); xiter != xattrs.cend(); ++xiter){
        if(!xiter->first.empty()){
            total += xiter->first.length() + 1;
        }
    }

    if(0 == total){
        return 0;
    }

    // check parameters
    if(0 == size){
        return static_cast<int>(total);
    }
    if(!list || size < total){
        return -ERANGE;
    }

    // copy to list
    char* setpos = list;
    for(auto xiter = xattrs.cbegin(); xiter != xattrs.cend(); ++xiter){
        if(!xiter->first.empty()){
            strcpy(setpos, xiter->first.c_str());
            setpos = &setpos[strlen(setpos) + 1];
        }
    }

    return static_cast<int>(total);
}

static int s3fs_removexattr(const char* _path, const char* name)
{
    if(!_path || !name){
        return -EIO;
    }

    WTF8_ENCODE(path)
    int         result;
    std::string curpath;
    std::string normpath;
    headers_t   meta;
    xattrs_t    xattrs;
    struct stat stbuf;
    struct stat newstbuf;
    objtype_t   ObjType = objtype_t::UNKNOWN;

    FUSE_CTX_INFO("[path=%s][name=%s]", path, name);

    if(0 == strcmp(path, "/")){
        S3FS_PRN_ERR("Could not change mode for mount point.");
        return -EIO;
    }
    if(0 != (result = check_parent_object_access(path, X_OK))){
        return result;
    }
    if(0 != (result = check_object_owner(path, &stbuf))){
        return result;
    }

    if(S_ISDIR(stbuf.st_mode)){
        result = chk_dir_object_type(path, normpath, curpath, &meta, &ObjType);
    }else{
        curpath  = path;
        normpath = curpath;
        result   = get_object_attribute(curpath.c_str(), nullptr, &meta);
    }
    if(0 != result){
        return result;
    }

    // get xattrs
    auto hiter = meta.find("x-amz-meta-xattr");
    if(meta.cend() == hiter){
        // object does not have xattrs
        return -ENOATTR;
    }
    const auto& strxattrs = hiter->second;

    parse_xattrs(strxattrs, xattrs);

    // check name xattrs
    std::string strname = name;
    auto xiter = xattrs.find(strname);
    if(xattrs.cend() == xiter){
        return -ENOATTR;
    }

    // make new header_t after deleting name xattr
    xattrs.erase(xiter);

    S3FS_PRN_DBG("Reset xattrs(after delete %s key) = %s", name, raw_build_xattrs(xattrs).c_str());

    if(S_ISDIR(stbuf.st_mode) && (NEED_REPLACEDIR_OBJ(ObjType) || IS_CREATE_MP_STAT(normpath.c_str()))){
        // Should rebuild directory object(except new type)
        // Need to remove old dir("dir" etc) and make new dir("dir/")

        // At first, remove directory old object
        if(0 != (result = remove_old_type_dir(curpath, ObjType))){
            return result;
        }

        // Make new directory object("dir/")
        struct timespec ts_atime;
        struct timespec ts_mtime;
        struct timespec ts_ctime;
        set_stat_to_timespec(stbuf, stat_time_type::ATIME, ts_atime);
        set_stat_to_timespec(stbuf, stat_time_type::MTIME, ts_mtime);
        set_stat_to_timespec(stbuf, stat_time_type::CTIME, ts_ctime);

        if(0 != (result = create_directory_object(normpath.c_str(), stbuf.st_mode, ts_atime, ts_mtime, ts_ctime, stbuf.st_uid, stbuf.st_gid, nullptr, &newstbuf))){
            return result;
        }

        // Add only stat structure to stat cache
        if(!StatCache::getStatCacheData()->AddStat(normpath, newstbuf, objtype_t::DIR_NORMAL)){
            S3FS_PRN_ERR("succeed to remove xattrs directory(%s), but could not add stat cache. So remove stat cache.", normpath.c_str());
            StatCache::getStatCacheData()->DelStat(normpath);
        }

        // need to set xattr header for directory.
        curpath  = normpath;
    }

    // set xattr all object
    std::string strSourcePath              = (mount_prefix.empty() && "/" == curpath) ? "//" : curpath;
    headers_t   updatemeta;
    updatemeta["x-amz-copy-source"]        = urlEncodePath(service_path + S3fsCred::GetBucket() + get_realpath(strSourcePath.c_str()));
    updatemeta["x-amz-metadata-directive"] = "REPLACE";
    if(!xattrs.empty()){
        updatemeta["x-amz-meta-xattr"]     = build_xattrs(xattrs);
    }else{
        updatemeta["x-amz-meta-xattr"]     = "";      // This is a special case. If empty, this header will eventually be removed.
    }

    // check opened file handle.
    //
    // If the file starts uploading by multipart when the disk capacity is insufficient,
    // we need to put these header after finishing upload.
    // Or if the file is only open, we must update to FdEntity's internal meta.
    //
    AutoFdEntity autoent;
    FdEntity*    ent;
    bool         need_put_header = true;
    if(nullptr != (ent = autoent.OpenExistFdEntity(curpath.c_str()))){
        if(ent->MergeOrgMeta(updatemeta)){
            // meta is changed, but now uploading.
            //
            // [NOTE]
            // Then the meta is pending and accumulated to be put after the upload is complete.
            // If there is no need to hold it, need_put_header will remain true.
            // Please note that if "x-amz-meta-xattr" in updatemeta is empty, it will be deleted
            // by ent->MergeOrgMeta.
            //
            S3FS_PRN_INFO("meta pending until upload is complete");
            need_put_header = false;

            // get current entity's meta headers
            if(!ent->GetOrgMeta(meta)){
                S3FS_PRN_ERR("failed get original meta from fd entity object");
                return -EIO;
            }

            // set stat structure
            if(!convert_header_to_stat(curpath, meta, stbuf, false)){
                S3FS_PRN_ERR("failed convert headers to stat[path=%s]", curpath.c_str());
                return -EIO;
            }

            // update cache(if exists)
            if(!StatCache::getStatCacheData()->UpdateStat(curpath, stbuf, meta)){
                // maybe cache is not found, so add new cache

                // check object type(if UNKNOWN, to symbolic link or file)
                if(is_symlink_fmt(meta)){
                    ObjType = objtype_t::SYMLINK;
                }else if(is_reg_fmt(meta)){
                    ObjType = objtype_t::FILE;
                }
                if(!StatCache::getStatCacheData()->AddStat(curpath, stbuf, meta, ObjType, true)){     // [NOTICE] notruncate = true
                    S3FS_PRN_ERR("failed add new stat cache [path=%s]", curpath.c_str());
                    return -EIO;
                }
            }
        }
    }
    if(need_put_header){
        // not found opened file or not have pending meta
        //
        // [NOTE]
        // If "x-amz-meta-xattr" exists in updatemeta but its value is empty,
        // this key will be deleted here.
        // After that, if the "x-amz-meta-xattr" key does not exist,
        // "x-amz-meta-xattr" will also be deleted from meta.
        //
        // Please note that ent->MergeOrgMeta() may be called before this
        // process. In ent->MergeOrgMeta(), if "x-amz-meta-xattr" exists in
        // updatemeta but its value is empty, it will be deleted first.
        //
        auto iter = updatemeta.find("x-amz-meta-xattr");
        if(iter != updatemeta.end() && iter->second.empty()){
            updatemeta.erase(iter);
        }
        if(updatemeta.end() == updatemeta.find("x-amz-meta-xattr")){
            auto miter = meta.find("x-amz-meta-xattr");
            if(miter != meta.end()){
                meta.erase(miter);
            }
        }
        merge_headers(meta, updatemeta, true);

        // upload meta directly.
        if(0 != (result = put_headers(curpath.c_str(), meta, true))){
            return result;
        }

        // Add only stat structure to stat cache
        if(convert_header_to_stat(curpath, meta, newstbuf)){
            ObjType = derive_object_type(curpath, meta, objtype_t::FILE);
            if(!StatCache::getStatCacheData()->AddStat(curpath, newstbuf, ObjType)){
                S3FS_PRN_ERR("succeed to remove xattrs for %s, but could not add stat cache. So remove stat cache.", curpath.c_str());
                StatCache::getStatCacheData()->DelStat(curpath);
            }
        }else{
            S3FS_PRN_ERR("failed convert headers to stat[path=%s]. So remove stat cache.", curpath.c_str());
            StatCache::getStatCacheData()->DelStat(curpath);
        }
    }
    return 0;
}

// s3fs_init calls this function to exit cleanly from the fuse event loop.
//
// There's no way to pass an exit status to the high-level event loop API, so 
// this function stores the exit value in a global for main()
static void s3fs_exit_fuseloop(int exit_status)
{
      S3FS_PRN_ERR("Exiting FUSE event loop due to errors\n");
      s3fs_init_deferred_exit_status = exit_status;
      struct fuse_context *ctx = fuse_get_context();
      if (nullptr != ctx) {
            fuse_exit(ctx->fuse);
      }
}

#if FUSE_USE_VERSION >= 30
static void* s3fs_init(struct fuse_conn_info* conn, fuse_config* config)
#else
static void* s3fs_init(struct fuse_conn_info* conn)
#endif
{
    S3FS_PRN_INIT_INFO("init v%s%s with %s, credential-library(%s)", VERSION, COMMIT_HASH_VAL, s3fs_crypt_lib_name(), ps3fscred->GetCredFuncVersion(false));

    // cache(remove cache dirs at first)
    if(is_remove_cache && (!CacheFileStat::DeleteCacheFileStatDirectory() || !FdManager::DeleteCacheDirectory())){
        S3FS_PRN_DBG("Could not initialize cache directory.");
    }

    if(!ThreadPoolMan::Initialize()){
        S3FS_PRN_CRIT("Could not create thread pool(%d)", ThreadPoolMan::GetWorkerCount());
        s3fs_exit_fuseloop(EXIT_FAILURE);
    }

    // check loading IAM role name
    if(!ps3fscred->LoadIAMRoleFromMetaData()){
        S3FS_PRN_CRIT("could not load IAM role name from meta data.");
        s3fs_exit_fuseloop(EXIT_FAILURE);
        return nullptr;
    }

    // Check Bucket
    {
        int result;
        if(EXIT_SUCCESS != (result = s3fs_check_service())){
            s3fs_exit_fuseloop(result);
            return nullptr;
        }
    }

    // Investigate system capabilities
    #ifndef __APPLE__
    if(conn->capable & FUSE_CAP_ATOMIC_O_TRUNC){
         conn->want |= FUSE_CAP_ATOMIC_O_TRUNC;
    }
    #endif

#if FUSE_USE_VERSION < 30
    if(conn->capable & FUSE_CAP_BIG_WRITES){
         conn->want |= FUSE_CAP_BIG_WRITES;
    }
#endif

    // Signal object
    if(!S3fsSignals::Initialize()){
        S3FS_PRN_ERR("Failed to initialize signal object, but continue...");
    }

    return nullptr;
}

static void s3fs_destroy(void*)
{
    S3FS_PRN_INFO("destroy");

    // Signal object
    if(!S3fsSignals::Destroy()){
        S3FS_PRN_WARN("Failed to clean up signal object.");
    }

    ThreadPoolMan::Destroy();

    // cache(remove at last)
    if(is_remove_cache && (!CacheFileStat::DeleteCacheFileStatDirectory() || !FdManager::DeleteCacheDirectory())){
        S3FS_PRN_WARN("Could not remove cache directory.");
    }
}

static int s3fs_access(const char* path, int mask)
{
    FUSE_CTX_INFO("[path=%s][mask=%s%s%s%s]", path,
            ((mask & R_OK) == R_OK) ? "R_OK " : "",
            ((mask & W_OK) == W_OK) ? "W_OK " : "",
            ((mask & X_OK) == X_OK) ? "X_OK " : "",
            (mask == F_OK) ? "F_OK" : "");

    int result = check_object_access(path, mask, nullptr);
    return result;
}

//
// If calling with wrong region, s3fs gets following error body as 400 error code.
// "<Error>
//    <Code>AuthorizationHeaderMalformed</Code>
//    <Message>The authorization header is malformed; the region 'us-east-1' is wrong; expecting 'ap-northeast-1'</Message>
//    <Region>ap-northeast-1</Region>
//    <RequestId>...</RequestId>
//    <HostId>...</HostId>
//  </Error>"
//
// So this is cheap code but s3fs should get correct region automatically.
//
static bool check_region_error(const char* pbody, size_t len, std::string& expectregion)
{
    if(!pbody){
        return false;
    }

    std::string code;
    if(!simple_parse_xml(pbody, len, "Code", code) || code != "AuthorizationHeaderMalformed"){
        return false;
    }

    if(!simple_parse_xml(pbody, len, "Region", expectregion)){
        return false;
    }

    return true;
}

//
// Checks whether an invalid access error that cannot be retried has occurred.
// This is determined by the combination of the following response codes and the
// <Code> in the response body:
//    [Response code]    [Code string]
//    400                InvalidToken
//                       ExpiredToken
//    403                AccessDenied
//                       RequestTimeTooSkewed
//                       SignatureDoesNotMatch
//                       InvalidAccessKeyId
// ex) InvalidAccessKeyId
//       "<Error>
//          <Code>InvalidAccessKeyId</Code>
//          <Message>The AWS Access Key Id you provided does not exist in our records.</Message>
//          <AWSAccessKeyId>...</AWSAccessKeyId>
//          <RequestId>...</RequestId>
//          <HostId>...</HostId>
//        </Error>"
//
static bool check_invalid_access(long responseCode, const char* pbody, size_t len, std::string& strErrorCode)
{
    constexpr std::array<const char*, 2> strErrCodes400 = {"InvalidToken", "ExpiredToken"};
    constexpr std::array<const char*, 4> strErrCodes403 = {"AccessDenied", "RequestTimeTooSkewed", "SignatureDoesNotMatch", "InvalidAccessKeyId"};

    if(!pbody){
        return false;
    }
    if(!simple_parse_xml(pbody, len, "Code", strErrorCode)){
        return false;
    }

    if(400 == responseCode){
        for(const auto& strTgCode: strErrCodes400){
            if(strErrorCode == strTgCode){
                return true;
            }
        }
    }else if(403 == responseCode){
        for(const auto& strTgCode: strErrCodes403){
            if(strErrorCode == strTgCode){
                return true;
            }
        }
    }
    return false;
}

static bool check_endpoint_error(const char* pbody, size_t len, std::string& expectendpoint)
{
    if(!pbody){
        return false;
    }

    std::string code;
    if(!simple_parse_xml(pbody, len, "Code", code) || code != "PermanentRedirect"){
        return false;
    }

    if(!simple_parse_xml(pbody, len, "Endpoint", expectendpoint)){
        return false;
    }

    return true;
}

static bool check_invalid_sse_arg_error(const char* pbody, size_t len)
{
    if(!pbody){
        return false;
    }

    std::string code;
    if(!simple_parse_xml(pbody, len, "Code", code) || code != "InvalidArgument"){
        return false;
    }
    std::string argname;
    if(!simple_parse_xml(pbody, len, "ArgumentName", argname) || argname != "x-amz-server-side-encryption"){
        return false;
    }
    return true;
}

static bool check_error_message(const char* pbody, size_t len, std::string& message)
{
    message.clear();
    if(!pbody){
        return false;
    }
    if(!simple_parse_xml(pbody, len, "Message", message)){
        return false;
    }
    return true;
}

// [NOTE]
// This function checks if the bucket is accessible when s3fs starts.
//
// The following patterns for mount points are supported by s3fs:
// (1) Mount the bucket top
// (2) Mount to a directory(folder) under the bucket. In this case:
//     (2A) Directories created by clients other than s3fs
//     (2B) Directory created by s3fs
//
// Both case of (1) and (2) check access permissions to the mount point
// path(directory).
// In the case of (2A), if the directory(object) for the mount point does
// not exist, the check fails. However, launching s3fs with the "compat_dir"
// option avoids this error and the check succeeds. If you do not specify
// the "compat_dir" option in case (2A), please create a directory(object)
// for the mount point before launching s3fs.
//
static int s3fs_check_service()
{
    S3FS_PRN_INFO("check services.");

    // At first time for access S3, we check IAM role if it sets.
    if(!ps3fscred->CheckIAMCredentialUpdate()){
        S3FS_PRN_CRIT("Failed to initialize IAM credential.");
        return EXIT_FAILURE;
    }

    bool forceNoSSE = false;        // it is not mandatory at first.

    for(bool isLoop = true; isLoop; ){
        long        responseCode = S3fsCurl::S3FSCURL_RESPONSECODE_NOTSET;
        std::string responseBody;
        if(0 > check_service_request(get_realpath("/"), forceNoSSE, support_compat_dir, responseCode, responseBody)){
            // check wrong region, and automatically switch region
            if(300 <= responseCode && responseCode < 500){
                // check region error(for putting message or retrying)
                std::string expectregion;
                std::string expectendpoint;
                std::string invalidAccessCode;

                // Check if any case can be retried
                if(check_region_error(responseBody.c_str(), responseBody.size(), expectregion)){
                    // [NOTE]
                    // If region is not specified(using us-east-1 region) and
                    // an error is encountered accessing a different region, we
                    // will retry the check on the expected region.
                    // see) https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingBucket.html#access-bucket-intro
                    //
                    if(s3host != "http://s3.amazonaws.com" && s3host != "https://s3.amazonaws.com"){
                        // specified region for specified url is wrong.
                        if(is_region_specified){
                            S3FS_PRN_CRIT("The bucket region is not '%s'(specified) for specified url(%s), it is correctly '%s'. You should specify url(http(s)://s3-%s.amazonaws.com) and region(%s) option.", region.c_str(), s3host.c_str(), expectregion.c_str(), expectregion.c_str(), expectregion.c_str());
                        }else{
                            S3FS_PRN_CRIT("The bucket region is not '%s'(default) for specified url(%s), it is correctly '%s'. You should specify url(http(s)://s3-%s.amazonaws.com) and region(%s) option.", region.c_str(), s3host.c_str(), expectregion.c_str(), expectregion.c_str(), expectregion.c_str());
                        }
                        isLoop = false;

                    }else if(is_region_specified){
                        // specified region is wrong.
                        S3FS_PRN_CRIT("The bucket region is not '%s'(specified), it is correctly '%s'. You should specify region(%s) option.", region.c_str(), expectregion.c_str(), expectregion.c_str());
                        isLoop = false;

                    }else if(S3fsCurl::GetSignatureType() == signature_type_t::V4_ONLY || S3fsCurl::GetSignatureType() == signature_type_t::V2_OR_V4){
                        // current region and url are default value, so try to connect to expected region.
                        S3FS_PRN_CRIT("Failed to connect region '%s'(default), so retry to connect region '%s' for url(http(s)://s3-%s.amazonaws.com).", region.c_str(), expectregion.c_str(), expectregion.c_str());

                        // change region
                        region = expectregion;

                        // change url
                        if(s3host == "http://s3.amazonaws.com"){
                            s3host = "http://s3-" + region + ".amazonaws.com";
                        }else if(s3host == "https://s3.amazonaws.com"){
                            s3host = "https://s3-" + region + ".amazonaws.com";
                        }

                    }else{
                        S3FS_PRN_CRIT("The bucket region is not '%s'(default), it is correctly '%s'. You should specify region(%s) option.", region.c_str(), expectregion.c_str(), expectregion.c_str());
                        isLoop = false;
                    }

                }else if(check_invalid_access(responseCode, responseBody.c_str(), responseBody.size(), invalidAccessCode)){
                    // Invalid Access error
                    S3FS_PRN_CRIT("Received '%s' error from the S3 service. Please check and resolve the cause of this error and try again.", invalidAccessCode.c_str());
                    return EXIT_FAILURE;

                }else if(check_endpoint_error(responseBody.c_str(), responseBody.size(), expectendpoint)){
                    // redirect error
                    if(pathrequeststyle){
                        S3FS_PRN_CRIT("S3 service returned PermanentRedirect (current is url(%s) and region(%s)). You need to specify correct url(http(s)://s3-<region>.amazonaws.com) and region option with use_path_request_style option.", s3host.c_str(), region.c_str());
                    }else{
                        S3FS_PRN_CRIT("S3 service returned PermanentRedirect with %s (current is url(%s) and region(%s)). You need to specify correct region option.", expectendpoint.c_str(), s3host.c_str(), region.c_str());
                    }
                    return EXIT_FAILURE;

                }else if(check_invalid_sse_arg_error(responseBody.c_str(), responseBody.size())){
                    // SSE argument error, so retry it without SSE
                    S3FS_PRN_CRIT("S3 service returned InvalidArgument(x-amz-server-side-encryption), so retry without adding x-amz-server-side-encryption.");

                    // Retry without sse parameters
                    forceNoSSE = true;
                }

            }else if(S3fsCurl::S3FSCURL_RESPONSECODE_FATAL_ERROR == responseCode){
                // Curl error cases(ex, about SSL)
                isLoop = false;
            }

            // Try changing signature from v4 to v2
            //
            // [NOTE]
            // If there is no case to retry with the previous checks, and there
            // is a chance to retry with signature v2, prepare to retry with v2.
            //
            if(!isLoop && (responseCode == 400 || responseCode == 403) && S3fsCurl::GetSignatureType() == signature_type_t::V2_OR_V4){
                // switch sigv2
                S3FS_PRN_CRIT("Failed to connect by sigv4, so retry to connect by signature version 2. But you should to review url and region option.");

                // retry to check with sigv2
                isLoop = true;
                S3fsCurl::SetSignatureType(signature_type_t::V2_ONLY);
            }

            // check errors(after retrying)
            if(!isLoop && responseCode != 200 && responseCode != 301){
                if(S3fsCurl::S3FSCURL_RESPONSECODE_FATAL_ERROR == responseCode){
                    S3FS_PRN_CRIT("Failed to check bucket and directory for mount point : (host=%s, message=\"%s\")", s3host.c_str(), responseBody.c_str());
                }else{
                    // parse error message if existed
                    std::string errMessage;
                    check_error_message(responseBody.c_str(), responseBody.size(), errMessage);

                    if(responseCode == 400){
                        S3FS_PRN_CRIT("Failed to check bucket and directory for mount point : Bad Request(host=%s, message=%s)", s3host.c_str(), errMessage.c_str());
                    }else if(responseCode == 403){
                        S3FS_PRN_CRIT("Failed to check bucket and directory for mount point : Invalid Credentials(host=%s, message=%s)", s3host.c_str(), errMessage.c_str());
                    }else if(responseCode == 404){
                        if(mount_prefix.empty()){
                            S3FS_PRN_CRIT("Failed to check bucket and directory for mount point : Bucket or directory not found(host=%s, message=%s)", s3host.c_str(), errMessage.c_str());
                        }else{
                            S3FS_PRN_CRIT("Failed to check bucket and directory for mount point : Bucket or directory(%s) not found(host=%s, message=%s) - You may need to specify the compat_dir option.", mount_prefix.c_str(), s3host.c_str(), errMessage.c_str());
                        }
                    }else{
                        S3FS_PRN_CRIT("Failed to check bucket and directory for mount point : Unable to connect(host=%s, message=%s)", s3host.c_str(), errMessage.c_str());
                    }
                }
                return EXIT_FAILURE;
            }
        }else{
            // break loop
            isLoop = false;
        }
    }

    // make sure remote mountpath exists and is a directory
    if(!mount_prefix.empty()){
        if(remote_mountpath_exists("/", support_compat_dir) != 0){
            S3FS_PRN_CRIT("Remote mountpath %s not found, this may be resolved with the compat_dir option.", mount_prefix.c_str());
            return EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;
}

//
// Check & Set attributes for mount point.
//
static bool set_mountpoint_attribute(struct stat& mpst)
{
    mp_uid  = geteuid();
    mp_gid  = getegid();
    mp_mode = S_IFDIR | (allow_other ? (is_mp_umask ? (~mp_umask & (S_IRWXU | S_IRWXG | S_IRWXO)) : (S_IRWXU | S_IRWXG | S_IRWXO)) : S_IRWXU);

// In MSYS2 environment with WinFsp, it is not supported to change mode of mount point.
// Doing that forcibly will create a permission problem, so disabling it.
#ifdef __MSYS__
    return true;
#else
    S3FS_PRN_INFO2("PROC(uid=%u, gid=%u) - MountPoint(uid=%u, gid=%u, mode=%04o)",
           (unsigned int)mp_uid, (unsigned int)mp_gid, (unsigned int)(mpst.st_uid), (unsigned int)(mpst.st_gid), mpst.st_mode);

    // check owner
    if(0 == mp_uid || mpst.st_uid == mp_uid){
        return true;
    }
    // check group permission
    if(mpst.st_gid == mp_gid || 1 == is_uid_include_group(mp_uid, mpst.st_gid)){
        if(S_IRWXG == (mpst.st_mode & S_IRWXG)){
            return true;
        }
    }
    // check other permission
    if(S_IRWXO == (mpst.st_mode & S_IRWXO)){
        return true;
    }
    return false;
#endif
}

//
// Set bucket and mount_prefix based on passed bucket name.
//
static int set_bucket(const std::string& arg)
{
    size_t pos;
    if((pos = arg.find(':')) != std::string::npos){
        if(arg.find("://") != std::string::npos){
            S3FS_PRN_EXIT("bucket name and path(\"%s\") is wrong, it must be \"bucket[:/path]\".", arg.c_str());
            return -1;
        }
        std::string bucket_name = arg.substr(0, pos);
        if(!S3fsCred::SetBucket(bucket_name)){
            S3FS_PRN_EXIT("bucket name and path(\"%s\") is wrong, it must be \"bucket[:/path]\".", arg.c_str());
            return -1;
        }

        std::string pmount_prefix = arg.substr(pos + 1);
        if(pmount_prefix.empty() || '/' != pmount_prefix[0]){
            S3FS_PRN_EXIT("path(%s) must be prefix \"/\".", pmount_prefix.c_str());
            return -1;
        }
        mount_prefix = pmount_prefix;
        // Trim the last consecutive '/'
        mount_prefix = trim_right(mount_prefix, "/");
    }else{
        if(!S3fsCred::SetBucket(arg)){
            S3FS_PRN_EXIT("bucket name and path(\"%s\") is wrong, it must be \"bucket[:/path]\".", arg.c_str());
            return -1;
        }
    }
    return 0;
}

//
// Utility function for parse "--bucket_size" option
//
// max_size: A string like 20000000, 30GiB, 20TB etc
// return:   An integer of type fsblkcnt_t corresponding to the number
//           of blocks with max_size calculated with the s3fs block size,
//           or 0 on error
//
static fsblkcnt_t parse_bucket_size(std::string max_size)
{
    const unsigned long long ten00   = 1000L;
    const unsigned long long ten24   = 1024L;
    unsigned long long       scale   = 1;
    unsigned long long       n_bytes = 0;
    size_t pos;

    if((pos = max_size.find("GB")) != std::string::npos){
        scale = ten00 * ten00 * ten00;
        if(2 < max_size.size() - pos){
            return 0;   // no trailing garbage
        }
        max_size.erase(pos);
    }else if((pos = max_size.find("GiB")) != std::string::npos){
        scale = ten24 * ten24 * ten24;
        if(3 < max_size.size() - pos){
            return 0;   // no trailing garbage
        }
        max_size.erase(pos);
    }else if((pos = max_size.find("TB")) != std::string::npos){
        scale = ten00 * ten00 * ten00 * ten00;
        if(2 < max_size.size() - pos){
            return 0;   // no trailing garbage
        }
        max_size.erase(pos);
    }else if((pos = max_size.find("TiB")) != std::string::npos){
        scale = ten24 * ten24 * ten24 * ten24;
        if(3 < max_size.size() - pos){
            return 0;   // no trailing garbage
        }
        max_size.erase(pos);
    }else if((pos = max_size.find("PB")) != std::string::npos){
        scale = ten00 * ten00 * ten00 * ten00 * ten00;
        if(2 < max_size.size() - pos){
            return 0;   // no trailing garbage
        }
        max_size.erase(pos);
    }else if((pos = max_size.find("PiB")) != std::string::npos){
        scale = ten24 * ten24 * ten24 * ten24 * ten24;
        if(3 < max_size.size() - pos){
            return 0;   // no trailing garbage
        }
        max_size.erase(pos);
    }else if((pos = max_size.find("EB")) != std::string::npos){
        scale = ten00 * ten00 * ten00 * ten00 * ten00 * ten00;
        if(2 < max_size.size() - pos){
            return 0;   // no trailing garbage
        }
        max_size.erase(pos);
    }else if((pos = max_size.find("EiB")) != std::string::npos){
        scale = ten24 * ten24 * ten24 * ten24 * ten24 * ten24;
        if(3 < max_size.size() - pos){
            return 0;   // no trailing garbage
        }
        max_size.erase(pos);
    }

    // extra check
    for(size_t i = 0; i < pos; ++i){
        if(!isdigit(max_size[i])){
            return 0;   // wrong number
        }
        n_bytes = strtoull(max_size.c_str(), nullptr, 10);
        if((INT64_MAX / scale) < n_bytes){
            return 0;   // overflow
        }
        n_bytes *= scale;
    }

    // [NOTE]
    // To round a number by s3fs block size.
    // And need to check the result value because fsblkcnt_t is 32bit in macos etc.
    //
    n_bytes /= s3fs_block_size;

    if(sizeof(fsblkcnt_t) <= 4){
        if(INT32_MAX < n_bytes){
            return 0;   // overflow
        }
    }
    return static_cast<fsblkcnt_t>(n_bytes);    // cast to fsblkcnt_t
}

static bool is_cmd_exists(const std::string& command)
{
    // The `command -v` is a POSIX-compliant method for checking the existence of a program.
    std::string cmd = "command -v " + command + " >/dev/null 2>&1";
    int result = system(cmd.c_str());
    return (result !=-1 && WIFEXITED(result) && WEXITSTATUS(result) == 0);
}

static int print_umount_message(const std::string& mp, bool force)
{
    std::string cmd;
    if (is_cmd_exists("fusermount")){
        if (force){
            cmd = "fusermount -uz " + mp;
        } else {
            cmd = "fusermount -u " + mp;
        }
    }else{
        if (force){
            cmd = "umount -l " + mp;
        } else {
            cmd = "umount " + mp;
        }
    }

    S3FS_PRN_EXIT("MOUNTPOINT %s is stale, you could use this command to fix: %s", mp.c_str(), cmd.c_str());

    return 0;
}

// This is repeatedly called by the fuse option parser
// if the key is equal to FUSE_OPT_KEY_OPT, it's an option passed in prefixed by 
// '-' or '--' e.g.: -f -d -ousecache=/tmp
//
// if the key is equal to FUSE_OPT_KEY_NONOPT, it's either the bucket name 
//  or the mountpoint. The bucket name will always come before the mountpoint
//
static int my_fuse_opt_proc(void* data, const char* arg, int key, struct fuse_args* outargs)
{
    int ret;
    if(key == FUSE_OPT_KEY_NONOPT){
        // the first NONOPT option is the bucket name
        if(S3fsCred::GetBucket().empty()){
            if ((ret = set_bucket(arg)) != 0){
                return ret;
            }
            return 0;
        }else if (!strcmp(arg, "s3fs")) {
            return 0;
        }

        // the second NONOPT option is the mountpoint(not utility mode)
        if(mountpoint.empty() && utility_incomp_type::NO_UTILITY_MODE == utility_mode){
            // save the mountpoint and do some basic error checking
            mountpoint = arg;
            struct stat stbuf;

// In MSYS2 environment with WinFsp, it is not needed to create the mount point before mounting.
// Also it causes a conflict with WinFsp's validation, so disabling it.
#ifdef __MSYS__
            stbuf = {};
            set_mountpoint_attribute(stbuf);
#else
            if(stat(arg, &stbuf) == -1){
                // check stale mountpoint
                if(errno == ENOTCONN){
                    print_umount_message(mountpoint, true);
                } else {
                    S3FS_PRN_EXIT("unable to access MOUNTPOINT %s: %s", mountpoint.c_str(), strerror(errno));
                }
                return -1;
            }
            if(!(S_ISDIR(stbuf.st_mode))){
                S3FS_PRN_EXIT("MOUNTPOINT: %s is not a directory.", mountpoint.c_str());
                return -1;
            }
            if(!set_mountpoint_attribute(stbuf)){
                S3FS_PRN_EXIT("MOUNTPOINT: %s permission denied.", mountpoint.c_str());
                return -1;
            }

#if FUSE_USE_VERSION < 30
            if(!nonempty){
                const struct dirent *ent;
                DIR *dp = opendir(mountpoint.c_str());
                if(dp == nullptr){
                    S3FS_PRN_EXIT("failed to open MOUNTPOINT: %s: %s", mountpoint.c_str(), strerror(errno));
                    return -1;
                }
                scope_guard dir_guard([dp]() {
                    if(-1 == closedir(dp)){
                        S3FS_PRN_ERR("closedir() failed for %s - errno(%d)", mountpoint.c_str(), errno);
                    }
                });

                while((ent = readdir(dp)) != nullptr){
                    if(strcmp(ent->d_name, ".") != 0 && strcmp(ent->d_name, "..") != 0){
                        S3FS_PRN_EXIT("MOUNTPOINT directory %s is not empty. if you are sure this is safe, can use the 'nonempty' mount option.", mountpoint.c_str());
                        return -1;
                    }
                }
            }
#endif
#endif
            return 1;
        }

        // Unknown option
        if(utility_incomp_type::NO_UTILITY_MODE == utility_mode){
            S3FS_PRN_EXIT("specified unknown third option(%s).", arg);
        }else{
            S3FS_PRN_EXIT("specified unknown second option(%s). you don't need to specify second option(mountpoint) for utility mode(-u).", arg);
        }
        return -1;

    }else if(key == FUSE_OPT_KEY_OPT){
        if(is_prefix(arg, "uid=")){
            s3fs_uid = get_uid(strchr(arg, '=') + sizeof(char));
            if(0 != geteuid() && 0 == s3fs_uid){
                S3FS_PRN_EXIT("root user can only specify uid=0.");
                return -1;
            }
            is_s3fs_uid = true;
            return 1; // continue for fuse option
        }
        else if(is_prefix(arg, "gid=")){
            s3fs_gid = get_gid(strchr(arg, '=') + sizeof(char));
            if(0 != getegid() && 0 == s3fs_gid){
                S3FS_PRN_EXIT("root user can only specify gid=0.");
                return -1;
            }
            is_s3fs_gid = true;
            return 1; // continue for fuse option
        }
        else if(is_prefix(arg, "bucket_size=")){
            bucket_block_count = parse_bucket_size(strchr(arg, '=') + sizeof(char));
            if(0 == bucket_block_count){
                S3FS_PRN_EXIT("invalid bucket_size option.");
                return -1;
            }
            return 0;
        }
        else if(is_prefix(arg, "umask=")){
            off_t s3fs_umask_tmp = cvt_strtoofft(strchr(arg, '=') + sizeof(char), /*base=*/ 8);
            s3fs_umask = s3fs_umask_tmp & (S_IRWXU | S_IRWXG | S_IRWXO);
            is_s3fs_umask = true;
            return 1; // continue for fuse option
        }
        else if(0 == strcmp(arg, "allow_other")){
            allow_other = true;
            return 1; // continue for fuse option
        }
        else if(is_prefix(arg, "mp_umask=")){
            off_t mp_umask_tmp = cvt_strtoofft(strchr(arg, '=') + sizeof(char), /*base=*/ 8);
            mp_umask = mp_umask_tmp & (S_IRWXU | S_IRWXG | S_IRWXO);
            is_mp_umask = true;
            return 0;
        }
        else if(is_prefix(arg, "default_acl=")){
            const char* acl_string = strchr(arg, '=') + sizeof(char);
            acl_t acl = to_acl(acl_string);
            if(acl == acl_t::UNKNOWN){
                S3FS_PRN_EXIT("unknown value for default_acl: %s", acl_string);
                return -1;
            }
            S3fsCurl::SetDefaultAcl(acl);
            return 0;
        }
        else if(is_prefix(arg, "retries=")){
            off_t retries = cvt_strtoofft(strchr(arg, '=') + sizeof(char), /*base=*/ 10);
            if(retries == 0){
                S3FS_PRN_EXIT("retries must be greater than zero");
                return -1;
            }
            S3fsCurl::SetRetries(static_cast<int>(retries));
            return 0;
        }
        else if(is_prefix(arg, "tmpdir=")){
            FdManager::SetTmpDir(strchr(arg, '=') + sizeof(char));
            return 0;
        }
        else if(is_prefix(arg, "use_cache=")){
            FdManager::SetCacheDir(strchr(arg, '=') + sizeof(char));
            return 0;
        }
        else if(0 == strcmp(arg, "check_cache_dir_exist")){
            FdManager::SetCheckCacheDirExist(true);
            return 0;
        }
        else if(0 == strcmp(arg, "del_cache")){
            is_remove_cache = true;
            return 0;
        }
#if FUSE_USE_VERSION < 30
        else if(0 == strcmp(arg, "nonempty")){
            nonempty = true;
            return 1; // need to continue for fuse.
        }
#endif
        else if(0 == strcmp(arg, "nomultipart")){
            nomultipart = true;
            return 0;
        }
        // old format for storage_class
        else if(0 == strcmp(arg, "use_rrs") || is_prefix(arg, "use_rrs=")){
            off_t rrs = 1;
            // for an old format.
            if(is_prefix(arg, "use_rrs=")){
                rrs = cvt_strtoofft(strchr(arg, '=') + sizeof(char), /*base=*/ 10);
            }
            if(0 == rrs){
                S3fsCurl::SetStorageClass("STANDARD");
            }else if(1 == rrs){
                S3fsCurl::SetStorageClass("REDUCED_REDUNDANCY");
            }else{
                S3FS_PRN_EXIT("poorly formed argument to option: use_rrs");
                return -1;
            }
            return 0;
        }
        else if(is_prefix(arg, "storage_class=")){
            const char *storage_class = strchr(arg, '=') + sizeof(char);
            S3fsCurl::SetStorageClass(storage_class);
            return 0;
        }
        //
        // [NOTE]
        // use_sse                        Set Server Side Encrypting type to SSE-S3
        // use_sse=1
        // use_sse=file                   Set Server Side Encrypting type to Custom key(SSE-C) and load custom keys
        // use_sse=custom(c):file
        // use_sse=custom(c)              Set Server Side Encrypting type to Custom key(SSE-C)
        // use_sse=kmsid(k):kms-key-id    Set Server Side Encrypting type to AWS Key Management key id(SSE-KMS) and load KMS id
        // use_sse=kmsid(k)               Set Server Side Encrypting type to AWS Key Management key id(SSE-KMS)
        //
        // load_sse_c=file                Load Server Side Encrypting custom keys
        //
        // AWSSSECKEYS                    Loading Environment for Server Side Encrypting custom keys
        // AWSSSEKMSID                    Loading Environment for Server Side Encrypting Key id
        //
        else if(is_prefix(arg, "use_sse")){
            if(0 == strcmp(arg, "use_sse") || 0 == strcmp(arg, "use_sse=1")){ // use_sse=1 is old type parameter
                // sse type is SSE_S3
                if(!S3fsCurl::IsSseDisable() && !S3fsCurl::IsSseS3Type()){
                    S3FS_PRN_EXIT("already set SSE another type, so conflict use_sse option or environment.");
                    return -1;
                }
                S3fsCurl::SetSseType(sse_type_t::SSE_S3);

            }else if(0 == strcmp(arg, "use_sse=kmsid") || 0 == strcmp(arg, "use_sse=k")){
                // sse type is SSE_KMS with out kmsid(expecting id is loaded by environment)
                if(!S3fsCurl::IsSseDisable() && !S3fsCurl::IsSseKmsType()){
                    S3FS_PRN_EXIT("already set SSE another type, so conflict use_sse option or environment.");
                    return -1;
                }
                if(!S3fsCurl::IsSetSseKmsId()){
                    S3FS_PRN_EXIT("use_sse=kms but not loaded kms id by environment.");
                    return -1;
                }
                S3fsCurl::SetSseType(sse_type_t::SSE_KMS);

            }else if(is_prefix(arg, "use_sse=kmsid:") || is_prefix(arg, "use_sse=k:")){
                // sse type is SSE_KMS with kmsid
                if(!S3fsCurl::IsSseDisable() && !S3fsCurl::IsSseKmsType()){
                    S3FS_PRN_EXIT("already set SSE another type, so conflict use_sse option or environment.");
                    return -1;
                }
                const char* kmsid;
                if(is_prefix(arg, "use_sse=kmsid:")){
                    kmsid = &arg[strlen("use_sse=kmsid:")];
                }else{
                    kmsid = &arg[strlen("use_sse=k:")];
                }
                if(!S3fsCurl::SetSseKmsid(kmsid)){
                    S3FS_PRN_EXIT("failed to load use_sse kms id.");
                    return -1;
                }
                S3fsCurl::SetSseType(sse_type_t::SSE_KMS);

            }else if(0 == strcmp(arg, "use_sse=custom") || 0 == strcmp(arg, "use_sse=c")){
                // sse type is SSE_C with out custom keys(expecting keys are loaded by environment or load_sse_c option)
                if(!S3fsCurl::IsSseDisable() && !S3fsCurl::IsSseCType()){
                    S3FS_PRN_EXIT("already set SSE another type, so conflict use_sse option or environment.");
                    return -1;
                }
                // [NOTE]
                // do not check ckeys exists here.
                //
                S3fsCurl::SetSseType(sse_type_t::SSE_C);

            }else if(is_prefix(arg, "use_sse=custom:") || is_prefix(arg, "use_sse=c:")){
                // sse type is SSE_C with custom keys
                if(!S3fsCurl::IsSseDisable() && !S3fsCurl::IsSseCType()){
                    S3FS_PRN_EXIT("already set SSE another type, so conflict use_sse option or environment.");
                    return -1;
                }
                const char* ssecfile;
                if(is_prefix(arg, "use_sse=custom:")){
                    ssecfile = &arg[strlen("use_sse=custom:")];
                }else{
                    ssecfile = &arg[strlen("use_sse=c:")];
                }
                if(!S3fsCurl::SetSseCKeys(ssecfile)){
                    S3FS_PRN_EXIT("failed to load use_sse custom key file(%s).", ssecfile);
                    return -1;
                }
                S3fsCurl::SetSseType(sse_type_t::SSE_C);

            }else if(0 == strcmp(arg, "use_sse=")){    // this type is old style(parameter is custom key file path)
                // SSE_C with custom keys.
                const char* ssecfile = &arg[strlen("use_sse=")];
                if(!S3fsCurl::SetSseCKeys(ssecfile)){
                    S3FS_PRN_EXIT("failed to load use_sse custom key file(%s).", ssecfile);
                    return -1;
                }
                S3fsCurl::SetSseType(sse_type_t::SSE_C);

            }else{
                // never come here.
                S3FS_PRN_EXIT("something wrong use_sse option.");
                return -1;
            }
            return 0;
        }
        // [NOTE]
        // Do only load SSE custom keys, care for set without set sse type.
        else if(is_prefix(arg, "load_sse_c=")){
            const char* ssecfile = &arg[strlen("load_sse_c=")];
            if(!S3fsCurl::SetSseCKeys(ssecfile)){
                S3FS_PRN_EXIT("failed to load use_sse custom key file(%s).", ssecfile);
                return -1;
            }
            return 0;
        }
        else if(is_prefix(arg, "ssl_verify_hostname=")){
            long sslvh = static_cast<long>(cvt_strtoofft(strchr(arg, '=') + sizeof(char), /*base=*/ 10));
            if(-1 == S3fsCurl::SetSslVerifyHostname(sslvh)){
                S3FS_PRN_EXIT("poorly formed argument to option: ssl_verify_hostname.");
                return -1;
            }
            return 0;
        }
        else if(is_prefix(arg, "ssl_client_cert=")){
            std::string values = strchr(arg, '=') + sizeof(char);
            if(!S3fsCurl::SetSSLClientCertOptions(values)){
                S3FS_PRN_EXIT("failed to set SSL client certification options.");
                return -1;
            }
            return 0;
        }
        //
        // Detect options for credential
        //
        else if(0 >= (ret = ps3fscred->DetectParam(arg))){
            if(0 > ret){
                return -1;
            }
            return 0;
        }
        else if(is_prefix(arg, "public_bucket=")){
            off_t pubbucket = cvt_strtoofft(strchr(arg, '=') + sizeof(char), /*base=*/ 10);
            if(1 == pubbucket){
                S3fsCurl::SetPublicBucket(true);
                // [NOTE]
                // if bucket is public(without credential), s3 do not allow copy api.
                // so s3fs sets nocopyapi mode.
                //
                nocopyapi = true;
            }else if(0 == pubbucket){
                S3fsCurl::SetPublicBucket(false);
            }else{
                S3FS_PRN_EXIT("poorly formed argument to option: public_bucket.");
                return -1;
            }
            return 0;
        }
        else if(is_prefix(arg, "bucket=")){
            std::string bname = strchr(arg, '=') + sizeof(char);
            if ((ret = set_bucket(bname))){
                return ret;
            }
            return 0;
        }
        else if(0 == strcmp(arg, "no_check_certificate")){
            S3fsCurl::SetCheckCertificate(false);
            return 0;
        }
        else if(is_prefix(arg, "connect_timeout=")){
            long contimeout = static_cast<long>(cvt_strtoofft(strchr(arg, '=') + sizeof(char), /*base=*/ 10));
            S3fsCurl::SetConnectTimeout(contimeout);
            return 0;
        }
        else if(is_prefix(arg, "readwrite_timeout=")){
            auto rwtimeout = static_cast<time_t>(cvt_strtoofft(strchr(arg, '=') + sizeof(char), /*base=*/ 10));
            S3fsCurl::SetReadwriteTimeout(rwtimeout);
            return 0;
        }
        else if(is_prefix(arg, "list_object_max_keys=")){
            int max_keys = static_cast<int>(cvt_strtoofft(strchr(arg, '=') + sizeof(char), /*base=*/ 10));
            if(max_keys < 1000){
                S3FS_PRN_EXIT("argument should be over 1000: list_object_max_keys");
                return -1;
            }
            max_keys_list_object = max_keys;
            return 0;
        }
        else if(is_prefix(arg, "max_stat_cache_size=")){
            auto cache_size = static_cast<unsigned long>(cvt_strtoofft(strchr(arg, '=') + sizeof(char), 10));
            StatCache::getStatCacheData()->SetCacheSize(cache_size);
            return 0;
        }
        else if(is_prefix(arg, "stat_cache_expire=")){
            auto expr_time = static_cast<time_t>(cvt_strtoofft(strchr(arg, '=') + sizeof(char), 10));
            StatCacheNode::SetExpireTime(expr_time);
            return 0;
        }
        // [NOTE]
        // This option is for compatibility old version.
        else if(is_prefix(arg, "stat_cache_interval_expire=")){
            auto expr_time = static_cast<time_t>(cvt_strtoofft(strchr(arg, '=') + sizeof(char), /*base=*/ 10));
            StatCacheNode::SetExpireTime(expr_time, true);
            return 0;
        }
        else if(0 == strcmp(arg, "enable_negative_cache") || 0 == strcmp(arg, "enable_noobj_cache")){
            S3FS_PRN_WARN("enable_negative_cache(enable_noobj_cache) is enabled by default and a future version will remove this option.");
            StatCacheNode::EnableNegativeCache();
            return 0;
        }
        else if(0 == strcmp(arg, "disable_negative_cache") || 0 == strcmp(arg, "disable_noobj_cache")){
            StatCacheNode::DisableNegativeCache();
            return 0;
        }
        else if(0 == strcmp(arg, "nodnscache")){
            S3fsCurlShare::SetDnsCache(false);
            return 0;
        }
        else if(0 == strcmp(arg, "nosscache")){
            S3fsCurlShare::SetSslSessionCache(false);
            return 0;
        }
        else if(is_prefix(arg, "multireq_max=") || is_prefix(arg, "parallel_count=") || is_prefix(arg, "parallel_upload=")){
            S3FS_PRN_WARN("The multireq_max, parallel_count and parallel_upload options have been deprecated and merged with max_thread_count. In the near future, these options will no longer be available. For compatibility, the values you specify for these options will be treated as max_thread_count.");

            int max_thcount = static_cast<int>(cvt_strtoofft(strchr(arg, '=') + sizeof(char), /*base=*/ 10));
            if(0 >= max_thcount){
                S3FS_PRN_EXIT("argument should be over 1: max_thread_count");
                return -1;
            }
            ThreadPoolMan::SetWorkerCount(max_thcount);
            return 0;
        }
        else if(is_prefix(arg, "max_thread_count=")){
            int max_thcount = static_cast<int>(cvt_strtoofft(strchr(arg, '=') + sizeof(char), /*base=*/ 10));
            if(0 >= max_thcount){
                S3FS_PRN_EXIT("argument should be over 1: max_thread_count");
                return -1;
            }
            ThreadPoolMan::SetWorkerCount(max_thcount);
            return 0;
        }
        else if(is_prefix(arg, "fd_page_size=")){
            S3FS_PRN_ERR("option fd_page_size is no longer supported, so skip this option.");
            return 0;
        }
        else if(is_prefix(arg, "multipart_size=")){
            off_t size = cvt_strtoofft(strchr(arg, '=') + sizeof(char), /*base=*/ 10);
            if(!S3fsCurl::SetMultipartSize(size)){
                S3FS_PRN_EXIT("multipart_size option must be at least 5 MB.");
                return -1;
            }
            return 0;
        }
        else if(is_prefix(arg, "multipart_copy_size=")){
            off_t size = cvt_strtoofft(strchr(arg, '=') + sizeof(char), /*base=*/ 10);
            if(!S3fsCurl::SetMultipartCopySize(size)){
                S3FS_PRN_EXIT("multipart_copy_size option must be at least 5 MB.");
                return -1;
            }
            return 0;
        }
        else if(is_prefix(arg, "max_dirty_data=")){
            off_t size = cvt_strtoofft(strchr(arg, '=') + sizeof(char), /*base=*/ 10);
            if(size >= 50){
                size *= 1024 * 1024;
            }else if(size != -1){
                S3FS_PRN_EXIT("max_dirty_data option must be at least 50 MB.");
                return -1;
            }
            max_dirty_data = size;
            return 0;
        }
        if(is_prefix(arg, "free_space_ratio=")){
            int ratio = static_cast<int>(cvt_strtoofft(strchr(arg, '=') + sizeof(char), /*base=*/ 10));

            if(FdManager::GetEnsureFreeDiskSpace()!=0){
                S3FS_PRN_EXIT("option free_space_ratio conflicts with ensure_diskfree, please set only one of them.");
                return -1;
            }

            if(ratio < 0 || ratio > 100){
                S3FS_PRN_EXIT("option free_space_ratio must between 0 to 100, which is: %d", ratio);
                return -1;
            }

            off_t dfsize = FdManager::GetTotalDiskSpaceByRatio(ratio);
            S3FS_PRN_INFO("Free space ratio set to %d %%, ensure the available disk space is greater than %.3f MB", ratio, static_cast<double>(dfsize) / 1024 / 1024);

            if(dfsize < S3fsCurl::GetMultipartSize()){
                S3FS_PRN_WARN("specified size to ensure disk free space is smaller than multipart size, so set multipart size to it.");
                dfsize = S3fsCurl::GetMultipartSize();
            }
            FdManager::SetEnsureFreeDiskSpace(dfsize);
            return 0;
        }
        else if(is_prefix(arg, "ensure_diskfree=")){
            off_t dfsize = cvt_strtoofft(strchr(arg, '=') + sizeof(char), /*base=*/ 10) * 1024 * 1024;

            if(FdManager::GetEnsureFreeDiskSpace()!=0){
                S3FS_PRN_EXIT("option free_space_ratio conflicts with ensure_diskfree, please set only one of them.");
                return -1;
            }

            S3FS_PRN_INFO("Set and ensure the available disk space is greater than %.3f MB.", static_cast<double>(dfsize) / 1024 / 1024);
            if(dfsize < S3fsCurl::GetMultipartSize()){
                S3FS_PRN_WARN("specified size to ensure disk free space is smaller than multipart size, so set multipart size to it.");
                dfsize = S3fsCurl::GetMultipartSize();
            }
            FdManager::SetEnsureFreeDiskSpace(dfsize);
            return 0;
        }
        else if(is_prefix(arg, "fake_diskfree=")){
            S3FS_PRN_WARN("The fake_diskfree option was specified. Use this option for testing or debugging.");

            // [NOTE] This value is used for initializing to FdManager after parsing all options.
            fake_diskfree_size = cvt_strtoofft(strchr(arg, '=') + sizeof(char), /*base=*/ 10) * 1024 * 1024;
            return 0;
        }
        else if(is_prefix(arg, "multipart_threshold=")){
            multipart_threshold = static_cast<int64_t>(cvt_strtoofft(strchr(arg, '=') + sizeof(char), /*base=*/ 10)) * 1024 * 1024;
            if(multipart_threshold <= MIN_MULTIPART_SIZE){
                S3FS_PRN_EXIT("multipart_threshold must be at least %lld, was: %lld", static_cast<long long>(MIN_MULTIPART_SIZE), static_cast<long long>(multipart_threshold));
                return -1;
            }
            return 0;
        }
        else if(is_prefix(arg, "singlepart_copy_limit=")){
            singlepart_copy_limit = static_cast<int64_t>(cvt_strtoofft(strchr(arg, '=') + sizeof(char), /*base=*/ 10)) * 1024 * 1024;
            return 0;
        }
        else if(is_prefix(arg, "ahbe_conf=")){
            std::string ahbe_conf = strchr(arg, '=') + sizeof(char);
            if(!AdditionalHeader::get()->Load(ahbe_conf.c_str())){
                S3FS_PRN_EXIT("failed to load ahbe_conf file(%s).", ahbe_conf.c_str());
                return -1;
            }
            AdditionalHeader::get()->Dump();
            return 0;
        }
        else if(0 == strcmp(arg, "noxmlns")){
            noxmlns = true;
            return 0;
        }
        else if(0 == strcmp(arg, "nomixupload")){
            FdEntity::SetNoMixMultipart();
            return 0;
        }
        else if(0 == strcmp(arg, "nocopyapi")){
            nocopyapi = true;
            return 0;
        }
        else if(0 == strcmp(arg, "streamupload")){
            FdEntity::SetStreamUpload(true);
            S3FS_PRN_WARN("The streamupload option is not a formal option. Please note that it will change in the future.");
            return 0;
        }
        else if(0 == strcmp(arg, "norenameapi")){
            norenameapi = true;
            return 0;
        }
        else if(0 == strcmp(arg, "complement_stat")){
            complement_stat = true;
            return 0;
        }
        else if(0 == strcmp(arg, "notsup_compat_dir")){
            S3FS_PRN_WARN("notsup_compat_dir is enabled by default and a future version will remove this option.");
            support_compat_dir = false;
            return 0;
        }
        else if(0 == strcmp(arg, "compat_dir")){
            support_compat_dir = true;
            return 0;
        }
        else if(0 == strcmp(arg, "enable_content_md5")){
            S3fsCurl::SetContentMd5(true);
            return 0;
        }
        else if(0 == strcmp(arg, "enable_unsigned_payload")){
            S3fsCurl::SetUnsignedPayload(true);
            return 0;
        }
        else if(0 == strcmp(arg, "update_parent_dir_stat")){
            update_parent_dir_stat = true;
            return 0;
        }
        else if(is_prefix(arg, "host=")){
            s3host = strchr(arg, '=') + sizeof(char);
            return 0;
        }
        else if(is_prefix(arg, "servicepath=")){
            service_path = strchr(arg, '=') + sizeof(char);
            return 0;
        }
        else if(is_prefix(arg, "url=")){
            s3host = strchr(arg, '=') + sizeof(char);
            // strip the trailing '/', if any, off the end of the host
            // std::string
            size_t found, length;
            found  = s3host.find_last_of('/');
            length = s3host.length();
            while(found == (length - 1) && length > 0){
                s3host.erase(found);
                found  = s3host.find_last_of('/');
                length = s3host.length();
            }
            // Check url for http / https protocol std::string
            if(!is_prefix(s3host.c_str(), "https://") && !is_prefix(s3host.c_str(), "http://")){
                S3FS_PRN_EXIT("option url has invalid format, missing http / https protocol");
                return -1;
            }
            return 0;
        }
        else if(0 == strcmp(arg, "sigv2")){
            S3fsCurl::SetSignatureType(signature_type_t::V2_ONLY);
            return 0;
        }
        else if(0 == strcmp(arg, "sigv4")){
            S3fsCurl::SetSignatureType(signature_type_t::V4_ONLY);
            return 0;
        }
        else if(is_prefix(arg, "region=") || is_prefix(arg, "endpoint=")){
            region              = strchr(arg, '=') + sizeof(char);
            is_region_specified = true;
            return 0;
        }
        else if(0 == strcmp(arg, "use_path_request_style")){
            pathrequeststyle = true;
            return 0;
        }
        else if(0 == strcmp(arg, "noua")){
            S3fsCurl::SetUserAgentFlag(false);
            return 0;
        }
        else if(0 == strcmp(arg, "listobjectsv2")){
            S3fsCurl::SetListObjectsV2(true);
            return 0;
        }
        else if(0 == strcmp(arg, "use_xattr")){
            is_use_xattr = true;
            return 0;
        }else if(is_prefix(arg, "use_xattr=")){
            const char* strflag = strchr(arg, '=') + sizeof(char);
            if(0 == strcmp(strflag, "1")){
                is_use_xattr = true;
            }else if(0 == strcmp(strflag, "0")){
                is_use_xattr = false;
            }else{
                S3FS_PRN_EXIT("option use_xattr has unknown parameter(%s).", strflag);
                return -1;
            }
            return 0;
        }
        else if(is_prefix(arg, "cipher_suites=")){
            cipher_suites = strchr(arg, '=') + sizeof(char);
            return 0;
        }
        else if(is_prefix(arg, "instance_name=")){
            instance_name = strchr(arg, '=') + sizeof(char);
            instance_name = "[" + instance_name + "]";
            return 0;
        }
        else if(is_prefix(arg, "mime=")){
            mimetype_file = strchr(arg, '=') + sizeof(char);
            return 0;
        }
        else if(is_prefix(arg, "proxy=")){
            const char* url = &arg[strlen("proxy=")];
            if(!S3fsCurl::SetProxy(url)){
                S3FS_PRN_EXIT("failed to set proxy(%s).", url);
                return -1;
            }
            return 0;
        }
        else if(is_prefix(arg, "proxy_cred_file=")){
            const char* file = &arg[strlen("proxy_cred_file=")];
            if(!S3fsCurl::SetProxyUserPwd(file)){
                S3FS_PRN_EXIT("failed to set proxy user and passphrase from file(%s).", file);
                return -1;
            }
            return 0;
        }
        else if(is_prefix(arg, "ipresolve=")){
            const char* pipresolve = &arg[strlen("ipresolve=")];
            if(!S3fsCurl::SetIPResolveType(pipresolve)){
                S3FS_PRN_EXIT("failed to ip resolve option value(%s).", pipresolve);
                return -1;
            }
            return 0;
        }
        //
        // log file option
        //
        else if(is_prefix(arg, "logfile=")){
            const char* strlogfile = strchr(arg, '=') + sizeof(char);
            if(!S3fsLog::SetLogfile(strlogfile)){
                S3FS_PRN_EXIT("The file(%s) specified by logfile option could not be opened.", strlogfile);
                return -1;
            }
            return 0;
        }
        //
        // debug level option
        //
        else if(is_prefix(arg, "dbglevel=")){
            auto strlevel = CaseInsensitiveStringView(strchr(arg, '=') + sizeof(char));
            if(strlevel == "silent" || strlevel == "critical" || strlevel == "crit"){
                S3fsLog::SetLogLevel(S3fsLog::Level::CRIT);
            }else if(strlevel == "error" || strlevel == "err"){
                S3fsLog::SetLogLevel(S3fsLog::Level::ERR);
            }else if(strlevel == "wan" || strlevel == "warn" || strlevel == "warning"){
                S3fsLog::SetLogLevel(S3fsLog::Level::WARN);
            }else if(strlevel == "inf" || strlevel == "info" || strlevel == "information"){
                S3fsLog::SetLogLevel(S3fsLog::Level::INFO);
            }else if(strlevel == "dbg" || strlevel == "debug"){
                S3fsLog::SetLogLevel(S3fsLog::Level::DBG);
            }else{
                S3FS_PRN_EXIT("option dbglevel has unknown parameter(%s).", strlevel.c_str());
                return -1;
            }
            return 0;
        }
        //
        // debug option
        //
        // S3fsLog level is INFO, after second -d is passed to fuse.
        //
        else if(0 == strcmp(arg, "-d") || 0 == strcmp(arg, "--debug")){
            if(!S3fsLog::IsS3fsLogInfo() && !S3fsLog::IsS3fsLogDbg()){
                S3fsLog::SetLogLevel(S3fsLog::Level::INFO);
                return 0;
            }
            if(0 == strcmp(arg, "--debug")){
                // fuse doesn't understand "--debug", but it understands -d.
                // but we can't pass -d back to fuse.
                return 0;
            }
        }
        //
        // insecure logging option
        //
        else if(0 == strcmp(arg, "insecure_logging")){
            insecure_logging = true;
            return 0;
        }
        // "f2" is not used no more.
        // (set S3fsLog::Level::DBG)
        else if(0 == strcmp(arg, "f2")){
            S3fsLog::SetLogLevel(S3fsLog::Level::DBG);
            return 0;
        }
        else if(0 == strcmp(arg, "curldbg")){
            S3fsCurl::SetVerbose(true);
            return 0;
        }else if(is_prefix(arg, "curldbg=")){
            auto strlevel = CaseInsensitiveStringView(strchr(arg, '=') + sizeof(char));
            if(strlevel == "normal"){
                S3fsCurl::SetVerbose(true);
            }else if(strlevel == "body"){
                S3fsCurl::SetVerbose(true);
                S3fsCurl::SetDumpBody(true);
            }else{
                S3FS_PRN_EXIT("option curldbg has unknown parameter(%s).", strlevel.c_str());
                return -1;
            }
            return 0;
        }
        //
        // no time stamp in debug message
        //
        else if(0 == strcmp(arg, "no_time_stamp_msg")){
            S3fsLog::SetTimeStamp(false);
            return 0;
        }
        //
        // Check cache file, using SIGUSR1
        //
        else if(0 == strcmp(arg, "set_check_cache_sigusr1")){
            if(!S3fsSignals::SetUsr1Handler(nullptr)){
                S3FS_PRN_EXIT("could not set sigusr1 for checking cache.");
                return -1;
            }
            return 0;
        }else if(is_prefix(arg, "set_check_cache_sigusr1=")){
            const char* strfilepath = strchr(arg, '=') + sizeof(char);
            if(!S3fsSignals::SetUsr1Handler(strfilepath)){
                S3FS_PRN_EXIT("could not set sigusr1 for checking cache and output file(%s).", strfilepath);
                return -1;
            }
            return 0;
        }
        else if(is_prefix(arg, "accessKeyId=")){
            S3FS_PRN_EXIT("option accessKeyId is no longer supported.");
            return -1;
        }
        else if(is_prefix(arg, "secretAccessKey=")){
            S3FS_PRN_EXIT("option secretAccessKey is no longer supported.");
            return -1;
        }
        else if(0 == strcmp(arg, "use_wtf8")){
            use_wtf8 = true;
            return 0;
        }
        else if(0 == strcmp(arg, "requester_pays")){
            S3fsCurl::SetRequesterPays(true);
            return 0;
        }
        // [NOTE]
        // following option will be discarding, because these are not for fuse.
        // (Referenced sshfs.c)
        //
        else if(0 == strcmp(arg, "auto")   ||
           0 == strcmp(arg, "noauto") ||
           0 == strcmp(arg, "user")   ||
           0 == strcmp(arg, "nouser") ||
           0 == strcmp(arg, "users")  ||
           0 == strcmp(arg, "_netdev"))
        {
            return 0;
        }
    }
    return 1;
}

int main(int argc, char* argv[])
{
    int ch;
    int fuse_res;
    int option_index = 0; 
    struct fuse_operations s3fs_oper{};
    time_t incomp_abort_time = (24 * 60 * 60);
    S3fsLog singletonLog;

    static constexpr struct option long_opts[] = {
        {"help",                 no_argument,       nullptr, 'h'},
        {"version",              no_argument,       nullptr, 0},
        {"debug",                no_argument,       nullptr, 'd'},
        {"incomplete-mpu-list",  no_argument,       nullptr, 'u'},
        {"incomplete-mpu-abort", optional_argument, nullptr, 'a'}, // 'a' is only identifier and is not option.
        {nullptr, 0, nullptr, 0}
    };

    // Use uint32_t instead of fsblkcnt_t::max since the latter overflows and confuses df
    bucket_block_count = std::numeric_limits<uint32_t>::max();

    // init xml2
    xmlInitParser();
    LIBXML_TEST_VERSION

    init_sysconf_vars();

    // get program name - emulate basename
    program_name = argv[0];
    size_t found = program_name.find_last_of('/');
    if(found != std::string::npos){
        program_name.replace(0, found+1, "");
    }

    // set credential object
    //
    ps3fscred = std::make_unique<S3fsCred>();
    if(!S3fsCurl::InitCredentialObject(ps3fscred.get())){
        S3FS_PRN_EXIT("Failed to setup credential object to s3fs curl.");
        exit(EXIT_FAILURE);
    }

    while((ch = getopt_long(argc, argv, "dho:fsu", long_opts, &option_index)) != -1){
        switch(ch){
            case 0:
                if(strcmp(long_opts[option_index].name, "version") == 0){
                    show_version();
                    exit(EXIT_SUCCESS);
                }
                break;
            case 'h':
                show_help();
                exit(EXIT_SUCCESS);
            case 'o':
                break;
            case 'd':
                break;
            case 'f':
                foreground = true;
                break;
            case 's':
                break;
            case 'u':   // --incomplete-mpu-list
                if(utility_incomp_type::NO_UTILITY_MODE != utility_mode){
                    S3FS_PRN_EXIT("already utility mode option is specified.");
                    exit(EXIT_FAILURE);
                }
                utility_mode = utility_incomp_type::INCOMP_TYPE_LIST;
                break;
            case 'a':   // --incomplete-mpu-abort
                if(utility_incomp_type::NO_UTILITY_MODE != utility_mode){
                    S3FS_PRN_EXIT("already utility mode option is specified.");
                    exit(EXIT_FAILURE);
                }
                utility_mode = utility_incomp_type::INCOMP_TYPE_ABORT;

                // check expire argument
                if(nullptr != optarg && 0 == strcasecmp(optarg, "all")){ // all is 0s
                    incomp_abort_time = 0;
                }else if(nullptr != optarg){
                    if(!convert_unixtime_from_option_arg(optarg, incomp_abort_time)){
                        S3FS_PRN_EXIT("--incomplete-mpu-abort option argument is wrong.");
                        exit(EXIT_FAILURE);
                    }
                }
                // if optarg is null, incomp_abort_time is 24H(default)
                break;
            default:
                exit(EXIT_FAILURE);
        }
    }

    // Load SSE environment
    if(!S3fsCurl::LoadEnvSse()){
        S3FS_PRN_EXIT("something wrong about SSE environment.");
        exit(EXIT_FAILURE);
    }

    // ssl init
    if(!s3fs_init_global_ssl()){
        S3FS_PRN_EXIT("could not initialize for ssl libraries.");
        exit(EXIT_FAILURE);
    }

    // init curl (without mime types)
    //
    // [NOTE]
    // The curl initialization here does not load mime types.
    // The mime types file parameter are dynamic values according
    // to the user's environment, and are analyzed by the my_fuse_opt_proc
    // function.
    // The my_fuse_opt_proc function is executed after this curl
    // initialization. Because the curl method is used in the
    // my_fuse_opt_proc function, then it must be called here to
    // initialize. Fortunately, the processing using mime types
    // is only PUT/POST processing, and it is not used until the
    // call of my_fuse_opt_proc function is completed. Therefore,
    // the mime type is loaded just after calling the my_fuse_opt_proc
    // function.
    // 
    if(!S3fsCurl::InitS3fsCurl()){
        S3FS_PRN_EXIT("Could not initiate curl library.");
        s3fs_destroy_global_ssl();
        exit(EXIT_FAILURE);
    }

    // This is the fuse-style parser for the arguments
    // after which the bucket name and mountpoint names
    // should have been set
    struct fuse_args custom_args = FUSE_ARGS_INIT(argc, argv);
    if(0 != fuse_opt_parse(&custom_args, nullptr, nullptr, my_fuse_opt_proc)){
        S3fsCurl::DestroyS3fsCurl();
        s3fs_destroy_global_ssl();
        exit(EXIT_FAILURE);
    }

    // print launch message
    print_launch_message(argc, argv);

    // init mime types for curl
    if(!S3fsCurl::InitMimeType(mimetype_file)){
        S3FS_PRN_WARN("Missing MIME types prevents setting Content-Type on uploaded objects.");
    }

    // [NOTE]
    // exclusive option check here.
    //
    if(strcasecmp(S3fsCurl::GetStorageClass().c_str(), "REDUCED_REDUNDANCY") == 0 && !S3fsCurl::IsSseDisable()){
        S3FS_PRN_EXIT("use_sse option could not be specified with storage class reduced_redundancy.");
        S3fsCurl::DestroyS3fsCurl();
        s3fs_destroy_global_ssl();
        exit(EXIT_FAILURE);
    }
    if(!S3fsCurl::FinalCheckSse()){
        S3FS_PRN_EXIT("something wrong about SSE options.");
        S3fsCurl::DestroyS3fsCurl();
        s3fs_destroy_global_ssl();
        exit(EXIT_FAILURE);
    }

    if(S3fsCurl::GetSignatureType() == signature_type_t::V2_ONLY && S3fsCurl::GetUnsignedPayload()){
        S3FS_PRN_WARN("Ignoring enable_unsigned_payload with sigv2");
    }

    if(!FdEntity::GetNoMixMultipart() && max_dirty_data != -1){
        S3FS_PRN_WARN("Setting max_dirty_data to -1 when nomixupload is enabled");
        max_dirty_data = -1;
    }

    //
    // Check the combination of parameters for credential
    //
    if(!ps3fscred->CheckAllParams()){
        S3fsCurl::DestroyS3fsCurl();
        s3fs_destroy_global_ssl();
        exit(EXIT_FAILURE);
    }

    // The second plain argument is the mountpoint
    // if the option was given, we all ready checked for a
    // readable, non-empty directory, this checks determines
    // if the mountpoint option was ever supplied
    if(utility_incomp_type::NO_UTILITY_MODE == utility_mode){
        if(mountpoint.empty()){
            S3FS_PRN_EXIT("missing MOUNTPOINT argument.");
            show_usage();
            S3fsCurl::DestroyS3fsCurl();
            s3fs_destroy_global_ssl();
            exit(EXIT_FAILURE);
        }
    }

    // check tmp dir permission
    if(!FdManager::CheckTmpDirExist()){
        S3FS_PRN_EXIT("temporary directory doesn't exists.");
        S3fsCurl::DestroyS3fsCurl();
        s3fs_destroy_global_ssl();
        exit(EXIT_FAILURE);
    }

    // check cache dir permission
    if(!FdManager::CheckCacheDirExist() || !FdManager::CheckCacheTopDir() || !CacheFileStat::CheckCacheFileStatTopDir()){
        S3FS_PRN_EXIT("could not allow cache directory permission, check permission of cache directories.");
        S3fsCurl::DestroyS3fsCurl();
        s3fs_destroy_global_ssl();
        exit(EXIT_FAILURE);
    }

    // set user agent
    S3fsCurl::InitUserAgent();

    // There's room for more command line error checking

    // Check to see if the bucket name contains periods and https (SSL) is
    // being used. This is a known limitation:
    // https://docs.amazonwebservices.com/AmazonS3/latest/dev/
    // The Developers Guide suggests that either use HTTP of for us to write
    // our own certificate verification logic.
    // For now, this will be unsupported unless we get a request for it to
    // be supported. In that case, we have a couple of options:
    // - implement a command line option that bypasses the verify host 
    //   but doesn't bypass verifying the certificate
    // - write our own host verification (this might be complex)
    // See issue #128strncasecmp
    /* 
    if(1 == S3fsCurl::GetSslVerifyHostname()){
        found = S3fsCred::GetBucket().find_first_of('.');
        if(found != std::string::npos){
            found = s3host.find("https:");
            if(found != std::string::npos){
                S3FS_PRN_EXIT("Using https and a bucket name with periods is unsupported.");
                S3fsCurl::DestroyS3fsCurl();
                s3fs_destroy_global_ssl();
                exit(EXIT_FAILURE);
            }
        }
    }
    */

    if(utility_incomp_type::NO_UTILITY_MODE != utility_mode){
        int exitcode = s3fs_utility_processing(incomp_abort_time);

        S3fsCurl::DestroyS3fsCurl();
        s3fs_destroy_global_ssl();
        exit(exitcode);
    }

    // Check multipart / copy api for mix multipart uploading
    if(nomultipart || nocopyapi || norenameapi){
        FdEntity::SetNoMixMultipart();
        max_dirty_data = -1;
    }

    // Free disk space
    if(-1 != fake_diskfree_size){
        // Case: Set fake disk space
        //       Not check free disk space for multipart request
        FdManager::InitFakeUsedDiskSize(fake_diskfree_size);

    }else{
        if(0 == FdManager::GetEnsureFreeDiskSpace()){
            // Case: Not set any ensure disk free space
            //       Set default value of free_space_ratio to 10%
            //
            int   ratio  = 10;
            off_t dfsize = FdManager::GetTotalDiskSpaceByRatio(ratio);
            S3FS_PRN_INFO("Free space ratio default to %d %%, ensure the available disk space is greater than %.3f MB", ratio, static_cast<double>(dfsize) / 1024 / 1024);

            if(dfsize < S3fsCurl::GetMultipartSize()){
                S3FS_PRN_WARN("specified size to ensure disk free space is smaller than multipart size, so set multipart size to it.");
                dfsize = S3fsCurl::GetMultipartSize();
            }
            FdManager::SetEnsureFreeDiskSpace(dfsize);
        }

        // Check free disk space for multipart request
        if(!FdManager::IsSafeDiskSpace(nullptr, S3fsCurl::GetMultipartSize() * ThreadPoolMan::GetWorkerCount())){
            // Try to clean cache dir and retry
            S3FS_PRN_WARN("Not enough disk space for s3fs, try to clean cache dir");
            FdManager::get()->CleanupCacheDir();

            if(!FdManager::IsSafeDiskSpace(nullptr, S3fsCurl::GetMultipartSize() * ThreadPoolMan::GetWorkerCount(), true)){
                S3fsCurl::DestroyS3fsCurl();
                s3fs_destroy_global_ssl();
                exit(EXIT_FAILURE);
            }
        }
    }

    s3fs_oper.getattr     = s3fs_getattr;
    s3fs_oper.readlink    = s3fs_readlink;
    s3fs_oper.mknod       = s3fs_mknod;
    s3fs_oper.mkdir       = s3fs_mkdir;
    s3fs_oper.unlink      = s3fs_unlink;
    s3fs_oper.rmdir       = s3fs_rmdir;
    s3fs_oper.symlink     = s3fs_symlink;
    s3fs_oper.rename      = s3fs_rename;
    s3fs_oper.link        = s3fs_link;
    if(!nocopyapi){
        s3fs_oper.chmod   = s3fs_chmod;
        s3fs_oper.chown   = s3fs_chown;
        s3fs_oper.utimens = s3fs_utimens;
    }else{
        s3fs_oper.chmod   = s3fs_chmod_nocopy;
        s3fs_oper.chown   = s3fs_chown_nocopy;
        s3fs_oper.utimens = s3fs_utimens_nocopy;
    }
    s3fs_oper.truncate    = s3fs_truncate;
    s3fs_oper.open        = s3fs_open;
    s3fs_oper.read        = s3fs_read;
    s3fs_oper.write       = s3fs_write;
    s3fs_oper.statfs      = s3fs_statfs;
    s3fs_oper.flush       = s3fs_flush;
    s3fs_oper.fsync       = s3fs_fsync;
    s3fs_oper.release     = s3fs_release;
    s3fs_oper.opendir     = s3fs_opendir;
    s3fs_oper.readdir     = s3fs_readdir;
    s3fs_oper.init        = s3fs_init;
    s3fs_oper.destroy     = s3fs_destroy;
    s3fs_oper.access      = s3fs_access;
    s3fs_oper.create      = s3fs_create;
    // extended attributes
    if(is_use_xattr){
        s3fs_oper.setxattr    = s3fs_setxattr;
        s3fs_oper.getxattr    = s3fs_getxattr;
        s3fs_oper.listxattr   = s3fs_listxattr;
        s3fs_oper.removexattr = s3fs_removexattr;
    }

#if FUSE_USE_VERSION < 30
    s3fs_oper.flag_utime_omit_ok = true;
#endif

    // now passing things off to fuse, fuse will finish evaluating the command line args
    fuse_res = fuse_main(custom_args.argc, custom_args.argv, &s3fs_oper, nullptr);
    if(fuse_res == 0){
        fuse_res = s3fs_init_deferred_exit_status;
    }
    fuse_opt_free_args(&custom_args);

    // Destroy curl
    if(!S3fsCurl::DestroyS3fsCurl()){
        S3FS_PRN_WARN("Could not release curl library.");
    }
    s3fs_destroy_global_ssl();

    // cleanup xml2
    xmlCleanupParser();

    S3FS_PRN_DBG("Number of head object requests: %llu", num_requests_head_object.load());
    S3FS_PRN_DBG("Number of put object requests: %llu", num_requests_put_object.load());
    S3FS_PRN_DBG("Number of get object requests: %llu", num_requests_get_object.load());
    S3FS_PRN_DBG("Number of delete object requests: %llu", num_requests_delete_object.load());
    S3FS_PRN_DBG("Number of list bucket requests: %llu", num_requests_list_bucket.load());
    S3FS_PRN_DBG("Number of initiate MPU requests: %llu", num_requests_mpu_initiate.load());
    S3FS_PRN_DBG("Number of complete MPU requests: %llu", num_requests_mpu_complete.load());
    S3FS_PRN_DBG("Number of abort MPU requests: %llu", num_requests_mpu_abort.load());
    S3FS_PRN_DBG("Number of upload MPU part requests: %llu", num_requests_mpu_upload_part.load());
    S3FS_PRN_DBG("Number of copy MPU part requests: %llu", num_requests_mpu_copy_part.load());

    exit(fuse_res);
}

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
