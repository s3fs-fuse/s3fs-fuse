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

#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <dirent.h>
#include <pwd.h>
#include <sys/types.h>
#include <getopt.h>

#include <fstream>

#include "common.h"
#include "s3fs.h"
#include "metaheader.h"
#include "fdcache.h"
#include "fdcache_auto.h"
#include "curl.h"
#include "curl_multi.h"
#include "s3objlist.h"
#include "cache.h"
#include "mvnode.h"
#include "addhead.h"
#include "sighandlers.h"
#include "s3fs_xml.h"
#include "s3fs_util.h"
#include "string_util.h"
#include "s3fs_auth.h"
#include "s3fs_help.h"
#include "mpu_util.h"

//-------------------------------------------------------------------
// Symbols
//-------------------------------------------------------------------
#if !defined(ENOATTR)
#define ENOATTR                   ENODATA
#endif

enum dirtype {
    DIRTYPE_UNKNOWN = -1,
    DIRTYPE_NEW = 0,
    DIRTYPE_OLD = 1,
    DIRTYPE_FOLDER = 2,
    DIRTYPE_NOOBJ = 3,
};

//-------------------------------------------------------------------
// Static variables
//-------------------------------------------------------------------
static uid_t mp_uid               = 0;    // owner of mount point(only not specified uid opt)
static gid_t mp_gid               = 0;    // group of mount point(only not specified gid opt)
static mode_t mp_mode             = 0;    // mode of mount point
static mode_t mp_umask            = 0;    // umask for mount point
static bool is_mp_umask           = false;// default does not set.
static std::string mountpoint;
static std::string passwd_file;
static std::string mimetype_file;
static bool nocopyapi             = false;
static bool norenameapi           = false;
static bool nonempty              = false;
static bool allow_other           = false;
static bool load_iamrole          = false;
static uid_t s3fs_uid             = 0;
static gid_t s3fs_gid             = 0;
static mode_t s3fs_umask          = 0;
static bool is_s3fs_uid           = false;// default does not set.
static bool is_s3fs_gid           = false;// default does not set.
static bool is_s3fs_umask         = false;// default does not set.
static bool is_remove_cache       = false;
static bool is_ecs                = false;
static bool is_ibm_iam_auth       = false;
static bool is_use_xattr          = false;
static bool is_use_session_token  = false;
static bool create_bucket         = false;
static off_t multipart_threshold  = 25 * 1024 * 1024;
static int64_t singlepart_copy_limit = 512 * 1024 * 1024;
static bool is_specified_endpoint = false;
static int s3fs_init_deferred_exit_status = 0;
static bool support_compat_dir    = true;// default supports compatibility directory type
static int max_keys_list_object   = 1000;// default is 1000
static off_t max_dirty_data       = 5LL * 1024LL * 1024LL * 1024LL;
static bool use_wtf8              = false;

static const std::string allbucket_fields_type;              // special key for mapping(This name is absolutely not used as a bucket name)
static const std::string keyval_fields_type    = "\t";       // special key for mapping(This name is absolutely not used as a bucket name)
static const std::string aws_accesskeyid       = "AWSAccessKeyId";
static const std::string aws_secretkey         = "AWSSecretKey";

//-------------------------------------------------------------------
// Global functions : prototype
//-------------------------------------------------------------------
int put_headers(const char* path, headers_t& meta, bool is_copy);       // [NOTE] global function because this is called from FdEntity class

//-------------------------------------------------------------------
// Static functions : prototype
//-------------------------------------------------------------------
static bool is_special_name_folder_object(const char* path);
static int chk_dir_object_type(const char* path, std::string& newpath, std::string& nowpath, std::string& nowcache, headers_t* pmeta = NULL, dirtype* pDirType = NULL);
static int remove_old_type_dir(const std::string& path, dirtype type);
static int get_object_attribute(const char* path, struct stat* pstbuf, headers_t* pmeta = NULL, bool overcheck = true, bool* pisforce = NULL, bool add_no_truncate_cache = false);
static int check_object_access(const char* path, int mask, struct stat* pstbuf);
static int check_object_owner(const char* path, struct stat* pstbuf);
static int check_parent_object_access(const char* path, int mask);
static int get_local_fent(AutoFdEntity& autoent, FdEntity **entity, const char* path, bool is_load = false);
static bool multi_head_callback(S3fsCurl* s3fscurl);
static S3fsCurl* multi_head_retry_callback(S3fsCurl* s3fscurl);
static int readdir_multi_head(const char* path, const S3ObjList& head, void* buf, fuse_fill_dir_t filler);
static int list_bucket(const char* path, S3ObjList& head, const char* delimiter, bool check_content_only = false);
static int directory_empty(const char* path);
static int rename_large_object(const char* from, const char* to);
static int create_file_object(const char* path, mode_t mode, uid_t uid, gid_t gid);
static int create_directory_object(const char* path, mode_t mode, time_t atime, time_t mtime, time_t ctime, uid_t uid, gid_t gid);
static int rename_object(const char* from, const char* to, bool update_ctime);
static int rename_object_nocopy(const char* from, const char* to, bool update_ctime);
static int clone_directory_object(const char* from, const char* to, bool update_ctime);
static int rename_directory(const char* from, const char* to);
static int remote_mountpath_exists(const char* path);
static void free_xattrs(xattrs_t& xattrs);
static bool parse_xattr_keyval(const std::string& xattrpair, std::string& key, PXATTRVAL& pval);
static size_t parse_xattrs(const std::string& strxattrs, xattrs_t& xattrs);
static std::string build_xattrs(const xattrs_t& xattrs);
static int s3fs_check_service();
static int parse_passwd_file(bucketkvmap_t& resmap);
static int check_for_aws_format(const kvmap_t& kvmap);
static int check_passwd_file_perms();
static int read_aws_credentials_file(const std::string &filename);
static int read_passwd_file();
static int get_access_keys();
static bool set_mountpoint_attribute(struct stat& mpst);
static int set_bucket(const char* arg);
static int my_fuse_opt_proc(void* data, const char* arg, int key, struct fuse_args* outargs);

//-------------------------------------------------------------------
// fuse interface functions
//-------------------------------------------------------------------
static int s3fs_getattr(const char* path, struct stat* stbuf);
static int s3fs_readlink(const char* path, char* buf, size_t size);
static int s3fs_mknod(const char* path, mode_t mode, dev_t rdev);
static int s3fs_mkdir(const char* path, mode_t mode);
static int s3fs_unlink(const char* path);
static int s3fs_rmdir(const char* path);
static int s3fs_symlink(const char* from, const char* to);
static int s3fs_rename(const char* from, const char* to);
static int s3fs_link(const char* from, const char* to);
static int s3fs_chmod(const char* path, mode_t mode);
static int s3fs_chmod_nocopy(const char* path, mode_t mode);
static int s3fs_chown(const char* path, uid_t uid, gid_t gid);
static int s3fs_chown_nocopy(const char* path, uid_t uid, gid_t gid);
static int s3fs_utimens(const char* path, const struct timespec ts[2]);
static int s3fs_utimens_nocopy(const char* path, const struct timespec ts[2]);
static int s3fs_truncate(const char* path, off_t size);
static int s3fs_create(const char* path, mode_t mode, struct fuse_file_info* fi);
static int s3fs_open(const char* path, struct fuse_file_info* fi);
static int s3fs_read(const char* path, char* buf, size_t size, off_t offset, struct fuse_file_info* fi);
static int s3fs_write(const char* path, const char* buf, size_t size, off_t offset, struct fuse_file_info* fi);
static int s3fs_statfs(const char* path, struct statvfs* stbuf);
static int s3fs_flush(const char* path, struct fuse_file_info* fi);
static int s3fs_fsync(const char* path, int datasync, struct fuse_file_info* fi);
static int s3fs_release(const char* path, struct fuse_file_info* fi);
static int s3fs_opendir(const char* path, struct fuse_file_info* fi);
static int s3fs_readdir(const char* path, void* buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info* fi);
static int s3fs_access(const char* path, int mask);
static void* s3fs_init(struct fuse_conn_info* conn);
static void s3fs_destroy(void*);
#if defined(__APPLE__)
static int s3fs_setxattr(const char* path, const char* name, const char* value, size_t size, int flags, uint32_t position);
static int s3fs_getxattr(const char* path, const char* name, char* value, size_t size, uint32_t position);
#else
static int s3fs_setxattr(const char* path, const char* name, const char* value, size_t size, int flags);
static int s3fs_getxattr(const char* path, const char* name, char* value, size_t size);
#endif
static int s3fs_listxattr(const char* path, char* list, size_t size);
static int s3fs_removexattr(const char* path, const char* name);

//-------------------------------------------------------------------
// Functions
//-------------------------------------------------------------------
static bool IS_REPLACEDIR(dirtype type)
{
    return DIRTYPE_OLD == type || DIRTYPE_FOLDER == type || DIRTYPE_NOOBJ == type;
}

static bool IS_RMTYPEDIR(dirtype type)
{
    return DIRTYPE_OLD == type || DIRTYPE_FOLDER == type;
}

static bool is_special_name_folder_object(const char* path)
{
    if(!support_compat_dir){
        // s3fs does not support compatibility directory type("_$folder$" etc) now,
        // thus always returns false.
        return false;
    }

    if(!path || '\0' == path[0]){
        return false;
    }

    std::string strpath = path;
    headers_t header;

    if(std::string::npos == strpath.find("_$folder$", 0)){
        if('/' == strpath[strpath.length() - 1]){
            strpath.erase(strpath.length() - 1);
        }
        strpath += "_$folder$";
    }
    S3fsCurl s3fscurl;
    if(0 != s3fscurl.HeadRequest(strpath.c_str(), header)){
        return false;
    }
    header.clear();
    S3FS_MALLOCTRIM(0);
    return true;
}

// [Detail]
// This function is complicated for checking directory object type.
// Arguments is used for deleting cache/path, and remake directory object.
// Please see the codes which calls this function.
//
// path:      target path
// newpath:   should be object path for making/putting/getting after checking
// nowpath:   now object name for deleting after checking
// nowcache:  now cache path for deleting after checking
// pmeta:     headers map
// pDirType:  directory object type
//
static int chk_dir_object_type(const char* path, std::string& newpath, std::string& nowpath, std::string& nowcache, headers_t* pmeta, dirtype* pDirType)
{
    dirtype TypeTmp;
    int  result  = -1;
    bool isforce = false;
    dirtype* pType = pDirType ? pDirType : &TypeTmp;

    // Normalize new path.
    newpath = path;
    if('/' != newpath[newpath.length() - 1]){
        std::string::size_type Pos;
        if(std::string::npos != (Pos = newpath.find("_$folder$", 0))){
            newpath.erase(Pos);
        }
        newpath += "/";
    }

    // Always check "dir/" at first.
    if(0 == (result = get_object_attribute(newpath.c_str(), NULL, pmeta, false, &isforce))){
        // Found "dir/" cache --> Check for "_$folder$", "no dir object"
        nowcache = newpath;
        if(is_special_name_folder_object(newpath.c_str())){     // check support_compat_dir in this function
            // "_$folder$" type.
            (*pType) = DIRTYPE_FOLDER;
            nowpath.erase(newpath.length() - 1);
            nowpath += "_$folder$"; // cut and add
        }else if(isforce){
            // "no dir object" type.
            (*pType) = DIRTYPE_NOOBJ;
            nowpath  = "";
        }else{
            nowpath = newpath;
            if(0 < nowpath.length() && '/' == nowpath[nowpath.length() - 1]){
                // "dir/" type
                (*pType) = DIRTYPE_NEW;
            }else{
                // "dir" type
                (*pType) = DIRTYPE_OLD;
            }
        }
    }else if(support_compat_dir){
        // Check "dir" when support_compat_dir is enabled
        nowpath.erase(newpath.length() - 1);
        if(0 == (result = get_object_attribute(nowpath.c_str(), NULL, pmeta, false, &isforce))){
            // Found "dir" cache --> this case is only "dir" type.
            // Because, if object is "_$folder$" or "no dir object", the cache is "dir/" type.
            // (But "no dir object" is checked here.)
            nowcache = nowpath;
            if(isforce){
                (*pType) = DIRTYPE_NOOBJ;
                nowpath  = "";
            }else{
                (*pType) = DIRTYPE_OLD;
            }
        }else{
            // Not found cache --> check for "_$folder$" and "no dir object".
            // (come here is that support_compat_dir is enabled)
            nowcache = "";  // This case is no cache.
            nowpath += "_$folder$";
            if(is_special_name_folder_object(nowpath.c_str())){
                // "_$folder$" type.
                (*pType) = DIRTYPE_FOLDER;
                result   = 0;             // result is OK.
            }else if(-ENOTEMPTY == directory_empty(newpath.c_str())){
                // "no dir object" type.
                (*pType) = DIRTYPE_NOOBJ;
                nowpath  = "";            // now path.
                result   = 0;             // result is OK.
            }else{
                // Error: Unknown type.
                (*pType) = DIRTYPE_UNKNOWN;
                newpath = "";
                nowpath = "";
            }
        }
    }
    return result;
}

static int remove_old_type_dir(const std::string& path, dirtype type)
{
    if(IS_RMTYPEDIR(type)){
        S3fsCurl s3fscurl;
        int      result = s3fscurl.DeleteRequest(path.c_str());
        if(0 != result && -ENOENT != result){
            return result;
        }
        // succeed removing or not found the directory
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
static int get_object_attribute(const char* path, struct stat* pstbuf, headers_t* pmeta, bool overcheck, bool* pisforce, bool add_no_truncate_cache)
{
    int          result = -1;
    struct stat  tmpstbuf;
    struct stat* pstat = pstbuf ? pstbuf : &tmpstbuf;
    headers_t    tmpHead;
    headers_t*   pheader = pmeta ? pmeta : &tmpHead;
    std::string  strpath;
    S3fsCurl     s3fscurl;
    bool         forcedir = false;
    std::string::size_type Pos;

    S3FS_PRN_DBG("[path=%s]", path);

    if(!path || '\0' == path[0]){
        return -ENOENT;
    }

    memset(pstat, 0, sizeof(struct stat));
    if(0 == strcmp(path, "/") || 0 == strcmp(path, ".")){
        pstat->st_nlink = 1; // see fuse faq
        pstat->st_mode  = mp_mode;
        pstat->st_uid   = is_s3fs_uid ? s3fs_uid : mp_uid;
        pstat->st_gid   = is_s3fs_gid ? s3fs_gid : mp_gid;
        return 0;
    }

    // Check cache.
    pisforce    = (NULL != pisforce ? pisforce : &forcedir);
    (*pisforce) = false;
    strpath     = path;
    if(support_compat_dir && overcheck && std::string::npos != (Pos = strpath.find("_$folder$", 0))){
        strpath.erase(Pos);
        strpath += "/";
    }
    if(StatCache::getStatCacheData()->GetStat(strpath, pstat, pheader, overcheck, pisforce)){
        StatCache::getStatCacheData()->ChangeNoTruncateFlag(strpath, add_no_truncate_cache);
        return 0;
    }
    if(StatCache::getStatCacheData()->IsNoObjectCache(strpath)){
        // there is the path in the cache for no object, it is no object.
        return -ENOENT;
    }

    // At first, check path
    strpath     = path;
    result      = s3fscurl.HeadRequest(strpath.c_str(), (*pheader));
    s3fscurl.DestroyCurlHandle();

    // if not found target path object, do over checking
    if(-EPERM == result){
        // [NOTE]
        // In case of a permission error, it exists in directory
        // file list but inaccessible. So there is a problem that
        // it will send a HEAD request every time, because it is
        // not registered in the Stats cache.
        // Therefore, even if the file has a permission error, it
        // should be registered in the Stats cache. However, if
        // the response without modifiying is registered in the
        // cache, the file permission will be 0644(umask dependent)
        // because the meta header does not exist.
        // Thus, set the mode of 0000 here in the meta header so
        // that s3fs can print a permission error when the file
        // is actually accessed.
        // It is better not to set meta header other than mode,
        // so do not do it.
        //
        (*pheader)["x-amz-meta-mode"] = str(0);

    }else if(0 != result){
        if(overcheck){
            // when support_compat_dir is disabled, strpath maybe have "_$folder$".
            if('/' != strpath[strpath.length() - 1] && std::string::npos == strpath.find("_$folder$", 0)){
                // now path is "object", do check "object/" for over checking
                strpath    += "/";
                result      = s3fscurl.HeadRequest(strpath.c_str(), (*pheader));
                s3fscurl.DestroyCurlHandle();
            }
            if(support_compat_dir && 0 != result){
                // now path is "object/", do check "object_$folder$" for over checking
                strpath.erase(strpath.length() - 1);
                strpath    += "_$folder$";
                result      = s3fscurl.HeadRequest(strpath.c_str(), (*pheader));
                s3fscurl.DestroyCurlHandle();

              if(0 != result){
                  // cut "_$folder$" for over checking "no dir object" after here
                  if(std::string::npos != (Pos = strpath.find("_$folder$", 0))){
                      strpath.erase(Pos);
                  }
              }
            }
        }
        if(support_compat_dir && 0 != result && std::string::npos == strpath.find("_$folder$", 0)){
            // now path is "object" or "object/", do check "no dir object" which is not object but has only children.
            if('/' == strpath[strpath.length() - 1]){
                strpath.erase(strpath.length() - 1);
            }
            if(-ENOTEMPTY == directory_empty(strpath.c_str())){
                // found "no dir object".
                strpath  += "/";
                *pisforce = true;
                result    = 0;
            }
        }
    }else{
        if(support_compat_dir && '/' != strpath[strpath.length() - 1] && std::string::npos == strpath.find("_$folder$", 0) && is_need_check_obj_detail(*pheader)){
            // check a case of that "object" does not have attribute and "object" is possible to be directory.
            if(-ENOTEMPTY == directory_empty(strpath.c_str())){
                // found "no dir object".
                strpath  += "/";
                *pisforce = true;
                result    = 0;
            }
        }
    }

    // [NOTE]
    // If the file is listed but not allowed access, put it in
    // the positive cache instead of the negative cache.
    // 
    if(0 != result && -EPERM != result){
        // finally, "path" object did not find. Add no object cache.
        strpath = path;  // reset original
        StatCache::getStatCacheData()->AddNoObjectCache(strpath);
        return result;
    }

    // if path has "_$folder$", need to cut it.
    if(std::string::npos != (Pos = strpath.find("_$folder$", 0))){
        strpath.erase(Pos);
        strpath += "/";
    }

    // Set into cache
    //
    // [NOTE]
    // When add_no_truncate_cache is true, the stats is always cached.
    // This cached stats is only removed by DelStat().
    // This is necessary for the case to access the attribute of opened file.
    // (ex. getxattr() is called while writing to the opened file.)
    //
    if(add_no_truncate_cache || 0 != StatCache::getStatCacheData()->GetCacheSize()){
        // add into stat cache
        if(!StatCache::getStatCacheData()->AddStat(strpath, (*pheader), forcedir, add_no_truncate_cache)){
            S3FS_PRN_ERR("failed adding stat cache [path=%s]", strpath.c_str());
            return -ENOENT;
        }
        if(!StatCache::getStatCacheData()->GetStat(strpath, pstat, pheader, overcheck, pisforce)){
            // There is not in cache.(why?) -> retry to convert.
            if(!convert_header_to_stat(strpath.c_str(), (*pheader), pstat, forcedir)){
                S3FS_PRN_ERR("failed convert headers to stat[path=%s]", strpath.c_str());
                return -ENOENT;
            }
        }
    }else{
        // cache size is Zero -> only convert.
        if(!convert_header_to_stat(strpath.c_str(), (*pheader), pstat, forcedir)){
            S3FS_PRN_ERR("failed convert headers to stat[path=%s]", strpath.c_str());
            return -ENOENT;
        }
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
// stat:   NULL or the pointer of struct stat.
//
static int check_object_access(const char* path, int mask, struct stat* pstbuf)
{
    int result;
    struct stat st;
    struct stat* pst = (pstbuf ? pstbuf : &st);
    struct fuse_context* pcxt;

    S3FS_PRN_DBG("[path=%s]", path);

    if(NULL == (pcxt = fuse_get_context())){
        return -EIO;
    }
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
    }
    if(1 == is_uid_include_group(pcxt->uid, obj_gid)){
        base_mask |= S_IRWXG;
    }
    mode &= base_mask;

    if(X_OK == (mask & X_OK)){
        if(0 == (mode & (S_IXUSR | S_IXGRP | S_IXOTH))){
            return -EPERM;
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
    struct fuse_context* pcxt;

    S3FS_PRN_DBG("[path=%s]", path);

    if(NULL == (pcxt = fuse_get_context())){
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
            if(0 != (result = check_object_access(parent.c_str(), X_OK, NULL))){
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
        if(0 != (result = check_object_access(parent.c_str(), mask, NULL))){
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
    if(0 != get_object_attribute(path, NULL, &meta)){
        S3FS_PRN_ERR("Failed to get object(%s) headers", path);
        return false;
    }

    ssetype = sse_type_t::SSE_DISABLE;
    ssevalue.erase();
    for(headers_t::iterator iter = meta.begin(); iter != meta.end(); ++iter){
        std::string key = (*iter).first;
        if(0 == strcasecmp(key.c_str(), "x-amz-server-side-encryption") && 0 == strcasecmp((*iter).second.c_str(), "AES256")){
            ssetype  = sse_type_t::SSE_S3;
        }else if(0 == strcasecmp(key.c_str(), "x-amz-server-side-encryption-aws-kms-key-id")){
            ssetype  = sse_type_t::SSE_KMS;
            ssevalue = (*iter).second;
        }else if(0 == strcasecmp(key.c_str(), "x-amz-server-side-encryption-customer-key-md5")){
            ssetype  = sse_type_t::SSE_C;
            ssevalue = (*iter).second;
        }
    }
    return true;
}

static int get_local_fent(AutoFdEntity& autoent, FdEntity **entity, const char* path, bool is_load)
{
    int         result;
    struct stat stobj;
    FdEntity*   ent;
    headers_t   meta;

    S3FS_PRN_INFO2("[path=%s]", path);

    if(0 != (result = get_object_attribute(path, &stobj, &meta))){
        return result;
    }

    // open
    time_t mtime         = (!S_ISREG(stobj.st_mode) && !S_ISLNK(stobj.st_mode)) ? -1 : stobj.st_mtime;
    bool   force_tmpfile = S_ISREG(stobj.st_mode) ? false : true;

    if(NULL == (ent = autoent.Open(path, &meta, stobj.st_size, mtime, force_tmpfile, true))){
        S3FS_PRN_ERR("Could not open file. errno(%d)", errno);
        return -EIO;
    }
    // load
    if(is_load && !ent->OpenAndLoadAll(&meta)){
        S3FS_PRN_ERR("Could not load file. errno(%d)", errno);
        autoent.Close();
        return -EIO;
    }
    *entity = ent;
    return 0;
}

//
// create or update s3 meta
// ow_sse_flg is for over writing sse header by use_sse option.
// @return fuse return code
//
int put_headers(const char* path, headers_t& meta, bool is_copy)
{
    int         result;
    S3fsCurl    s3fscurl(true);
    struct stat buf;

    S3FS_PRN_INFO2("[path=%s]", path);

    // files larger than 5GB must be modified via the multipart interface
    // *** If there is not target object(a case of move command),
    //     get_object_attribute() returns error with initializing buf.
    (void)get_object_attribute(path, &buf);

    if(!nocopyapi && !nomultipart && buf.st_size >= multipart_threshold){
        if(0 != (result = s3fscurl.MultipartHeadRequest(path, buf.st_size, meta, is_copy))){
            return result;
        }
    }else{
        if(0 != (result = s3fscurl.PutHeadRequest(path, meta, is_copy))){
            return result;
        }
    }
    return 0;
}

static int s3fs_getattr(const char* _path, struct stat* stbuf)
{
    WTF8_ENCODE(path)
    int result;

    S3FS_PRN_INFO("[path=%s]", path);

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
        FdEntity*    ent;
        if(NULL != (ent = autoent.ExistOpen(path))){
            struct stat tmpstbuf;
            if(ent->GetStats(tmpstbuf)){
                stbuf->st_size = tmpstbuf.st_size;
            }
        }
        stbuf->st_blksize = 4096;
        stbuf->st_blocks  = get_blocks(stbuf->st_size);

        S3FS_PRN_DBG("[path=%s] uid=%u, gid=%u, mode=%04o", path, (unsigned int)(stbuf->st_uid), (unsigned int)(stbuf->st_gid), stbuf->st_mode);
    }
    S3FS_MALLOCTRIM(0);

    return result;
}

static int s3fs_readlink(const char* _path, char* buf, size_t size)
{
    if(!_path || !buf || 0 == size){
        return 0;
    }
    WTF8_ENCODE(path)
    std::string strValue;

    // check symblic link cache
    if(!StatCache::getStatCacheData()->GetSymlink(std::string(path), strValue)){
        // not found in cache, then open the path
        {   // scope for AutoFdEntity
            AutoFdEntity autoent;
            FdEntity*    ent;
            int          result;
            if(0 != (result = get_local_fent(autoent, &ent, path))){
                S3FS_PRN_ERR("could not get fent(file=%s)", path);
                return result;
            }
            // Get size
            off_t readsize;
            if(!ent->GetSize(readsize)){
                S3FS_PRN_ERR("could not get file size(file=%s)", path);
                return -EIO;
            }
            if(static_cast<off_t>(size) <= readsize){
                readsize = size - 1;
            }
            // Read
            ssize_t ressize;
            if(0 > (ressize = ent->Read(buf, 0, readsize))){
                S3FS_PRN_ERR("could not read file(file=%s, ressize=%zd)", path, ressize);
                return static_cast<int>(ressize);
            }
            buf[ressize] = '\0';
        }

        // check buf if it has space words.
        strValue = trim(std::string(buf));

        // decode wtf8. This will always be shorter
        if(use_wtf8){
          strValue = s3fs_wtf8_decode(strValue);
        }

        // add symblic link cache
        if(!StatCache::getStatCacheData()->AddSymlink(std::string(path), strValue)){
          S3FS_PRN_ERR("failed to add symbolic link cache for %s", path);
        }
    }
    // copy result
    strncpy(buf, strValue.c_str(), size);

    S3FS_MALLOCTRIM(0);

    return 0;
}

static int do_create_bucket()
{
    S3FS_PRN_INFO2("/");

    FILE* ptmpfp;
    int   tmpfd;
    if(endpoint == "us-east-1"){
        ptmpfp = NULL;
        tmpfd = -1;
    }else{
        if(NULL == (ptmpfp = tmpfile())   ||
           -1 == (tmpfd = fileno(ptmpfp)) ||
           0 >= fprintf(ptmpfp, "<CreateBucketConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\n"
                                "  <LocationConstraint>%s</LocationConstraint>\n"
                                "</CreateBucketConfiguration>", endpoint.c_str()) ||
           0 != fflush(ptmpfp) ||
           -1 == fseek(ptmpfp, 0L, SEEK_SET))
        {
            S3FS_PRN_ERR("failed to create temporary file. err(%d)", errno);
            if(ptmpfp){
              fclose(ptmpfp);
            }
            return (0 == errno ? -EIO : -errno);
        }
    }

    headers_t meta;

    S3fsCurl s3fscurl(true);
    int      res = s3fscurl.PutRequest("/", meta, tmpfd);
    if(res < 0){
        long responseCode = s3fscurl.GetLastResponseCode();
        if((responseCode == 400 || responseCode == 403) && S3fsCurl::GetSignatureType() == V2_OR_V4){
            S3FS_PRN_ERR("Could not connect, so retry to connect by signature version 2.");
            S3fsCurl::SetSignatureType(V2_ONLY);

            // retry to check
            s3fscurl.DestroyCurlHandle();
            res = s3fscurl.PutRequest("/", meta, tmpfd);
        }else if(responseCode == 409){
            // bucket already exists
            res = 0;
        }
    }
    if(ptmpfp != NULL){
        fclose(ptmpfp);
    }
    return res;
}

// common function for creation of a plain object
static int create_file_object(const char* path, mode_t mode, uid_t uid, gid_t gid)
{
    S3FS_PRN_INFO2("[path=%s][mode=%04o]", path, mode);

    time_t now = time(NULL);
    headers_t meta;
    meta["Content-Type"]     = S3fsCurl::LookupMimeType(std::string(path));
    meta["x-amz-meta-uid"]   = str(uid);
    meta["x-amz-meta-gid"]   = str(gid);
    meta["x-amz-meta-mode"]  = str(mode);
    meta["x-amz-meta-atime"] = str(now);
    meta["x-amz-meta-ctime"] = str(now);
    meta["x-amz-meta-mtime"] = str(now);

    S3fsCurl s3fscurl(true);
    return s3fscurl.PutRequest(path, meta, -1);    // fd=-1 means for creating zero byte object.
}

static int s3fs_mknod(const char *_path, mode_t mode, dev_t rdev)
{
    WTF8_ENCODE(path)
    int       result;
    struct fuse_context* pcxt;

    S3FS_PRN_INFO("[path=%s][mode=%04o][dev=%llu]", path, mode, (unsigned long long)rdev);

    if(NULL == (pcxt = fuse_get_context())){
        return -EIO;
    }

    if(0 != (result = create_file_object(path, mode, pcxt->uid, pcxt->gid))){
        S3FS_PRN_ERR("could not create object for special file(result=%d)", result);
        return result;
    }
    StatCache::getStatCacheData()->DelStat(path);
    S3FS_MALLOCTRIM(0);

    return result;
}

static int s3fs_create(const char* _path, mode_t mode, struct fuse_file_info* fi)
{
    WTF8_ENCODE(path)
    int result;
    struct fuse_context* pcxt;

    S3FS_PRN_INFO("[path=%s][mode=%04o][flags=0x%x]", path, mode, fi->flags);

    if(NULL == (pcxt = fuse_get_context())){
        return -EIO;
    }

    // check parent directory attribute.
    if(0 != (result = check_parent_object_access(path, X_OK))){
        return result;
    }
    result = check_object_access(path, W_OK, NULL);
    if(-ENOENT == result){
        if(0 != (result = check_parent_object_access(path, W_OK))){
            return result;
        }
    }else if(0 != result){
        return result;
    }
    result = create_file_object(path, mode, pcxt->uid, pcxt->gid);
    StatCache::getStatCacheData()->DelStat(path);
    if(result != 0){
        return result;
    }

    AutoFdEntity autoent;
    FdEntity*    ent;
    headers_t    meta;
    get_object_attribute(path, NULL, &meta, true, NULL, true);    // no truncate cache
    if(NULL == (ent = autoent.Open(path, &meta, 0, -1, false, true))){
        StatCache::getStatCacheData()->DelStat(path);
        return -EIO;
    }
    autoent.Detach();       // KEEP fdentity open
    fi->fh = ent->GetFd();

    S3FS_MALLOCTRIM(0);

    return 0;
}

static int create_directory_object(const char* path, mode_t mode, time_t atime, time_t mtime, time_t ctime, uid_t uid, gid_t gid)
{
    S3FS_PRN_INFO1("[path=%s][mode=%04o][atime=%lld][mtime=%lld][ctime=%lld][uid=%u][gid=%u]", path, mode, static_cast<long long>(atime), static_cast<long long>(ctime), static_cast<long long>(mtime), (unsigned int)uid, (unsigned int)gid);

    if(!path || '\0' == path[0]){
        return -EINVAL;
    }
    std::string tpath = path;
    if('/' != tpath[tpath.length() - 1]){
        tpath += "/";
    }

    headers_t meta;
    meta["x-amz-meta-uid"]   = str(uid);
    meta["x-amz-meta-gid"]   = str(gid);
    meta["x-amz-meta-mode"]  = str(mode);
    meta["x-amz-meta-atime"] = str(atime);
    meta["x-amz-meta-mtime"] = str(mtime);
    meta["x-amz-meta-ctime"] = str(ctime);

    S3fsCurl s3fscurl;
    return s3fscurl.PutRequest(tpath.c_str(), meta, -1);    // fd=-1 means for creating zero byte object.
}

static int s3fs_mkdir(const char* _path, mode_t mode)
{
    WTF8_ENCODE(path)
    int result;
    struct fuse_context* pcxt;

    S3FS_PRN_INFO("[path=%s][mode=%04o]", path, mode);

    if(NULL == (pcxt = fuse_get_context())){
        return -EIO;
    }

    // check parent directory attribute.
    if(0 != (result = check_parent_object_access(path, W_OK | X_OK))){
        return result;
    }
    if(-ENOENT != (result = check_object_access(path, F_OK, NULL))){
        if(0 == result){
            result = -EEXIST;
        }
        return result;
    }
    result = create_directory_object(path, mode, time(NULL), time(NULL), time(NULL), pcxt->uid, pcxt->gid);

    StatCache::getStatCacheData()->DelStat(path);
    S3FS_MALLOCTRIM(0);

    return result;
}

static int s3fs_unlink(const char* _path)
{
    WTF8_ENCODE(path)
    int result;

    S3FS_PRN_INFO("[path=%s]", path);

    if(0 != (result = check_parent_object_access(path, W_OK | X_OK))){
        return result;
    }
    S3fsCurl s3fscurl;
    result = s3fscurl.DeleteRequest(path);
    FdManager::DeleteCacheFile(path);
    StatCache::getStatCacheData()->DelStat(path);
    StatCache::getStatCacheData()->DelSymlink(path);
    S3FS_MALLOCTRIM(0);

    return result;
}

static int directory_empty(const char* path)
{
    int result;
    S3ObjList head;

    if((result = list_bucket(path, head, "/", true)) != 0){
        S3FS_PRN_ERR("list_bucket returns error.");
        return result;
    }
    if(!head.IsEmpty()){
        return -ENOTEMPTY;
    }
    return 0;
}

static int s3fs_rmdir(const char* _path)
{
    WTF8_ENCODE(path)
    int result;
    std::string strpath;
    struct stat stbuf;

    S3FS_PRN_INFO("[path=%s]", path);

    if(0 != (result = check_parent_object_access(path, W_OK | X_OK))){
        return result;
    }

    // directory must be empty
    if(directory_empty(path) != 0){
        return -ENOTEMPTY;
    }

    strpath = path;
    if('/' != strpath[strpath.length() - 1]){
        strpath += "/";
    }
    S3fsCurl s3fscurl;
    result = s3fscurl.DeleteRequest(strpath.c_str());
    s3fscurl.DestroyCurlHandle();
    StatCache::getStatCacheData()->DelStat(strpath.c_str());

    // double check for old version(before 1.63)
    // The old version makes "dir" object, newer version makes "dir/".
    // A case, there is only "dir", the first removing object is "dir/".
    // Then "dir/" is not exists, but curl_delete returns 0.
    // So need to check "dir" and should be removed it.
    if('/' == strpath[strpath.length() - 1]){
        strpath.erase(strpath.length() - 1);
    }
    if(0 == get_object_attribute(strpath.c_str(), &stbuf, NULL, false)){
        if(S_ISDIR(stbuf.st_mode)){
            // Found "dir" object.
            result = s3fscurl.DeleteRequest(strpath.c_str());
            s3fscurl.DestroyCurlHandle();
            StatCache::getStatCacheData()->DelStat(strpath.c_str());
        }
    }
    // If there is no "dir" and "dir/" object(this case is made by s3cmd/s3sync),
    // the cache key is "dir/". So we get error only once(delete "dir/").

    // check for "_$folder$" object.
    // This processing is necessary for other S3 clients compatibility.
    if(is_special_name_folder_object(strpath.c_str())){
        strpath += "_$folder$";
        result   = s3fscurl.DeleteRequest(strpath.c_str());
    }
    S3FS_MALLOCTRIM(0);

    return result;
}

static int s3fs_symlink(const char* _from, const char* _to)
{
    WTF8_ENCODE(from)
    WTF8_ENCODE(to)
    int result;
    struct fuse_context* pcxt;

    S3FS_PRN_INFO("[from=%s][to=%s]", from, to);

    if(NULL == (pcxt = fuse_get_context())){
        return -EIO;
    }
    if(0 != (result = check_parent_object_access(to, W_OK | X_OK))){
        return result;
    }
    if(-ENOENT != (result = check_object_access(to, F_OK, NULL))){
        if(0 == result){
            result = -EEXIST;
        }
        return result;
    }

    time_t now = time(NULL);
    headers_t headers;
    headers["Content-Type"]     = std::string("application/octet-stream"); // Static
    headers["x-amz-meta-mode"]  = str(S_IFLNK | S_IRWXU | S_IRWXG | S_IRWXO);
    headers["x-amz-meta-atime"] = str(now);
    headers["x-amz-meta-ctime"] = str(now);
    headers["x-amz-meta-mtime"] = str(now);
    headers["x-amz-meta-uid"]   = str(pcxt->uid);
    headers["x-amz-meta-gid"]   = str(pcxt->gid);

    // open tmpfile
    std::string strFrom;
    {   // scope for AutoFdEntity
        AutoFdEntity autoent;
        FdEntity*    ent;
        if(NULL == (ent = autoent.Open(to, &headers, 0, -1, true, true))){
            S3FS_PRN_ERR("could not open tmpfile(errno=%d)", errno);
            return -errno;
        }
        // write(without space words)
        strFrom           = trim(std::string(from));
        ssize_t from_size = static_cast<ssize_t>(strFrom.length());
        if(from_size != ent->Write(strFrom.c_str(), 0, from_size)){
            S3FS_PRN_ERR("could not write tmpfile(errno=%d)", errno);
            return -errno;
        }
        // upload
        if(0 != (result = ent->Flush(true))){
            S3FS_PRN_WARN("could not upload tmpfile(result=%d)", result);
        }
    }

    StatCache::getStatCacheData()->DelStat(to);
    if(!StatCache::getStatCacheData()->AddSymlink(std::string(to), strFrom)){
        S3FS_PRN_ERR("failed to add symbolic link cache for %s", to);
    }
    S3FS_MALLOCTRIM(0);

    return result;
}

static int rename_object(const char* from, const char* to, bool update_ctime)
{
    int         result;
    std::string s3_realpath;
    headers_t   meta;
    struct stat buf;

    S3FS_PRN_INFO1("[from=%s][to=%s]", from , to);

    if(0 != (result = check_parent_object_access(to, W_OK | X_OK))){
        // not permit writing "to" object parent dir.
        return result;
    }
    if(0 != (result = check_parent_object_access(from, W_OK | X_OK))){
        // not permit removing "from" object parent dir.
        return result;
    }
    if(0 != (result = get_object_attribute(from, &buf, &meta))){
        return result;
    }
    s3_realpath = get_realpath(from);

    if(update_ctime){
        meta["x-amz-meta-ctime"]     = str(time(NULL));
    }
    meta["x-amz-copy-source"]        = urlEncode(service_path + bucket + s3_realpath);
    meta["Content-Type"]             = S3fsCurl::LookupMimeType(std::string(to));
    meta["x-amz-metadata-directive"] = "REPLACE";

    // [NOTE]
    // If it has a cache, open it first and leave it open until rename.
    // The cache is renamed after put_header, because it must be open
    // at the time of renaming.
    {
        // update time
        AutoFdEntity autoent;
        FdEntity*    ent;
        if(NULL == (ent = autoent.ExistOpen(from, -1, !FdManager::IsCacheDir()))){
            // no opened fd
            if(FdManager::IsCacheDir()){
                // create cache file if be needed
                ent = autoent.Open(from, &meta, buf.st_size, -1, false, true);
            }
            if(ent){
                time_t mtime = get_mtime(meta);
                time_t ctime = get_ctime(meta);
                time_t atime = get_atime(meta);
                if(mtime < 0){
                    mtime = 0L;
                }
                if(ctime < 0){
                    ctime = 0L;
                }
                if(atime < 0){
                    atime = 0L;
                }
                ent->SetMCtime(mtime, ctime);
                ent->SetAtime(atime);
            }
        }

        // copy
        if(0 != (result = put_headers(to, meta, true))){
            return result;
        }

        // rename
        FdManager::get()->Rename(from, to);
    }

    // Remove file
    result = s3fs_unlink(from);

    StatCache::getStatCacheData()->DelStat(to);

    return result;
}

static int rename_object_nocopy(const char* from, const char* to, bool update_ctime)
{
    int result;

    S3FS_PRN_INFO1("[from=%s][to=%s]", from , to);

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
        if(0 != (result = get_local_fent(autoent, &ent, from, true))){
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
            ent->SetCtime(time(NULL));
        }

        // upload
        if(0 != (result = ent->RowFlush(to, true))){
            S3FS_PRN_ERR("could not upload file(%s): result=%d", to, result);
            return result;
        }
        FdManager::get()->Rename(from, to);
    }

    // Remove file
    result = s3fs_unlink(from);

    // Stats
    StatCache::getStatCacheData()->DelStat(to);

    return result;
}

static int rename_large_object(const char* from, const char* to)
{
    int         result;
    struct stat buf;
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
    if(0 != (result = get_object_attribute(from, &buf, &meta, false))){
        return result;
    }

    S3fsCurl s3fscurl(true);
    if(0 != (result = s3fscurl.MultipartRenameRequest(from, to, meta, buf.st_size))){
        return result;
    }
    s3fscurl.DestroyCurlHandle();

    // Remove file
    result = s3fs_unlink(from);

    StatCache::getStatCacheData()->DelStat(to);
    FdManager::DeleteCacheFile(to);

    return result;
}

static int clone_directory_object(const char* from, const char* to, bool update_ctime)
{
    int result = -1;
    struct stat stbuf;

    S3FS_PRN_INFO1("[from=%s][to=%s]", from, to);

    // get target's attributes
    if(0 != (result = get_object_attribute(from, &stbuf))){
        return result;
    }
    result = create_directory_object(to, stbuf.st_mode, stbuf.st_atime, stbuf.st_mtime, (update_ctime ? time(NULL) : stbuf.st_ctime), stbuf.st_uid, stbuf.st_gid);

    StatCache::getStatCacheData()->DelStat(to);

    return result;
}

static int rename_directory(const char* from, const char* to)
{
    S3ObjList head;
    s3obj_list_t headlist;
    std::string strfrom  = from ? from : "";   // from is without "/".
    std::string strto    = to ? to : "";       // to is without "/" too.
    std::string basepath = strfrom + "/";
    std::string newpath;                       // should be from name(not used)
    std::string nowcache;                      // now cache path(not used)
    dirtype DirType;
    bool normdir; 
    MVNODE* mn_head = NULL;
    MVNODE* mn_tail = NULL;
    MVNODE* mn_cur;
    struct stat stbuf;
    int result;
    bool is_dir;

    S3FS_PRN_INFO1("[from=%s][to=%s]", from, to);

    //
    // Initiate and Add base directory into MVNODE struct.
    //
    strto += "/";
    if(0 == chk_dir_object_type(from, newpath, strfrom, nowcache, NULL, &DirType) && DIRTYPE_UNKNOWN != DirType){
        if(DIRTYPE_NOOBJ != DirType){
            normdir = false;
        }else{
            normdir = true;
            strfrom = from;               // from directory is not removed, but from directory attr is needed.
        }
        if(NULL == (add_mvnode(&mn_head, &mn_tail, strfrom.c_str(), strto.c_str(), true, normdir))){
            return -ENOMEM;
        }
    }else{
        // Something wrong about "from" directory.
    }

    //
    // get a list of all the objects
    //
    // No delimiter is specified, the result(head) is all object keys.
    // (CommonPrefixes is empty, but all object is listed in Key.)
    if(0 != (result = list_bucket(basepath.c_str(), head, NULL))){
        S3FS_PRN_ERR("list_bucket returns error.");
        return result; 
    }
    head.GetNameList(headlist);                       // get name without "/".
    S3ObjList::MakeHierarchizedList(headlist, false); // add hierarchized dir.

    s3obj_list_t::const_iterator liter;
    for(liter = headlist.begin(); headlist.end() != liter; ++liter){
        // make "from" and "to" object name.
        std::string from_name = basepath + (*liter);
        std::string to_name   = strto + (*liter);
        std::string etag      = head.GetETag((*liter).c_str());

        // Check subdirectory.
        StatCache::getStatCacheData()->HasStat(from_name, etag.c_str()); // Check ETag
        if(0 != get_object_attribute(from_name.c_str(), &stbuf, NULL)){
            S3FS_PRN_WARN("failed to get %s object attribute.", from_name.c_str());
            continue;
        }
        if(S_ISDIR(stbuf.st_mode)){
            is_dir = true;
            if(0 != chk_dir_object_type(from_name.c_str(), newpath, from_name, nowcache, NULL, &DirType) || DIRTYPE_UNKNOWN == DirType){
                S3FS_PRN_WARN("failed to get %s%s object directory type.", basepath.c_str(), (*liter).c_str());
                continue;
            }
            if(DIRTYPE_NOOBJ != DirType){
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
        if(NULL == add_mvnode(&mn_head, &mn_tail, from_name.c_str(), to_name.c_str(), is_dir, normdir)){
            return -ENOMEM;
        }
    }

    //
    // rename
    //
    // rename directory objects.
    for(mn_cur = mn_head; mn_cur; mn_cur = mn_cur->next){
        if(mn_cur->is_dir && mn_cur->old_path && '\0' != mn_cur->old_path[0]){
            // [NOTE]
            // The ctime is updated only for the top (from) directory.
            // Other than that, it will not be updated.
            //
            if(0 != (result = clone_directory_object(mn_cur->old_path, mn_cur->new_path, (strfrom == mn_cur->old_path)))){
                S3FS_PRN_ERR("clone_directory_object returned an error(%d)", result);
                free_mvnodes(mn_head);
                return result;
            }
        }
    }

    // iterate over the list - copy the files with rename_object
    // does a safe copy - copies first and then deletes old
    for(mn_cur = mn_head; mn_cur; mn_cur = mn_cur->next){
        if(!mn_cur->is_dir){
            if(!nocopyapi && !norenameapi){
                result = rename_object(mn_cur->old_path, mn_cur->new_path, false);          // keep ctime
            }else{
                result = rename_object_nocopy(mn_cur->old_path, mn_cur->new_path, false);   // keep ctime
            }
            if(0 != result){
                S3FS_PRN_ERR("rename_object returned an error(%d)", result);
                free_mvnodes(mn_head);
                return result;
            }
        }
    }

    // Iterate over old the directories, bottoms up and remove
    for(mn_cur = mn_tail; mn_cur; mn_cur = mn_cur->prev){
        if(mn_cur->is_dir && mn_cur->old_path && '\0' != mn_cur->old_path[0]){
            if(!(mn_cur->is_normdir)){
                if(0 != (result = s3fs_rmdir(mn_cur->old_path))){
                    S3FS_PRN_ERR("s3fs_rmdir returned an error(%d)", result);
                    free_mvnodes(mn_head);
                    return result;
                }
            }else{
                // cache clear.
                StatCache::getStatCacheData()->DelStat(mn_cur->old_path);
            }
        }
    }
    free_mvnodes(mn_head);

    return 0;
}

static int s3fs_rename(const char* _from, const char* _to)
{
    WTF8_ENCODE(from)
    WTF8_ENCODE(to)
    struct stat buf;
    int result;

    S3FS_PRN_INFO("[from=%s][to=%s]", from, to);

    if(0 != (result = check_parent_object_access(to, W_OK | X_OK))){
        // not permit writing "to" object parent dir.
        return result;
    }
    if(0 != (result = check_parent_object_access(from, W_OK | X_OK))){
        // not permit removing "from" object parent dir.
        return result;
    }
    if(0 != (result = get_object_attribute(from, &buf, NULL))){
        return result;
    }

    // flush pending writes if file is open
    {   // scope for AutoFdEntity
        AutoFdEntity autoent;
        FdEntity*    ent;
        if(NULL != (ent = autoent.ExistOpen(from))){
            if(0 != (result = ent->Flush(true))){
                S3FS_PRN_ERR("could not upload file(%s): result=%d", to, result);
                return result;
            }
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
    S3FS_MALLOCTRIM(0);

    return result;
}

static int s3fs_link(const char* _from, const char* _to)
{
    WTF8_ENCODE(from)
    WTF8_ENCODE(to)
    S3FS_PRN_INFO("[from=%s][to=%s]", from, to);
    return -ENOTSUP;
}

static int s3fs_chmod(const char* _path, mode_t mode)
{
    WTF8_ENCODE(path)
    int result;
    std::string strpath;
    std::string newpath;
    std::string nowcache;
    headers_t meta;
    struct stat stbuf;
    dirtype nDirType = DIRTYPE_UNKNOWN;

    S3FS_PRN_INFO("[path=%s][mode=%04o]", path, mode);

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
        result = chk_dir_object_type(path, newpath, strpath, nowcache, &meta, &nDirType);
    }else{
        strpath  = path;
        nowcache = strpath;
        result   = get_object_attribute(strpath.c_str(), NULL, &meta);
    }
    if(0 != result){
        return result;
    }

    if(S_ISDIR(stbuf.st_mode) && IS_REPLACEDIR(nDirType)){
        // Should rebuild directory object(except new type)
        // Need to remove old dir("dir" etc) and make new dir("dir/")

        // At first, remove directory old object
        if(0 != (result = remove_old_type_dir(strpath, nDirType))){
            return result;
        }
        StatCache::getStatCacheData()->DelStat(nowcache);

        // Make new directory object("dir/")
        if(0 != (result = create_directory_object(newpath.c_str(), mode, stbuf.st_atime, stbuf.st_mtime, time(NULL), stbuf.st_uid, stbuf.st_gid))){
            return result;
        }
    }else{
        // normal object or directory object of newer version
        headers_t updatemeta;
        updatemeta["x-amz-meta-ctime"]         = str(time(NULL));
        updatemeta["x-amz-meta-mode"]          = str(mode);
        updatemeta["x-amz-copy-source"]        = urlEncode(service_path + bucket + get_realpath(strpath.c_str()));
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
        if(NULL != (ent = autoent.ExistOpen(path, -1, true))){
            if(ent->MergeOrgMeta(updatemeta)){
                // meta is changed, but now uploading.
                // then the meta is pending and accumulated to be put after the upload is complete.
                S3FS_PRN_INFO("meta pending until upload is complete");
                need_put_header = false;
            }
        }
        if(need_put_header){
            // not found opened file.
            merge_headers(meta, updatemeta, true);

            // upload meta directly.
            if(0 != (result = put_headers(strpath.c_str(), meta, true))){
                return result;
            }
            StatCache::getStatCacheData()->DelStat(nowcache);
        }
    }
    S3FS_MALLOCTRIM(0);

    return 0;
}

static int s3fs_chmod_nocopy(const char* _path, mode_t mode)
{
    WTF8_ENCODE(path)
    int         result;
    std::string strpath;
    std::string newpath;
    std::string nowcache;
    struct stat stbuf;
    dirtype     nDirType = DIRTYPE_UNKNOWN;

    S3FS_PRN_INFO1("[path=%s][mode=%04o]", path, mode);

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

    // Get attributes
    if(S_ISDIR(stbuf.st_mode)){
        result = chk_dir_object_type(path, newpath, strpath, nowcache, NULL, &nDirType);
    }else{
        strpath  = path;
        nowcache = strpath;
        result   = get_object_attribute(strpath.c_str(), NULL, NULL);
    }
    if(0 != result){
        return result;
    }

    if(S_ISDIR(stbuf.st_mode)){
        // Should rebuild all directory object
        // Need to remove old dir("dir" etc) and make new dir("dir/")

        // At first, remove directory old object
        if(0 != (result = remove_old_type_dir(strpath, nDirType))){
            return result;
        }
        StatCache::getStatCacheData()->DelStat(nowcache);

        // Make new directory object("dir/")
        if(0 != (result = create_directory_object(newpath.c_str(), mode, stbuf.st_atime, stbuf.st_mtime, time(NULL), stbuf.st_uid, stbuf.st_gid))){
            return result;
        }
    }else{
        // normal object or directory object of newer version

        // open & load
        AutoFdEntity autoent;
        FdEntity*    ent;
        if(0 != (result = get_local_fent(autoent, &ent, strpath.c_str(), true))){
            S3FS_PRN_ERR("could not open and read file(%s)", strpath.c_str());
            return result;
        }

        ent->SetCtime(time(NULL));

        // Change file mode
        ent->SetMode(mode);

        // upload
        if(0 != (result = ent->Flush(true))){
            S3FS_PRN_ERR("could not upload file(%s): result=%d", strpath.c_str(), result);
            return result;
        }
        StatCache::getStatCacheData()->DelStat(nowcache);
    }
    S3FS_MALLOCTRIM(0);
  
    return result;
}

static int s3fs_chown(const char* _path, uid_t uid, gid_t gid)
{
    WTF8_ENCODE(path)
    int result;
    std::string strpath;
    std::string newpath;
    std::string nowcache;
    headers_t meta;
    struct stat stbuf;
    dirtype nDirType = DIRTYPE_UNKNOWN;

    S3FS_PRN_INFO("[path=%s][uid=%u][gid=%u]", path, (unsigned int)uid, (unsigned int)gid);

    if(0 == strcmp(path, "/")){
        S3FS_PRN_ERR("Could not change owner for mount point.");
        return -EIO;
    }
    if(0 != (result = check_parent_object_access(path, X_OK))){
        return result;
    }
    if(0 != (result = check_object_owner(path, &stbuf))){
        return result;
    }

    if((uid_t)(-1) == uid){
        uid = stbuf.st_uid;
    }
    if((gid_t)(-1) == gid){
        gid = stbuf.st_gid;
    }
    if(S_ISDIR(stbuf.st_mode)){
        result = chk_dir_object_type(path, newpath, strpath, nowcache, &meta, &nDirType);
    }else{
        strpath  = path;
        nowcache = strpath;
        result   = get_object_attribute(strpath.c_str(), NULL, &meta);
    }
    if(0 != result){
        return result;
    }

    if(S_ISDIR(stbuf.st_mode) && IS_REPLACEDIR(nDirType)){
        // Should rebuild directory object(except new type)
        // Need to remove old dir("dir" etc) and make new dir("dir/")

        // At first, remove directory old object
        if(0 != (result = remove_old_type_dir(strpath, nDirType))){
            return result;
        }
        StatCache::getStatCacheData()->DelStat(nowcache);

        // Make new directory object("dir/")
        if(0 != (result = create_directory_object(newpath.c_str(), stbuf.st_mode, stbuf.st_atime, stbuf.st_mtime, time(NULL), uid, gid))){
            return result;
        }
    }else{
        headers_t updatemeta;
        updatemeta["x-amz-meta-ctime"]         = str(time(NULL));
        updatemeta["x-amz-meta-uid"]           = str(uid);
        updatemeta["x-amz-meta-gid"]           = str(gid);
        updatemeta["x-amz-copy-source"]        = urlEncode(service_path + bucket + get_realpath(strpath.c_str()));
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
        if(NULL != (ent = autoent.ExistOpen(path, -1, true))){
            if(ent->MergeOrgMeta(updatemeta)){
                // meta is changed, but now uploading.
                // then the meta is pending and accumulated to be put after the upload is complete.
                S3FS_PRN_INFO("meta pending until upload is complete");
                need_put_header = false;
            }
        }
        if(need_put_header){
            // not found opened file.
            merge_headers(meta, updatemeta, true);

            // upload meta directly.
            if(0 != (result = put_headers(strpath.c_str(), meta, true))){
                return result;
            }
            StatCache::getStatCacheData()->DelStat(nowcache);
        }
    }
    S3FS_MALLOCTRIM(0);

    return 0;
}

static int s3fs_chown_nocopy(const char* _path, uid_t uid, gid_t gid)
{
    WTF8_ENCODE(path)
    int         result;
    std::string strpath;
    std::string newpath;
    std::string nowcache;
    struct stat stbuf;
    dirtype     nDirType = DIRTYPE_UNKNOWN;

    S3FS_PRN_INFO1("[path=%s][uid=%u][gid=%u]", path, (unsigned int)uid, (unsigned int)gid);

    if(0 == strcmp(path, "/")){
        S3FS_PRN_ERR("Could not change owner for mount point.");
        return -EIO;
    }
    if(0 != (result = check_parent_object_access(path, X_OK))){
        return result;
    }
    if(0 != (result = check_object_owner(path, &stbuf))){
        return result;
    }

    if((uid_t)(-1) == uid){
        uid = stbuf.st_uid;
    }
    if((gid_t)(-1) == gid){
        gid = stbuf.st_gid;
    }

    // Get attributes
    if(S_ISDIR(stbuf.st_mode)){
        result = chk_dir_object_type(path, newpath, strpath, nowcache, NULL, &nDirType);
    }else{
        strpath  = path;
        nowcache = strpath;
        result   = get_object_attribute(strpath.c_str(), NULL, NULL);
    }
    if(0 != result){
        return result;
    }

    if(S_ISDIR(stbuf.st_mode)){
        // Should rebuild all directory object
        // Need to remove old dir("dir" etc) and make new dir("dir/")

        // At first, remove directory old object
        if(0 != (result = remove_old_type_dir(strpath, nDirType))){
            return result;
        }
        StatCache::getStatCacheData()->DelStat(nowcache);

        // Make new directory object("dir/")
        if(0 != (result = create_directory_object(newpath.c_str(), stbuf.st_mode, stbuf.st_atime, stbuf.st_mtime, time(NULL), uid, gid))){
            return result;
        }
    }else{
        // normal object or directory object of newer version

        // open & load
        AutoFdEntity autoent;
        FdEntity*    ent;
        if(0 != (result = get_local_fent(autoent, &ent, strpath.c_str(), true))){
            S3FS_PRN_ERR("could not open and read file(%s)", strpath.c_str());
            return result;
        }

        ent->SetCtime(time(NULL));

        // Change owner
        ent->SetUId(uid);
        ent->SetGId(gid);
  
        // upload
        if(0 != (result = ent->Flush(true))){
            S3FS_PRN_ERR("could not upload file(%s): result=%d", strpath.c_str(), result);
            return result;
        }
        StatCache::getStatCacheData()->DelStat(nowcache);
    }
    S3FS_MALLOCTRIM(0);
  
    return result;
}

static int s3fs_utimens(const char* _path, const struct timespec ts[2])
{
    WTF8_ENCODE(path)
    int result;
    std::string strpath;
    std::string newpath;
    std::string nowcache;
    headers_t meta;
    struct stat stbuf;
    dirtype nDirType = DIRTYPE_UNKNOWN;

    S3FS_PRN_INFO("[path=%s][mtime=%lld][ctime/atime=%lld]", path, static_cast<long long>(ts[1].tv_sec), static_cast<long long>(ts[0].tv_sec));

    if(0 == strcmp(path, "/")){
        S3FS_PRN_ERR("Could not change mtime for mount point.");
        return -EIO;
    }
    if(0 != (result = check_parent_object_access(path, X_OK))){
        return result;
    }
    if(0 != (result = check_object_access(path, W_OK, &stbuf))){
        if(0 != check_object_owner(path, &stbuf)){
            return result;
        }
    }

    if(S_ISDIR(stbuf.st_mode)){
        result = chk_dir_object_type(path, newpath, strpath, nowcache, &meta, &nDirType);
    }else{
        strpath  = path;
        nowcache = strpath;
        result   = get_object_attribute(strpath.c_str(), NULL, &meta);
    }
    if(0 != result){
        return result;
    }

    if(S_ISDIR(stbuf.st_mode) && IS_REPLACEDIR(nDirType)){
        // Should rebuild directory object(except new type)
        // Need to remove old dir("dir" etc) and make new dir("dir/")

        // At first, remove directory old object
        if(0 != (result = remove_old_type_dir(strpath, nDirType))){
            return result;
        }
        StatCache::getStatCacheData()->DelStat(nowcache);

        // Make new directory object("dir/")
        if(0 != (result = create_directory_object(newpath.c_str(), stbuf.st_mode, ts[0].tv_sec, ts[1].tv_sec, ts[0].tv_sec, stbuf.st_uid, stbuf.st_gid))){
            return result;
        }
    }else{
        headers_t updatemeta;
        updatemeta["x-amz-meta-mtime"]         = str(ts[1].tv_sec);
        updatemeta["x-amz-meta-ctime"]         = str(ts[0].tv_sec);
        updatemeta["x-amz-meta-atime"]         = str(ts[0].tv_sec);
        updatemeta["x-amz-copy-source"]        = urlEncode(service_path + bucket + get_realpath(strpath.c_str()));
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
        bool         keep_mtime      = false;
        if(NULL != (ent = autoent.ExistOpen(path, -1, true))){
            if(ent->MergeOrgMeta(updatemeta)){
                // meta is changed, but now uploading.
                // then the meta is pending and accumulated to be put after the upload is complete.
                S3FS_PRN_INFO("meta pending until upload is complete");
                need_put_header = false;

            }else{
                S3FS_PRN_INFO("meta is not pending, but need to keep current mtime.");

                // [NOTE]
                // Depending on the order in which write/flush and utimens are called,
                // the mtime updated here may be overwritten at the time of flush.
                // To avoid that, set a special flag.
                //
                keep_mtime = true;
            }
        }
        if(need_put_header){
            // not found opened file.
            merge_headers(meta, updatemeta, true);

            // upload meta directly.
            if(0 != (result = put_headers(strpath.c_str(), meta, true))){
                return result;
            }
            StatCache::getStatCacheData()->DelStat(nowcache);

            if(keep_mtime){
                ent->SetHoldingMtime(ts[1].tv_sec);     // ts[1].tv_sec is mtime
            }
        }
    }
    S3FS_MALLOCTRIM(0);

    return 0;
}

static int s3fs_utimens_nocopy(const char* _path, const struct timespec ts[2])
{
    WTF8_ENCODE(path)
    int         result;
    std::string strpath;
    std::string newpath;
    std::string nowcache;
    struct stat stbuf;
    dirtype     nDirType = DIRTYPE_UNKNOWN;

    S3FS_PRN_INFO1("[path=%s][mtime=%lld][atime/ctime=%lld]", path, static_cast<long long>(ts[1].tv_sec), static_cast<long long>(ts[0].tv_sec));

    if(0 == strcmp(path, "/")){
        S3FS_PRN_ERR("Could not change mtime for mount point.");
        return -EIO;
    }
    if(0 != (result = check_parent_object_access(path, X_OK))){
        return result;
    }
    if(0 != (result = check_object_access(path, W_OK, &stbuf))){
        if(0 != check_object_owner(path, &stbuf)){
            return result;
        }
    }

    // Get attributes
    if(S_ISDIR(stbuf.st_mode)){
        result = chk_dir_object_type(path, newpath, strpath, nowcache, NULL, &nDirType);
    }else{
        strpath  = path;
        nowcache = strpath;
        result   = get_object_attribute(strpath.c_str(), NULL, NULL);
    }
    if(0 != result){
        return result;
    }

    if(S_ISDIR(stbuf.st_mode)){
        // Should rebuild all directory object
        // Need to remove old dir("dir" etc) and make new dir("dir/")

        // At first, remove directory old object
        if(0 != (result = remove_old_type_dir(strpath, nDirType))){
            return result;
        }
        StatCache::getStatCacheData()->DelStat(nowcache);

        // Make new directory object("dir/")
        if(0 != (result = create_directory_object(newpath.c_str(), stbuf.st_mode, ts[0].tv_sec, ts[1].tv_sec, ts[0].tv_sec, stbuf.st_uid, stbuf.st_gid))){
            return result;
        }
    }else{
        // normal object or directory object of newer version

        // open & load
        AutoFdEntity autoent;
        FdEntity*    ent;
        if(0 != (result = get_local_fent(autoent, &ent, strpath.c_str(), true))){
            S3FS_PRN_ERR("could not open and read file(%s)", strpath.c_str());
            return result;
        }

        // set mtime/ctime
        if(0 != (result = ent->SetMCtime(ts[1].tv_sec, ts[0].tv_sec))){
            S3FS_PRN_ERR("could not set mtime and ctime to file(%s): result=%d", strpath.c_str(), result);
            return result;
        }

        // set atime
        if(0 != (result = ent->SetAtime(ts[0].tv_sec))){
            S3FS_PRN_ERR("could not set atime to file(%s): result=%d", strpath.c_str(), result);
            return result;
        }

        // upload
        if(0 != (result = ent->Flush(true))){
            S3FS_PRN_ERR("could not upload file(%s): result=%d", strpath.c_str(), result);
            return result;
        }
        StatCache::getStatCacheData()->DelStat(nowcache);
    }
    S3FS_MALLOCTRIM(0);

    return result;
}

static int s3fs_truncate(const char* _path, off_t size)
{
    WTF8_ENCODE(path)
    int          result;
    headers_t    meta;
    AutoFdEntity autoent;
    FdEntity*    ent = NULL;

    S3FS_PRN_INFO("[path=%s][size=%lld]", path, static_cast<long long>(size));

    if(size < 0){
        size = 0;
    }

    if(0 != (result = check_parent_object_access(path, X_OK))){
        return result;
    }
    if(0 != (result = check_object_access(path, W_OK, NULL))){
        return result;
    }

    // Get file information
    if(0 == (result = get_object_attribute(path, NULL, &meta))){
        // Exists -> Get file(with size)
        if(NULL == (ent = autoent.Open(path, &meta, size, -1, false, true))){
            S3FS_PRN_ERR("could not open file(%s): errno=%d", path, errno);
            return -EIO;
        }
        if(0 != (result = ent->Load(0, size))){
            S3FS_PRN_ERR("could not download file(%s): result=%d", path, result);
            return result;
        }

    }else{
        // Not found -> Make tmpfile(with size)

        struct fuse_context* pcxt;
        if(NULL == (pcxt = fuse_get_context())){
            return -EIO;
        }
        time_t now = time(NULL);
        meta["Content-Type"]     = std::string("application/octet-stream"); // Static
        meta["x-amz-meta-mode"]  = str(S_IFLNK | S_IRWXU | S_IRWXG | S_IRWXO);
        meta["x-amz-meta-ctime"] = str(now);
        meta["x-amz-meta-mtime"] = str(now);
        meta["x-amz-meta-uid"]   = str(pcxt->uid);
        meta["x-amz-meta-gid"]   = str(pcxt->gid);

        if(NULL == (ent = autoent.Open(path, &meta, size, -1, true, true))){
            S3FS_PRN_ERR("could not open file(%s): errno=%d", path, errno);
            return -EIO;
        }
    }

    // upload
    if(0 != (result = ent->Flush(true))){
        S3FS_PRN_ERR("could not upload file(%s): result=%d", path, result);
        return result;
    }

    StatCache::getStatCacheData()->DelStat(path);
    S3FS_MALLOCTRIM(0);

    return result;
}

static int s3fs_open(const char* _path, struct fuse_file_info* fi)
{
    WTF8_ENCODE(path)
    int result;
    struct stat st;
    bool needs_flush = false;

    S3FS_PRN_INFO("[path=%s][flags=0x%x]", path, fi->flags);

    // clear stat for reading fresh stat.
    // (if object stat is changed, we refresh it. then s3fs gets always
    // stat when s3fs open the object).
    if(StatCache::getStatCacheData()->HasStat(path)){
        // flush any dirty data so that subsequent stat gets correct size
        if((result = s3fs_flush(_path, fi)) != 0){
            S3FS_PRN_ERR("could not flush(%s): result=%d", path, result);
        }
        StatCache::getStatCacheData()->DelStat(path);
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

    if((unsigned int)fi->flags & O_TRUNC){
        if(0 != st.st_size){
            st.st_size = 0;
            needs_flush = true;
        }
    }
    if(!S_ISREG(st.st_mode) || S_ISLNK(st.st_mode)){
        st.st_mtime = -1;
    }

    AutoFdEntity autoent;
    FdEntity*    ent;
    headers_t    meta;
    get_object_attribute(path, NULL, &meta, true, NULL, true);    // no truncate cache
    if(NULL == (ent = autoent.Open(path, &meta, st.st_size, st.st_mtime, false, true))){
        StatCache::getStatCacheData()->DelStat(path);
        return -EIO;
    }

    if (needs_flush){
        if(0 != (result = ent->RowFlush(path, true))){
            S3FS_PRN_ERR("could not upload file(%s): result=%d", path, result);
            StatCache::getStatCacheData()->DelStat(path);
            return result;
        }
    }
    autoent.Detach();       // KEEP fdentity open
    fi->fh = ent->GetFd();

    S3FS_MALLOCTRIM(0);

    return 0;
}

static int s3fs_read(const char* _path, char* buf, size_t size, off_t offset, struct fuse_file_info* fi)
{
    WTF8_ENCODE(path)
    ssize_t res;

    S3FS_PRN_DBG("[path=%s][size=%zu][offset=%lld][fd=%llu]", path, size, static_cast<long long>(offset), (unsigned long long)(fi->fh));

    AutoFdEntity autoent;
    FdEntity*    ent;
    if(NULL == (ent = autoent.ExistOpen(path, static_cast<int>(fi->fh)))){
        S3FS_PRN_ERR("could not find opened fd(%s)", path);
        return -EIO;
    }
    if(ent->GetFd() != static_cast<int>(fi->fh)){
        S3FS_PRN_WARN("different fd(%d - %llu)", ent->GetFd(), (unsigned long long)(fi->fh));
    }

    // check real file size
    off_t realsize = 0;
    if(!ent->GetSize(realsize) || 0 == realsize){
        S3FS_PRN_DBG("file size is 0, so break to read.");
        return 0;
    }

    if(0 > (res = ent->Read(buf, offset, size, false))){
        S3FS_PRN_WARN("failed to read file(%s). result=%zd", path, res);
    }

    return static_cast<int>(res);
}

static int s3fs_write(const char* _path, const char* buf, size_t size, off_t offset, struct fuse_file_info* fi)
{
    WTF8_ENCODE(path)
    ssize_t res;

    S3FS_PRN_DBG("[path=%s][size=%zu][offset=%lld][fd=%llu]", path, size, static_cast<long long int>(offset), (unsigned long long)(fi->fh));

    AutoFdEntity autoent;
    FdEntity*    ent;
    if(NULL == (ent = autoent.ExistOpen(path, static_cast<int>(fi->fh)))){
        S3FS_PRN_ERR("could not find opened fd(%s)", path);
        return -EIO;
    }
    if(ent->GetFd() != static_cast<int>(fi->fh)){
        S3FS_PRN_WARN("different fd(%d - %llu)", ent->GetFd(), (unsigned long long)(fi->fh));
    }
    if(0 > (res = ent->Write(buf, offset, size))){
        S3FS_PRN_WARN("failed to write file(%s). result=%zd", path, res);
    }

    if(max_dirty_data != -1 && ent->BytesModified() >= max_dirty_data){
        int flushres;
        if(0 != (flushres = ent->RowFlush(path, true))){
            S3FS_PRN_ERR("could not upload file(%s): result=%d", path, flushres);
            StatCache::getStatCacheData()->DelStat(path);
            return -EIO;
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
    // 256T
    stbuf->f_bsize  = 0X1000000;
    stbuf->f_blocks = 0X1000000;
    stbuf->f_bfree  = 0x1000000;
    stbuf->f_bavail = 0x1000000;
    stbuf->f_namemax = NAME_MAX;
    return 0;
}

static int s3fs_flush(const char* _path, struct fuse_file_info* fi)
{
    WTF8_ENCODE(path)
    int result;

    S3FS_PRN_INFO("[path=%s][fd=%llu]", path, (unsigned long long)(fi->fh));

    int mask = (O_RDONLY != (fi->flags & O_ACCMODE) ? W_OK : R_OK);
    if(0 != (result = check_parent_object_access(path, X_OK))){
        return result;
    }
    result = check_object_access(path, mask, NULL);
    if(-ENOENT == result){
        if(0 != (result = check_parent_object_access(path, W_OK))){
            return result;
        }
    }else if(0 != result){
        return result;
    }

    AutoFdEntity autoent;
    FdEntity*    ent;
    if(NULL != (ent = autoent.ExistOpen(path, static_cast<int>(fi->fh)))){
        ent->UpdateMtime(true);         // clear the flag not to update mtime.
        ent->UpdateCtime();
        result = ent->Flush(false);
    }
    S3FS_MALLOCTRIM(0);

    return result;
}

// [NOTICE]
// Assumption is a valid fd.
//
static int s3fs_fsync(const char* _path, int datasync, struct fuse_file_info* fi)
{
    WTF8_ENCODE(path)
    int result = 0;

    S3FS_PRN_INFO("[path=%s][fd=%llu]", path, (unsigned long long)(fi->fh));

    AutoFdEntity autoent;
    FdEntity*    ent;
    if(NULL != (ent = autoent.ExistOpen(path, static_cast<int>(fi->fh)))){
        if(0 == datasync){
            ent->UpdateMtime();
            ent->UpdateCtime();
        }
        result = ent->Flush(false);
    }
    S3FS_MALLOCTRIM(0);

    // Issue 320: Delete stat cache entry because st_size may have changed.
    StatCache::getStatCacheData()->DelStat(path);

    return result;
}

static int s3fs_release(const char* _path, struct fuse_file_info* fi)
{
    WTF8_ENCODE(path)
    S3FS_PRN_INFO("[path=%s][fd=%llu]", path, (unsigned long long)(fi->fh));

    // [NOTE]
    // All opened file's stats is cached with no truncate flag.
    // Thus we unset it here.
    StatCache::getStatCacheData()->ChangeNoTruncateFlag(std::string(path), false);

    // [NOTICE]
    // At first, we remove stats cache.
    // Because fuse does not wait for response from "release" function. :-(
    // And fuse runs next command before this function returns.
    // Thus we call deleting stats function ASSAP.
    //
    if((fi->flags & O_RDWR) || (fi->flags & O_WRONLY)){
        StatCache::getStatCacheData()->DelStat(path);
    }

    {   // scope for AutoFdEntity
        AutoFdEntity autoent;
        FdEntity*    ent;

        // [NOTE]
        // The number of references to fdEntity corresponding to fi-> fh is already incremented
        // when it is opened. Therefore, when an existing fdEntity is detected here, the reference
        // count must not be incremented. And if detected, the number of references incremented
        // when opened will be decremented when the AutoFdEntity object is subsequently destroyed.
        //
        if(NULL == (ent = autoent.GetFdEntity(path, static_cast<int>(fi->fh), false))){
            S3FS_PRN_ERR("could not find fd(file=%s)", path);
            return -EIO;
        }
        if(ent->GetFd() != static_cast<int>(fi->fh)){
            S3FS_PRN_WARN("different fd(%d - %llu)", ent->GetFd(), (unsigned long long)(fi->fh));
        }
    }

    // check - for debug
    if(S3fsLog::IsS3fsLogDbg()){
        AutoFdEntity autoent;
        FdEntity*    ent;
        if(NULL != (ent = autoent.GetFdEntity(path, static_cast<int>(fi->fh)))){
            S3FS_PRN_WARN("file(%s),fd(%d) is still opened.", path, ent->GetFd());
        }
    }
    S3FS_MALLOCTRIM(0);

    return 0;
}

static int s3fs_opendir(const char* _path, struct fuse_file_info* fi)
{
    WTF8_ENCODE(path)
    int result;
    int mask = (O_RDONLY != (fi->flags & O_ACCMODE) ? W_OK : R_OK);

    S3FS_PRN_INFO("[path=%s][flags=0x%x]", path, fi->flags);

    if(0 == (result = check_object_access(path, mask, NULL))){
        result = check_parent_object_access(path, X_OK);
    }
    S3FS_MALLOCTRIM(0);

    return result;
}

static bool multi_head_callback(S3fsCurl* s3fscurl)
{
    if(!s3fscurl){
        return false;
    }
    std::string saved_path = s3fscurl->GetSpacialSavedPath();
    if(!StatCache::getStatCacheData()->AddStat(saved_path, *(s3fscurl->GetResponseHeaders()))){
        S3FS_PRN_ERR("failed adding stat cache [path=%s]", saved_path.c_str());
        return false;
    }
    return true;
}

static S3fsCurl* multi_head_retry_callback(S3fsCurl* s3fscurl)
{
    if(!s3fscurl){
        return NULL;
    }
    int ssec_key_pos= s3fscurl->GetLastPreHeadSeecKeyPos();
    int retry_count = s3fscurl->GetMultipartRetryCount();

    // retry next sse key.
    // if end of sse key, set retry master count is up.
    ssec_key_pos = (ssec_key_pos < 0 ? 0 : ssec_key_pos + 1);
    if(0 == S3fsCurl::GetSseKeyCount() || S3fsCurl::GetSseKeyCount() <= ssec_key_pos){
        if(s3fscurl->IsOverMultipartRetryCount()){
            S3FS_PRN_ERR("Over retry count(%d) limit(%s).", s3fscurl->GetMultipartRetryCount(), s3fscurl->GetSpacialSavedPath().c_str());
            return NULL;
        }
        ssec_key_pos= -1;
        retry_count++;
    }

    S3fsCurl* newcurl = new S3fsCurl(s3fscurl->IsUseAhbe());
    std::string path       = s3fscurl->GetPath();
    std::string base_path  = s3fscurl->GetBasePath();
    std::string saved_path = s3fscurl->GetSpacialSavedPath();

    if(!newcurl->PreHeadRequest(path, base_path, saved_path, ssec_key_pos)){
        S3FS_PRN_ERR("Could not duplicate curl object(%s).", saved_path.c_str());
        delete newcurl;
        return NULL;
    }
    newcurl->SetMultipartRetryCount(retry_count);

    return newcurl;
}

static int readdir_multi_head(const char* path, const S3ObjList& head, void* buf, fuse_fill_dir_t filler)
{
    S3fsMultiCurl curlmulti(S3fsCurl::GetMaxMultiRequest());
    s3obj_list_t  headlist;
    s3obj_list_t  fillerlist;
    int           result = 0;

    S3FS_PRN_INFO1("[path=%s][list=%zu]", path, headlist.size());

    // Make base path list.
    head.GetNameList(headlist, true, false);  // get name with "/".

    // Initialize S3fsMultiCurl
    curlmulti.SetSuccessCallback(multi_head_callback);
    curlmulti.SetRetryCallback(multi_head_retry_callback);

    s3obj_list_t::iterator iter;

    fillerlist.clear();
    // Make single head request(with max).
    for(iter = headlist.begin(); headlist.end() != iter; iter = headlist.erase(iter)){
        std::string disppath = path + (*iter);
        std::string etag     = head.GetETag((*iter).c_str());

        std::string fillpath = disppath;
        if('/' == disppath[disppath.length() - 1]){
            fillpath.erase(fillpath.length() -1);
        }
        fillerlist.push_back(fillpath);

        if(StatCache::getStatCacheData()->HasStat(disppath, etag.c_str())){
            continue;
        }

        // First check for directory, start checking "not SSE-C".
        // If checking failed, retry to check with "SSE-C" by retry callback func when SSE-C mode.
        S3fsCurl* s3fscurl = new S3fsCurl();
        if(!s3fscurl->PreHeadRequest(disppath, (*iter), disppath)){  // target path = cache key path.(ex "dir/")
            S3FS_PRN_WARN("Could not make curl object for head request(%s).", disppath.c_str());
            delete s3fscurl;
            continue;
        }

        if(!curlmulti.SetS3fsCurlObject(s3fscurl)){
            S3FS_PRN_WARN("Could not make curl object into multi curl(%s).", disppath.c_str());
            delete s3fscurl;
            continue;
        }
    }

    // Multi request
    if(0 != (result = curlmulti.Request())){
        // If result is -EIO, it is something error occurred.
        // This case includes that the object is encrypting(SSE) and s3fs does not have keys.
        // So s3fs set result to 0 in order to continue the process.
        if(-EIO == result){
            S3FS_PRN_WARN("error occurred in multi request(errno=%d), but continue...", result);
            result = 0;
        }else{
            S3FS_PRN_ERR("error occurred in multi request(errno=%d).", result);
            return result;
        }
    }

    // populate fuse buffer
    // here is best position, because a case is cache size < files in directory
    //
    for(iter = fillerlist.begin(); fillerlist.end() != iter; ++iter){
        struct stat st;
        bool in_cache = StatCache::getStatCacheData()->GetStat((*iter), &st);
        std::string bpath = mybasename((*iter));
        if(use_wtf8){
            bpath = s3fs_wtf8_decode(bpath);
        }
        if(in_cache){
            filler(buf, bpath.c_str(), &st, 0);
        }else{
            S3FS_PRN_INFO2("Could not find %s file in stat cache.", (*iter).c_str());
            filler(buf, bpath.c_str(), 0, 0);
        }
    }

    return result;
}

static int s3fs_readdir(const char* _path, void* buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info* fi)
{
    WTF8_ENCODE(path)
    S3ObjList head;
    int result;

    S3FS_PRN_INFO("[path=%s]", path);

    if(0 != (result = check_object_access(path, R_OK, NULL))){
        return result;
    }

    // get a list of all the objects
    if((result = list_bucket(path, head, "/")) != 0){
        S3FS_PRN_ERR("list_bucket returns error(%d).", result);
        return result;
    }

    // force to add "." and ".." name.
    filler(buf, ".", 0, 0);
    filler(buf, "..", 0, 0);
    if(head.IsEmpty()){
        return 0;
    }

    // Send multi head request for stats caching.
    std::string strpath = path;
    if(strcmp(path, "/") != 0){
        strpath += "/";
    }
    if(0 != (result = readdir_multi_head(strpath.c_str(), head, buf, filler))){
        S3FS_PRN_ERR("readdir_multi_head returns error(%d).", result);
    }
    S3FS_MALLOCTRIM(0);

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
    S3fsCurl  s3fscurl;
    xmlDocPtr doc;

    S3FS_PRN_INFO1("[path=%s]", path);

    if(delimiter && 0 < strlen(delimiter)){
        query_delimiter += "delimiter=";
        query_delimiter += delimiter;
        query_delimiter += "&";
    }

    query_prefix += "&prefix=";
    s3_realpath = get_realpath(path);
    if(0 == s3_realpath.length() || '/' != s3_realpath[s3_realpath.length() - 1]){
        // last word must be "/"
        query_prefix += urlEncode(s3_realpath.substr(1) + "/");
    }else{
        query_prefix += urlEncode(s3_realpath.substr(1));
    }
    if (check_content_only){
        // Just need to know if there are child objects in dir
        // For dir with children, expect "dir/" and "dir/child"
        query_maxkey += "max-keys=2";
    }else{
        query_maxkey += "max-keys=" + str(max_keys_list_object);
    }

    while(truncated){
        // append parameters to query in alphabetical order
        std::string each_query = "";
        if(!next_continuation_token.empty()){
            each_query += "continuation-token=" + urlEncode(next_continuation_token) + "&";
            next_continuation_token = "";
        }
        each_query += query_delimiter;
        if(S3fsCurl::IsListObjectsV2()){
            each_query += "list-type=2&";
        }
        if(!next_marker.empty()){
            each_query += "marker=" + urlEncode(next_marker) + "&";
            next_marker = "";
        }
        each_query += query_maxkey;
        each_query += query_prefix;

        // request
        int result; 
        if(0 != (result = s3fscurl.ListBucketRequest(path, each_query.c_str()))){
            S3FS_PRN_ERR("ListBucketRequest returns with error.");
            return result;
        }
        BodyData* body = s3fscurl.GetBodyData();

        // xmlDocPtr
        if(NULL == (doc = xmlReadMemory(body->str(), static_cast<int>(body->size()), "", NULL, 0))){
            S3FS_PRN_ERR("xmlReadMemory returns with error.");
            return -EIO;
        }
        if(0 != append_objects_from_xml(path, doc, head)){
            S3FS_PRN_ERR("append_objects_from_xml returns with error.");
            xmlFreeDoc(doc);
            return -EIO;
        }
        if(true == (truncated = is_truncated(doc))){
            xmlChar* tmpch;
            if(NULL != (tmpch = get_next_contination_token(doc))){
                next_continuation_token = (char*)tmpch;
                xmlFree(tmpch);
            }else if(NULL != (tmpch = get_next_marker(doc))){
                next_marker = (char*)tmpch;
                xmlFree(tmpch);
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
                    if(0 == s3_realpath.length() || '/' != s3_realpath[s3_realpath.length() - 1]){
                        next_marker += "/";
                    }
                    next_marker += lastname;
                }
            }
        }
        S3FS_XMLFREEDOC(doc);

        // reset(initialize) curl object
        s3fscurl.DestroyCurlHandle();

        if(check_content_only){
            break;
        }
    }
    S3FS_MALLOCTRIM(0);

    return 0;
}

static int remote_mountpath_exists(const char* path)
{
    struct stat stbuf;
    int result;

    S3FS_PRN_INFO1("[path=%s]", path);

    // getattr will prefix the path with the remote mountpoint
    if(0 != (result = get_object_attribute("/", &stbuf, NULL))){
        return result;
    }
    if(!S_ISDIR(stbuf.st_mode)){
        return -ENOTDIR;
    }
    return 0;
}


static void free_xattrs(xattrs_t& xattrs)
{
    for(xattrs_t::iterator iter = xattrs.begin(); iter != xattrs.end(); ++iter){
        delete iter->second;
    }
    xattrs.clear();
}

static bool parse_xattr_keyval(const std::string& xattrpair, std::string& key, PXATTRVAL& pval)
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

    pval = new XATTRVAL;
    pval->length = 0;
    pval->pvalue = s3fs_decode64(tmpval.c_str(), &pval->length);

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
    for(size_t pair_nextpos = restxattrs.find_first_of(','); 0 < restxattrs.length(); restxattrs = (pair_nextpos != std::string::npos ? restxattrs.substr(pair_nextpos + 1) : std::string("")), pair_nextpos = restxattrs.find_first_of(',')){
        std::string pair = pair_nextpos != std::string::npos ? restxattrs.substr(0, pair_nextpos) : restxattrs;
        std::string key;
        PXATTRVAL pval = NULL;
        if(!parse_xattr_keyval(pair, key, pval)){
            // something format error, so skip this.
            continue;
        }
        xattrs[key] = pval;
    }
    return xattrs.size();
}

static std::string build_xattrs(const xattrs_t& xattrs)
{
    std::string strxattrs("{");

    bool is_set = false;
    for(xattrs_t::const_iterator iter = xattrs.begin(); iter != xattrs.end(); ++iter){
        if(is_set){
            strxattrs += ',';
        }else{
            is_set = true;
        }
        strxattrs += '\"';
        strxattrs += iter->first;
        strxattrs += "\":\"";

        if(iter->second){
            char* base64val = s3fs_base64((iter->second)->pvalue, (iter->second)->length);
            if(base64val){
                strxattrs += base64val;
                delete[] base64val;
            }
        }
        strxattrs += '\"';
    }
    strxattrs += '}';

    strxattrs = urlEncode(strxattrs);

    return strxattrs;
}

static int set_xattrs_to_header(headers_t& meta, const char* name, const char* value, size_t size, int flags)
{
    std::string strxattrs;
    xattrs_t xattrs;

    headers_t::iterator iter;
    if(meta.end() == (iter = meta.find("x-amz-meta-xattr"))){
#if defined(XATTR_REPLACE)
        if(XATTR_REPLACE == (flags & XATTR_REPLACE)){
            // there is no xattr header but flags is replace, so failure.
            return -ENOATTR;
        }
#endif
    }else{
#if defined(XATTR_CREATE)
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
    xattrs_t::iterator xiter;
    if(xattrs.end() != (xiter = xattrs.find(std::string(name)))){
        // found same head. free value.
        delete xiter->second;
    }

    PXATTRVAL pval = new XATTRVAL;
    pval->length = size;
    if(0 < size){
        pval->pvalue = new unsigned char[size];
        memcpy(pval->pvalue, value, size);
    }else{
        pval->pvalue = NULL;
    }
    xattrs[std::string(name)] = pval;

    // build new strxattrs(not encoded) and set it to headers_t
    meta["x-amz-meta-xattr"] = build_xattrs(xattrs);

    free_xattrs(xattrs);

    return 0;
}

#if defined(__APPLE__)
static int s3fs_setxattr(const char* path, const char* name, const char* value, size_t size, int flags, uint32_t position)
#else
static int s3fs_setxattr(const char* path, const char* name, const char* value, size_t size, int flags)
#endif
{
    S3FS_PRN_INFO("[path=%s][name=%s][value=%p][size=%zu][flags=0x%x]", path, name, value, size, flags);

    if((value && 0 == size) || (!value && 0 < size)){
        S3FS_PRN_ERR("Wrong parameter: value(%p), size(%zu)", value, size);
        return 0;
    }

#if defined(__APPLE__)
    if (position != 0) {
        // No resource fork support
        return -EINVAL;
    }
#endif

    int         result;
    std::string strpath;
    std::string newpath;
    std::string nowcache;
    headers_t   meta;
    struct stat stbuf;
    dirtype     nDirType = DIRTYPE_UNKNOWN;

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
        result = chk_dir_object_type(path, newpath, strpath, nowcache, &meta, &nDirType);
    }else{
        strpath  = path;
        nowcache = strpath;
        result   = get_object_attribute(strpath.c_str(), NULL, &meta);
    }
    if(0 != result){
        return result;
    }

    if(S_ISDIR(stbuf.st_mode) && IS_REPLACEDIR(nDirType)){
        // Should rebuild directory object(except new type)
        // Need to remove old dir("dir" etc) and make new dir("dir/")

        // At first, remove directory old object
        if(0 != (result = remove_old_type_dir(strpath, nDirType))){
            return result;
        }
        StatCache::getStatCacheData()->DelStat(nowcache);

        // Make new directory object("dir/")
        if(0 != (result = create_directory_object(newpath.c_str(), stbuf.st_mode, stbuf.st_atime, stbuf.st_mtime, stbuf.st_ctime, stbuf.st_uid, stbuf.st_gid))){
          return result;
        }

        // need to set xattr header for directory.
        strpath  = newpath;
        nowcache = strpath;
    }

    // set xattr all object
    headers_t updatemeta;
    updatemeta["x-amz-meta-ctime"]         = str(time(NULL));
    updatemeta["x-amz-copy-source"]        = urlEncode(service_path + bucket + get_realpath(strpath.c_str()));
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
    if(NULL != (ent = autoent.ExistOpen(path, -1, true))){
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
        if(0 != (result = set_xattrs_to_header(updatemeta, name, value, size, flags))){
            return result;
        }

        if(ent->MergeOrgMeta(updatemeta)){
            // meta is changed, but now uploading.
            // then the meta is pending and accumulated to be put after the upload is complete.
            S3FS_PRN_INFO("meta pending until upload is complete");
            need_put_header = false;
        }
    }
    if(need_put_header){
        // not found opened file.
        if(0 != (result = set_xattrs_to_header(meta, name, value, size, flags))){
            return result;
        }
        merge_headers(meta, updatemeta, true);

        // upload meta directly.
        if(0 != (result = put_headers(strpath.c_str(), meta, true))){
            return result;
        }
        StatCache::getStatCacheData()->DelStat(nowcache);
    }

    return 0;
}

#if defined(__APPLE__)
static int s3fs_getxattr(const char* path, const char* name, char* value, size_t size, uint32_t position)
#else
static int s3fs_getxattr(const char* path, const char* name, char* value, size_t size)
#endif
{
    S3FS_PRN_INFO("[path=%s][name=%s][value=%p][size=%zu]", path, name, value, size);

    if(!path || !name){
        return -EIO;
    }

#if defined(__APPLE__)
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
    if(0 != (result = get_object_attribute(path, NULL, &meta))){
        return result;
    }

    // get xattrs
    headers_t::iterator hiter = meta.find("x-amz-meta-xattr");
    if(meta.end() == hiter){
        // object does not have xattrs
        return -ENOATTR;
    }
    std::string strxattrs = hiter->second;

    parse_xattrs(strxattrs, xattrs);

    // search name
    std::string strname = name;
    xattrs_t::iterator xiter = xattrs.find(strname);
    if(xattrs.end() == xiter){
        // not found name in xattrs
        free_xattrs(xattrs);
        return -ENOATTR;
    }

    // decode
    size_t         length = 0;
    unsigned char* pvalue = NULL;
    if(NULL != xiter->second){
        length = xiter->second->length;
        pvalue = xiter->second->pvalue;
    }

    if(0 < size){
        if(static_cast<size_t>(size) < length){
            // over buffer size
            free_xattrs(xattrs);
            return -ERANGE;
        }
        if(pvalue){
            memcpy(value, pvalue, length);
        }
    }
    free_xattrs(xattrs);

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
    if(0 != (result = get_object_attribute(path, NULL, &meta))){
        return result;
    }

    // get xattrs
    headers_t::iterator iter;
    if(meta.end() == (iter = meta.find("x-amz-meta-xattr"))){
        // object does not have xattrs
        return 0;
    }
    std::string strxattrs = iter->second;

    parse_xattrs(strxattrs, xattrs);

    // calculate total name length
    size_t total = 0;
    for(xattrs_t::const_iterator xiter = xattrs.begin(); xiter != xattrs.end(); ++xiter){
        if(0 < xiter->first.length()){
            total += xiter->first.length() + 1;
        }
    }

    if(0 == total){
        free_xattrs(xattrs);
        return 0;
    }

    // check parameters
    if(0 == size){
        free_xattrs(xattrs);
        return total;
    }
    if(!list || size < total){
        free_xattrs(xattrs);
        return -ERANGE;
    }

    // copy to list
    char* setpos = list;
    for(xattrs_t::const_iterator xiter = xattrs.begin(); xiter != xattrs.end(); ++xiter){
        if(0 < xiter->first.length()){
            strcpy(setpos, xiter->first.c_str());
            setpos = &setpos[strlen(setpos) + 1];
        }
    }
    free_xattrs(xattrs);

    return total;
}

static int s3fs_removexattr(const char* path, const char* name)
{
    S3FS_PRN_INFO("[path=%s][name=%s]", path, name);

    if(!path || !name){
        return -EIO;
    }

    int         result;
    std::string strpath;
    std::string newpath;
    std::string nowcache;
    headers_t   meta;
    xattrs_t    xattrs;
    struct stat stbuf;
    dirtype     nDirType = DIRTYPE_UNKNOWN;

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
        result = chk_dir_object_type(path, newpath, strpath, nowcache, &meta, &nDirType);
    }else{
        strpath  = path;
        nowcache = strpath;
        result   = get_object_attribute(strpath.c_str(), NULL, &meta);
    }
    if(0 != result){
        return result;
    }

    // get xattrs
    headers_t::iterator hiter = meta.find("x-amz-meta-xattr");
    if(meta.end() == hiter){
        // object does not have xattrs
        return -ENOATTR;
    }
    std::string strxattrs = hiter->second;

    parse_xattrs(strxattrs, xattrs);

    // check name xattrs
    std::string strname = name;
    xattrs_t::iterator xiter = xattrs.find(strname);
    if(xattrs.end() == xiter){
        free_xattrs(xattrs);
        return -ENOATTR;
    }

    // make new header_t after deleting name xattr
    delete xiter->second;
    xattrs.erase(xiter);

    if(S_ISDIR(stbuf.st_mode) && IS_REPLACEDIR(nDirType)){
        // Should rebuild directory object(except new type)
        // Need to remove old dir("dir" etc) and make new dir("dir/")

        // At first, remove directory old object
        if(0 != (result = remove_old_type_dir(strpath, nDirType))){
            return result;
        }
        StatCache::getStatCacheData()->DelStat(nowcache);

        // Make new directory object("dir/")
        if(0 != (result = create_directory_object(newpath.c_str(), stbuf.st_mode, stbuf.st_atime, stbuf.st_mtime, stbuf.st_ctime, stbuf.st_uid, stbuf.st_gid))){
            free_xattrs(xattrs);
            return result;
        }

        // need to set xattr header for directory.
        strpath  = newpath;
        nowcache = strpath;
    }

    // set xattr all object
    headers_t updatemeta;
    updatemeta["x-amz-copy-source"]        = urlEncode(service_path + bucket + get_realpath(strpath.c_str()));
    updatemeta["x-amz-metadata-directive"] = "REPLACE";
    if(!xattrs.empty()){
        updatemeta["x-amz-meta-xattr"]     = build_xattrs(xattrs);
    }else{
        updatemeta["x-amz-meta-xattr"]     = std::string("");      // This is a special case. If empty, this header will eventually be removed.
    }
    free_xattrs(xattrs);

    // check opened file handle.
    //
    // If the file starts uploading by multipart when the disk capacity is insufficient,
    // we need to put these header after finishing upload.
    // Or if the file is only open, we must update to FdEntity's internal meta.
    //
    AutoFdEntity autoent;
    FdEntity*    ent;
    bool         need_put_header = true;
    if(NULL != (ent = autoent.ExistOpen(path, -1, true))){
        if(ent->MergeOrgMeta(updatemeta)){
            // meta is changed, but now uploading.
            // then the meta is pending and accumulated to be put after the upload is complete.
            S3FS_PRN_INFO("meta pending until upload is complete");
            need_put_header = false;
        }
    }
    if(need_put_header){
        // not found opened file.
        if(updatemeta["x-amz-meta-xattr"].empty()){
            updatemeta.erase("x-amz-meta-xattr");
        }

        merge_headers(meta, updatemeta, true);

        // upload meta directly.
        if(0 != (result = put_headers(strpath.c_str(), meta, true))){
            return result;
        }
        StatCache::getStatCacheData()->DelStat(nowcache);
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
      if (NULL != ctx) {
            fuse_exit(ctx->fuse);
      }
}

static void* s3fs_init(struct fuse_conn_info* conn)
{
    S3FS_PRN_INIT_INFO("init v%s(commit:%s) with %s", VERSION, COMMIT_HASH_VAL, s3fs_crypt_lib_name());

    // cache(remove cache dirs at first)
    if(is_remove_cache && (!CacheFileStat::DeleteCacheFileStatDirectory() || !FdManager::DeleteCacheDirectory())){
        S3FS_PRN_DBG("Could not initialize cache directory.");
    }

    // check loading IAM role name
    if(load_iamrole){
      // load IAM role name from http://169.254.169.254/latest/meta-data/iam/security-credentials
      //
      S3fsCurl s3fscurl;
      if(!s3fscurl.LoadIAMRoleFromMetaData()){
          S3FS_PRN_CRIT("could not load IAM role name from meta data.");
          s3fs_exit_fuseloop(EXIT_FAILURE);
          return NULL;
      }
      S3FS_PRN_INFO("loaded IAM role name = %s", S3fsCurl::GetIAMRole());
    }

    if (create_bucket){
        int result = do_create_bucket();
        if(result != 0){
            s3fs_exit_fuseloop(result);
            return NULL;
        }
    }

    // Check Bucket
    {
        int result;
        if(EXIT_SUCCESS != (result = s3fs_check_service())){
            s3fs_exit_fuseloop(result);
            return NULL;
        }
    }

    // Investigate system capabilities
    #ifndef __APPLE__
    if((unsigned int)conn->capable & FUSE_CAP_ATOMIC_O_TRUNC){
         conn->want |= FUSE_CAP_ATOMIC_O_TRUNC;
    }
    #endif

    if((unsigned int)conn->capable & FUSE_CAP_BIG_WRITES){
         conn->want |= FUSE_CAP_BIG_WRITES;
    }

    // Signal object
    if(!S3fsSignals::Initialize()){
        S3FS_PRN_ERR("Failed to initialize signal object, but continue...");
    }

    return NULL;
}

static void s3fs_destroy(void*)
{
    S3FS_PRN_INFO("destroy");

    // Signal object
    if(!S3fsSignals::Destroy()){
        S3FS_PRN_WARN("Failed to clean up signal object.");
    }

    // cache(remove at last)
    if(is_remove_cache && (!CacheFileStat::DeleteCacheFileStatDirectory() || !FdManager::DeleteCacheDirectory())){
        S3FS_PRN_WARN("Could not remove cache directory.");
    }
}

static int s3fs_access(const char* path, int mask)
{
    S3FS_PRN_INFO("[path=%s][mask=%s%s%s%s]", path,
            ((mask & R_OK) == R_OK) ? "R_OK " : "",
            ((mask & W_OK) == W_OK) ? "W_OK " : "",
            ((mask & X_OK) == X_OK) ? "X_OK " : "",
            (mask == F_OK) ? "F_OK" : "");

    int result = check_object_access(path, mask, NULL);
    S3FS_MALLOCTRIM(0);
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

static int s3fs_check_service()
{
    S3FS_PRN_INFO("check services.");

    // At first time for access S3, we check IAM role if it sets.
    if(!S3fsCurl::CheckIAMCredentialUpdate()){
        S3FS_PRN_CRIT("Failed to check IAM role name(%s).", S3fsCurl::GetIAMRole());
        return EXIT_FAILURE;
    }

    S3fsCurl s3fscurl;
    int      res;
    if(0 > (res = s3fscurl.CheckBucket())){
        // get response code
        long responseCode = s3fscurl.GetLastResponseCode();

        // check wrong endpoint, and automatically switch endpoint
        if(300 <= responseCode && responseCode < 500){

            // check region error(for putting message or retrying)
            BodyData* body = s3fscurl.GetBodyData();
            std::string expectregion;
            if(check_region_error(body->str(), body->size(), expectregion)){
                // [NOTE]
                // If endpoint is not specified(using us-east-1 region) and
                // an error is encountered accessing a different region, we
                // will retry the check on the expected region.
                // see) https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingBucket.html#access-bucket-intro
                //
                if(is_specified_endpoint){
                    const char* tmp_expect_ep = expectregion.c_str();
                    S3FS_PRN_CRIT("The bucket region is not '%s', it is correctly '%s'. You should specify 'endpoint=%s' option.", endpoint.c_str(), tmp_expect_ep, tmp_expect_ep);

                }else{
                    // current endpoint is wrong, so try to connect to expected region.
                    S3FS_PRN_CRIT("Failed to connect region '%s'(default), so retry to connect region '%s'.", endpoint.c_str(), expectregion.c_str());
                    endpoint = expectregion;
                    if(S3fsCurl::GetSignatureType() == V4_ONLY ||
                       S3fsCurl::GetSignatureType() == V2_OR_V4){
                        if(s3host == "http://s3.amazonaws.com"){
                            s3host = "http://s3-" + endpoint + ".amazonaws.com";
                        }else if(s3host == "https://s3.amazonaws.com"){
                            s3host = "https://s3-" + endpoint + ".amazonaws.com";
                        }
                    }

                    // retry to check with new endpoint
                    s3fscurl.DestroyCurlHandle();
                    res          = s3fscurl.CheckBucket();
                    responseCode = s3fscurl.GetLastResponseCode();
                }
            }
        }

        // try signature v2
        if(0 > res && (responseCode == 400 || responseCode == 403) && S3fsCurl::GetSignatureType() == V2_OR_V4){
            // switch sigv2
            S3FS_PRN_CRIT("Failed to connect by sigv4, so retry to connect by signature version 2.");
            S3fsCurl::SetSignatureType(V2_ONLY);

            // retry to check with sigv2
            s3fscurl.DestroyCurlHandle();
            res          = s3fscurl.CheckBucket();
            responseCode = s3fscurl.GetLastResponseCode();
        }

        // check errors(after retrying)
        if(0 > res && responseCode != 200 && responseCode != 301){
            if(responseCode == 400){
                S3FS_PRN_CRIT("Bad Request(host=%s) - result of checking service.", s3host.c_str());

            }else if(responseCode == 403){
                S3FS_PRN_CRIT("invalid credentials(host=%s) - result of checking service.", s3host.c_str());

            }else if(responseCode == 404){
                S3FS_PRN_CRIT("bucket or key not found(host=%s) - result of checking service.", s3host.c_str());

            }else{
                // another error
                S3FS_PRN_CRIT("unable to connect(host=%s) - result of checking service.", s3host.c_str());
            }
            return EXIT_FAILURE;
        }
    }
    s3fscurl.DestroyCurlHandle();

    // make sure remote mountpath exists and is a directory
    if(!mount_prefix.empty()){
        if(remote_mountpath_exists(mount_prefix.c_str()) != 0){
            S3FS_PRN_CRIT("remote mountpath %s not found.", mount_prefix.c_str());
            return EXIT_FAILURE;
        }
    }
    S3FS_MALLOCTRIM(0);

    return EXIT_SUCCESS;
}

//
// Read and Parse passwd file
//
// The line of the password file is one of the following formats:
//   (1) "accesskey:secretkey"         : AWS format for default(all) access key/secret key
//   (2) "bucket:accesskey:secretkey"  : AWS format for bucket's access key/secret key
//   (3) "key=value"                   : Content-dependent KeyValue contents
//
// This function sets result into bucketkvmap_t, it bucket name and key&value mapping.
// If bucket name is empty(1 or 3 format), bucket name for mapping is set "\t" or "".
//
// Return:  1 - OK(could parse and set mapping etc.)
//          0 - NG(could not read any value)
//         -1 - Should shutdown immediately
//
static int parse_passwd_file(bucketkvmap_t& resmap)
{
    std::string          line;
    size_t               first_pos;
    readline_t           linelist;
    readline_t::iterator iter;

    // open passwd file
    std::ifstream PF(passwd_file.c_str());
    if(!PF.good()){
        S3FS_PRN_EXIT("could not open passwd file : %s", passwd_file.c_str());
        return -1;
    }

    // read each line
    while(getline(PF, line)){
        line = trim(line);
        if(line.empty()){
            continue;
        }
        if('#' == line[0]){
            continue;
        }
        if(std::string::npos != line.find_first_of(" \t")){
            S3FS_PRN_EXIT("invalid line in passwd file, found whitespace character.");
            return -1;
        }
        if('[' == line[0]){
            S3FS_PRN_EXIT("invalid line in passwd file, found a bracket \"[\" character.");
            return -1;
        }
        linelist.push_back(line);
    }

    // read '=' type
    kvmap_t kv;
    for(iter = linelist.begin(); iter != linelist.end(); ++iter){
        first_pos = iter->find_first_of('=');
        if(first_pos == std::string::npos){
            continue;
        }
        // formatted by "key=val"
        std::string key = trim(iter->substr(0, first_pos));
        std::string val = trim(iter->substr(first_pos + 1, std::string::npos));
        if(key.empty()){
            continue;
        }
        if(kv.end() != kv.find(key)){
            S3FS_PRN_WARN("same key name(%s) found in passwd file, skip this.", key.c_str());
            continue;
        }
        kv[key] = val;
    }
    // set special key name
    resmap[std::string(keyval_fields_type)] = kv;

    // read ':' type
    for(iter = linelist.begin(); iter != linelist.end(); ++iter){
        first_pos       = iter->find_first_of(':');
        size_t last_pos = iter->find_last_of(':');
        if(first_pos == std::string::npos){
            continue;
        }
        std::string bucketname;
        std::string accesskey;
        std::string secret;
        if(first_pos != last_pos){
            // formatted by "bucket:accesskey:secretkey"
            bucketname    = trim(iter->substr(0, first_pos));
            accesskey = trim(iter->substr(first_pos + 1, last_pos - first_pos - 1));
            secret    = trim(iter->substr(last_pos + 1, std::string::npos));
        }else{
            // formatted by "accesskey:secretkey"
            bucketname    = allbucket_fields_type;
            accesskey = trim(iter->substr(0, first_pos));
            secret    = trim(iter->substr(first_pos + 1, std::string::npos));
        }
        if(resmap.end() != resmap.find(bucketname)){
            S3FS_PRN_EXIT("there are multiple entries for the same bucket(%s) in the passwd file.", (bucketname.empty() ? "default" : bucketname.c_str()));
            return -1;
        }
        kv.clear();
        kv[std::string(aws_accesskeyid)] = accesskey;
        kv[std::string(aws_secretkey)] = secret;
        resmap[bucketname] = kv;
    }
    return (resmap.empty() ? 0 : 1);
}

//
// Return:  1 - OK(could read and set accesskey etc.)
//          0 - NG(could not read)
//         -1 - Should shutdown immediately
//
static int check_for_aws_format(const kvmap_t& kvmap)
{
    std::string str1(aws_accesskeyid);
    std::string str2(aws_secretkey);

    if(kvmap.empty()){
        return 0;
    }
    kvmap_t::const_iterator str1_it = kvmap.find(str1);
    kvmap_t::const_iterator str2_it = kvmap.find(str2);
    if(kvmap.end() == str1_it && kvmap.end() == str2_it){
        return 0;
    }
    if(kvmap.end() == str1_it || kvmap.end() == str2_it){
        S3FS_PRN_EXIT("AWSAccesskey or AWSSecretkey is not specified.");
        return -1;
    }
    if(!S3fsCurl::SetAccessKey(str1_it->second.c_str(), str2_it->second.c_str())){
        S3FS_PRN_EXIT("failed to set access key/secret key.");
        return -1;
    }
    return 1;
}

//
// check_passwd_file_perms
// 
// expect that global passwd_file variable contains
// a non-empty value and is readable by the current user
//
// Check for too permissive access to the file
// help save users from themselves via a security hole
//
// only two options: return or error out
//
static int check_passwd_file_perms()
{
    struct stat info;

    // let's get the file info
    if(stat(passwd_file.c_str(), &info) != 0){
        S3FS_PRN_EXIT("unexpected error from stat(%s).", passwd_file.c_str());
        return EXIT_FAILURE;
    }

    // return error if any file has others permissions 
    if( (info.st_mode & S_IROTH) ||
        (info.st_mode & S_IWOTH) || 
        (info.st_mode & S_IXOTH)) {
        S3FS_PRN_EXIT("credentials file %s should not have others permissions.", passwd_file.c_str());
        return EXIT_FAILURE;
    }

    // Any local file should not have any group permissions 
    // /etc/passwd-s3fs can have group permissions 
    if(passwd_file != "/etc/passwd-s3fs"){
        if( (info.st_mode & S_IRGRP) ||
            (info.st_mode & S_IWGRP) || 
            (info.st_mode & S_IXGRP)) {
            S3FS_PRN_EXIT("credentials file %s should not have group permissions.", passwd_file.c_str());
            return EXIT_FAILURE;
        }
    }else{
        // "/etc/passwd-s3fs" does not allow group write.
        if((info.st_mode & S_IWGRP)){
            S3FS_PRN_EXIT("credentials file %s should not have group writable permissions.", passwd_file.c_str());
            return EXIT_FAILURE;
        }
    }
    if((info.st_mode & S_IXUSR) || (info.st_mode & S_IXGRP)){
        S3FS_PRN_EXIT("credentials file %s should not have executable permissions.", passwd_file.c_str());
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

static int read_aws_credentials_file(const std::string &filename)
{
    // open passwd file
    std::ifstream PF(filename.c_str());
    if(!PF.good()){
        return -1;
    }

    std::string profile;
    std::string accesskey;
    std::string secret;
    std::string session_token;

    // read each line
    std::string line;
    while(getline(PF, line)){
        line = trim(line);
        if(line.empty()){
            continue;
        }
        if('#' == line[0]){
            continue;
        }

        if(line.size() > 2 && line[0] == '[' && line[line.size() - 1] == ']') {
            if(profile == aws_profile){
                break;
            }
            profile = line.substr(1, line.size() - 2);
            accesskey.clear();
            secret.clear();
            session_token.clear();
        }
    
        size_t pos = line.find_first_of('=');
        if(pos == std::string::npos){
            continue;
        }
        std::string key   = trim(line.substr(0, pos));
        std::string value = trim(line.substr(pos + 1, std::string::npos));
        if(key == "aws_access_key_id"){
            accesskey = value;
        }else if(key == "aws_secret_access_key"){
            secret = value;
        }else if(key == "aws_session_token"){
            session_token = value;
        }
    }

    if(profile != aws_profile){
      return EXIT_FAILURE;
    }
    if (session_token.empty()) {
        if (is_use_session_token) {
            S3FS_PRN_EXIT("AWS session token was expected but wasn't provided in aws/credentials file for profile: %s.", aws_profile.c_str());
            return EXIT_FAILURE;
        }
        if(!S3fsCurl::SetAccessKey(accesskey.c_str(), secret.c_str())){
            S3FS_PRN_EXIT("failed to set internal data for access key/secret key from aws credential file.");
            return EXIT_FAILURE;
        }
    } else {
        if (!S3fsCurl::SetAccessKeyWithSessionToken(accesskey.c_str(), secret.c_str(), session_token.c_str())) {
            S3FS_PRN_EXIT("session token is invalid.");
            return EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;
}

//
// read_passwd_file
//
// Support for per bucket credentials
// 
// Format for the credentials file:
// [bucket:]AccessKeyId:SecretAccessKey
// 
// Lines beginning with # are considered comments
// and ignored, as are empty lines
//
// Uncommented lines without the ":" character are flagged as
// an error, so are lines with spaces or tabs
//
// only one default key pair is allowed, but not required
//
static int read_passwd_file()
{
    bucketkvmap_t bucketmap;
    kvmap_t       keyval;
    int           result;

    // if you got here, the password file
    // exists and is readable by the
    // current user, check for permissions
    if(EXIT_SUCCESS != check_passwd_file_perms()){
        return EXIT_FAILURE;
    }

    //
    // parse passwd file
    //
    result = parse_passwd_file(bucketmap);
    if(-1 == result){
         return EXIT_FAILURE;
    }

    //
    // check key=value type format.
    //
    bucketkvmap_t::iterator it = bucketmap.find(keyval_fields_type);
    if(bucketmap.end() != it){
        // aws format
        result = check_for_aws_format(it->second);
        if(-1 == result){
            return EXIT_FAILURE;
        }else if(1 == result){
            // success to set
            return EXIT_SUCCESS;
        }
    }

    std::string bucket_key = allbucket_fields_type;
    if(!bucket.empty() && bucketmap.end() != bucketmap.find(bucket)){
        bucket_key = bucket;
    }
    it = bucketmap.find(bucket_key);
    if(bucketmap.end() == it){
        S3FS_PRN_EXIT("Not found access key/secret key in passwd file.");
        return EXIT_FAILURE;
    }
    keyval = it->second;
    kvmap_t::iterator aws_accesskeyid_it = keyval.find(aws_accesskeyid);
    kvmap_t::iterator aws_secretkey_it = keyval.find(aws_secretkey);
    if(keyval.end() == aws_accesskeyid_it || keyval.end() == aws_secretkey_it){
        S3FS_PRN_EXIT("Not found access key/secret key in passwd file.");
        return EXIT_FAILURE;
    }
    if(!S3fsCurl::SetAccessKey(aws_accesskeyid_it->second.c_str(), aws_secretkey_it->second.c_str())){
        S3FS_PRN_EXIT("failed to set internal data for access key/secret key from passwd file.");
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

//
// get_access_keys
//
// called only when were are not mounting a 
// public bucket
//
// Here is the order precedence for getting the
// keys:
//
// 1 - from the command line  (security risk)
// 2 - from a password file specified on the command line
// 3 - from environment variables
// 3a - from the AWS_CREDENTIAL_FILE environment variable
// 3b - from ${HOME}/.aws/credentials
// 4 - from the users ~/.passwd-s3fs
// 5 - from /etc/passwd-s3fs
//
static int get_access_keys()
{
    // should be redundant
    if(S3fsCurl::IsPublicBucket()){
        return EXIT_SUCCESS;
    }

    // access key loading is deferred
    if(load_iamrole || is_ecs){
        return EXIT_SUCCESS;
    }

    // 1 - keys specified on the command line
    if(S3fsCurl::IsSetAccessKeys()){
        return EXIT_SUCCESS;
    }

    // 2 - was specified on the command line
    if(!passwd_file.empty()){
        std::ifstream PF(passwd_file.c_str());
        if(PF.good()){
             PF.close();
             return read_passwd_file();
        }else{
            S3FS_PRN_EXIT("specified passwd_file is not readable.");
            return EXIT_FAILURE;
        }
    }

    // 3  - environment variables
    char* AWSACCESSKEYID     = getenv("AWSACCESSKEYID");
    char* AWSSECRETACCESSKEY = getenv("AWSSECRETACCESSKEY");
    char* AWSSESSIONTOKEN    = getenv("AWSSESSIONTOKEN");
    if(AWSACCESSKEYID != NULL || AWSSECRETACCESSKEY != NULL){
        if( (AWSACCESSKEYID == NULL && AWSSECRETACCESSKEY != NULL) ||
            (AWSACCESSKEYID != NULL && AWSSECRETACCESSKEY == NULL) ){
            S3FS_PRN_EXIT("if environment variable AWSACCESSKEYID is set then AWSSECRETACCESSKEY must be set too.");
            return EXIT_FAILURE;
        }
        S3FS_PRN_INFO2("access key from env variables");
        if (AWSSESSIONTOKEN != NULL) {
            S3FS_PRN_INFO2("session token is available");
            if (!S3fsCurl::SetAccessKeyWithSessionToken(AWSACCESSKEYID, AWSSECRETACCESSKEY, AWSSESSIONTOKEN)) {
                 S3FS_PRN_EXIT("session token is invalid.");
                 return EXIT_FAILURE;
            }
        } else {
            S3FS_PRN_INFO2("session token is not available");
            if (is_use_session_token) {
                S3FS_PRN_EXIT("environment variable AWSSESSIONTOKEN is expected to be set.");
                return EXIT_FAILURE;
            }
        }
        if(!S3fsCurl::SetAccessKey(AWSACCESSKEYID, AWSSECRETACCESSKEY)){
            S3FS_PRN_EXIT("if one access key is specified, both keys need to be specified.");
            return EXIT_FAILURE;
        }
        return EXIT_SUCCESS;
    }

    // 3a - from the AWS_CREDENTIAL_FILE environment variable
    char * AWS_CREDENTIAL_FILE;
    AWS_CREDENTIAL_FILE = getenv("AWS_CREDENTIAL_FILE");
    if(AWS_CREDENTIAL_FILE != NULL){
        passwd_file = AWS_CREDENTIAL_FILE;
        if(!passwd_file.empty()){
            std::ifstream PF(passwd_file.c_str());
            if(PF.good()){
                 PF.close();
                 return read_passwd_file();
            }else{
                S3FS_PRN_EXIT("AWS_CREDENTIAL_FILE: \"%s\" is not readable.", passwd_file.c_str());
                return EXIT_FAILURE;
            }
        }
    }

    // 3b - check ${HOME}/.aws/credentials
    std::string aws_credentials = std::string(getpwuid(getuid())->pw_dir) + "/.aws/credentials";
    if(read_aws_credentials_file(aws_credentials) == EXIT_SUCCESS) {
        return EXIT_SUCCESS;
    }else if(aws_profile != "default"){
        S3FS_PRN_EXIT("Could not find profile: %s in file: %s", aws_profile.c_str(), aws_credentials.c_str());
        return EXIT_FAILURE;
    }

    // 4 - from the default location in the users home directory
    char * HOME;
    HOME = getenv ("HOME");
    if(HOME != NULL){
         passwd_file = HOME;
         passwd_file += "/.passwd-s3fs";
         std::ifstream PF(passwd_file.c_str());
         if(PF.good()){
             PF.close();
             if(EXIT_SUCCESS != read_passwd_file()){
                 return EXIT_FAILURE;
             }
             // It is possible that the user's file was there but
             // contained no key pairs i.e. commented out
             // in that case, go look in the final location
             if(S3fsCurl::IsSetAccessKeys()){
                  return EXIT_SUCCESS;
             }
         }
     }

    // 5 - from the system default location
    passwd_file = "/etc/passwd-s3fs";
    std::ifstream PF(passwd_file.c_str());
    if(PF.good()){
        PF.close();
        return read_passwd_file();
    }
    S3FS_PRN_EXIT("could not determine how to establish security credentials.");

    return EXIT_FAILURE;
}

//
// Check & Set attributes for mount point.
//
static bool set_mountpoint_attribute(struct stat& mpst)
{
    mp_uid  = geteuid();
    mp_gid  = getegid();
    mp_mode = S_IFDIR | (allow_other ? (is_mp_umask ? (~mp_umask & (S_IRWXU | S_IRWXG | S_IRWXO)) : (S_IRWXU | S_IRWXG | S_IRWXO)) : S_IRWXU);

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
}

//
// Set bucket and mount_prefix based on passed bucket name.
//
static int set_bucket(const char* arg)
{
    char *bucket_name = (char*)arg;
    if(strstr(arg, ":")){
        if(strstr(arg, "://")){
            S3FS_PRN_EXIT("bucket name and path(\"%s\") is wrong, it must be \"bucket[:/path]\".", arg);
            return -1;
        }
        bucket = strtok(bucket_name, ":");
        char* pmount_prefix = strtok(NULL, "");
        if(pmount_prefix){
            if(0 == strlen(pmount_prefix) || '/' != pmount_prefix[0]){
                S3FS_PRN_EXIT("path(%s) must be prefix \"/\".", pmount_prefix);
                return -1;
            }
            mount_prefix = pmount_prefix;
            // remove trailing slash
            if(mount_prefix[mount_prefix.size() - 1] == '/'){
                mount_prefix.erase(mount_prefix.size() - 1);
            }
        }
    }else{
        bucket = arg;
    }
    return 0;
}

// This is repeatedly called by the fuse option parser
// if the key is equal to FUSE_OPT_KEY_OPT, it's an option passed in prefixed by 
// '-' or '--' e.g.: -f -d -ousecache=/tmp
//
// if the key is equal to FUSE_OPT_KEY_NONOPT, it's either the bucket name 
//  or the mountpoint. The bucket name will always come before the mountpoint
static int my_fuse_opt_proc(void* data, const char* arg, int key, struct fuse_args* outargs)
{
    int ret;
    if(key == FUSE_OPT_KEY_NONOPT){
        // the first NONOPT option is the bucket name
        if(bucket.empty()){
            if ((ret = set_bucket(arg))){
                return ret;
            }
            return 0;
        }else if (!strcmp(arg, "s3fs")) {
            return 0;
        }

        // the second NONOPT option is the mountpoint(not utility mode)
        if(mountpoint.empty() && NO_UTILITY_MODE == utility_mode){
            // save the mountpoint and do some basic error checking
            mountpoint = arg;
            struct stat stbuf;

            if(stat(arg, &stbuf) == -1){
                S3FS_PRN_EXIT("unable to access MOUNTPOINT %s: %s", mountpoint.c_str(), strerror(errno));
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

            if(!nonempty){
                struct dirent *ent;
                DIR *dp = opendir(mountpoint.c_str());
                if(dp == NULL){
                    S3FS_PRN_EXIT("failed to open MOUNTPOINT: %s: %s", mountpoint.c_str(), strerror(errno));
                    return -1;
                }
                while((ent = readdir(dp)) != NULL){
                    if(strcmp(ent->d_name, ".") != 0 && strcmp(ent->d_name, "..") != 0){
                        closedir(dp);
                        S3FS_PRN_EXIT("MOUNTPOINT directory %s is not empty. if you are sure this is safe, can use the 'nonempty' mount option.", mountpoint.c_str());
                        return -1;
                    }
                }
                closedir(dp);
            }
            return 1;
        }

        // Unknown option
        if(NO_UTILITY_MODE == utility_mode){
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
        if(is_prefix(arg, "gid=")){
            s3fs_gid = get_gid(strchr(arg, '=') + sizeof(char));
            if(0 != getegid() && 0 == s3fs_gid){
                S3FS_PRN_EXIT("root user can only specify gid=0.");
                return -1;
            }
            is_s3fs_gid = true;
            return 1; // continue for fuse option
        }
        if(is_prefix(arg, "umask=")){
            s3fs_umask = cvt_strtoofft(strchr(arg, '=') + sizeof(char), /*base=*/ 8);
            s3fs_umask &= (S_IRWXU | S_IRWXG | S_IRWXO);
            is_s3fs_umask = true;
            return 1; // continue for fuse option
        }
        if(0 == strcmp(arg, "allow_other")){
            allow_other = true;
            return 1; // continue for fuse option
        }
        if(is_prefix(arg, "mp_umask=")){
            mp_umask = cvt_strtoofft(strchr(arg, '=') + sizeof(char), /*base=*/ 8);
            mp_umask &= (S_IRWXU | S_IRWXG | S_IRWXO);
            is_mp_umask = true;
            return 0;
        }
        if(is_prefix(arg, "default_acl=")){
            const char* acl_string = strchr(arg, '=') + sizeof(char);
            acl_t acl = acl_t::from_str(acl_string);
            if(acl == acl_t::UNKNOWN){
                S3FS_PRN_EXIT("unknown value for default_acl: %s", acl_string);
                return -1;
            }
            S3fsCurl::SetDefaultAcl(acl);
            return 0;
        }
        if(is_prefix(arg, "retries=")){
            off_t retries = static_cast<int>(cvt_strtoofft(strchr(arg, '=') + sizeof(char)));
            if(retries == 0){
                S3FS_PRN_EXIT("retries must be greater than zero");
                return -1;
            }
            S3fsCurl::SetRetries(retries);
            return 0;
        }
        if(is_prefix(arg, "use_cache=")){
            FdManager::SetCacheDir(strchr(arg, '=') + sizeof(char));
            return 0;
        }
        if(0 == strcmp(arg, "check_cache_dir_exist")){
            FdManager::SetCheckCacheDirExist(true);
            return 0;
        }
        if(0 == strcmp(arg, "del_cache")){
            is_remove_cache = true;
            return 0;
        }
        if(is_prefix(arg, "multireq_max=")){
            int maxreq = static_cast<int>(cvt_strtoofft(strchr(arg, '=') + sizeof(char)));
            S3fsCurl::SetMaxMultiRequest(maxreq);
            return 0;
        }
        if(0 == strcmp(arg, "nonempty")){
            nonempty = true;
            return 1; // need to continue for fuse.
        }
        if(0 == strcmp(arg, "nomultipart")){
            nomultipart = true;
            return 0;
        }
        // old format for storage_class
        if(0 == strcmp(arg, "use_rrs") || is_prefix(arg, "use_rrs=")){
            off_t rrs = 1;
            // for an old format.
            if(is_prefix(arg, "use_rrs=")){
                rrs = cvt_strtoofft(strchr(arg, '=') + sizeof(char));
            }
            if(0 == rrs){
                S3fsCurl::SetStorageClass(storage_class_t::STANDARD);
            }else if(1 == rrs){
                S3fsCurl::SetStorageClass(storage_class_t::REDUCED_REDUNDANCY);
            }else{
                S3FS_PRN_EXIT("poorly formed argument to option: use_rrs");
                return -1;
            }
            return 0;
        }
        if(is_prefix(arg, "storage_class=")){
            const char *storage_class_str = strchr(arg, '=') + sizeof(char);
            storage_class_t storage_class = storage_class_t::from_str(storage_class_str);
            if(storage_class == storage_class_t::UNKNOWN){
                S3FS_PRN_EXIT("unknown value for storage_class: %s", storage_class_str);
                return -1;
            }
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
        if(is_prefix(arg, "use_sse")){
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
        if(is_prefix(arg, "load_sse_c=")){
            const char* ssecfile = &arg[strlen("load_sse_c=")];
            if(!S3fsCurl::SetSseCKeys(ssecfile)){
                S3FS_PRN_EXIT("failed to load use_sse custom key file(%s).", ssecfile);
                return -1;
            }
            return 0;
        }
        if(is_prefix(arg, "ssl_verify_hostname=")){
            long sslvh = static_cast<long>(cvt_strtoofft(strchr(arg, '=') + sizeof(char)));
            if(-1 == S3fsCurl::SetSslVerifyHostname(sslvh)){
                S3FS_PRN_EXIT("poorly formed argument to option: ssl_verify_hostname.");
                return -1;
            }
            return 0;
        }
        if(is_prefix(arg, "passwd_file=")){
            passwd_file = strchr(arg, '=') + sizeof(char);
            return 0;
        }
        if(0 == strcmp(arg, "ibm_iam_auth")){
            S3fsCurl::SetIsIBMIAMAuth(true);
            S3fsCurl::SetIAMCredentialsURL("https://iam.bluemix.net/oidc/token");
            S3fsCurl::SetIAMTokenField("\"access_token\"");
            S3fsCurl::SetIAMExpiryField("\"expiration\"");
            S3fsCurl::SetIAMFieldCount(2);
            S3fsCurl::SetIMDSVersion(1);
            is_ibm_iam_auth = true;
            return 0;
        }
        if (0 == strcmp(arg, "use_session_token")) {
            is_use_session_token = true;
            return 0;
        }
        if(is_prefix(arg, "ibm_iam_endpoint=")){
            std::string endpoint_url;
            const char *iam_endpoint = strchr(arg, '=') + sizeof(char);
            // Check url for http / https protocol std::string
            if(!is_prefix(iam_endpoint, "https://") && !is_prefix(iam_endpoint, "http://")) {
                 S3FS_PRN_EXIT("option ibm_iam_endpoint has invalid format, missing http / https protocol");
                 return -1;
            }
            endpoint_url = std::string(iam_endpoint) + "/oidc/token";
            S3fsCurl::SetIAMCredentialsURL(endpoint_url.c_str());
            return 0;
        }
        if(0 == strcmp(arg, "imdsv1only")){
            S3fsCurl::SetIMDSVersion(1);
            return 0;
        }
        if(0 == strcmp(arg, "ecs")){
            if (is_ibm_iam_auth) {
                S3FS_PRN_EXIT("option ecs cannot be used in conjunction with ibm");
                return -1;
            }
            S3fsCurl::SetIsECS(true);
            S3fsCurl::SetIMDSVersion(1);
            S3fsCurl::SetIAMCredentialsURL("http://169.254.170.2");
            S3fsCurl::SetIAMFieldCount(5);
            is_ecs = true;
            return 0;
        }
        if(is_prefix(arg, "iam_role")){
            if (is_ecs || is_ibm_iam_auth) {
                S3FS_PRN_EXIT("option iam_role cannot be used in conjunction with ecs or ibm");
                return -1;
            }
            if(0 == strcmp(arg, "iam_role") || 0 == strcmp(arg, "iam_role=auto")){
                // loading IAM role name in s3fs_init(), because we need to wait initializing curl.
                //
                load_iamrole = true;
                return 0;

            }else if(is_prefix(arg, "iam_role=")){
                const char* role = strchr(arg, '=') + sizeof(char);
                S3fsCurl::SetIAMRole(role);
                load_iamrole = false;
                return 0;
            }
        }
        if(is_prefix(arg, "profile=")){
            aws_profile = strchr(arg, '=') + sizeof(char);
            return 0;
        }
        if(is_prefix(arg, "public_bucket=")){
            off_t pubbucket = cvt_strtoofft(strchr(arg, '=') + sizeof(char));
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
        if(is_prefix(arg, "bucket=")){
            std::string bname = strchr(arg, '=') + sizeof(char);
            if ((ret = set_bucket(bname.c_str()))){
                return ret;
            }
            return 0;
        }
        if(0 == strcmp(arg, "no_check_certificate")){
            S3fsCurl::SetCheckCertificate(false);
            return 0;
        }
        if(is_prefix(arg, "connect_timeout=")){
            long contimeout = static_cast<long>(cvt_strtoofft(strchr(arg, '=') + sizeof(char)));
            S3fsCurl::SetConnectTimeout(contimeout);
            return 0;
        }
        if(is_prefix(arg, "readwrite_timeout=")){
            time_t rwtimeout = static_cast<time_t>(cvt_strtoofft(strchr(arg, '=') + sizeof(char)));
            S3fsCurl::SetReadwriteTimeout(rwtimeout);
            return 0;
        }
        if(is_prefix(arg, "list_object_max_keys=")){
            int max_keys = static_cast<int>(cvt_strtoofft(strchr(arg, '=') + sizeof(char)));
            if(max_keys < 1000){
                S3FS_PRN_EXIT("argument should be over 1000: list_object_max_keys");
                return -1;
            }
            max_keys_list_object = max_keys;
            return 0;
        }
        if(is_prefix(arg, "max_stat_cache_size=")){
            unsigned long cache_size = static_cast<unsigned long>(cvt_strtoofft(strchr(arg, '=') + sizeof(char)));
            StatCache::getStatCacheData()->SetCacheSize(cache_size);
            return 0;
        }
        if(is_prefix(arg, "stat_cache_expire=")){
            time_t expr_time = static_cast<time_t>(cvt_strtoofft(strchr(arg, '=') + sizeof(char)));
            StatCache::getStatCacheData()->SetExpireTime(expr_time);
            return 0;
        }
        // [NOTE]
        // This option is for compatibility old version.
        if(is_prefix(arg, "stat_cache_interval_expire=")){
            time_t expr_time = static_cast<time_t>(cvt_strtoofft(strchr(arg, '=') + sizeof(char)));
            StatCache::getStatCacheData()->SetExpireTime(expr_time, true);
            return 0;
        }
        if(0 == strcmp(arg, "enable_noobj_cache")){
            StatCache::getStatCacheData()->EnableCacheNoObject();
            return 0;
        }
        if(0 == strcmp(arg, "nodnscache")){
            S3fsCurl::SetDnsCache(false);
            return 0;
        }
        if(0 == strcmp(arg, "nosscache")){
            S3fsCurl::SetSslSessionCache(false);
            return 0;
        }
        if(is_prefix(arg, "parallel_count=") || is_prefix(arg, "parallel_upload=")){
            int maxpara = static_cast<int>(cvt_strtoofft(strchr(arg, '=') + sizeof(char)));
            if(0 >= maxpara){
                S3FS_PRN_EXIT("argument should be over 1: parallel_count");
                return -1;
            }
            S3fsCurl::SetMaxParallelCount(maxpara);
            return 0;
        }
        if(is_prefix(arg, "fd_page_size=")){
            S3FS_PRN_ERR("option fd_page_size is no longer supported, so skip this option.");
            return 0;
        }
        if(is_prefix(arg, "multipart_size=")){
            off_t size = static_cast<off_t>(cvt_strtoofft(strchr(arg, '=') + sizeof(char)));
            if(!S3fsCurl::SetMultipartSize(size)){
                S3FS_PRN_EXIT("multipart_size option must be at least 5 MB.");
                return -1;
            }
            return 0;
        }
        if(is_prefix(arg, "multipart_copy_size=")){
            off_t size = static_cast<off_t>(cvt_strtoofft(strchr(arg, '=') + sizeof(char)));
            if(!S3fsCurl::SetMultipartCopySize(size)){
                S3FS_PRN_EXIT("multipart_copy_size option must be at least 5 MB.");
                return -1;
            }
            return 0;
        }
        if(is_prefix(arg, "max_dirty_data=")){
            off_t size = static_cast<off_t>(cvt_strtoofft(strchr(arg, '=') + sizeof(char)));
            if(size >= 50){
                size *= 1024 * 1024;
            }else if(size != -1){
                S3FS_PRN_EXIT("max_dirty_data option must be at least 50 MB.");
                return -1;
            }
            max_dirty_data = size;
            return 0;
        }
        if(is_prefix(arg, "ensure_diskfree=")){
            off_t dfsize = cvt_strtoofft(strchr(arg, '=') + sizeof(char)) * 1024 * 1024;
            if(dfsize < S3fsCurl::GetMultipartSize()){
                S3FS_PRN_WARN("specified size to ensure disk free space is smaller than multipart size, so set multipart size to it.");
                dfsize = S3fsCurl::GetMultipartSize();
            }
            FdManager::SetEnsureFreeDiskSpace(dfsize);
            return 0;
        }
        if(is_prefix(arg, "multipart_threshold=")){
            multipart_threshold = static_cast<int64_t>(cvt_strtoofft(strchr(arg, '=') + sizeof(char))) * 1024 * 1024;
            if(multipart_threshold <= MIN_MULTIPART_SIZE){
                S3FS_PRN_EXIT("multipart_threshold must be at least %lld, was: %lld", static_cast<long long>(MIN_MULTIPART_SIZE), static_cast<long long>(multipart_threshold));
                return -1;
            }
            return 0;
        }
        if(is_prefix(arg, "singlepart_copy_limit=")){
            singlepart_copy_limit = static_cast<int64_t>(cvt_strtoofft(strchr(arg, '=') + sizeof(char))) * 1024 * 1024;
            return 0;
        }
        if(is_prefix(arg, "ahbe_conf=")){
            std::string ahbe_conf = strchr(arg, '=') + sizeof(char);
            if(!AdditionalHeader::get()->Load(ahbe_conf.c_str())){
                S3FS_PRN_EXIT("failed to load ahbe_conf file(%s).", ahbe_conf.c_str());
                return -1;
            }
            AdditionalHeader::get()->Dump();
            return 0;
        }
        if(0 == strcmp(arg, "noxmlns")){
            noxmlns = true;
            return 0;
        }
        if(0 == strcmp(arg, "nomixupload")){
            FdEntity::SetNoMixMultipart();
            return 0;
        }
        if(0 == strcmp(arg, "nocopyapi")){
            nocopyapi = true;
            return 0;
        }
        if(0 == strcmp(arg, "norenameapi")){
            norenameapi = true;
            return 0;
        }
        if(0 == strcmp(arg, "complement_stat")){
            complement_stat = true;
            return 0;
        }
        if(0 == strcmp(arg, "notsup_compat_dir")){
            support_compat_dir = false;
            return 0;
        }
        if(0 == strcmp(arg, "enable_content_md5")){
            S3fsCurl::SetContentMd5(true);
            return 0;
        }
        if(is_prefix(arg, "host=")){
            s3host = strchr(arg, '=') + sizeof(char);
            return 0;
        }
        if(is_prefix(arg, "servicepath=")){
            service_path = strchr(arg, '=') + sizeof(char);
            return 0;
        }
        if(is_prefix(arg, "url=")){
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
        if(0 == strcmp(arg, "sigv2")){
            S3fsCurl::SetSignatureType(V2_ONLY);
            return 0;
        }
        if(0 == strcmp(arg, "sigv4")){
            S3fsCurl::SetSignatureType(V4_ONLY);
            return 0;
        }
        if(0 == strcmp(arg, "createbucket")){
            create_bucket = true;
            return 0;
        }
        if(is_prefix(arg, "endpoint=")){
            endpoint              = strchr(arg, '=') + sizeof(char);
            is_specified_endpoint = true;
            return 0;
        }
        if(0 == strcmp(arg, "use_path_request_style")){
            pathrequeststyle = true;
            return 0;
        }
        if(0 == strcmp(arg, "noua")){
            S3fsCurl::SetUserAgentFlag(false);
            return 0;
        }
        if(0 == strcmp(arg, "listobjectsv2")){
            S3fsCurl::SetListObjectsV2(true);
            return 0;
        }
        if(0 == strcmp(arg, "use_xattr")){
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
        if(is_prefix(arg, "cipher_suites=")){
            cipher_suites = strchr(arg, '=') + sizeof(char);
            return 0;
        }
        if(is_prefix(arg, "instance_name=")){
            instance_name = strchr(arg, '=') + sizeof(char);
            instance_name = "[" + instance_name + "]";
            return 0;
        }
        if(is_prefix(arg, "mime=")){
            mimetype_file = strchr(arg, '=') + sizeof(char);
            return 0;
        }
        //
        // log file option
        //
        if(is_prefix(arg, "logfile=")){
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
        if(is_prefix(arg, "dbglevel=")){
            const char* strlevel = strchr(arg, '=') + sizeof(char);
            if(0 == strcasecmp(strlevel, "silent") || 0 == strcasecmp(strlevel, "critical") || 0 == strcasecmp(strlevel, "crit")){
                S3fsLog::SetLogLevel(S3fsLog::LEVEL_CRIT);
            }else if(0 == strcasecmp(strlevel, "error") || 0 == strcasecmp(strlevel, "err")){
                S3fsLog::SetLogLevel(S3fsLog::LEVEL_ERR);
            }else if(0 == strcasecmp(strlevel, "wan") || 0 == strcasecmp(strlevel, "warn") || 0 == strcasecmp(strlevel, "warning")){
                S3fsLog::SetLogLevel(S3fsLog::LEVEL_WARN);
            }else if(0 == strcasecmp(strlevel, "inf") || 0 == strcasecmp(strlevel, "info") || 0 == strcasecmp(strlevel, "information")){
                S3fsLog::SetLogLevel(S3fsLog::LEVEL_INFO);
            }else if(0 == strcasecmp(strlevel, "dbg") || 0 == strcasecmp(strlevel, "debug")){
                S3fsLog::SetLogLevel(S3fsLog::LEVEL_DBG);
            }else{
                S3FS_PRN_EXIT("option dbglevel has unknown parameter(%s).", strlevel);
                return -1;
            }
            return 0;
        }
        //
        // debug option
        //
        // S3fsLog level is LEVEL_INFO, after second -d is passed to fuse.
        //
        if(0 == strcmp(arg, "-d") || 0 == strcmp(arg, "--debug")){
            if(!S3fsLog::IsS3fsLogInfo() && !S3fsLog::IsS3fsLogDbg()){
                S3fsLog::SetLogLevel(S3fsLog::LEVEL_INFO);
                return 0;
            }
            if(0 == strcmp(arg, "--debug")){
                // fuse doesn't understand "--debug", but it understands -d.
                // but we can't pass -d back to fuse.
                return 0;
            }
        }
        // "f2" is not used no more.
        // (set S3fsLog::LEVEL_DBG)
        if(0 == strcmp(arg, "f2")){
            S3fsLog::SetLogLevel(S3fsLog::LEVEL_DBG);
            return 0;
        }
        if(0 == strcmp(arg, "curldbg")){
            S3fsCurl::SetVerbose(true);
            return 0;
        }else if(is_prefix(arg, "curldbg=")){
            const char* strlevel = strchr(arg, '=') + sizeof(char);
            if(0 == strcasecmp(strlevel, "normal")){
                S3fsCurl::SetVerbose(true);
            }else if(0 == strcasecmp(strlevel, "body")){
                S3fsCurl::SetVerbose(true);
                S3fsCurl::SetDumpBody(true);
            }else{
                S3FS_PRN_EXIT("option curldbg has unknown parameter(%s).", strlevel);
                return -1;
            }
            return 0;
        }
        //
        // no time stamp in debug message
        //
        if(0 == strcmp(arg, "no_time_stamp_msg")){
            S3fsLog::SetTimeStamp(false);
            return 0;
        }
        //
        // Check cache file, using SIGUSR1
        //
        if(0 == strcmp(arg, "set_check_cache_sigusr1")){
            if(!S3fsSignals::SetUsr1Handler(NULL)){
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
        if(is_prefix(arg, "accessKeyId=")){
            S3FS_PRN_EXIT("option accessKeyId is no longer supported.");
            return -1;
        }
        if(is_prefix(arg, "secretAccessKey=")){
            S3FS_PRN_EXIT("option secretAccessKey is no longer supported.");
            return -1;
        }
        if(0 == strcmp(arg, "use_wtf8")){
            use_wtf8 = true;
            return 0;
        }
        if(0 == strcmp(arg, "requester_pays")){
            S3fsCurl::SetRequesterPays(true);
            return 0;
        }
        // [NOTE]
        // following option will be discarding, because these are not for fuse.
        // (Referenced sshfs.c)
        //
        if(0 == strcmp(arg, "auto")   ||
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
    struct fuse_operations s3fs_oper;
    time_t incomp_abort_time = (24 * 60 * 60);
    S3fsLog singletonLog;

    static const struct option long_opts[] = {
        {"help",                 no_argument,       NULL, 'h'},
        {"version",              no_argument,       0,     0},
        {"debug",                no_argument,       NULL, 'd'},
        {"incomplete-mpu-list",  no_argument,       NULL, 'u'},
        {"incomplete-mpu-abort", optional_argument, NULL, 'a'}, // 'a' is only identifier and is not option.
        {NULL, 0, NULL, 0}
    };

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
                if(NO_UTILITY_MODE != utility_mode){
                    S3FS_PRN_EXIT("already utility mode option is specified.");
                    exit(EXIT_FAILURE);
                }
                utility_mode = INCOMP_TYPE_LIST;
                break;
            case 'a':   // --incomplete-mpu-abort
                if(NO_UTILITY_MODE != utility_mode){
                    S3FS_PRN_EXIT("already utility mode option is specified.");
                    exit(EXIT_FAILURE);
                }
                utility_mode = INCOMP_TYPE_ABORT;

                // check expire argument
                if(NULL != optarg && 0 == strcasecmp(optarg, "all")){ // all is 0s
                    incomp_abort_time = 0;
                }else if(NULL != optarg){
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
    // print launch message
    print_launch_message(argc, argv);

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

    // clear this structure
    memset(&s3fs_oper, 0, sizeof(s3fs_oper));

    // This is the fuse-style parser for the arguments
    // after which the bucket name and mountpoint names
    // should have been set
    struct fuse_args custom_args = FUSE_ARGS_INIT(argc, argv);
    if(0 != fuse_opt_parse(&custom_args, NULL, NULL, my_fuse_opt_proc)){
        S3fsCurl::DestroyS3fsCurl();
        s3fs_destroy_global_ssl();
        exit(EXIT_FAILURE);
    }

    // init mime types for curl
    if(!S3fsCurl::InitMimeType(mimetype_file)){
        S3FS_PRN_WARN("Missing MIME types prevents setting Content-Type on uploaded objects.");
    }

    // [NOTE]
    // exclusive option check here.
    //
    if(storage_class_t::REDUCED_REDUNDANCY == S3fsCurl::GetStorageClass() && !S3fsCurl::IsSseDisable()){
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

    if(!FdEntity::GetNoMixMultipart() && max_dirty_data != -1){
        S3FS_PRN_WARN("Setting max_dirty_data to -1 when nomixupload is enabled");
        max_dirty_data = -1;
    }

    // The first plain argument is the bucket
    if(bucket.empty()){
        S3FS_PRN_EXIT("missing BUCKET argument.");
        show_usage();
        S3fsCurl::DestroyS3fsCurl();
        s3fs_destroy_global_ssl();
        exit(EXIT_FAILURE);
    }

    // bucket names cannot contain upper case characters in virtual-hosted style
    if((!pathrequeststyle) && (lower(bucket) != bucket)){
        S3FS_PRN_EXIT("BUCKET %s, name not compatible with virtual-hosted style.", bucket.c_str());
        S3fsCurl::DestroyS3fsCurl();
        s3fs_destroy_global_ssl();
        exit(EXIT_FAILURE);
    }

    // check bucket name for illegal characters
    found = bucket.find_first_of("/:\\;!@#$%^&*?|+=");
    if(found != std::string::npos){
        S3FS_PRN_EXIT("BUCKET %s -- bucket name contains an illegal character.", bucket.c_str());
        S3fsCurl::DestroyS3fsCurl();
        s3fs_destroy_global_ssl();
        exit(EXIT_FAILURE);
    }

    if(!pathrequeststyle && is_prefix(s3host.c_str(), "https://") && bucket.find_first_of('.') != std::string::npos) {
        S3FS_PRN_EXIT("BUCKET %s -- cannot mount bucket with . while using HTTPS without use_path_request_style", bucket.c_str());
        S3fsCurl::DestroyS3fsCurl();
        s3fs_destroy_global_ssl();
        exit(EXIT_FAILURE);
    }

    // The second plain argument is the mountpoint
    // if the option was given, we all ready checked for a
    // readable, non-empty directory, this checks determines
    // if the mountpoint option was ever supplied
    if(NO_UTILITY_MODE == utility_mode){
        if(mountpoint.empty()){
            S3FS_PRN_EXIT("missing MOUNTPOINT argument.");
            show_usage();
            S3fsCurl::DestroyS3fsCurl();
            s3fs_destroy_global_ssl();
            exit(EXIT_FAILURE);
        }
    }

    // error checking of command line arguments for compatibility
    if(S3fsCurl::IsPublicBucket() && S3fsCurl::IsSetAccessKeys()){
        S3FS_PRN_EXIT("specifying both public_bucket and the access keys options is invalid.");
        S3fsCurl::DestroyS3fsCurl();
        s3fs_destroy_global_ssl();
        exit(EXIT_FAILURE);
    }
    if(!passwd_file.empty() && S3fsCurl::IsSetAccessKeys()){
        S3FS_PRN_EXIT("specifying both passwd_file and the access keys options is invalid.");
        S3fsCurl::DestroyS3fsCurl();
        s3fs_destroy_global_ssl();
        exit(EXIT_FAILURE);
    }
    if(!S3fsCurl::IsPublicBucket() && !load_iamrole && !is_ecs){
        if(EXIT_SUCCESS != get_access_keys()){
            S3fsCurl::DestroyS3fsCurl();
            s3fs_destroy_global_ssl();
            exit(EXIT_FAILURE);
        }
        if(!S3fsCurl::IsSetAccessKeys()){
            S3FS_PRN_EXIT("could not establish security credentials, check documentation.");
            S3fsCurl::DestroyS3fsCurl();
            s3fs_destroy_global_ssl();
            exit(EXIT_FAILURE);
        }
        // More error checking on the access key pair can be done
        // like checking for appropriate lengths and characters  
    }

    // check cache dir permission
    if(!FdManager::CheckCacheDirExist() || !FdManager::CheckCacheTopDir() || !CacheFileStat::CheckCacheFileStatTopDir()){
        S3FS_PRN_EXIT("could not allow cache directory permission, check permission of cache directories.");
        S3fsCurl::DestroyS3fsCurl();
        s3fs_destroy_global_ssl();
        exit(EXIT_FAILURE);
    }

    // check IBM IAM requirements
    if(is_ibm_iam_auth){
        // check that default ACL is either public-read or private
        acl_t defaultACL = S3fsCurl::GetDefaultAcl();
        if(defaultACL != acl_t::PRIVATE && defaultACL != acl_t::PUBLIC_READ){
            S3FS_PRN_EXIT("can only use 'public-read' or 'private' ACL while using ibm_iam_auth");
            S3fsCurl::DestroyS3fsCurl();
            s3fs_destroy_global_ssl();
            exit(EXIT_FAILURE);
        }

        if(create_bucket && !S3fsCurl::IsSetAccessKeyID()){
            S3FS_PRN_EXIT("missing service instance ID for bucket creation");
            S3fsCurl::DestroyS3fsCurl();
            s3fs_destroy_global_ssl();
            exit(EXIT_FAILURE);
        }
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
        found = bucket.find_first_of('.');
        if(found != std::string::npos){
            found = s3host.find("https:");
            if(found != std::string::npos){
                S3FS_PRN_EXIT("Using https and a bucket name with periods is unsupported.");
                exit(1);
            }
        }
    }
    */

    if(NO_UTILITY_MODE != utility_mode){
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

    // check free disk space
    if(!FdManager::IsSafeDiskSpace(NULL, S3fsCurl::GetMultipartSize() * S3fsCurl::GetMaxParallelCount())){
        S3FS_PRN_EXIT("There is no enough disk space for used as cache(or temporary) directory by s3fs.");
        S3fsCurl::DestroyS3fsCurl();
        s3fs_destroy_global_ssl();
        exit(EXIT_FAILURE);
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

    // now passing things off to fuse, fuse will finish evaluating the command line args
    fuse_res = fuse_main(custom_args.argc, custom_args.argv, &s3fs_oper, NULL);
    fuse_opt_free_args(&custom_args);

    // Destroy curl
    if(!S3fsCurl::DestroyS3fsCurl()){
        S3FS_PRN_WARN("Could not release curl library.");
    }
    s3fs_destroy_global_ssl();

    // cleanup xml2
    xmlCleanupParser();
    S3FS_MALLOCTRIM(0);

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
