/*
 * s3fs - FUSE-based file system backed by Amazon S3
 *
 * Copyright 2007-2008 Randy Rizun <rrizun@gmail.com>
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include <libxml/tree.h>
#include <curl/curl.h>
#include <pwd.h>
#include <grp.h>
#include <getopt.h>
#include <signal.h>

#include <fstream>
#include <vector>
#include <algorithm>
#include <map>
#include <string>
#include <list>

#include "common.h"
#include "s3fs.h"
#include "curl.h"
#include "cache.h"
#include "string_util.h"
#include "s3fs_util.h"
#include "fdcache.h"
#include "s3fs_auth.h"
#include "addhead.h"

using namespace std;

//-------------------------------------------------------------------
// Define
//-------------------------------------------------------------------
#define	DIRTYPE_UNKNOWN    -1
#define	DIRTYPE_NEW         0
#define	DIRTYPE_OLD         1
#define	DIRTYPE_FOLDER      2
#define	DIRTYPE_NOOBJ       3

#define	IS_REPLACEDIR(type) (DIRTYPE_OLD == type || DIRTYPE_FOLDER == type || DIRTYPE_NOOBJ == type)
#define	IS_RMTYPEDIR(type)  (DIRTYPE_OLD == type || DIRTYPE_FOLDER == type)

#if !defined(ENOATTR)
#define ENOATTR				ENODATA
#endif

//-------------------------------------------------------------------
// Structs
//-------------------------------------------------------------------
typedef struct incomplete_multipart_info{
  string key;
  string id;
  string date;
}UNCOMP_MP_INFO;

typedef std::list<UNCOMP_MP_INFO> uncomp_mp_list_t;

//-------------------------------------------------------------------
// Global variables
//-------------------------------------------------------------------
bool foreground                   = false;
bool nomultipart                  = false;
bool pathrequeststyle             = false;
std::string program_name;
std::string service_path          = "/";
std::string host                  = "http://s3.amazonaws.com";
std::string bucket                = "";
std::string endpoint              = "us-east-1";
s3fs_log_level debug_level        = S3FS_LOG_CRIT;
const char*    s3fs_log_nest[S3FS_LOG_NEST_MAX] = {"", "  ", "    ", "      "};

//-------------------------------------------------------------------
// Static variables
//-------------------------------------------------------------------
static uid_t mp_uid               = 0;    // owner of mount point(only not specified uid opt)
static gid_t mp_gid               = 0;    // group of mount point(only not specified gid opt)
static mode_t mp_mode             = 0;    // mode of mount point
static mode_t mp_umask            = 0;    // umask for mount point
static bool is_mp_umask           = false;// default does not set.
static std::string mountpoint;
static std::string passwd_file    = "";
static bool utility_mode          = false;
static bool noxmlns               = false;
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
static bool is_use_xattr          = false;
static bool create_bucket         = false;
static int64_t singlepart_copy_limit = FIVE_GB;
static bool is_specified_endpoint = false;
static int s3fs_init_deferred_exit_status = 0;

//-------------------------------------------------------------------
// Static functions : prototype
//-------------------------------------------------------------------
static void s3fs_usr2_handler(int sig);
static bool set_s3fs_usr2_handler(void);
static s3fs_log_level set_s3fs_log_level(s3fs_log_level level);
static s3fs_log_level bumpup_s3fs_log_level(void);
static bool is_special_name_folder_object(const char* path);
static int chk_dir_object_type(const char* path, string& newpath, string& nowpath, string& nowcache, headers_t* pmeta = NULL, int* pDirType = NULL);
static int get_object_attribute(const char* path, struct stat* pstbuf, headers_t* pmeta = NULL, bool overcheck = true, bool* pisforce = NULL, bool add_no_truncate_cache = false);
static int check_object_access(const char* path, int mask, struct stat* pstbuf);
static int check_object_owner(const char* path, struct stat* pstbuf);
static int check_parent_object_access(const char* path, int mask);
static FdEntity* get_local_fent(const char* path, bool is_load = false);
static bool multi_head_callback(S3fsCurl* s3fscurl);
static S3fsCurl* multi_head_retry_callback(S3fsCurl* s3fscurl);
static int readdir_multi_head(const char* path, S3ObjList& head, void* buf, fuse_fill_dir_t filler);
static int list_bucket(const char* path, S3ObjList& head, const char* delimiter, bool check_content_only = false);
static int directory_empty(const char* path);
static bool is_truncated(xmlDocPtr doc);
static int append_objects_from_xml_ex(const char* path, xmlDocPtr doc, xmlXPathContextPtr ctx, 
              const char* ex_contents, const char* ex_key, const char* ex_etag, int isCPrefix, S3ObjList& head);
static int append_objects_from_xml(const char* path, xmlDocPtr doc, S3ObjList& head);
static bool GetXmlNsUrl(xmlDocPtr doc, string& nsurl);
static xmlChar* get_base_exp(xmlDocPtr doc, const char* exp);
static xmlChar* get_prefix(xmlDocPtr doc);
static xmlChar* get_next_marker(xmlDocPtr doc);
static char* get_object_name(xmlDocPtr doc, xmlNodePtr node, const char* path);
static int put_headers(const char* path, headers_t& meta, bool is_copy);
static int rename_large_object(const char* from, const char* to);
static int create_file_object(const char* path, mode_t mode, uid_t uid, gid_t gid);
static int create_directory_object(const char* path, mode_t mode, time_t time, uid_t uid, gid_t gid);
static int rename_object(const char* from, const char* to);
static int rename_object_nocopy(const char* from, const char* to);
static int clone_directory_object(const char* from, const char* to);
static int rename_directory(const char* from, const char* to);
static int remote_mountpath_exists(const char* path);
static xmlChar* get_exp_value_xml(xmlDocPtr doc, xmlXPathContextPtr ctx, const char* exp_key);
static void print_uncomp_mp_list(uncomp_mp_list_t& list);
static bool abort_uncomp_mp_list(uncomp_mp_list_t& list);
static bool get_uncomp_mp_list(xmlDocPtr doc, uncomp_mp_list_t& list);
static void free_xattrs(xattrs_t& xattrs);
static bool parse_xattr_keyval(const std::string& xattrpair, string& key, PXATTRVAL& pval);
static size_t parse_xattrs(const std::string& strxattrs, xattrs_t& xattrs);
static std::string build_xattrs(const xattrs_t& xattrs);
static int s3fs_utility_mode(void);
static int s3fs_check_service(void);
static int check_for_aws_format(void);
static int check_passwd_file_perms(void);
static int read_passwd_file(void);
static int get_access_keys(void);
static int set_mountpoint_attribute(struct stat& mpst);
static int set_bucket(const char* arg);
static int my_fuse_opt_proc(void* data, const char* arg, int key, struct fuse_args* outargs);

// fuse interface functions
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
static void s3fs_usr2_handler(int sig)
{
  if(SIGUSR2 == sig){
    bumpup_s3fs_log_level();
  }
}
static bool set_s3fs_usr2_handler(void)
{
  struct sigaction sa;

  memset(&sa, 0, sizeof(struct sigaction));
  sa.sa_handler = s3fs_usr2_handler;
  sa.sa_flags   = SA_RESTART;
  if(0 != sigaction(SIGUSR2, &sa, NULL)){
    return false;
  }
  return true;
}

static s3fs_log_level set_s3fs_log_level(s3fs_log_level level)
{
  if(level == debug_level){
    return debug_level;
  }
  s3fs_log_level old = debug_level;
  debug_level        = level;
  setlogmask(LOG_UPTO(S3FS_LOG_LEVEL_TO_SYSLOG(debug_level)));
  S3FS_PRN_CRIT("change debug level from %sto %s", S3FS_LOG_LEVEL_STRING(old), S3FS_LOG_LEVEL_STRING(debug_level));
  return old;
}

static s3fs_log_level bumpup_s3fs_log_level(void)
{
  s3fs_log_level old = debug_level;
  debug_level        = ( S3FS_LOG_CRIT == debug_level ? S3FS_LOG_ERR :
                         S3FS_LOG_ERR  == debug_level ? S3FS_LOG_WARN :
                         S3FS_LOG_WARN == debug_level ? S3FS_LOG_INFO :
                         S3FS_LOG_INFO == debug_level ? S3FS_LOG_DBG :
                         S3FS_LOG_CRIT );
  setlogmask(LOG_UPTO(S3FS_LOG_LEVEL_TO_SYSLOG(debug_level)));
  S3FS_PRN_CRIT("change debug level from %sto %s", S3FS_LOG_LEVEL_STRING(old), S3FS_LOG_LEVEL_STRING(debug_level));
  return old;
}

static bool is_special_name_folder_object(const char* path)
{
  if(!path || '\0' == path[0]){
    return false;
  }

  string    strpath = path;
  headers_t header;

  if(string::npos == strpath.find("_$folder$", 0)){
    if('/' == strpath[strpath.length() - 1]){
      strpath = strpath.substr(0, strpath.length() - 1);
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
static int chk_dir_object_type(const char* path, string& newpath, string& nowpath, string& nowcache, headers_t* pmeta, int* pDirType)
{
  int  TypeTmp;
  int  result  = -1;
  bool isforce = false;
  int* pType   = pDirType ? pDirType : &TypeTmp;

  // Normalize new path.
  newpath = path;
  if('/' != newpath[newpath.length() - 1]){
    string::size_type Pos;
    if(string::npos != (Pos = newpath.find("_$folder$", 0))){
      newpath = newpath.substr(0, Pos);
    }
    newpath += "/";
  }

  // Always check "dir/" at first.
  if(0 == (result = get_object_attribute(newpath.c_str(), NULL, pmeta, false, &isforce))){
    // Found "dir/" cache --> Check for "_$folder$", "no dir object"
    nowcache = newpath;
    if(is_special_name_folder_object(newpath.c_str())){
      // "_$folder$" type.
      (*pType) = DIRTYPE_FOLDER;
      nowpath = newpath.substr(0, newpath.length() - 1) + "_$folder$"; // cut and add
    }else if(isforce){
      // "no dir object" type.
      (*pType) = DIRTYPE_NOOBJ;
      nowpath  = "";
    }else{
      nowpath = path;
      if(0 < nowpath.length() && '/' == nowpath[nowpath.length() - 1]){
        // "dir/" type
        (*pType) = DIRTYPE_NEW;
      }else{
        // "dir" type
        (*pType) = DIRTYPE_OLD;
      }
    }
  }else{
    // Check "dir"
    nowpath = newpath.substr(0, newpath.length() - 1);
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
  string       strpath;
  S3fsCurl     s3fscurl;
  bool         forcedir = false;
  string::size_type Pos;

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
  strpath = path;
  if(overcheck && string::npos != (Pos = strpath.find("_$folder$", 0))){
    strpath = strpath.substr(0, Pos);
    strpath += "/";
  }
  if(pisforce){
    (*pisforce) = false;
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

  // overcheck
  if(overcheck && 0 != result){
    if('/' != strpath[strpath.length() - 1] && string::npos == strpath.find("_$folder$", 0)){
      // path is "object", check "object/" for overcheck
      strpath    += "/";
      result      = s3fscurl.HeadRequest(strpath.c_str(), (*pheader));
      s3fscurl.DestroyCurlHandle();
    }
    if(0 != result){
      // not found "object/", check "_$folder$"
      strpath = path;
      if(string::npos == strpath.find("_$folder$", 0)){
        if('/' == strpath[strpath.length() - 1]){
          strpath = strpath.substr(0, strpath.length() - 1);
        }
        strpath    += "_$folder$";
        result      = s3fscurl.HeadRequest(strpath.c_str(), (*pheader));
        s3fscurl.DestroyCurlHandle();
      }
    }
    if(0 != result){
      // not found "object/" and "object_$folder$", check no dir object.
      strpath = path;
      if(string::npos == strpath.find("_$folder$", 0)){
        if('/' == strpath[strpath.length() - 1]){
          strpath = strpath.substr(0, strpath.length() - 1);
        }
        if(-ENOTEMPTY == directory_empty(strpath.c_str())){
          // found "no dir object".
          strpath += "/";
          forcedir = true;
          if(pisforce){
            (*pisforce) = true;
          }
          result = 0;
        }
      }
    }
  }else{
    // found "path" object.
    if('/' != strpath[strpath.length() - 1]){
      // check a case of that "object" does not have attribute and "object" is possible to be directory.
      if(is_need_check_obj_detail(*pheader)){
        if(-ENOTEMPTY == directory_empty(strpath.c_str())){
          strpath += "/";
          forcedir = true;
          if(pisforce){
            (*pisforce) = true;
          }
          result = 0;
        }
      }
    }
  }

  if(0 != result){
    // finally, "path" object did not find. Add no object cache.
    strpath = path;  // reset original
    StatCache::getStatCacheData()->AddNoObjectCache(strpath);
    return result;
  }

  // if path has "_$folder$", need to cut it.
  if(string::npos != (Pos = strpath.find("_$folder$", 0))){
    strpath = strpath.substr(0, Pos);
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
  string parent;
  int result;

  S3FS_PRN_DBG("[path=%s]", path);

  if(0 == strcmp(path, "/") || 0 == strcmp(path, ".")){
    // path is mount point.
    return 0;
  }
  if(X_OK == (mask & X_OK)){
    for(parent = mydirname(path); 0 < parent.size(); parent = mydirname(parent)){
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
bool get_object_sse_type(const char* path, sse_type_t& ssetype, string& ssevalue)
{
  if(!path){
    return false;
  }

  headers_t meta;
  if(0 != get_object_attribute(path, NULL, &meta)){
    S3FS_PRN_ERR("Failed to get object(%s) headers", path);
    return false;
  }

  ssetype = SSE_DISABLE;
  ssevalue.erase();
  for(headers_t::iterator iter = meta.begin(); iter != meta.end(); ++iter){
    string key = (*iter).first;
    if(0 == strcasecmp(key.c_str(), "x-amz-server-side-encryption") && 0 == strcasecmp((*iter).second.c_str(), "AES256")){
      ssetype  = SSE_S3;
    }else if(0 == strcasecmp(key.c_str(), "x-amz-server-side-encryption-aws-kms-key-id")){
      ssetype  = SSE_KMS;
      ssevalue = (*iter).second;
    }else if(0 == strcasecmp(key.c_str(), "x-amz-server-side-encryption-customer-key-md5")){
      ssetype  = SSE_C;
      ssevalue = (*iter).second;
    }
  }
  return true;
}

static FdEntity* get_local_fent(const char* path, bool is_load)
{
  struct stat stobj;
  FdEntity*   ent;
  headers_t   meta;

  S3FS_PRN_INFO2("[path=%s]", path);

  if(0 != get_object_attribute(path, &stobj, &meta)){
    return NULL;
  }

  // open
  time_t mtime         = (!S_ISREG(stobj.st_mode) || S_ISLNK(stobj.st_mode)) ? -1 : stobj.st_mtime;
  bool   force_tmpfile = S_ISREG(stobj.st_mode) ? false : true;

  if(NULL == (ent = FdManager::get()->Open(path, &meta, static_cast<ssize_t>(stobj.st_size), mtime, force_tmpfile, true))){
    S3FS_PRN_ERR("Could not open file. errno(%d)", errno);
    return NULL;
  }
  // load
  if(is_load && !ent->OpenAndLoadAll(&meta)){
    S3FS_PRN_ERR("Could not load file. errno(%d)", errno);
    FdManager::get()->Close(ent);
    return NULL;
  }
  return ent;
}

/**
 * create or update s3 meta
 * ow_sse_flg is for over writing sse header by use_sse option.
 * @return fuse return code
 */
static int put_headers(const char* path, headers_t& meta, bool is_copy)
{
  int         result;
  S3fsCurl    s3fscurl(true);
  struct stat buf;

  S3FS_PRN_INFO2("[path=%s]", path);

  // files larger than 5GB must be modified via the multipart interface
  // *** If there is not target object(a case of move command),
  //     get_object_attribute() returns error with initializing buf.
  (void)get_object_attribute(path, &buf);

  if(buf.st_size >= FIVE_GB){
    // multipart
    if(0 != (result = s3fscurl.MultipartHeadRequest(path, buf.st_size, meta, is_copy))){
      return result;
    }
  }else{
    if(0 != (result = s3fscurl.PutHeadRequest(path, meta, is_copy))){
      return result;
    }
  }

  FdEntity* ent = NULL;
  if(NULL == (ent = FdManager::get()->ExistOpen(path, -1, !(FdManager::get()->IsCacheDir())))){
    // no opened fd
    if(FdManager::get()->IsCacheDir()){
      // create cache file if be needed
      ent = FdManager::get()->Open(path, &meta, static_cast<ssize_t>(buf.st_size), -1, false, true);
    }
  }
  if(ent){
    time_t mtime = get_mtime(meta);
    ent->SetMtime(mtime);
    FdManager::get()->Close(ent);
  }

  return 0;
}

static int s3fs_getattr(const char* path, struct stat* stbuf)
{
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
    FdEntity*   ent;

    if(NULL != (ent = FdManager::get()->ExistOpen(path))){
      struct stat tmpstbuf;
      if(ent->GetStats(tmpstbuf)){
        stbuf->st_size = tmpstbuf.st_size;
      }
      FdManager::get()->Close(ent);
    }
    stbuf->st_blksize = 4096;
    stbuf->st_blocks  = get_blocks(stbuf->st_size);
  }
  S3FS_PRN_DBG("[path=%s] uid=%u, gid=%u, mode=%04o", path, (unsigned int)(stbuf->st_uid), (unsigned int)(stbuf->st_gid), stbuf->st_mode);
  S3FS_MALLOCTRIM(0);

  return result;
}

static int s3fs_readlink(const char* path, char* buf, size_t size)
{
  if(!path || !buf || 0 >= size){
    return 0;
  }
  // Open
  FdEntity*   ent;
  if(NULL == (ent = get_local_fent(path))){
    S3FS_PRN_ERR("could not get fent(file=%s)", path);
    return -EIO;
  }
  // Get size
  size_t readsize;
  if(!ent->GetSize(readsize)){
    S3FS_PRN_ERR("could not get file size(file=%s)", path);
    FdManager::get()->Close(ent);
    return -EIO;
  }
  if(size <= readsize){
    readsize = size - 1;
  }
  // Read
  ssize_t ressize;
  if(0 > (ressize = ent->Read(buf, 0, readsize))){
    S3FS_PRN_ERR("could not read file(file=%s, errno=%zd)", path, ressize);
    FdManager::get()->Close(ent);
    return static_cast<int>(ressize);
  }
  buf[ressize] = '\0';

  // check buf if it has space words.
  string strTmp = trim(string(buf));
  strcpy(buf, strTmp.c_str());

  FdManager::get()->Close(ent);
  S3FS_MALLOCTRIM(0);

  return 0;
}

static int do_create_bucket(void)
{
  S3FS_PRN_INFO2("/");

  FILE* ptmpfp;
  int   tmpfd;
  if(endpoint == "us-east-1"){
    ptmpfp = NULL;
    tmpfd = -1;
  }else{
    if(NULL == (ptmpfp = tmpfile()) ||
       -1 == (tmpfd = fileno(ptmpfp)) ||
       0 >= fprintf(ptmpfp, "<CreateBucketConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\n"
        "  <LocationConstraint>%s</LocationConstraint>\n"
        "</CreateBucketConfiguration>", endpoint.c_str()) ||
       0 != fflush(ptmpfp) ||
       -1 == fseek(ptmpfp, 0L, SEEK_SET)){
      S3FS_PRN_ERR("failed to create temporary file. err(%d)", errno);
      if(ptmpfp){
        fclose(ptmpfp);
      }
      return (0 == errno ? -EIO : -errno);
    }
  }

  headers_t meta;

  S3fsCurl s3fscurl(true);
  long     res = s3fscurl.PutRequest("/", meta, tmpfd);
  if(res < 0){
    long responseCode = s3fscurl.GetLastResponseCode();
    if((responseCode == 400 || responseCode == 403) && S3fsCurl::IsSignatureV4()){
      S3FS_PRN_ERR("Could not connect, so retry to connect by signature version 2.");
      S3fsCurl::SetSignatureV4(false);

      // retry to check
      s3fscurl.DestroyCurlHandle();
      res = s3fscurl.PutRequest("/", meta, tmpfd);
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

  headers_t meta;
  meta["Content-Type"]     = S3fsCurl::LookupMimeType(string(path));
  meta["x-amz-meta-uid"]   = str(uid);
  meta["x-amz-meta-gid"]   = str(gid);
  meta["x-amz-meta-mode"]  = str(mode);
  meta["x-amz-meta-mtime"] = str(time(NULL));

  S3fsCurl s3fscurl(true);
  return s3fscurl.PutRequest(path, meta, -1);    // fd=-1 means for creating zero byte object.
}

static int s3fs_mknod(const char *path, mode_t mode, dev_t rdev)
{
  int       result;
  struct fuse_context* pcxt;

  S3FS_PRN_INFO("[path=%s][mode=%04o][dev=%ju]", path, mode, (uintmax_t)rdev);

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

static int s3fs_create(const char* path, mode_t mode, struct fuse_file_info* fi)
{
  int result;
  struct fuse_context* pcxt;

  S3FS_PRN_INFO("[path=%s][mode=%04o][flags=%d]", path, mode, fi->flags);

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


  FdEntity*   ent;
  headers_t   meta;
  get_object_attribute(path, NULL, &meta, true, NULL, true);    // no truncate cache
  if(NULL == (ent = FdManager::get()->Open(path, &meta, 0, -1, false, true))){
    StatCache::getStatCacheData()->DelStat(path);
    return -EIO;
  }
  fi->fh = ent->GetFd();
  S3FS_MALLOCTRIM(0);

  return 0;
}

static int create_directory_object(const char* path, mode_t mode, time_t time, uid_t uid, gid_t gid)
{
  S3FS_PRN_INFO1("[path=%s][mode=%04o][time=%jd][uid=%u][gid=%u]", path, mode, (intmax_t)time, (unsigned int)uid, (unsigned int)gid);

  if(!path || '\0' == path[0]){
    return -1;
  }
  string tpath = path;
  if('/' != tpath[tpath.length() - 1]){
    tpath += "/";
  }

  headers_t meta;
  meta["Content-Type"]     = string("application/x-directory");
  meta["x-amz-meta-uid"]   = str(uid);
  meta["x-amz-meta-gid"]   = str(gid);
  meta["x-amz-meta-mode"]  = str(mode);
  meta["x-amz-meta-mtime"] = str(time);

  S3fsCurl s3fscurl;
  return s3fscurl.PutRequest(tpath.c_str(), meta, -1);    // fd=-1 means for creating zero byte object.
}

static int s3fs_mkdir(const char* path, mode_t mode)
{
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

  result = create_directory_object(path, mode, time(NULL), pcxt->uid, pcxt->gid);
  StatCache::getStatCacheData()->DelStat(path);
  S3FS_MALLOCTRIM(0);

  return result;
}

static int s3fs_unlink(const char* path)
{
  int result;

  S3FS_PRN_INFO("[path=%s]", path);

  if(0 != (result = check_parent_object_access(path, W_OK | X_OK))){
    return result;
  }
  S3fsCurl s3fscurl;
  result = s3fscurl.DeleteRequest(path);
  FdManager::DeleteCacheFile(path);
  StatCache::getStatCacheData()->DelStat(path);
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

static int s3fs_rmdir(const char* path)
{
  int result;
  string strpath;
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
    strpath = strpath.substr(0, strpath.length() - 1);
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

static int s3fs_symlink(const char* from, const char* to)
{
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

  headers_t headers;
  headers["Content-Type"]     = string("application/octet-stream"); // Static
  headers["x-amz-meta-mode"]  = str(S_IFLNK | S_IRWXU | S_IRWXG | S_IRWXO);
  headers["x-amz-meta-mtime"] = str(time(NULL));
  headers["x-amz-meta-uid"]   = str(pcxt->uid);
  headers["x-amz-meta-gid"]   = str(pcxt->gid);

  // open tmpfile
  FdEntity* ent;
  if(NULL == (ent = FdManager::get()->Open(to, &headers, 0, -1, true, true))){
    S3FS_PRN_ERR("could not open tmpfile(errno=%d)", errno);
    return -errno;
  }
  // write(without space words)
  string  strFrom   = trim(string(from));
  ssize_t from_size = static_cast<ssize_t>(strFrom.length());
  if(from_size != ent->Write(strFrom.c_str(), 0, from_size)){
    S3FS_PRN_ERR("could not write tmpfile(errno=%d)", errno);
    FdManager::get()->Close(ent);
    return -errno;
  }
  // upload
  if(0 != (result = ent->Flush(true))){
    S3FS_PRN_WARN("could not upload tmpfile(result=%d)", result);
  }
  FdManager::get()->Close(ent);

  StatCache::getStatCacheData()->DelStat(to);
  S3FS_MALLOCTRIM(0);

  return result;
}

static int rename_object(const char* from, const char* to)
{
  int result;
  string s3_realpath;
  headers_t meta;

  S3FS_PRN_INFO1("[from=%s][to=%s]", from , to);

  if(0 != (result = check_parent_object_access(to, W_OK | X_OK))){
    // not permit writing "to" object parent dir.
    return result;
  }
  if(0 != (result = check_parent_object_access(from, W_OK | X_OK))){
    // not permit removing "from" object parent dir.
    return result;
  }
  if(0 != (result = get_object_attribute(from, NULL, &meta))){
    return result;
  }
  s3_realpath = get_realpath(from);

  meta["x-amz-copy-source"]        = urlEncode(service_path + bucket + s3_realpath);
  meta["Content-Type"]             = S3fsCurl::LookupMimeType(string(to));
  meta["x-amz-metadata-directive"] = "REPLACE";

  if(0 != (result = put_headers(to, meta, true))){
    return result;
  }

  FdManager::get()->Rename(from, to);

  result = s3fs_unlink(from);
  StatCache::getStatCacheData()->DelStat(to);

  return result;
}

static int rename_object_nocopy(const char* from, const char* to)
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
  FdEntity* ent;
  if(NULL == (ent = get_local_fent(from, true))){
    S3FS_PRN_ERR("could not open and read file(%s)", from);
    return -EIO;
  }

  // Set header
  if(!ent->SetContentType(to)){
    S3FS_PRN_ERR("could not set content-type for %s", to);
    return -EIO;
  }

  // upload
  if(0 != (result = ent->RowFlush(to, true))){
    S3FS_PRN_ERR("could not upload file(%s): result=%d", to, result);
    FdManager::get()->Close(ent);
    return result;
  }
  FdManager::get()->Close(ent);

  // Remove file
  result = s3fs_unlink(from);

  // Stats
  StatCache::getStatCacheData()->DelStat(to);
  StatCache::getStatCacheData()->DelStat(from);

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
  StatCache::getStatCacheData()->DelStat(to);

  return s3fs_unlink(from);
}

static int clone_directory_object(const char* from, const char* to)
{
  int result = -1;
  struct stat stbuf;

  S3FS_PRN_INFO1("[from=%s][to=%s]", from, to);

  // get target's attributes
  if(0 != (result = get_object_attribute(from, &stbuf))){
    return result;
  }
  result = create_directory_object(to, stbuf.st_mode, stbuf.st_mtime, stbuf.st_uid, stbuf.st_gid);
  StatCache::getStatCacheData()->DelStat(to);

  return result;
}

static int rename_directory(const char* from, const char* to)
{
  S3ObjList head;
  s3obj_list_t headlist;
  string strfrom  = from ? from : "";	// from is without "/".
  string strto    = to ? to : "";	// to is without "/" too.
  string basepath = strfrom + "/";
  string newpath;                       // should be from name(not used)
  string nowcache;                      // now cache path(not used)
  int DirType;
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
      strfrom = from;	// from directory is not removed, but from directory attr is needed.
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
    string from_name = basepath + (*liter);
    string to_name   = strto + (*liter);
    string etag      = head.GetETag((*liter).c_str());

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
      if(0 != (result = clone_directory_object(mn_cur->old_path, mn_cur->new_path))){
        S3FS_PRN_ERR("clone_directory_object returned an error(%d)", result);
        free_mvnodes(mn_head);
        return -EIO;
      }
    }
  }

  // iterate over the list - copy the files with rename_object
  // does a safe copy - copies first and then deletes old
  for(mn_cur = mn_head; mn_cur; mn_cur = mn_cur->next){
    if(!mn_cur->is_dir){
      if(!nocopyapi && !norenameapi){
        result = rename_object(mn_cur->old_path, mn_cur->new_path);
      }else{
        result = rename_object_nocopy(mn_cur->old_path, mn_cur->new_path);
      }
      if(0 != result){
        S3FS_PRN_ERR("rename_object returned an error(%d)", result);
        free_mvnodes(mn_head);
        return -EIO;
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
          return -EIO;
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

static int s3fs_rename(const char* from, const char* to)
{
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

  // files larger than 5GB must be modified via the multipart interface
  if(S_ISDIR(buf.st_mode)){
    result = rename_directory(from, to);
  }else if(!nomultipart && buf.st_size >= singlepart_copy_limit){
    result = rename_large_object(from, to);
  }else{
    if(!nocopyapi && !norenameapi){
      result = rename_object(from, to);
    }else{
      result = rename_object_nocopy(from, to);
    }
  }
  S3FS_MALLOCTRIM(0);

  return result;
}

static int s3fs_link(const char* from, const char* to)
{
  S3FS_PRN_INFO("[from=%s][to=%s]", from, to);
  return -EPERM;
}

static int s3fs_chmod(const char* path, mode_t mode)
{
  int result;
  string strpath;
  string newpath;
  string nowcache;
  headers_t meta;
  struct stat stbuf;
  int nDirType = DIRTYPE_UNKNOWN;

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
    if(IS_RMTYPEDIR(nDirType)){
      S3fsCurl s3fscurl;
      if(0 != (result = s3fscurl.DeleteRequest(strpath.c_str()))){
        return result;
      }
    }
    StatCache::getStatCacheData()->DelStat(nowcache);

    // Make new directory object("dir/")
    if(0 != (result = create_directory_object(newpath.c_str(), mode, stbuf.st_mtime, stbuf.st_uid, stbuf.st_gid))){
      return result;
    }
  }else{
    // normal object or directory object of newer version
    meta["x-amz-meta-mode"]          = str(mode);
    meta["x-amz-copy-source"]        = urlEncode(service_path + bucket + get_realpath(strpath.c_str()));
    meta["x-amz-metadata-directive"] = "REPLACE";

    if(put_headers(strpath.c_str(), meta, true) != 0){
      return -EIO;
    }
    StatCache::getStatCacheData()->DelStat(nowcache);

    // check opened file handle.
    //
    // If we have already opened file handle, should set mode to it.
    // And new mode is set when the file handle is closed.
    //
    FdEntity* ent;
    if(NULL != (ent = FdManager::get()->ExistOpen(path))){
      ent->SetMode(mode);      // Set new mode to opened fd.
      FdManager::get()->Close(ent);
    }
  }
  S3FS_MALLOCTRIM(0);

  return 0;
}

static int s3fs_chmod_nocopy(const char* path, mode_t mode)
{
  int         result;
  string      strpath;
  string      newpath;
  string      nowcache;
  struct stat stbuf;
  int         nDirType = DIRTYPE_UNKNOWN;

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
    if(IS_RMTYPEDIR(nDirType)){
      S3fsCurl s3fscurl;
      if(0 != (result = s3fscurl.DeleteRequest(strpath.c_str()))){
        return result;
      }
    }
    StatCache::getStatCacheData()->DelStat(nowcache);

    // Make new directory object("dir/")
    if(0 != (result = create_directory_object(newpath.c_str(), mode, stbuf.st_mtime, stbuf.st_uid, stbuf.st_gid))){
      return result;
    }
  }else{
    // normal object or directory object of newer version

    // open & load
    FdEntity* ent;
    if(NULL == (ent = get_local_fent(strpath.c_str(), true))){
      S3FS_PRN_ERR("could not open and read file(%s)", strpath.c_str());
      return -EIO;
    }

    // Change file mode
    ent->SetMode(mode);

    // upload
    if(0 != (result = ent->Flush(true))){
      S3FS_PRN_ERR("could not upload file(%s): result=%d", strpath.c_str(), result);
      FdManager::get()->Close(ent);
      return result;
    }
    FdManager::get()->Close(ent);

    StatCache::getStatCacheData()->DelStat(nowcache);
  }
  S3FS_MALLOCTRIM(0);

  return result;
}

static int s3fs_chown(const char* path, uid_t uid, gid_t gid)
{
  int result;
  string strpath;
  string newpath;
  string nowcache;
  headers_t meta;
  struct stat stbuf;
  int nDirType = DIRTYPE_UNKNOWN;

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

  struct passwd* pwdata= getpwuid(uid);
  struct group* grdata = getgrgid(gid);
  if(pwdata){
    uid = pwdata->pw_uid;
  }
  if(grdata){
    gid = grdata->gr_gid;
  }

  if(S_ISDIR(stbuf.st_mode) && IS_REPLACEDIR(nDirType)){
    // Should rebuild directory object(except new type)
    // Need to remove old dir("dir" etc) and make new dir("dir/")

    // At first, remove directory old object
    if(IS_RMTYPEDIR(nDirType)){
      S3fsCurl s3fscurl;
      if(0 != (result = s3fscurl.DeleteRequest(strpath.c_str()))){
        return result;
      }
    }
    StatCache::getStatCacheData()->DelStat(nowcache);

    // Make new directory object("dir/")
    if(0 != (result = create_directory_object(newpath.c_str(), stbuf.st_mode, stbuf.st_mtime, uid, gid))){
      return result;
    }
  }else{
    meta["x-amz-meta-uid"]           = str(uid);
    meta["x-amz-meta-gid"]           = str(gid);
    meta["x-amz-copy-source"]        = urlEncode(service_path + bucket + get_realpath(strpath.c_str()));
    meta["x-amz-metadata-directive"] = "REPLACE";

    if(put_headers(strpath.c_str(), meta, true) != 0){
      return -EIO;
    }
    StatCache::getStatCacheData()->DelStat(nowcache);
  }
  S3FS_MALLOCTRIM(0);

  return 0;
}

static int s3fs_chown_nocopy(const char* path, uid_t uid, gid_t gid)
{
  int         result;
  string      strpath;
  string      newpath;
  string      nowcache;
  struct stat stbuf;
  int         nDirType = DIRTYPE_UNKNOWN;

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

  struct passwd* pwdata= getpwuid(uid);
  struct group* grdata = getgrgid(gid);
  if(pwdata){
    uid = pwdata->pw_uid;
  }
  if(grdata){
    gid = grdata->gr_gid;
  }

  if(S_ISDIR(stbuf.st_mode)){
    // Should rebuild all directory object
    // Need to remove old dir("dir" etc) and make new dir("dir/")

    // At first, remove directory old object
    if(IS_RMTYPEDIR(nDirType)){
      S3fsCurl s3fscurl;
      if(0 != (result = s3fscurl.DeleteRequest(strpath.c_str()))){
        return result;
      }
    }
    StatCache::getStatCacheData()->DelStat(nowcache);

    // Make new directory object("dir/")
    if(0 != (result = create_directory_object(newpath.c_str(), stbuf.st_mode, stbuf.st_mtime, uid, gid))){
      return result;
    }
  }else{
    // normal object or directory object of newer version

    // open & load
    FdEntity* ent;
    if(NULL == (ent = get_local_fent(strpath.c_str(), true))){
      S3FS_PRN_ERR("could not open and read file(%s)", strpath.c_str());
      return -EIO;
    }

    // Change owner
    ent->SetUId(uid);
    ent->SetGId(gid);

    // upload
    if(0 != (result = ent->Flush(true))){
      S3FS_PRN_ERR("could not upload file(%s): result=%d", strpath.c_str(), result);
      FdManager::get()->Close(ent);
      return result;
    }
    FdManager::get()->Close(ent);

    StatCache::getStatCacheData()->DelStat(nowcache);
  }
  S3FS_MALLOCTRIM(0);

  return result;
}

static int s3fs_utimens(const char* path, const struct timespec ts[2])
{
  int result;
  string strpath;
  string newpath;
  string nowcache;
  headers_t meta;
  struct stat stbuf;
  int nDirType = DIRTYPE_UNKNOWN;

  S3FS_PRN_INFO("[path=%s][mtime=%jd]", path, (intmax_t)(ts[1].tv_sec));

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
    if(IS_RMTYPEDIR(nDirType)){
      S3fsCurl s3fscurl;
      if(0 != (result = s3fscurl.DeleteRequest(strpath.c_str()))){
        return result;
      }
    }
    StatCache::getStatCacheData()->DelStat(nowcache);

    // Make new directory object("dir/")
    if(0 != (result = create_directory_object(newpath.c_str(), stbuf.st_mode, ts[1].tv_sec, stbuf.st_uid, stbuf.st_gid))){
      return result;
    }
  }else{
    meta["x-amz-meta-mtime"]         = str(ts[1].tv_sec);
    meta["x-amz-copy-source"]        = urlEncode(service_path + bucket + get_realpath(strpath.c_str()));
    meta["x-amz-metadata-directive"] = "REPLACE";

    if(put_headers(strpath.c_str(), meta, true) != 0){
      return -EIO;
    }
    StatCache::getStatCacheData()->DelStat(nowcache);
  }
  S3FS_MALLOCTRIM(0);

  return 0;
}

static int s3fs_utimens_nocopy(const char* path, const struct timespec ts[2])
{
  int         result;
  string      strpath;
  string      newpath;
  string      nowcache;
  struct stat stbuf;
  int         nDirType = DIRTYPE_UNKNOWN;

  S3FS_PRN_INFO1("[path=%s][mtime=%s]", path, str(ts[1].tv_sec).c_str());

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
    if(IS_RMTYPEDIR(nDirType)){
      S3fsCurl s3fscurl;
      if(0 != (result = s3fscurl.DeleteRequest(strpath.c_str()))){
        return result;
      }
    }
    StatCache::getStatCacheData()->DelStat(nowcache);

    // Make new directory object("dir/")
    if(0 != (result = create_directory_object(newpath.c_str(), stbuf.st_mode, ts[1].tv_sec, stbuf.st_uid, stbuf.st_gid))){
      return result;
    }
  }else{
    // normal object or directory object of newer version

    // open & load
    FdEntity* ent;
    if(NULL == (ent = get_local_fent(strpath.c_str(), true))){
      S3FS_PRN_ERR("could not open and read file(%s)", strpath.c_str());
      return -EIO;
    }

    // set mtime
    if(0 != (result = ent->SetMtime(ts[1].tv_sec))){
      S3FS_PRN_ERR("could not set mtime to file(%s): result=%d", strpath.c_str(), result);
      FdManager::get()->Close(ent);
      return result;
    }

    // upload
    if(0 != (result = ent->Flush(true))){
      S3FS_PRN_ERR("could not upload file(%s): result=%d", strpath.c_str(), result);
      FdManager::get()->Close(ent);
      return result;
    }
    FdManager::get()->Close(ent);

    StatCache::getStatCacheData()->DelStat(nowcache);
  }
  S3FS_MALLOCTRIM(0);

  return result;
}

static int s3fs_truncate(const char* path, off_t size)
{
  int result;
  headers_t meta;
  FdEntity* ent = NULL;

  S3FS_PRN_INFO("[path=%s][size=%jd]", path, (intmax_t)size);

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
    if(NULL == (ent = FdManager::get()->Open(path, &meta, static_cast<ssize_t>(size), -1, false, true))){
      S3FS_PRN_ERR("could not open file(%s): errno=%d", path, errno);
      return -EIO;
    }
    if(0 != (result = ent->Load(0, static_cast<size_t>(size)))){
      S3FS_PRN_ERR("could not download file(%s): result=%d", path, result);
      FdManager::get()->Close(ent);
      return result;
    }

  }else{
    // Not found -> Make tmpfile(with size)

    struct fuse_context* pcxt;
    if(NULL == (pcxt = fuse_get_context())){
      return -EIO;
    }
    meta["Content-Type"]     = string("application/octet-stream"); // Static
    meta["x-amz-meta-mode"]  = str(S_IFLNK | S_IRWXU | S_IRWXG | S_IRWXO);
    meta["x-amz-meta-mtime"] = str(time(NULL));
    meta["x-amz-meta-uid"]   = str(pcxt->uid);
    meta["x-amz-meta-gid"]   = str(pcxt->gid);

    if(NULL == (ent = FdManager::get()->Open(path, &meta, static_cast<ssize_t>(size), -1, true, true))){
      S3FS_PRN_ERR("could not open file(%s): errno=%d", path, errno);
      return -EIO;
    }
  }

  // upload
  if(0 != (result = ent->Flush(true))){
    S3FS_PRN_ERR("could not upload file(%s): result=%d", path, result);
    FdManager::get()->Close(ent);
    return result;
  }
  FdManager::get()->Close(ent);

  StatCache::getStatCacheData()->DelStat(path);
  S3FS_MALLOCTRIM(0);

  return result;
}

static int s3fs_open(const char* path, struct fuse_file_info* fi)
{
  int result;
  struct stat st;
  bool needs_flush = false;

  S3FS_PRN_INFO("[path=%s][flags=%d]", path, fi->flags);

  // clear stat for reading fresh stat.
  // (if object stat is changed, we refresh it. then s3fs gets always
  // stat when s3fs open the object).
  StatCache::getStatCacheData()->DelStat(path);

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

  FdEntity*   ent;
  headers_t   meta;
  get_object_attribute(path, NULL, &meta, true, NULL, true);    // no truncate cache
  if(NULL == (ent = FdManager::get()->Open(path, &meta, static_cast<ssize_t>(st.st_size), st.st_mtime, false, true))){
    StatCache::getStatCacheData()->DelStat(path);
    return -EIO;
  }
  
  if (needs_flush){
    if(0 != (result = ent->RowFlush(path, true))){
      S3FS_PRN_ERR("could not upload file(%s): result=%d", path, result);
      FdManager::get()->Close(ent);
      StatCache::getStatCacheData()->DelStat(path);
      return result;
    }
  }

  fi->fh = ent->GetFd();
  S3FS_MALLOCTRIM(0);

  return 0;
}

static int s3fs_read(const char* path, char* buf, size_t size, off_t offset, struct fuse_file_info* fi)
{
  ssize_t res;

  S3FS_PRN_DBG("[path=%s][size=%zu][offset=%jd][fd=%llu]", path, size, (intmax_t)offset, (unsigned long long)(fi->fh));

  FdEntity* ent;
  if(NULL == (ent = FdManager::get()->ExistOpen(path, static_cast<int>(fi->fh)))){
    S3FS_PRN_ERR("could not find opened fd(%s)", path);
    return -EIO;
  }
  if(ent->GetFd() != static_cast<int>(fi->fh)){
    S3FS_PRN_WARN("different fd(%d - %llu)", ent->GetFd(), (unsigned long long)(fi->fh));
  }

  // check real file size
  size_t realsize = 0;
  if(!ent->GetSize(realsize) || realsize <= 0){
    S3FS_PRN_DBG("file size is 0, so break to read.");
    FdManager::get()->Close(ent);
    return 0;
  }

  if(0 > (res = ent->Read(buf, offset, size, false))){
    S3FS_PRN_WARN("failed to read file(%s). result=%zd", path, res);
  }
  FdManager::get()->Close(ent);

  return static_cast<int>(res);
}

static int s3fs_write(const char* path, const char* buf, size_t size, off_t offset, struct fuse_file_info* fi)
{
  ssize_t res;

  S3FS_PRN_DBG("[path=%s][size=%zu][offset=%jd][fd=%llu]", path, size, (intmax_t)offset, (unsigned long long)(fi->fh));

  FdEntity* ent;
  if(NULL == (ent = FdManager::get()->ExistOpen(path, static_cast<int>(fi->fh)))){
    S3FS_PRN_ERR("could not find opened fd(%s)", path);
    return -EIO;
  }
  if(ent->GetFd() != static_cast<int>(fi->fh)){
    S3FS_PRN_WARN("different fd(%d - %llu)", ent->GetFd(), (unsigned long long)(fi->fh));
  }
  if(0 > (res = ent->Write(buf, offset, size))){
    S3FS_PRN_WARN("failed to write file(%s). result=%zd", path, res);
  }
  FdManager::get()->Close(ent);

  return static_cast<int>(res);
}

static int s3fs_statfs(const char* path, struct statvfs* stbuf)
{
  // 256T
  stbuf->f_bsize  = 0X1000000;
  stbuf->f_blocks = 0X1000000;
  stbuf->f_bfree  = 0x1000000;
  stbuf->f_bavail = 0x1000000;
  stbuf->f_namemax = NAME_MAX;
  return 0;
}

static int s3fs_flush(const char* path, struct fuse_file_info* fi)
{
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

  FdEntity* ent;
  if(NULL != (ent = FdManager::get()->ExistOpen(path, static_cast<int>(fi->fh)))){
    ent->UpdateMtime();
    result = ent->Flush(false);
    FdManager::get()->Close(ent);
  }
  S3FS_MALLOCTRIM(0);

  return result;
}

// [NOTICE]
// Assumption is a valid fd.
//
static int s3fs_fsync(const char* path, int datasync, struct fuse_file_info* fi)
{
  int result = 0;

  S3FS_PRN_INFO("[path=%s][fd=%llu]", path, (unsigned long long)(fi->fh));

  FdEntity* ent;
  if(NULL != (ent = FdManager::get()->ExistOpen(path, static_cast<int>(fi->fh)))){
    if(0 == datasync){
      ent->UpdateMtime();
    }
    result = ent->Flush(false);
    FdManager::get()->Close(ent);
  }
  S3FS_MALLOCTRIM(0);

  // Issue 320: Delete stat cache entry because st_size may have changed.
  StatCache::getStatCacheData()->DelStat(path);

  return result;
}

static int s3fs_release(const char* path, struct fuse_file_info* fi)
{
  S3FS_PRN_INFO("[path=%s][fd=%llu]", path, (unsigned long long)(fi->fh));

  // [NOTE]
  // All opened file's stats is cached with no truncate flag.
  // Thus we unset it here.
  StatCache::getStatCacheData()->ChangeNoTruncateFlag(string(path), false);

  // [NOTICE]
  // At first, we remove stats cache.
  // Because fuse does not wait for response from "release" function. :-(
  // And fuse runs next command before this function returns.
  // Thus we call deleting stats function ASSAP.
  //
  if((fi->flags & O_RDWR) || (fi->flags & O_WRONLY)){
    StatCache::getStatCacheData()->DelStat(path);
  }

  FdEntity* ent;
  if(NULL == (ent = FdManager::get()->GetFdEntity(path, static_cast<int>(fi->fh)))){
    S3FS_PRN_ERR("could not find fd(file=%s)", path);
    return -EIO;
  }
  if(ent->GetFd() != static_cast<int>(fi->fh)){
    S3FS_PRN_WARN("different fd(%d - %llu)", ent->GetFd(), (unsigned long long)(fi->fh));
  }
  FdManager::get()->Close(ent);

  // check - for debug
  if(IS_S3FS_LOG_DBG()){
    if(NULL != (ent = FdManager::get()->GetFdEntity(path, static_cast<int>(fi->fh)))){
      S3FS_PRN_WARN("file(%s),fd(%d) is still opened.", path, ent->GetFd());
    }
  }
  S3FS_MALLOCTRIM(0);

  return 0;
}

static int s3fs_opendir(const char* path, struct fuse_file_info* fi)
{
  int result;
  int mask = (O_RDONLY != (fi->flags & O_ACCMODE) ? W_OK : R_OK) | X_OK;

  S3FS_PRN_INFO("[path=%s][flags=%d]", path, fi->flags);

  if(0 == (result = check_object_access(path, mask, NULL))){
    result = check_parent_object_access(path, mask);
  }
  S3FS_MALLOCTRIM(0);

  return result;
}

static bool multi_head_callback(S3fsCurl* s3fscurl)
{
  if(!s3fscurl){
    return false;
  }
  string saved_path = s3fscurl->GetSpacialSavedPath();
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
  string path       = s3fscurl->GetPath();
  string base_path  = s3fscurl->GetBasePath();
  string saved_path = s3fscurl->GetSpacialSavedPath();

  if(!newcurl->PreHeadRequest(path, base_path, saved_path, ssec_key_pos)){
    S3FS_PRN_ERR("Could not duplicate curl object(%s).", saved_path.c_str());
    delete newcurl;
    return NULL;
  }
  newcurl->SetMultipartRetryCount(retry_count);

  return newcurl;
}

static int readdir_multi_head(const char* path, S3ObjList& head, void* buf, fuse_fill_dir_t filler)
{
  S3fsMultiCurl curlmulti;
  s3obj_list_t  headlist;
  s3obj_list_t  fillerlist;
  int           result = 0;

  S3FS_PRN_INFO1("[path=%s][list=%zu]", path, headlist.size());

  // Make base path list.
  head.GetNameList(headlist, true, false);  // get name with "/".

  // Initialize S3fsMultiCurl
  curlmulti.SetSuccessCallback(multi_head_callback);
  curlmulti.SetRetryCallback(multi_head_retry_callback);

  // Loop
  while(!headlist.empty()){
    s3obj_list_t::iterator iter;
    long                   cnt;

    fillerlist.clear();
    // Make single head request(with max).
    for(iter = headlist.begin(), cnt = 0; headlist.end() != iter && cnt < S3fsMultiCurl::GetMaxMultiRequest(); iter = headlist.erase(iter)){
      string disppath = path + (*iter);
      string etag     = head.GetETag((*iter).c_str());

      string fillpath = disppath;
      if('/' == disppath[disppath.length() - 1]){
        fillpath = fillpath.substr(0, fillpath.length() -1);
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
      cnt++;     // max request count within S3fsMultiCurl::GetMaxMultiRequest()
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
        break;
      }
    }

    // populate fuse buffer
    // here is best position, because a case is cache size < files in directory
    //
    for(iter = fillerlist.begin(); fillerlist.end() != iter; ++iter){
      struct stat st;
      string bpath = mybasename((*iter));
      if(StatCache::getStatCacheData()->GetStat((*iter), &st)){
        filler(buf, bpath.c_str(), &st, 0);
      }else{
        S3FS_PRN_INFO2("Could not find %s file in stat cache.", (*iter).c_str());
        filler(buf, bpath.c_str(), 0, 0);
      }
    }

    // reinit for loop.
    curlmulti.Clear();
  }
  return result;
}

static int s3fs_readdir(const char* path, void* buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info* fi)
{
  S3ObjList head;
  int result;

  S3FS_PRN_INFO("[path=%s]", path);

  if(0 != (result = check_object_access(path, X_OK, NULL))){
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
  string strpath = path;
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
  int       result; 
  string    s3_realpath;
  string    query_delimiter;;
  string    query_prefix;;
  string    query_maxkey;;
  string    next_marker = "";
  bool      truncated = true;
  S3fsCurl  s3fscurl;
  xmlDocPtr doc;
  BodyData* body;

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
    query_maxkey += "max-keys=1000";
  }

  while(truncated){
    string each_query = query_delimiter;
    if(next_marker != ""){
      each_query += "marker=" + urlEncode(next_marker) + "&";
      next_marker = "";
    }
    each_query += query_maxkey;
    each_query += query_prefix;

    // request
    if(0 != (result = s3fscurl.ListBucketRequest(path, each_query.c_str()))){
      S3FS_PRN_ERR("ListBucketRequest returns with error.");
      return result;
    }
    body = s3fscurl.GetBodyData();

    // xmlDocPtr
    if(NULL == (doc = xmlReadMemory(body->str(), static_cast<int>(body->size()), "", NULL, 0))){
      S3FS_PRN_ERR("xmlReadMemory returns with error.");
      return -1;
    }
    if(0 != append_objects_from_xml(path, doc, head)){
      S3FS_PRN_ERR("append_objects_from_xml returns with error.");
      xmlFreeDoc(doc);
      return -1;
    }
    if(true == (truncated = is_truncated(doc))){
      xmlChar*	tmpch = get_next_marker(doc);
      if(tmpch){
        next_marker = (char*)tmpch;
        xmlFree(tmpch);
      }else{
        // If did not specify "delimiter", s3 did not return "NextMarker".
        // On this case, can use last name for next marker.
        //
        string lastname;
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

    if (check_content_only)
      break;
  }
  S3FS_MALLOCTRIM(0);

  return 0;
}

static const char* c_strErrorObjectName = "FILE or SUBDIR in DIR";

static int append_objects_from_xml_ex(const char* path, xmlDocPtr doc, xmlXPathContextPtr ctx, 
       const char* ex_contents, const char* ex_key, const char* ex_etag, int isCPrefix, S3ObjList& head)
{
  xmlXPathObjectPtr contents_xp;
  xmlNodeSetPtr content_nodes;

  if(NULL == (contents_xp = xmlXPathEvalExpression((xmlChar*)ex_contents, ctx))){
    S3FS_PRN_ERR("xmlXPathEvalExpression returns null.");
    return -1;
  }
  if(xmlXPathNodeSetIsEmpty(contents_xp->nodesetval)){
    S3FS_PRN_WARN("contents_xp->nodesetval is empty.");
    S3FS_XMLXPATHFREEOBJECT(contents_xp);
    return 0;
  }
  content_nodes = contents_xp->nodesetval;

  bool   is_dir;
  string stretag;
  int    i;
  for(i = 0; i < content_nodes->nodeNr; i++){
    ctx->node = content_nodes->nodeTab[i];

    // object name
    xmlXPathObjectPtr key;
    if(NULL == (key = xmlXPathEvalExpression((xmlChar*)ex_key, ctx))){
      S3FS_PRN_WARN("key is null. but continue.");
      continue;
    }
    if(xmlXPathNodeSetIsEmpty(key->nodesetval)){
      S3FS_PRN_WARN("node is empty. but continue.");
      xmlXPathFreeObject(key);
      continue;
    }
    xmlNodeSetPtr key_nodes = key->nodesetval;
    char* name = get_object_name(doc, key_nodes->nodeTab[0]->xmlChildrenNode, path);

    if(!name){
      S3FS_PRN_WARN("name is something wrong. but continue.");

    }else if((const char*)name != c_strErrorObjectName){
      is_dir  = isCPrefix ? true : false;
      stretag = "";

      if(!isCPrefix && ex_etag){
        // Get ETag
        xmlXPathObjectPtr ETag;
        if(NULL != (ETag = xmlXPathEvalExpression((xmlChar*)ex_etag, ctx))){
          if(xmlXPathNodeSetIsEmpty(ETag->nodesetval)){
            S3FS_PRN_INFO("ETag->nodesetval is empty.");
          }else{
            xmlNodeSetPtr etag_nodes = ETag->nodesetval;
            xmlChar* petag = xmlNodeListGetString(doc, etag_nodes->nodeTab[0]->xmlChildrenNode, 1);
            if(petag){
              stretag = (char*)petag;
              xmlFree(petag);
            }
          }
          xmlXPathFreeObject(ETag);
        }
      }
      if(!head.insert(name, (0 < stretag.length() ? stretag.c_str() : NULL), is_dir)){
        S3FS_PRN_ERR("insert_object returns with error.");
        xmlXPathFreeObject(key);
        xmlXPathFreeObject(contents_xp);
        free(name);
        S3FS_MALLOCTRIM(0);
        return -1;
      }
      free(name);
    }else{
      S3FS_PRN_DBG("name is file or subdir in dir. but continue.");
    }
    xmlXPathFreeObject(key);
  }
  S3FS_XMLXPATHFREEOBJECT(contents_xp);

  return 0;
}

static bool GetXmlNsUrl(xmlDocPtr doc, string& nsurl)
{
  static time_t tmLast = 0;  // cache for 60 sec.
  static string strNs("");
  bool result = false;

  if(!doc){
    return result;
  }
  if((tmLast + 60) < time(NULL)){
    // refresh
    tmLast = time(NULL);
    strNs  = "";
    xmlNodePtr pRootNode = xmlDocGetRootElement(doc);
    if(pRootNode){
      xmlNsPtr* nslist = xmlGetNsList(doc, pRootNode);
      if(nslist){
        if(nslist[0] && nslist[0]->href){
          strNs  = (const char*)(nslist[0]->href);
        }
        S3FS_XMLFREE(nslist);
      }
    }
  }
  if(0 < strNs.size()){
    nsurl  = strNs;
    result = true;
  }
  return result;
}

static int append_objects_from_xml(const char* path, xmlDocPtr doc, S3ObjList& head)
{
  string xmlnsurl;
  string ex_contents = "//";
  string ex_key      = "";
  string ex_cprefix  = "//";
  string ex_prefix   = "";
  string ex_etag     = "";

  if(!doc){
    return -1;
  }

  // If there is not <Prefix>, use path instead of it.
  xmlChar* pprefix = get_prefix(doc);
  string   prefix  = (pprefix ? (char*)pprefix : path ? path : "");
  if(pprefix){
    xmlFree(pprefix);
  }

  xmlXPathContextPtr ctx = xmlXPathNewContext(doc);

  if(!noxmlns && GetXmlNsUrl(doc, xmlnsurl)){
    xmlXPathRegisterNs(ctx, (xmlChar*)"s3", (xmlChar*)xmlnsurl.c_str());
    ex_contents+= "s3:";
    ex_key     += "s3:";
    ex_cprefix += "s3:";
    ex_prefix  += "s3:";
    ex_etag    += "s3:";
  }
  ex_contents+= "Contents";
  ex_key     += "Key";
  ex_cprefix += "CommonPrefixes";
  ex_prefix  += "Prefix";
  ex_etag    += "ETag";

  if(-1 == append_objects_from_xml_ex(prefix.c_str(), doc, ctx, ex_contents.c_str(), ex_key.c_str(), ex_etag.c_str(), 0, head) ||
     -1 == append_objects_from_xml_ex(prefix.c_str(), doc, ctx, ex_cprefix.c_str(), ex_prefix.c_str(), NULL, 1, head) )
  {
    S3FS_PRN_ERR("append_objects_from_xml_ex returns with error.");
    S3FS_XMLXPATHFREECONTEXT(ctx);
    return -1;
  }
  S3FS_XMLXPATHFREECONTEXT(ctx);

  return 0;
}

static xmlChar* get_base_exp(xmlDocPtr doc, const char* exp)
{
  xmlXPathObjectPtr  marker_xp;
  string xmlnsurl;
  string exp_string = "//";

  if(!doc){
    return NULL;
  }
  xmlXPathContextPtr ctx = xmlXPathNewContext(doc);

  if(!noxmlns && GetXmlNsUrl(doc, xmlnsurl)){
    xmlXPathRegisterNs(ctx, (xmlChar*)"s3", (xmlChar*)xmlnsurl.c_str());
    exp_string += "s3:";
  }
  exp_string += exp;

  if(NULL == (marker_xp = xmlXPathEvalExpression((xmlChar *)exp_string.c_str(), ctx))){
    xmlXPathFreeContext(ctx);
    return NULL;
  }
  if(xmlXPathNodeSetIsEmpty(marker_xp->nodesetval)){
    S3FS_PRN_ERR("marker_xp->nodesetval is empty.");
    xmlXPathFreeObject(marker_xp);
    xmlXPathFreeContext(ctx);
    return NULL;
  }
  xmlNodeSetPtr nodes  = marker_xp->nodesetval;
  xmlChar*      result = xmlNodeListGetString(doc, nodes->nodeTab[0]->xmlChildrenNode, 1);

  xmlXPathFreeObject(marker_xp);
  xmlXPathFreeContext(ctx);

  return result;
}

static xmlChar* get_prefix(xmlDocPtr doc)
{
  return get_base_exp(doc, "Prefix");
}

static xmlChar* get_next_marker(xmlDocPtr doc)
{
  return get_base_exp(doc, "NextMarker");
}

static bool is_truncated(xmlDocPtr doc)
{
  bool result = false;

  xmlChar* strTruncate = get_base_exp(doc, "IsTruncated");
  if(!strTruncate){
    return result;
  }
  if(0 == strcasecmp((const char*)strTruncate, "true")){
    result = true;
  }
  xmlFree(strTruncate);
  return result;
}

// return: the pointer to object name on allocated memory.
//         the pointer to "c_strErrorObjectName".(not allocated)
//         NULL(a case of something error occurred)
static char* get_object_name(xmlDocPtr doc, xmlNodePtr node, const char* path)
{
  // Get full path
  xmlChar* fullpath = xmlNodeListGetString(doc, node, 1);
  if(!fullpath){
    S3FS_PRN_ERR("could not get object full path name..");
    return NULL;
  }
  // basepath(path) is as same as fullpath.
  if(0 == strcmp((char*)fullpath, path)){
    xmlFree(fullpath);
    return (char*)c_strErrorObjectName;
  }

  // Make dir path and filename
  string   strdirpath = mydirname(string((char*)fullpath));
  string   strmybpath = mybasename(string((char*)fullpath));
  const char* dirpath = strdirpath.c_str();
  const char* mybname = strmybpath.c_str();
  const char* basepath= (path && '/' == path[0]) ? &path[1] : path;
  xmlFree(fullpath);

  if(!mybname || '\0' == mybname[0]){
    return NULL;
  }

  // check subdir & file in subdir
  if(dirpath && 0 < strlen(dirpath)){
    // case of "/"
    if(0 == strcmp(mybname, "/") && 0 == strcmp(dirpath, "/")){
      return (char*)c_strErrorObjectName;
    }
    // case of "."
    if(0 == strcmp(mybname, ".") && 0 == strcmp(dirpath, ".")){
      return (char*)c_strErrorObjectName;
    }
    // case of ".."
    if(0 == strcmp(mybname, "..") && 0 == strcmp(dirpath, ".")){
      return (char*)c_strErrorObjectName;
    }
    // case of "name"
    if(0 == strcmp(dirpath, ".")){
      // OK
      return strdup(mybname);
    }else{
      if(basepath && 0 == strcmp(dirpath, basepath)){
        // OK
        return strdup(mybname);
      }else if(basepath && 0 < strlen(basepath) && '/' == basepath[strlen(basepath) - 1] && 0 == strncmp(dirpath, basepath, strlen(basepath) - 1)){
        string withdirname = "";
        if(strlen(dirpath) > strlen(basepath)){
          withdirname = &dirpath[strlen(basepath)];
        }
        if(0 < withdirname.length() && '/' != withdirname[withdirname.length() - 1]){
          withdirname += "/";
        }
        withdirname += mybname;
        return strdup(withdirname.c_str());
      }
    }
  }
  // case of something wrong
  return (char*)c_strErrorObjectName;
}

static int remote_mountpath_exists(const char* path)
{
  struct stat stbuf;

  S3FS_PRN_INFO1("[path=%s]", path);

  // getattr will prefix the path with the remote mountpoint
  if(0 != get_object_attribute("/", &stbuf, NULL)){
    return -1;
  }
  if(!S_ISDIR(stbuf.st_mode)){
    return -1;
  }
  return 0;
}


static void free_xattrs(xattrs_t& xattrs)
{
  for(xattrs_t::iterator iter = xattrs.begin(); iter != xattrs.end(); xattrs.erase(iter++)){
    if(iter->second){
      delete iter->second;
    }
  }
}

static bool parse_xattr_keyval(const std::string& xattrpair, string& key, PXATTRVAL& pval)
{
  // parse key and value
  size_t pos;
  string tmpval;
  if(string::npos == (pos = xattrpair.find_first_of(":"))){
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
  string jsonxattrs = urlDecode(strxattrs);

  // get from "{" to "}"
  string restxattrs;
  {
    size_t startpos = string::npos;
    size_t endpos   = string::npos;
    if(string::npos != (startpos = jsonxattrs.find_first_of("{"))){
      endpos = jsonxattrs.find_last_of("}");
    }
    if(startpos == string::npos || endpos == string::npos || endpos <= startpos){
      S3FS_PRN_WARN("xattr header(%s) is not json format.", jsonxattrs.c_str());
      return 0;
    }
    restxattrs = jsonxattrs.substr(startpos + 1, endpos - (startpos + 1));
  }

  // parse each key:val
  for(size_t pair_nextpos = restxattrs.find_first_of(","); 0 < restxattrs.length(); restxattrs = (pair_nextpos != string::npos ? restxattrs.substr(pair_nextpos + 1) : string("")), pair_nextpos = restxattrs.find_first_of(",")){
    string pair = pair_nextpos != string::npos ? restxattrs.substr(0, pair_nextpos) : restxattrs;
    string    key  = "";
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
  string strxattrs("{");

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
        free(base64val);
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
  string   strxattrs;
  xattrs_t xattrs;

  headers_t::iterator iter;
  if(meta.end() == (iter = meta.find("x-amz-meta-xattr"))){
    if(XATTR_REPLACE == (flags & XATTR_REPLACE)){
      // there is no xattr header but flags is replace, so failure.
      return -ENOATTR;
    }
  }else{
    if(XATTR_CREATE == (flags & XATTR_CREATE)){
      // found xattr header but flags is only creating, so failure.
      return -EEXIST;
    }
    strxattrs = iter->second;
  }

  // get map as xattrs_t
  parse_xattrs(strxattrs, xattrs);

  // add name(do not care overwrite and empty name/value)
  xattrs_t::iterator xiter;
  if(xattrs.end() != (xiter = xattrs.find(string(name)))){
    // found same head. free value.
    delete xiter->second;
  }

  PXATTRVAL pval = new XATTRVAL;
  pval->length = size;
  if(0 < size){
    if(NULL == (pval->pvalue = (unsigned char*)malloc(size))){
      delete pval;
      free_xattrs(xattrs);
      return -ENOMEM;
    }
    memcpy(pval->pvalue, value, size);
  }else{
    pval->pvalue = NULL;
  }
  xattrs[string(name)] = pval;

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
  S3FS_PRN_INFO("[path=%s][name=%s][value=%p][size=%zu][flags=%d]", path, name, value, size, flags);

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
  string      strpath;
  string      newpath;
  string      nowcache;
  headers_t   meta;
  struct stat stbuf;
  int         nDirType = DIRTYPE_UNKNOWN;

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

  // make new header_t
  if(0 != (result = set_xattrs_to_header(meta, name, value, size, flags))){
    return result;
  }

  if(S_ISDIR(stbuf.st_mode) && IS_REPLACEDIR(nDirType)){
    // Should rebuild directory object(except new type)
    // Need to remove old dir("dir" etc) and make new dir("dir/")

    // At first, remove directory old object
    if(IS_RMTYPEDIR(nDirType)){
      S3fsCurl s3fscurl;
      if(0 != (result = s3fscurl.DeleteRequest(strpath.c_str()))){
        return result;
      }
    }
    StatCache::getStatCacheData()->DelStat(nowcache);

    // Make new directory object("dir/")
    if(0 != (result = create_directory_object(newpath.c_str(), stbuf.st_mode, stbuf.st_mtime, stbuf.st_uid, stbuf.st_gid))){
      return result;
    }

    // need to set xattr header for directory.
    strpath  = newpath;
    nowcache = strpath;
  }

  // set xattr all object
  meta["x-amz-copy-source"]        = urlEncode(service_path + bucket + get_realpath(strpath.c_str()));
  meta["x-amz-metadata-directive"] = "REPLACE";

  if(0 != put_headers(strpath.c_str(), meta, true)){
    return -EIO;
  }
  StatCache::getStatCacheData()->DelStat(nowcache);

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
  string strxattrs = hiter->second;

  parse_xattrs(strxattrs, xattrs);

  // search name
  string             strname = name;
  xattrs_t::iterator xiter   = xattrs.find(strname);
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
  string strxattrs = iter->second;

  parse_xattrs(strxattrs, xattrs);

  // calculate total name length
  size_t total = 0;
  for(xattrs_t::const_iterator iter = xattrs.begin(); iter != xattrs.end(); ++iter){
    if(0 < iter->first.length()){
      total += iter->first.length() + 1;
    }
  }

  if(0 == total){
    free_xattrs(xattrs);
    return 0;
  }

  // check parameters
  if(size <= 0){
    free_xattrs(xattrs);
    return total;
  }
  if(!list || size < total){
    free_xattrs(xattrs);
    return -ERANGE;
  }

  // copy to list
  char* setpos = list;
  for(xattrs_t::const_iterator iter = xattrs.begin(); iter != xattrs.end(); ++iter){
    if(0 < iter->first.length()){
      strcpy(setpos, iter->first.c_str());
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
  string      strpath;
  string      newpath;
  string      nowcache;
  headers_t   meta;
  xattrs_t    xattrs;
  struct stat stbuf;
  int         nDirType = DIRTYPE_UNKNOWN;

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
  string strxattrs = hiter->second;

  parse_xattrs(strxattrs, xattrs);

  // check name xattrs
  string             strname = name;
  xattrs_t::iterator xiter   = xattrs.find(strname);
  if(xattrs.end() == xiter){
    free_xattrs(xattrs);
    return -ENOATTR;
  }

  // make new header_t after deleting name xattr
  if(xiter->second){
    delete xiter->second;
  }
  xattrs.erase(xiter);

  // build new xattr
  if(!xattrs.empty()){
    meta["x-amz-meta-xattr"] = build_xattrs(xattrs);
  }else{
    meta.erase("x-amz-meta-xattr");
  }

  if(S_ISDIR(stbuf.st_mode) && IS_REPLACEDIR(nDirType)){
    // Should rebuild directory object(except new type)
    // Need to remove old dir("dir" etc) and make new dir("dir/")

    // At first, remove directory old object
    if(IS_RMTYPEDIR(nDirType)){
      S3fsCurl s3fscurl;
      if(0 != (result = s3fscurl.DeleteRequest(strpath.c_str()))){
        free_xattrs(xattrs);
        return result;
      }
    }
    StatCache::getStatCacheData()->DelStat(nowcache);

    // Make new directory object("dir/")
    if(0 != (result = create_directory_object(newpath.c_str(), stbuf.st_mode, stbuf.st_mtime, stbuf.st_uid, stbuf.st_gid))){
      free_xattrs(xattrs);
      return result;
    }

    // need to set xattr header for directory.
    strpath  = newpath;
    nowcache = strpath;
  }

  // set xattr all object
  meta["x-amz-copy-source"]        = urlEncode(service_path + bucket + get_realpath(strpath.c_str()));
  meta["x-amz-metadata-directive"] = "REPLACE";

  if(0 != put_headers(strpath.c_str(), meta, true)){
    free_xattrs(xattrs);
    return -EIO;
  }
  StatCache::getStatCacheData()->DelStat(nowcache);

  free_xattrs(xattrs);

  return 0;
}
   
// s3fs_init calls this function to exit cleanly from the fuse event loop.
//
// There's no way to pass an exit status to the high-level event loop API, so 
// this function stores the exit value in a global for main()
static void s3fs_exit_fuseloop(int exit_status) {
    S3FS_PRN_ERR("Exiting FUSE event loop due to errors\n");
    s3fs_init_deferred_exit_status = exit_status;
    struct fuse_context *ctx = fuse_get_context();
    if (NULL != ctx) {
        fuse_exit(ctx->fuse);
    }
}

static void* s3fs_init(struct fuse_conn_info* conn)
{
  S3FS_PRN_CRIT("init v%s(commit:%s) with %s", VERSION, COMMIT_HASH_VAL, s3fs_crypt_lib_name());

  // cache(remove cache dirs at first)
  if(is_remove_cache && (!CacheFileStat::DeleteCacheFileStatDirectory() || !FdManager::DeleteCacheDirectory())){
    S3FS_PRN_DBG("Could not initialize cache directory.");
  }

  // ssl init
  if(!s3fs_init_global_ssl()){
    S3FS_PRN_CRIT("could not initialize for ssl libraries.");
    s3fs_exit_fuseloop(EXIT_FAILURE);
    return NULL;
  }

  // init curl
  if(!S3fsCurl::InitS3fsCurl("/etc/mime.types")){
    S3FS_PRN_CRIT("Could not initiate curl library.");
    s3fs_exit_fuseloop(EXIT_FAILURE);
    return NULL;
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
  // If the network is up, check for valid credentials and if the bucket
  // exists. skip check if mounting a public bucket
  if(!S3fsCurl::IsPublicBucket()){
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

  return NULL;
}

static void s3fs_destroy(void*)
{
  S3FS_PRN_INFO("destroy");

  // Destroy curl
  if(!S3fsCurl::DestroyS3fsCurl()){
    S3FS_PRN_WARN("Could not release curl library.");
  }
  // cache(remove at last)
  if(is_remove_cache && (!CacheFileStat::DeleteCacheFileStatDirectory() || !FdManager::DeleteCacheDirectory())){
    S3FS_PRN_WARN("Could not remove cache directory.");
  }
  // ssl
  s3fs_destroy_global_ssl();
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

static xmlChar* get_exp_value_xml(xmlDocPtr doc, xmlXPathContextPtr ctx, const char* exp_key)
{
  if(!doc || !ctx || !exp_key){
    return NULL;
  }

  xmlXPathObjectPtr exp;
  xmlNodeSetPtr     exp_nodes;
  xmlChar*          exp_value;

  // search exp_key tag
  if(NULL == (exp = xmlXPathEvalExpression((xmlChar*)exp_key, ctx))){
    S3FS_PRN_ERR("Could not find key(%s).", exp_key);
    return NULL;
  }
  if(xmlXPathNodeSetIsEmpty(exp->nodesetval)){
    S3FS_PRN_ERR("Key(%s) node is empty.", exp_key);
    S3FS_XMLXPATHFREEOBJECT(exp);
    return NULL;
  }
  // get exp_key value & set in struct
  exp_nodes = exp->nodesetval;
  if(NULL == (exp_value = xmlNodeListGetString(doc, exp_nodes->nodeTab[0]->xmlChildrenNode, 1))){
    S3FS_PRN_ERR("Key(%s) value is empty.", exp_key);
    S3FS_XMLXPATHFREEOBJECT(exp);
    return NULL;
  }

  S3FS_XMLXPATHFREEOBJECT(exp);
  return exp_value;
}

static void print_uncomp_mp_list(uncomp_mp_list_t& list)
{
  printf("\n");
  printf("Lists the parts that have been uploaded for a specific multipart upload.\n");
  printf("\n");

  if(!list.empty()){
    printf("---------------------------------------------------------------\n");

    int cnt = 0;
    for(uncomp_mp_list_t::iterator iter = list.begin(); iter != list.end(); ++iter, ++cnt){
      printf(" Path     : %s\n", (*iter).key.c_str());
      printf(" UploadId : %s\n", (*iter).id.c_str());
      printf(" Date     : %s\n", (*iter).date.c_str());
      printf("\n");
    }
    printf("---------------------------------------------------------------\n");

  }else{
    printf("There is no list.\n");
  }
}

static bool abort_uncomp_mp_list(uncomp_mp_list_t& list)
{
  char buff[1024];

  if(list.empty()){
    return true;
  }
  memset(buff, 0, sizeof(buff));

  // confirm
  while(true){
    printf("Would you remove all objects? [Y/N]\n");
    if(NULL != fgets(buff, sizeof(buff), stdin)){
      if(0 == strcasecmp(buff, "Y\n") || 0 == strcasecmp(buff, "YES\n")){
        break;
      }else if(0 == strcasecmp(buff, "N\n") || 0 == strcasecmp(buff, "NO\n")){
        return true;
      }
      printf("*** please put Y(yes) or N(no).\n");
    }
  }

  // do removing their.
  S3fsCurl s3fscurl;
  bool     result = true;
  for(uncomp_mp_list_t::iterator iter = list.begin(); iter != list.end(); ++iter){
    const char* tpath     = (*iter).key.c_str();
    string      upload_id = (*iter).id;

    if(0 != s3fscurl.AbortMultipartUpload(tpath, upload_id)){
      S3FS_PRN_EXIT("Failed to remove %s multipart uploading object.", tpath);
      result = false;
    }else{
      printf("Succeed to remove %s multipart uploading object.\n", tpath);
    }

    // reset(initialize) curl object
    s3fscurl.DestroyCurlHandle();
  }

  return result;
}

static bool get_uncomp_mp_list(xmlDocPtr doc, uncomp_mp_list_t& list)
{
  if(!doc){
    return false;
  }

  xmlXPathContextPtr ctx = xmlXPathNewContext(doc);;

  string xmlnsurl;
  string ex_upload = "//";
  string ex_key    = "";
  string ex_id     = "";
  string ex_date   = "";

  if(!noxmlns && GetXmlNsUrl(doc, xmlnsurl)){
    xmlXPathRegisterNs(ctx, (xmlChar*)"s3", (xmlChar*)xmlnsurl.c_str());
    ex_upload += "s3:";
    ex_key    += "s3:";
    ex_id     += "s3:";
    ex_date   += "s3:";
  }
  ex_upload += "Upload";
  ex_key    += "Key";
  ex_id     += "UploadId";
  ex_date   += "Initiated";

  // get "Upload" Tags
  xmlXPathObjectPtr  upload_xp;
  if(NULL == (upload_xp = xmlXPathEvalExpression((xmlChar*)ex_upload.c_str(), ctx))){
    S3FS_PRN_ERR("xmlXPathEvalExpression returns null.");
    return false;
  }
  if(xmlXPathNodeSetIsEmpty(upload_xp->nodesetval)){
    S3FS_PRN_INFO("upload_xp->nodesetval is empty.");
    S3FS_XMLXPATHFREEOBJECT(upload_xp);
    S3FS_XMLXPATHFREECONTEXT(ctx);
    return true;
  }

  // Make list
  int           cnt;
  xmlNodeSetPtr upload_nodes;
  list.clear();
  for(cnt = 0, upload_nodes = upload_xp->nodesetval; cnt < upload_nodes->nodeNr; cnt++){
    ctx->node = upload_nodes->nodeTab[cnt];

    UNCOMP_MP_INFO  part;
    xmlChar*        ex_value;

    // search "Key" tag
    if(NULL == (ex_value = get_exp_value_xml(doc, ctx, ex_key.c_str()))){
      continue;
    }
    if('/' != *((char*)ex_value)){
      part.key = "/";
    }else{
      part.key = "";
    }
    part.key += (char*)ex_value;
    S3FS_XMLFREE(ex_value);

    // search "UploadId" tag
    if(NULL == (ex_value = get_exp_value_xml(doc, ctx, ex_id.c_str()))){
      continue;
    }
    part.id = (char*)ex_value;
    S3FS_XMLFREE(ex_value);

    // search "Initiated" tag
    if(NULL == (ex_value = get_exp_value_xml(doc, ctx, ex_date.c_str()))){
      continue;
    }
    part.date = (char*)ex_value;
    S3FS_XMLFREE(ex_value);

    list.push_back(part);
  }

  S3FS_XMLXPATHFREEOBJECT(upload_xp);
  S3FS_XMLXPATHFREECONTEXT(ctx);

  return true;
}

static int s3fs_utility_mode(void)
{
  if(!utility_mode){
    return EXIT_FAILURE;
  }

  // ssl init
  if(!s3fs_init_global_ssl()){
    S3FS_PRN_EXIT("could not initialize for ssl libraries.");
    return EXIT_FAILURE;
  }

  // init curl
  if(!S3fsCurl::InitS3fsCurl("/etc/mime.types")){
    S3FS_PRN_EXIT("Could not initiate curl library.");
    s3fs_destroy_global_ssl();
    return EXIT_FAILURE;
  }

  printf("Utility Mode\n");

  S3fsCurl s3fscurl;
  string   body;
  int      result = EXIT_SUCCESS;
  if(0 != s3fscurl.MultipartListRequest(body)){
    S3FS_PRN_EXIT("Could not get list multipart upload.");
    result = EXIT_FAILURE;
  }else{
    // parse result(incomplete multipart upload information)
    S3FS_PRN_DBG("response body = {\n%s\n}", body.c_str());

    xmlDocPtr doc;
    if(NULL == (doc = xmlReadMemory(body.c_str(), static_cast<int>(body.size()), "", NULL, 0))){
      S3FS_PRN_DBG("xmlReadMemory exited with error.");
      result = EXIT_FAILURE;

    }else{
      // make working uploads list
      uncomp_mp_list_t list;
      if(!get_uncomp_mp_list(doc, list)){
        S3FS_PRN_DBG("get_uncomp_mp_list exited with error.");
        result = EXIT_FAILURE;

      }else{
        // print list
        print_uncomp_mp_list(list);
        // remove
        if(!abort_uncomp_mp_list(list)){
          S3FS_PRN_DBG("an error occurred during removal process.");
          result = EXIT_FAILURE;
        }
      }
      S3FS_XMLFREEDOC(doc);
    }
  }

  // Destroy curl
  if(!S3fsCurl::DestroyS3fsCurl()){
    S3FS_PRN_WARN("Could not release curl library.");
  }

  // ssl
  s3fs_destroy_global_ssl();

  return result;
}

//
// If calling with wrong region, s3fs gets following error body as 400 error code.
// "<Error><Code>AuthorizationHeaderMalformed</Code><Message>The authorization header is 
//  malformed; the region 'us-east-1' is wrong; expecting 'ap-northeast-1'</Message>
//  <Region>ap-northeast-1</Region><RequestId>...</RequestId><HostId>...</HostId>
//  </Error>"
//
// So this is cheep codes but s3fs should get correct region automatically.
//
static bool check_region_error(const char* pbody, string& expectregion)
{
  if(!pbody){
    return false;
  }
  const char* region;
  const char* regionend;
  if(NULL == (region = strcasestr(pbody, "<Message>The authorization header is malformed; the region "))){
    return false;
  }
  if(NULL == (region = strcasestr(region, "expecting \'"))){
    return false;
  }
  region += strlen("expecting \'");
  if(NULL == (regionend = strchr(region, '\''))){
    return false;
  }
  string strtmp(region, (regionend - region));
  if(0 == strtmp.length()){
    return false;
  }
  expectregion = strtmp;

  return true;
}

static int s3fs_check_service(void)
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
    if(responseCode == 400 && !is_specified_endpoint){
      // check region error
      BodyData* body = s3fscurl.GetBodyData();
      string    expectregion;
      if(check_region_error(body->str(), expectregion)){
        // not specified endpoint, so try to connect to expected region.
        S3FS_PRN_CRIT("Could not connect wrong region %s, so retry to connect region %s.", endpoint.c_str(), expectregion.c_str());
        endpoint = expectregion;
        if(S3fsCurl::IsSignatureV4()){
            if(host == "http://s3.amazonaws.com"){
                host = "http://s3-" + endpoint + ".amazonaws.com";
            }else if(host == "https://s3.amazonaws.com"){
                host = "https://s3-" + endpoint + ".amazonaws.com";
            }
        }

        // retry to check with new endpoint
        s3fscurl.DestroyCurlHandle();
        res          = s3fscurl.CheckBucket();
        responseCode = s3fscurl.GetLastResponseCode();
      }
    }

    // try signature v2
    if(0 > res && (responseCode == 400 || responseCode == 403) && S3fsCurl::IsSignatureV4()){
      // switch sigv2
      S3FS_PRN_WARN("Could not connect, so retry to connect by signature version 2.");
      S3fsCurl::SetSignatureV4(false);

      // retry to check with sigv2
      s3fscurl.DestroyCurlHandle();
      res          = s3fscurl.CheckBucket();
      responseCode = s3fscurl.GetLastResponseCode();
    }

    // check errors(after retrying)
    if(0 > res && responseCode != 200 && responseCode != 301){
      if(responseCode == 400){
        S3FS_PRN_CRIT("Bad Request - result of checking service.");
        return EXIT_FAILURE;
      }
      if(responseCode == 403){
        S3FS_PRN_CRIT("invalid credentials - result of checking service.");
        return EXIT_FAILURE;
      }
      if(responseCode == 404){
        S3FS_PRN_CRIT("bucket not found - result of checking service.");
        return EXIT_FAILURE;
      }
      // unable to connect
      if(responseCode == CURLE_OPERATION_TIMEDOUT){
        S3FS_PRN_CRIT("unable to connect bucket and timeout - result of checking service.");
        return EXIT_FAILURE;
      }

      // another error
      S3FS_PRN_CRIT("unable to connect - result of checking service.");
      return EXIT_FAILURE;
    }
  }

  // make sure remote mountpath exists and is a directory
  if(mount_prefix.size() > 0){
    if(remote_mountpath_exists(mount_prefix.c_str()) != 0){
      S3FS_PRN_CRIT("remote mountpath %s not found.", mount_prefix.c_str());
      return EXIT_FAILURE;
    }
  }
  S3FS_MALLOCTRIM(0);

  return EXIT_SUCCESS;
}

// Return:  1 - OK(could read and set accesskey etc.)
//          0 - NG(could not read)
//         -1 - Should shutdown immediately
static int check_for_aws_format(void)
{
  size_t first_pos = string::npos;
  string line;
  bool   got_access_key_id_line = 0;
  bool   got_secret_key_line = 0;
  string str1 ("AWSAccessKeyId=");
  string str2 ("AWSSecretKey=");
  size_t found;
  string AccessKeyId;
  string SecretAccesskey;


  ifstream PF(passwd_file.c_str());
  if(PF.good()){
    while (getline(PF, line)){
      if(line[0]=='#'){
        continue;
      }
      if(line.size() == 0){
        continue;
      }
      if('\r' == line[line.size() - 1]){
        line = line.substr(0, line.size() - 1);
        if(line.size() == 0){
          continue;
        }
      }

      first_pos = line.find_first_of(" \t");
      if(first_pos != string::npos){
        S3FS_PRN_EXIT("invalid line in passwd file, found whitespace character.");
        return -1;
      }

      first_pos = line.find_first_of("[");
      if(first_pos != string::npos && first_pos == 0){
        S3FS_PRN_EXIT("invalid line in passwd file, found a bracket \"[\" character.");
        return -1;
      }

      found = line.find(str1);
      if(found != string::npos){
         first_pos = line.find_first_of("=");
         AccessKeyId = line.substr(first_pos + 1, string::npos);
         got_access_key_id_line = 1;
         continue;
      }

      found = line.find(str2);
      if(found != string::npos){
         first_pos = line.find_first_of("=");
         SecretAccesskey = line.substr(first_pos + 1, string::npos);
         got_secret_key_line = 1;
         continue;
      }
    }
  }

  if(got_access_key_id_line && got_secret_key_line){
    if(!S3fsCurl::SetAccessKey(AccessKeyId.c_str(), SecretAccesskey.c_str())){
      S3FS_PRN_EXIT("if one access key is specified, both keys need to be specified.");
      return 0;
    }
    return 1;
  }else{
    return 0;
  }
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
static int check_passwd_file_perms(void)
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
static int read_passwd_file(void)
{
  string line;
  string field1, field2, field3;
  size_t first_pos = string::npos;
  size_t last_pos = string::npos;
  bool default_found = 0;
  int aws_format;

  // if you got here, the password file
  // exists and is readable by the
  // current user, check for permissions
  if(EXIT_SUCCESS != check_passwd_file_perms()){
    return EXIT_FAILURE;
  }

  aws_format = check_for_aws_format();
  if(1 == aws_format){
     return EXIT_SUCCESS;
  }else if(-1 == aws_format){
     return EXIT_FAILURE;
  }

  ifstream PF(passwd_file.c_str());
  if(PF.good()){
    while (getline(PF, line)){
      if(line[0]=='#'){
        continue;
      }
      if(line.size() == 0){
        continue;
      }
      if('\r' == line[line.size() - 1]){
        line = line.substr(0, line.size() - 1);
        if(line.size() == 0){
          continue;
        }
      }

      first_pos = line.find_first_of(" \t");
      if(first_pos != string::npos){
        S3FS_PRN_EXIT("invalid line in passwd file, found whitespace character.");
        return EXIT_FAILURE;
      }

      first_pos = line.find_first_of("[");
      if(first_pos != string::npos && first_pos == 0){
        S3FS_PRN_EXIT("invalid line in passwd file, found a bracket \"[\" character.");
        return EXIT_FAILURE;
      }

      first_pos = line.find_first_of(":");
      if(first_pos == string::npos){
        S3FS_PRN_EXIT("invalid line in passwd file, no \":\" separator found.");
        return EXIT_FAILURE;
      }
      last_pos = line.find_last_of(":");

      if(first_pos != last_pos){
        // bucket specified
        field1 = line.substr(0,first_pos);
        field2 = line.substr(first_pos + 1, last_pos - first_pos - 1);
        field3 = line.substr(last_pos + 1, string::npos);
      }else{
        // no bucket specified - original style - found default key
        if(default_found == 1){
          S3FS_PRN_EXIT("more than one default key pair found in passwd file.");
          return EXIT_FAILURE;
        }
        default_found = 1;
        field1.assign("");
        field2 = line.substr(0,first_pos);
        field3 = line.substr(first_pos + 1, string::npos);
        if(!S3fsCurl::SetAccessKey(field2.c_str(), field3.c_str())){
          S3FS_PRN_EXIT("if one access key is specified, both keys need to be specified.");
          return EXIT_FAILURE;
        }
      }

      // does the bucket we are mounting match this passwd file entry?
      // if so, use that key pair, otherwise use the default key, if found,
      // will be used
      if(field1.size() != 0 && field1 == bucket){
        if(!S3fsCurl::SetAccessKey(field2.c_str(), field3.c_str())){
          S3FS_PRN_EXIT("if one access key is specified, both keys need to be specified.");
          return EXIT_FAILURE;
        }
        break;
      }
    }
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
// 4 - from the users ~/.passwd-s3fs
// 5 - from /etc/passwd-s3fs
//
static int get_access_keys(void)
{
  // should be redundant
  if(S3fsCurl::IsPublicBucket()){
     return EXIT_SUCCESS;
  }

  // access key loading is deferred
  if(load_iamrole){
     return EXIT_SUCCESS;
  }

  // 1 - keys specified on the command line
  if(S3fsCurl::IsSetAccessKeyId()){
     return EXIT_SUCCESS;
  }

  // 2 - was specified on the command line
  if(passwd_file.size() > 0){
    ifstream PF(passwd_file.c_str());
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
  if(AWSACCESSKEYID != NULL || AWSSECRETACCESSKEY != NULL){
    if( (AWSACCESSKEYID == NULL && AWSSECRETACCESSKEY != NULL) ||
        (AWSACCESSKEYID != NULL && AWSSECRETACCESSKEY == NULL) ){
      S3FS_PRN_EXIT("if environment variable AWSACCESSKEYID is set then AWSSECRETACCESSKEY must be set too.");
      return EXIT_FAILURE;
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
    passwd_file.assign(AWS_CREDENTIAL_FILE);
    if(passwd_file.size() > 0){
      ifstream PF(passwd_file.c_str());
      if(PF.good()){
         PF.close();
         return read_passwd_file();
      }else{
        S3FS_PRN_EXIT("AWS_CREDENTIAL_FILE: \"%s\" is not readable.", passwd_file.c_str());
        return EXIT_FAILURE;
      }
    }
  }

  // 4 - from the default location in the users home directory
  char * HOME;
  HOME = getenv ("HOME");
  if(HOME != NULL){
     passwd_file.assign(HOME);
     passwd_file.append("/.passwd-s3fs");
     ifstream PF(passwd_file.c_str());
     if(PF.good()){
       PF.close();
       if(EXIT_SUCCESS != read_passwd_file()){
         return EXIT_FAILURE;
       }
       // It is possible that the user's file was there but
       // contained no key pairs i.e. commented out
       // in that case, go look in the final location
       if(S3fsCurl::IsSetAccessKeyId()){
          return EXIT_SUCCESS;
       }
     }
   }

  // 5 - from the system default location
  passwd_file.assign("/etc/passwd-s3fs"); 
  ifstream PF(passwd_file.c_str());
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
static int set_mountpoint_attribute(struct stat& mpst)
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
    bucket = strtok(bucket_name, ":");
    char* pmount_prefix = strtok(NULL, ":");
    if(pmount_prefix){
      if(0 == strlen(pmount_prefix) || '/' != pmount_prefix[0]){
        S3FS_PRN_EXIT("path(%s) must be prefix \"/\".", pmount_prefix);
        return -1;
      }
      mount_prefix = pmount_prefix;
      // remove trailing slash
      if(mount_prefix.at(mount_prefix.size() - 1) == '/'){
        mount_prefix = mount_prefix.substr(0, mount_prefix.size() - 1);
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
    if(bucket.size() == 0){
      if ((ret = set_bucket(arg))){
        return ret;
      }
      return 0;
    }
    else if (!strcmp(arg, "s3fs")) {
      return 0;
    }

    // the second NONPOT option is the mountpoint(not utility mode)
    if(0 == mountpoint.size() && 0 == utility_mode){
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
    if(0 == utility_mode){
      S3FS_PRN_EXIT("specified unknown third optioni(%s).", arg);
    }else{
      S3FS_PRN_EXIT("specified unknown second optioni(%s). you don't need to specify second option(mountpoint) for utility mode(-u).", arg);
    }
    return -1;

  }else if(key == FUSE_OPT_KEY_OPT){
    if(0 == STR2NCMP(arg, "uid=")){
      s3fs_uid = get_uid(strchr(arg, '=') + sizeof(char));
      if(0 != geteuid() && 0 == s3fs_uid){
        S3FS_PRN_EXIT("root user can only specify uid=0.");
        return -1;
      }
      is_s3fs_uid = true;
      return 1; // continue for fuse option
    }
    if(0 == STR2NCMP(arg, "gid=")){
      s3fs_gid = get_gid(strchr(arg, '=') + sizeof(char));
      if(0 != getegid() && 0 == s3fs_gid){
        S3FS_PRN_EXIT("root user can only specify gid=0.");
        return -1;
      }
      is_s3fs_gid = true;
      return 1; // continue for fuse option
    }
    if(0 == STR2NCMP(arg, "umask=")){
      s3fs_umask = strtol(strchr(arg, '=') + sizeof(char), NULL, 0);
      s3fs_umask &= (S_IRWXU | S_IRWXG | S_IRWXO);
      is_s3fs_umask = true;
      return 1; // continue for fuse option
    }
    if(0 == strcmp(arg, "allow_other")){
      allow_other = true;
      return 1; // continue for fuse option
    }
    if(0 == STR2NCMP(arg, "mp_umask=")){
      mp_umask = strtol(strchr(arg, '=') + sizeof(char), NULL, 0);
      mp_umask &= (S_IRWXU | S_IRWXG | S_IRWXO);
      is_mp_umask = true;
      return 0;
    }
    if(0 == STR2NCMP(arg, "default_acl=")){
      const char* acl = strchr(arg, '=') + sizeof(char);
      S3fsCurl::SetDefaultAcl(acl);
      return 0;
    }
    if(0 == STR2NCMP(arg, "retries=")){
      S3fsCurl::SetRetries(static_cast<int>(s3fs_strtoofft(strchr(arg, '=') + sizeof(char))));
      return 0;
    }
    if(0 == STR2NCMP(arg, "use_cache=")){
      if(!FdManager::SetCacheDir(strchr(arg, '=') + sizeof(char))){
        S3FS_PRN_EXIT("cache directory(%s) is specified, but it does not exist or is not directory.", strchr(arg, '=') + sizeof(char));
        return -1;
      }
      return 0;
    }
    if(0 == strcmp(arg, "del_cache")){
      is_remove_cache = true;
      return 0;
    }
    if(0 == STR2NCMP(arg, "multireq_max=")){
      long maxreq = static_cast<long>(s3fs_strtoofft(strchr(arg, '=') + sizeof(char)));
      S3fsMultiCurl::SetMaxMultiRequest(maxreq);
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
    if(0 == strcmp(arg, "use_rrs") || 0 == STR2NCMP(arg, "use_rrs=")){
      off_t rrs = 1;
      // for an old format.
      if(0 == STR2NCMP(arg, "use_rrs=")){
        rrs = s3fs_strtoofft(strchr(arg, '=') + sizeof(char));
      }
      if(0 == rrs){
        S3fsCurl::SetStorageClass(STANDARD);
      }else if(1 == rrs){
        S3fsCurl::SetStorageClass(REDUCED_REDUNDANCY);
      }else{
        S3FS_PRN_EXIT("poorly formed argument to option: use_rrs");
        return -1;
      }
      return 0;
    }
    if(0 == STR2NCMP(arg, "storage_class=")){
      const char *storage_class = strchr(arg, '=') + sizeof(char);
      if(0 == strcmp(storage_class, "standard")){
        S3fsCurl::SetStorageClass(STANDARD);
      }else if(0 == strcmp(storage_class, "standard_ia")){
        S3fsCurl::SetStorageClass(STANDARD_IA);
      }else if(0 == strcmp(storage_class, "reduced_redundancy")){
        S3fsCurl::SetStorageClass(REDUCED_REDUNDANCY);
      }else{
        S3FS_PRN_EXIT("unknown value for storage_class: %s", storage_class);
        return -1;
      }
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
    if(0 == STR2NCMP(arg, "use_sse")){
      if(0 == strcmp(arg, "use_sse") || 0 == strcmp(arg, "use_sse=1")){ // use_sse=1 is old type parameter
        // sse type is SSE_S3
        if(!S3fsCurl::IsSseDisable() && !S3fsCurl::IsSseS3Type()){
          S3FS_PRN_EXIT("already set SSE another type, so conflict use_sse option or environment.");
          return -1;
        }
        S3fsCurl::SetSseType(SSE_S3);

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
        S3fsCurl::SetSseType(SSE_KMS);

      }else if(0 == STR2NCMP(arg, "use_sse=kmsid:") || 0 == STR2NCMP(arg, "use_sse=k:")){
        // sse type is SSE_KMS with kmsid
        if(!S3fsCurl::IsSseDisable() && !S3fsCurl::IsSseKmsType()){
          S3FS_PRN_EXIT("already set SSE another type, so conflict use_sse option or environment.");
          return -1;
        }
        const char* kmsid;
        if(0 == STR2NCMP(arg, "use_sse=kmsid:")){
          kmsid = &arg[strlen("use_sse=kmsid:")];
        }else{
          kmsid = &arg[strlen("use_sse=k:")];
        }
        if(!S3fsCurl::SetSseKmsid(kmsid)){
          S3FS_PRN_EXIT("failed to load use_sse kms id.");
          return -1;
        }
        S3fsCurl::SetSseType(SSE_KMS);

      }else if(0 == strcmp(arg, "use_sse=custom") || 0 == strcmp(arg, "use_sse=c")){
        // sse type is SSE_C with out custom keys(expecting keys are loaded by environment or load_sse_c option)
        if(!S3fsCurl::IsSseDisable() && !S3fsCurl::IsSseCType()){
          S3FS_PRN_EXIT("already set SSE another type, so conflict use_sse option or environment.");
          return -1;
        }
        // [NOTE]
        // do not check ckeys exists here.
        //
        S3fsCurl::SetSseType(SSE_C);

      }else if(0 == STR2NCMP(arg, "use_sse=custom:") || 0 == STR2NCMP(arg, "use_sse=c:")){
        // sse type is SSE_C with custom keys
        if(!S3fsCurl::IsSseDisable() && !S3fsCurl::IsSseCType()){
          S3FS_PRN_EXIT("already set SSE another type, so conflict use_sse option or environment.");
          return -1;
        }
        const char* ssecfile;
        if(0 == STR2NCMP(arg, "use_sse=custom:")){
          ssecfile = &arg[strlen("use_sse=custom:")];
        }else{
          ssecfile = &arg[strlen("use_sse=c:")];
        }
        if(!S3fsCurl::SetSseCKeys(ssecfile)){
          S3FS_PRN_EXIT("failed to load use_sse custom key file(%s).", ssecfile);
          return -1;
        }
        S3fsCurl::SetSseType(SSE_C);

      }else if(0 == strcmp(arg, "use_sse=")){    // this type is old style(parameter is custom key file path)
        // SSE_C with custom keys.
        const char* ssecfile = &arg[strlen("use_sse=")];
        if(!S3fsCurl::SetSseCKeys(ssecfile)){
          S3FS_PRN_EXIT("failed to load use_sse custom key file(%s).", ssecfile);
          return -1;
        }
        S3fsCurl::SetSseType(SSE_C);

      }else{
        // never come here.
        S3FS_PRN_EXIT("something wrong use_sse option.");
        return -1;
      }
      return 0;
    }
    // [NOTE]
    // Do only load SSE custom keys, care for set without set sse type.
    if(0 == STR2NCMP(arg, "load_sse_c=")){
      const char* ssecfile = &arg[strlen("load_sse_c=")];
      if(!S3fsCurl::SetSseCKeys(ssecfile)){
        S3FS_PRN_EXIT("failed to load use_sse custom key file(%s).", ssecfile);
        return -1;
      }
      return 0;
    }
    if(0 == STR2NCMP(arg, "ssl_verify_hostname=")){
      long sslvh = static_cast<long>(s3fs_strtoofft(strchr(arg, '=') + sizeof(char)));
      if(-1 == S3fsCurl::SetSslVerifyHostname(sslvh)){
        S3FS_PRN_EXIT("poorly formed argument to option: ssl_verify_hostname.");
        return -1;
      }
      return 0;
    }
    if(0 == STR2NCMP(arg, "passwd_file=")){
      passwd_file = strchr(arg, '=') + sizeof(char);
      return 0;
    }
    if(0 == STR2NCMP(arg, "iam_role")){
      if(0 == strcmp(arg, "iam_role") || 0 == strcmp(arg, "iam_role=auto")){
        // loading IAM role name in s3fs_init(), because we need to wait initializing curl.
        //
        load_iamrole = true;
        return 0;

      }else if(0 == STR2NCMP(arg, "iam_role=")){
        const char* role = strchr(arg, '=') + sizeof(char);
        S3fsCurl::SetIAMRole(role);
        load_iamrole = false;
        return 0;
      }
    }
    if(0 == STR2NCMP(arg, "public_bucket=")){
      off_t pubbucket = s3fs_strtoofft(strchr(arg, '=') + sizeof(char));
      if(1 == pubbucket){
        S3fsCurl::SetPublicBucket(true);
      }else if(0 == pubbucket){
        S3fsCurl::SetPublicBucket(false);
      }else{
        S3FS_PRN_EXIT("poorly formed argument to option: public_bucket.");
        return -1;
      }
      return 0;
    }
    if(0 == STR2NCMP(arg, "bucket=")){
      std::string bname = strchr(arg, '=') + sizeof(char);
      if ((ret = set_bucket(bname.c_str()))){
        return ret;
      }
      return 0;
    }
    if(0 == STR2NCMP(arg, "host=")){
      host = strchr(arg, '=') + sizeof(char);
      return 0;
    }
    if(0 == STR2NCMP(arg, "servicepath=")){
      service_path = strchr(arg, '=') + sizeof(char);
      return 0;
    }
    if(0 == strcmp(arg, "no_check_certificate")){
        S3fsCurl::SetCheckCertificate(false);
        return 0;
    }
    if(0 == STR2NCMP(arg, "connect_timeout=")){
      long contimeout = static_cast<long>(s3fs_strtoofft(strchr(arg, '=') + sizeof(char)));
      S3fsCurl::SetConnectTimeout(contimeout);
      return 0;
    }
    if(0 == STR2NCMP(arg, "readwrite_timeout=")){
      time_t rwtimeout = static_cast<time_t>(s3fs_strtoofft(strchr(arg, '=') + sizeof(char)));
      S3fsCurl::SetReadwriteTimeout(rwtimeout);
      return 0;
    }
    if(0 == STR2NCMP(arg, "max_stat_cache_size=")){
      unsigned long cache_size = static_cast<unsigned long>(s3fs_strtoofft(strchr(arg, '=') + sizeof(char)));
      StatCache::getStatCacheData()->SetCacheSize(cache_size);
      return 0;
    }
    if(0 == STR2NCMP(arg, "stat_cache_expire=")){
      time_t expr_time = static_cast<time_t>(s3fs_strtoofft(strchr(arg, '=') + sizeof(char)));
      StatCache::getStatCacheData()->SetExpireTime(expr_time);
      return 0;
    }
    // [NOTE]
    // This option is for compatibility old version.
    if(0 == STR2NCMP(arg, "stat_cache_interval_expire=")){
      time_t expr_time = static_cast<time_t>(s3fs_strtoofft(strchr(arg, '=') + sizeof(char)));
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
    if(0 == STR2NCMP(arg, "parallel_count=") || 0 == STR2NCMP(arg, "parallel_upload=")){
      int maxpara = static_cast<int>(s3fs_strtoofft(strchr(arg, '=') + sizeof(char)));
      if(0 >= maxpara){
        S3FS_PRN_EXIT("argument should be over 1: parallel_count");
        return -1;
      }
      S3fsCurl::SetMaxParallelCount(maxpara);
      return 0;
    }
    if(0 == STR2NCMP(arg, "fd_page_size=")){
      S3FS_PRN_ERR("option fd_page_size is no longer supported, so skip this option.");
      return 0;
    }
    if(0 == STR2NCMP(arg, "multipart_size=")){
      off_t size = static_cast<off_t>(s3fs_strtoofft(strchr(arg, '=') + sizeof(char)));
      if(!S3fsCurl::SetMultipartSize(size)){
        S3FS_PRN_EXIT("multipart_size option must be at least 5 MB.");
        return -1;
      }
      // update ensure free disk space if it is not set.
      FdManager::InitEnsureFreeDiskSpace();
      return 0;
    }
    if(0 == STR2NCMP(arg, "ensure_diskfree=")){
      size_t dfsize = static_cast<size_t>(s3fs_strtoofft(strchr(arg, '=') + sizeof(char))) * 1024 * 1024;
      if(dfsize < static_cast<size_t>(S3fsCurl::GetMultipartSize())){
        S3FS_PRN_WARN("specified size to ensure disk free space is smaller than multipart size, so set multipart size to it.");
        dfsize = static_cast<size_t>(S3fsCurl::GetMultipartSize());
      }
      FdManager::SetEnsureFreeDiskSpace(dfsize);
      return 0;
    }
    if(0 == STR2NCMP(arg, "singlepart_copy_limit=")){
      singlepart_copy_limit = static_cast<int64_t>(s3fs_strtoofft(strchr(arg, '=') + sizeof(char))) * 1024;
      return 0;
    }
    if(0 == STR2NCMP(arg, "ahbe_conf=")){
      string ahbe_conf = strchr(arg, '=') + sizeof(char);
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
    if(0 == strcmp(arg, "nocopyapi")){
      nocopyapi = true;
      return 0;
    }
    if(0 == strcmp(arg, "norenameapi")){
      norenameapi = true;
      return 0;
    }
    if(0 == strcmp(arg, "enable_content_md5")){
      S3fsCurl::SetContentMd5(true);
      return 0;
    }
    if(0 == STR2NCMP(arg, "url=")){
      host = strchr(arg, '=') + sizeof(char);
      // strip the trailing '/', if any, off the end of the host
      // string
      size_t found, length;
      found  = host.find_last_of('/');
      length = host.length();
      while(found == (length - 1) && length > 0){
         host.erase(found);
         found  = host.find_last_of('/');
         length = host.length();
      }
      return 0;
    }
    if(0 == strcmp(arg, "sigv2")){
      S3fsCurl::SetSignatureV4(false);
      return 0;
    }
    if(0 == strcmp(arg, "createbucket")){
      create_bucket = true;
      return 0;
    }
    if(0 == STR2NCMP(arg, "endpoint=")){
      endpoint              = strchr(arg, '=') + sizeof(char);
      is_specified_endpoint = true;
      return 0;
    }
    if(0 == strcmp(arg, "use_path_request_style")){
      pathrequeststyle = true;
      return 0;
    }
    if(0 == STR2NCMP(arg, "noua")){
      S3fsCurl::SetUserAgentFlag(false);
      return 0;
    }
    if(0 == strcmp(arg, "use_xattr")){
      is_use_xattr = true;
      return 0;
    }else if(0 == STR2NCMP(arg, "use_xattr=")){
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
    //
    // debug option for s3fs
    //
    if(0 == STR2NCMP(arg, "dbglevel=")){
      const char* strlevel = strchr(arg, '=') + sizeof(char);
      if(0 == strcasecmp(strlevel, "silent") || 0 == strcasecmp(strlevel, "critical") || 0 == strcasecmp(strlevel, "crit")){
        set_s3fs_log_level(S3FS_LOG_CRIT);
      }else if(0 == strcasecmp(strlevel, "error") || 0 == strcasecmp(strlevel, "err")){
        set_s3fs_log_level(S3FS_LOG_ERR);
      }else if(0 == strcasecmp(strlevel, "wan") || 0 == strcasecmp(strlevel, "warn") || 0 == strcasecmp(strlevel, "warning")){
        set_s3fs_log_level(S3FS_LOG_WARN);
      }else if(0 == strcasecmp(strlevel, "inf") || 0 == strcasecmp(strlevel, "info") || 0 == strcasecmp(strlevel, "information")){
        set_s3fs_log_level(S3FS_LOG_INFO);
      }else if(0 == strcasecmp(strlevel, "dbg") || 0 == strcasecmp(strlevel, "debug")){
        set_s3fs_log_level(S3FS_LOG_DBG);
      }else{
        S3FS_PRN_EXIT("option dbglevel has unknown parameter(%s).", strlevel);
        return -1;
      }
      return 0;
    }
    //
    // debug option
    //
    // debug_level is S3FS_LOG_INFO, after second -d is passed to fuse.
    //
    if(0 == strcmp(arg, "-d") || 0 == strcmp(arg, "--debug")){
      if(!IS_S3FS_LOG_INFO() && !IS_S3FS_LOG_DBG()){
        set_s3fs_log_level(S3FS_LOG_INFO);
        return 0;
      }
      if(0 == strcmp(arg, "--debug")){
        // fuse doesn't understand "--debug", but it understands -d.
        // but we can't pass -d back to fuse.
        return 0;
      }
    }
    // "f2" is not used no more.
    // (set S3FS_LOG_DBG)
    if(0 == strcmp(arg, "f2")){
      set_s3fs_log_level(S3FS_LOG_DBG);
      return 0;
    }
    if(0 == strcmp(arg, "curldbg")){
      S3fsCurl::SetVerbose(true);
      return 0;
    }

    if(0 == STR2NCMP(arg, "accessKeyId=")){
      S3FS_PRN_EXIT("option accessKeyId is no longer supported.");
      return -1;
    }
    if(0 == STR2NCMP(arg, "secretAccessKey=")){
      S3FS_PRN_EXIT("option secretAccessKey is no longer supported.");
      return -1;
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

  static const struct option long_opts[] = {
    {"help",    no_argument, NULL, 'h'},
    {"version", no_argument, 0,     0},
    {"debug",   no_argument, NULL, 'd'},
    {0, 0, 0, 0}
  };

  // init syslog(default CRIT)
  openlog("s3fs", LOG_PID | LOG_ODELAY | LOG_NOWAIT, LOG_USER);
  set_s3fs_log_level(debug_level);

  // init xml2
  xmlInitParser();
  LIBXML_TEST_VERSION

  // get program name - emulate basename
  size_t found = string::npos;
  program_name.assign(argv[0]);
  found = program_name.find_last_of("/");
  if(found != string::npos){
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
    case 'u':
      utility_mode = 1;
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

  // clear this structure
  memset(&s3fs_oper, 0, sizeof(s3fs_oper));

  // This is the fuse-style parser for the arguments
  // after which the bucket name and mountpoint names
  // should have been set
  struct fuse_args custom_args = FUSE_ARGS_INIT(argc, argv);
  if(0 != fuse_opt_parse(&custom_args, NULL, NULL, my_fuse_opt_proc)){
    exit(EXIT_FAILURE);
  }

  // [NOTE]
  // exclusive option check here.
  //
  if(REDUCED_REDUNDANCY == S3fsCurl::GetStorageClass() && !S3fsCurl::IsSseDisable()){
    S3FS_PRN_EXIT("use_sse option could not be specified with storage class reduced_redundancy.");
    exit(EXIT_FAILURE);
  }
  if(!S3fsCurl::FinalCheckSse()){
    S3FS_PRN_EXIT("something wrong about SSE options.");
    exit(EXIT_FAILURE);
  }

  // The first plain argument is the bucket
  if(bucket.size() == 0){
    S3FS_PRN_EXIT("missing BUCKET argument.");
    show_usage();
    exit(EXIT_FAILURE);
  }

  // bucket names cannot contain upper case characters in virtual-hosted style
  if((!pathrequeststyle) && (lower(bucket) != bucket)){
    S3FS_PRN_EXIT("BUCKET %s, name not compatible with virtual-hosted style.", bucket.c_str());
    exit(EXIT_FAILURE);
  }

  // check bucket name for illegal characters
  found = bucket.find_first_of("/:\\;!@#$%^&*?|+=");
  if(found != string::npos){
    S3FS_PRN_EXIT("BUCKET %s -- bucket name contains an illegal character.", bucket.c_str());
    exit(EXIT_FAILURE);
  }

  // The second plain argument is the mountpoint
  // if the option was given, we all ready checked for a
  // readable, non-empty directory, this checks determines
  // if the mountpoint option was ever supplied
  if(utility_mode == 0){
    if(mountpoint.size() == 0){
      S3FS_PRN_EXIT("missing MOUNTPOINT argument.");
      show_usage();
      exit(EXIT_FAILURE);
    }
  }

  // error checking of command line arguments for compatibility
  if(S3fsCurl::IsPublicBucket() && S3fsCurl::IsSetAccessKeyId()){
    S3FS_PRN_EXIT("specifying both public_bucket and the access keys options is invalid.");
    exit(EXIT_FAILURE);
  }
  if(passwd_file.size() > 0 && S3fsCurl::IsSetAccessKeyId()){
    S3FS_PRN_EXIT("specifying both passwd_file and the access keys options is invalid.");
    exit(EXIT_FAILURE);
  }
  if(!S3fsCurl::IsPublicBucket() && !load_iamrole){
    if(EXIT_SUCCESS != get_access_keys()){
      exit(EXIT_FAILURE);
    }
    if(!S3fsCurl::IsSetAccessKeyId()){
      S3FS_PRN_EXIT("could not establish security credentials, check documentation.");
      exit(EXIT_FAILURE);
    }
    // More error checking on the access key pair can be done
    // like checking for appropriate lengths and characters  
  }

  // check cache dir permission
  if(!FdManager::CheckCacheTopDir() || !CacheFileStat::CheckCacheFileStatTopDir()){
    S3FS_PRN_EXIT("could not allow cache directory permission, check permission of cache directories.");
    exit(EXIT_FAILURE);
  }

  // There's room for more command line error checking

  // Check to see if the bucket name contains periods and https (SSL) is
  // being used. This is a known limitation:
  // http://docs.amazonwebservices.com/AmazonS3/latest/dev/
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
    found = bucket.find_first_of(".");
    if(found != string::npos){
      found = host.find("https:");
      if(found != string::npos){
        S3FS_PRN_EXIT("Using https and a bucket name with periods is unsupported.");
        exit(1);
      }
    }
  }
  */

  if(utility_mode){
    exit(s3fs_utility_mode());
  }

  // check free disk space
  FdManager::InitEnsureFreeDiskSpace();
  if(!FdManager::IsSafeDiskSpace(NULL, S3fsCurl::GetMultipartSize())){
    S3FS_PRN_EXIT("There is no enough disk space for used as cache(or temporary) directory by s3fs.");
    exit(EXIT_FAILURE);
  }

  s3fs_oper.getattr   = s3fs_getattr;
  s3fs_oper.readlink  = s3fs_readlink;
  s3fs_oper.mknod     = s3fs_mknod;
  s3fs_oper.mkdir     = s3fs_mkdir;
  s3fs_oper.unlink    = s3fs_unlink;
  s3fs_oper.rmdir     = s3fs_rmdir;
  s3fs_oper.symlink   = s3fs_symlink;
  s3fs_oper.rename    = s3fs_rename;
  s3fs_oper.link      = s3fs_link;
  if(!nocopyapi){
    s3fs_oper.chmod   = s3fs_chmod;
    s3fs_oper.chown   = s3fs_chown;
    s3fs_oper.utimens = s3fs_utimens;
  }else{
    s3fs_oper.chmod   = s3fs_chmod_nocopy;
    s3fs_oper.chown   = s3fs_chown_nocopy;
    s3fs_oper.utimens = s3fs_utimens_nocopy;
  }
  s3fs_oper.truncate  = s3fs_truncate;
  s3fs_oper.open      = s3fs_open;
  s3fs_oper.read      = s3fs_read;
  s3fs_oper.write     = s3fs_write;
  s3fs_oper.statfs    = s3fs_statfs;
  s3fs_oper.flush     = s3fs_flush;
  s3fs_oper.fsync     = s3fs_fsync;
  s3fs_oper.release   = s3fs_release;
  s3fs_oper.opendir   = s3fs_opendir;
  s3fs_oper.readdir   = s3fs_readdir;
  s3fs_oper.init      = s3fs_init;
  s3fs_oper.destroy   = s3fs_destroy;
  s3fs_oper.access    = s3fs_access;
  s3fs_oper.create    = s3fs_create;
  // extended attributes
  if(is_use_xattr){
    s3fs_oper.setxattr    = s3fs_setxattr;
    s3fs_oper.getxattr    = s3fs_getxattr;
    s3fs_oper.listxattr   = s3fs_listxattr;
    s3fs_oper.removexattr = s3fs_removexattr;
  }

  // set signal handler for debugging
  if(!set_s3fs_usr2_handler()){
    S3FS_PRN_EXIT("could not set signal handler for SIGUSR2.");
    exit(EXIT_FAILURE);
  }

  // now passing things off to fuse, fuse will finish evaluating the command line args
  fuse_res = fuse_main(custom_args.argc, custom_args.argv, &s3fs_oper, NULL);
  fuse_opt_free_args(&custom_args);

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
* vim600: noet sw=4 ts=4 fdm=marker
* vim<600: noet sw=4 ts=4
*/
