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
#include <openssl/crypto.h>
#include <pwd.h>
#include <grp.h>
#include <getopt.h>

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

//-------------------------------------------------------------------
// Structs
//-------------------------------------------------------------------
typedef struct uncomplete_multipart_info{
  string key;
  string id;
  string date;
}UNCOMP_MP_INFO;

typedef std::list<UNCOMP_MP_INFO> uncomp_mp_list_t;

//-------------------------------------------------------------------
// Global valiables
//-------------------------------------------------------------------
bool debug                        = false;
bool foreground                   = false;
bool foreground2                  = false;
bool nomultipart                  = false;
std::string program_name;
std::string service_path          = "/";
std::string host                  = "http://s3.amazonaws.com";
std::string bucket                = "";

//-------------------------------------------------------------------
// Static valiables
//-------------------------------------------------------------------
static uid_t mp_uid               = 0;    // owner of mount point(only not specified uid opt)
static gid_t mp_gid               = 0;    // group of mount point(only not specified gid opt)
static mode_t mp_mode             = 0;    // mode of mount point
static std::string mountpoint;
static std::string passwd_file    = "";
static bool utility_mode          = false;
static bool noxmlns               = false;
static bool nocopyapi             = false;
static bool norenameapi           = false;
static bool nonempty              = false;
static bool allow_other           = false;
static uid_t s3fs_uid             = 0;
static gid_t s3fs_gid             = 0;
static mode_t s3fs_umask          = 0;
static bool is_s3fs_uid           = false;// default does not set.
static bool is_s3fs_gid           = false;// default does not set.
static bool is_s3fs_umask         = false;// default does not set.
static bool is_remove_cache       = false;

//-------------------------------------------------------------------
// Static functions : prototype
//-------------------------------------------------------------------
static bool is_special_name_folder_object(const char* path);
static int chk_dir_object_type(const char* path, string& newpath, string& nowpath, string& nowcache, headers_t* pmeta = NULL, int* pDirType = NULL);
static int get_object_attribute(const char* path, struct stat* pstbuf, headers_t* pmeta = NULL, bool overcheck = true, bool* pisforce = NULL);
static int check_object_access(const char* path, int mask, struct stat* pstbuf);
static int check_object_owner(const char* path, struct stat* pstbuf);
static int check_parent_object_access(const char* path, int mask);
static FdEntity* get_local_fent(const char* path, bool is_load = false);
static bool multi_head_callback(S3fsCurl* s3fscurl);
static S3fsCurl* multi_head_retry_callback(S3fsCurl* s3fscurl);
static int readdir_multi_head(const char* path, S3ObjList& head, void* buf, fuse_fill_dir_t filler);
static int list_bucket(const char* path, S3ObjList& head, const char* delimiter);
static int directory_empty(const char* path);
static bool is_truncated(xmlDocPtr doc);;
static int append_objects_from_xml_ex(const char* path, xmlDocPtr doc, xmlXPathContextPtr ctx, 
              const char* ex_contents, const char* ex_key, const char* ex_etag, int isCPrefix, S3ObjList& head);
static int append_objects_from_xml(const char* path, xmlDocPtr doc, S3ObjList& head);
static bool GetXmlNsUrl(xmlDocPtr doc, string& nsurl);
static xmlChar* get_base_exp(xmlDocPtr doc, const char* exp);
static xmlChar* get_prefix(xmlDocPtr doc);
static xmlChar* get_next_marker(xmlDocPtr doc);
static char* get_object_name(xmlDocPtr doc, xmlNodePtr node, const char* path);
static int put_headers(const char* path, headers_t& meta, bool ow_sse_flg);
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
static int s3fs_utility_mode(void);
static int s3fs_check_service(void);
static int check_for_aws_format(void);
static int check_passwd_file_perms(void);
static int read_passwd_file(void);
static int get_access_keys(void);
static int set_moutpoint_attribute(struct stat& mpst);
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
static int s3fs_release(const char* path, struct fuse_file_info* fi);
static int s3fs_opendir(const char* path, struct fuse_file_info* fi);
static int s3fs_readdir(const char* path, void* buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info* fi);
static int s3fs_access(const char* path, int mask);
static void* s3fs_init(struct fuse_conn_info* conn);
static void s3fs_destroy(void*);

//-------------------------------------------------------------------
// Functions
//-------------------------------------------------------------------
static bool is_special_name_folder_object(const char* path)
{
  string    strpath = path;
  headers_t header;

  if(!path || '\0' == path[0]){
    return false;
  }

  strpath = path;
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

  // Alwayes check "dir/" at first.
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
      // (But "no dir objet" is checked here.)
      nowcache = nowpath;
      if(isforce){
        (*pType) = DIRTYPE_NOOBJ;
        nowpath  = "";
      }else{
        (*pType) = DIRTYPE_OLD;
      }
    }else{
      // Not found cache --> check for "_$folder$" and "no dir object".
      nowcache = "";  // This case is no cahce.
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
static int get_object_attribute(const char* path, struct stat* pstbuf, headers_t* pmeta, bool overcheck, bool* pisforce)
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

  FPRNINFO("[path=%s]", path);

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
          // found "no dir obejct".
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
  if(0 != StatCache::getStatCacheData()->GetCacheSize()){
    // add into stat cache
    if(!StatCache::getStatCacheData()->AddStat(strpath, (*pheader), forcedir)){
      DPRN("failed adding stat cache [path=%s]", strpath.c_str());
      return -ENOENT;
    }
    if(!StatCache::getStatCacheData()->GetStat(strpath, pstat, pheader, overcheck, pisforce)){
      // There is not in cache.(why?) -> retry to convert.
      if(!convert_header_to_stat(strpath.c_str(), (*pheader), pstat, forcedir)){
        DPRN("failed convert headers to stat[path=%s]", strpath.c_str());
        return -ENOENT;
      }
    }
  }else{
    // cache size is Zero -> only convert.
    if(!convert_header_to_stat(strpath.c_str(), (*pheader), pstat, forcedir)){
      DPRN("failed convert headers to stat[path=%s]", strpath.c_str());
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

  FPRNINFO("[path=%s]", path);

  if(NULL == (pcxt = fuse_get_context())){
    return -EIO;
  }
  if(0 != (result = get_object_attribute(path, pst))){
    // If there is not tha target file(object), reusult is -ENOENT.
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
  if(1 == is_uid_inculde_group(pcxt->uid, obj_gid)){
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

  FPRNINFO("[path=%s]", path);

  if(NULL == (pcxt = fuse_get_context())){
    return -EIO;
  }
  if(0 != (result = get_object_attribute(path, pst))){
    // If there is not tha target file(object), reusult is -ENOENT.
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

  FPRNINFO("[path=%s]", path);

  if(0 == strcmp(path, "/") || 0 == strcmp(path, ".")){
    // path is mount point.
    return 0;
  }
  if(X_OK == (mask & X_OK)){
    for(parent = mydirname(path); 0 < parent.size(); parent = mydirname(parent.c_str())){
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

static FdEntity* get_local_fent(const char* path, bool is_load)
{
  struct stat stobj;
  FdEntity*   ent;

  FPRNNN("[path=%s]", path);

  if(0 != get_object_attribute(path, &stobj)){
    return NULL;
  }

  // open
  time_t mtime         = (!S_ISREG(stobj.st_mode) || S_ISLNK(stobj.st_mode)) ? -1 : stobj.st_mtime;
  bool   force_tmpfile = S_ISREG(stobj.st_mode) ? false : true;

  if(NULL == (ent = FdManager::get()->Open(path, stobj.st_size, mtime, force_tmpfile, true))){
    DPRN("Coult not open file. errno(%d)", errno);
    return NULL;
  }
  // load
  if(is_load && !ent->LoadFull()){
    DPRN("Coult not load file. errno(%d)", errno);
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
static int put_headers(const char* path, headers_t& meta, bool ow_sse_flg)
{
  int         result;
  S3fsCurl    s3fscurl(true);
  struct stat buf;

  FPRNNN("[path=%s]", path);

  // files larger than 5GB must be modified via the multipart interface
  // *** If there is not target object(a case of move command),
  //     get_object_attribute() returns error with initilizing buf.
  get_object_attribute(path, &buf);

  if(buf.st_size >= FIVE_GB){
    // multipart
    if(0 != (result = s3fscurl.MultipartHeadRequest(path, buf.st_size, meta))){
      return result;
    }
  }else{
    if(0 != (result = s3fscurl.PutHeadRequest(path, meta, ow_sse_flg))){
      return result;
    }
  }

  FdEntity* ent = NULL;
  if(NULL == (ent = FdManager::get()->ExistOpen(path))){
    // no opened fd
    if(FdManager::get()->IsCacheDir()){
      // create cache file if be needed
      ent = FdManager::get()->Open(path, buf.st_size, -1, false, true);
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

  FPRN("[path=%s]", path);

  // check parent directory attribute.
  if(0 != (result = check_parent_object_access(path, X_OK))){
    return result;
  }
  if(0 != (result = check_object_access(path, F_OK, stbuf))){
    return result;
  }
  // If has already opened fd, the st_size shuld be instead.
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
  FPRNINFO("[path=%s] uid=%u, gid=%u, mode=%04o", path, (unsigned int)(stbuf->st_uid), (unsigned int)(stbuf->st_gid), stbuf->st_mode);
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
    DPRN("could not get fent(file=%s)", path);
    return -EIO;
  }
  // Get size
  off_t readsize;
  if(!ent->GetSize(readsize)){
    DPRN("could not get file size(file=%s)", path);
    FdManager::get()->Close(ent);
    return -EIO;
  }
  if(static_cast<off_t>(size) <= readsize){
    readsize = size - 1;
  }
  // Read
  ssize_t ressize;
  if(0 > (ressize = ent->Read(buf, 0, static_cast<size_t>(readsize)))){
    DPRN("could not read file(file=%s, errno=%zd)", path, ressize);
    FdManager::get()->Close(ent);
    return static_cast<int>(ressize);
  }
  buf[ressize] = '\0';

  FdManager::get()->Close(ent);
  S3FS_MALLOCTRIM(0);

  return 0;
}

// common function for creation of a plain object
static int create_file_object(const char* path, mode_t mode, uid_t uid, gid_t gid)
{
  FPRNNN("[path=%s][mode=%04o]", path, mode);

  headers_t meta;
  meta["Content-Type"]     = S3fsCurl::LookupMimeType(string(path));
  meta["x-amz-meta-uid"]   = str(uid);
  meta["x-amz-meta-gid"]   = str(gid);
  meta["x-amz-meta-mode"]  = str(mode);
  meta["x-amz-meta-mtime"] = str(time(NULL));

  S3fsCurl s3fscurl(true);
  return s3fscurl.PutRequest(path, meta, -1, false);    // fd=-1 means for creating zero byte object.
}

static int s3fs_mknod(const char *path, mode_t mode, dev_t rdev)
{
  int       result;
  headers_t meta;
  struct fuse_context* pcxt;

  FPRN("[path=%s][mode=%04o][dev=%ju]", path, mode, (uintmax_t)rdev);

  if(NULL == (pcxt = fuse_get_context())){
    return -EIO;
  }

  if(0 != (result = create_file_object(path, mode, pcxt->uid, pcxt->gid))){
    DPRN("could not create object for special file(result=%d)", result);
    return result;
  }
  StatCache::getStatCacheData()->DelStat(path);
  S3FS_MALLOCTRIM(0);

  return result;
}

static int s3fs_create(const char* path, mode_t mode, struct fuse_file_info* fi)
{
  int result;
  headers_t meta;
  struct fuse_context* pcxt;

  FPRN("[path=%s][mode=%04o][flags=%d]", path, mode, fi->flags);

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

  FdEntity* ent;
  if(NULL == (ent = FdManager::get()->Open(path, 0, -1, false, true))){
    return -EIO;
  }
  fi->fh = ent->GetFd();
  S3FS_MALLOCTRIM(0);

  return 0;
}

static int create_directory_object(const char* path, mode_t mode, time_t time, uid_t uid, gid_t gid)
{
  FPRNN("[path=%s][mode=%04o][time=%jd][uid=%u][gid=%u]", path, mode, (intmax_t)time, (unsigned int)uid, (unsigned int)gid);

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
  return s3fscurl.PutRequest(tpath.c_str(), meta, -1, false);    // fd=-1 means for creating zero byte object.
}

static int s3fs_mkdir(const char* path, mode_t mode)
{
  int result;
  struct fuse_context* pcxt;

  FPRN("[path=%s][mode=%04o]", path, mode);

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

  FPRN("[path=%s]", path);

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

  if((result = list_bucket(path, head, "/")) != 0){
    DPRNNN("list_bucket returns error.");
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

  FPRN("[path=%s]", path);

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
  // the cache key is "dir/". So we get error only onece(delete "dir/").

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

  FPRN("[from=%s][to=%s]", from, to);

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
  if(NULL == (ent = FdManager::get()->Open(to, 0, -1, true, true))){
    DPRN("could not open tmpfile(errno=%d)", errno);
    return -errno;
  }
  // write
  ssize_t from_size = strlen(from);
  if(from_size != ent->Write(from, 0, from_size)){
    DPRN("could not write tmpfile(errno=%d)", errno);
    FdManager::get()->Close(ent);
    return -errno;
  }
  // upload
  if(0 != (result = ent->Flush(headers, true, true))){
    DPRN("could not upload tmpfile(result=%d)", result);
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

  FPRNN("[from=%s][to=%s]", from , to);

  if(0 != (result = check_parent_object_access(to, W_OK | X_OK))){
    // not permmit writing "to" object parent dir.
    return result;
  }
  if(0 != (result = check_parent_object_access(from, W_OK | X_OK))){
    // not permmit removing "from" object parent dir.
    return result;
  }
  if(0 != (result = get_object_attribute(from, NULL, &meta))){
    return result;
  }
  s3_realpath = get_realpath(from);

  meta["x-amz-copy-source"]        = urlEncode(service_path + bucket + s3_realpath);
  meta["Content-Type"]             = S3fsCurl::LookupMimeType(string(to));
  meta["x-amz-metadata-directive"] = "REPLACE";

  if(0 != (result = put_headers(to, meta, false))){
    return result;
  }
  result = s3fs_unlink(from);
  StatCache::getStatCacheData()->DelStat(to);

  return result;
}

static int rename_object_nocopy(const char* from, const char* to)
{
  int       result;
  headers_t meta;

  FPRNN("[from=%s][to=%s]", from , to);

  if(0 != (result = check_parent_object_access(to, W_OK | X_OK))){
    // not permmit writing "to" object parent dir.
    return result;
  }
  if(0 != (result = check_parent_object_access(from, W_OK | X_OK))){
    // not permmit removing "from" object parent dir.
    return result;
  }

  // Get attributes
  if(0 != (result = get_object_attribute(from, NULL, &meta))){
    return result;
  }

  // Set header
  meta["Content-Type"] = S3fsCurl::LookupMimeType(string(to));

  // open & load
  FdEntity* ent;
  if(NULL == (ent = get_local_fent(from, true))){
    DPRN("could not open and read file(%s)", from);
    return -EIO;
  }

  // upload
  if(0 != (result = ent->RowFlush(to, meta, false, true))){
    DPRN("could not upload file(%s): result=%d", to, result);
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

  FPRNN("[from=%s][to=%s]", from , to);

  if(0 != (result = check_parent_object_access(to, W_OK | X_OK))){
    // not permmit writing "to" object parent dir.
    return result;
  }
  if(0 != (result = check_parent_object_access(from, W_OK | X_OK))){
    // not permmit removing "from" object parent dir.
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

  FPRNN("[from=%s][to=%s]", from, to);

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

  FPRNN("[from=%s][to=%s]", from, to);

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
    DPRNNN("list_bucket returns error.");
    return result; 
  }
  head.GetNameList(headlist);                       // get name without "/".
  S3ObjList::MakeHierarchizedList(headlist, false); // add hierarchized dir.

  s3obj_list_t::const_iterator liter;
  for(liter = headlist.begin(); headlist.end() != liter; liter++){
    // make "from" and "to" object name.
    string from_name = basepath + (*liter);
    string to_name   = strto + (*liter);
    string etag      = head.GetETag((*liter).c_str());

    // Check subdirectory.
    StatCache::getStatCacheData()->HasStat(from_name, etag.c_str()); // Check ETag
    if(0 != get_object_attribute(from_name.c_str(), &stbuf, NULL)){
      DPRNNN("failed to get %s object attribute.", from_name.c_str());
      continue;
    }
    if(S_ISDIR(stbuf.st_mode)){
      is_dir = true;
      if(0 != chk_dir_object_type(from_name.c_str(), newpath, from_name, nowcache, NULL, &DirType) || DIRTYPE_UNKNOWN == DirType){
        DPRNNN("failed to get %s%s object directory type.", basepath.c_str(), (*liter).c_str());
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
        DPRN("clone_directory_object returned an error(%d)", result);
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
        DPRN("rename_object returned an error(%d)", result);
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
          DPRN("s3fs_rmdir returned an error(%d)", result);
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

  FPRN("[from=%s][to=%s]", from, to);

  if(0 != (result = check_parent_object_access(to, W_OK | X_OK))){
    // not permmit writing "to" object parent dir.
    return result;
  }
  if(0 != (result = check_parent_object_access(from, W_OK | X_OK))){
    // not permmit removing "from" object parent dir.
    return result;
  }
  if(0 != (result = get_object_attribute(from, &buf, NULL))){
    return result;
  }

  // files larger than 5GB must be modified via the multipart interface
  if(S_ISDIR(buf.st_mode)){
    result = rename_directory(from, to);
  }else if(!nomultipart && buf.st_size >= FIVE_GB){
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
  FPRN("[from=%s][to=%s]", from, to);
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

  FPRN("[path=%s][mode=%04o]", path, mode);

  if(0 == strcmp(path, "/")){
    DPRNNN("Could not change mode for maount point.");
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

    if(put_headers(strpath.c_str(), meta, false) != 0){
      return -EIO;
    }
    StatCache::getStatCacheData()->DelStat(nowcache);
  }
  S3FS_MALLOCTRIM(0);

  return 0;
}

static int s3fs_chmod_nocopy(const char* path, mode_t mode)
{
  int result;
  string strpath;
  string newpath;
  string nowcache;
  headers_t meta;
  struct stat stbuf;
  int nDirType = DIRTYPE_UNKNOWN;

  FPRNN("[path=%s][mode=%04o]", path, mode);

  if(0 == strcmp(path, "/")){
    DPRNNN("Could not change mode for maount point.");
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
    result = chk_dir_object_type(path, newpath, strpath, nowcache, &meta, &nDirType);
  }else{
    strpath  = path;
    nowcache = strpath;
    result   = get_object_attribute(strpath.c_str(), NULL, &meta);
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

    // Change file mode
    meta["x-amz-meta-mode"] = str(mode);

    // open & load
    FdEntity* ent;
    if(NULL == (ent = get_local_fent(strpath.c_str(), true))){
      DPRN("could not open and read file(%s)", strpath.c_str());
      return -EIO;
    }

    // upload
    if(0 != (result = ent->Flush(meta, false, true))){
      DPRN("could not upload file(%s): result=%d", strpath.c_str(), result);
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

  FPRN("[path=%s][uid=%u][gid=%u]", path, (unsigned int)uid, (unsigned int)gid);

  if(0 == strcmp(path, "/")){
    DPRNNN("Could not change owner for maount point.");
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

    if(put_headers(strpath.c_str(), meta, false) != 0){
      return -EIO;
    }
    StatCache::getStatCacheData()->DelStat(nowcache);
  }
  S3FS_MALLOCTRIM(0);

  return 0;
}

static int s3fs_chown_nocopy(const char* path, uid_t uid, gid_t gid)
{
  int result;
  string strpath;
  string newpath;
  string nowcache;
  headers_t meta;
  struct stat stbuf;
  int nDirType = DIRTYPE_UNKNOWN;

  FPRNN("[path=%s][uid=%u][gid=%u]", path, (unsigned int)uid, (unsigned int)gid);

  if(0 == strcmp(path, "/")){
    DPRNNN("Could not change owner for maount point.");
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

    // Change owner
    meta["x-amz-meta-uid"] = str(uid);
    meta["x-amz-meta-gid"] = str(gid);

    // open & load
    FdEntity* ent;
    if(NULL == (ent = get_local_fent(strpath.c_str(), true))){
      DPRN("could not open and read file(%s)", strpath.c_str());
      return -EIO;
    }

    // upload
    if(0 != (result = ent->Flush(meta, false, true))){
      DPRN("could not upload file(%s): result=%d", strpath.c_str(), result);
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

  FPRN("[path=%s][mtime=%jd]", path, (intmax_t)(ts[1].tv_sec));

  if(0 == strcmp(path, "/")){
    DPRNNN("Could not change mtime for maount point.");
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

    if(put_headers(strpath.c_str(), meta, false) != 0){
      return -EIO;
    }
    StatCache::getStatCacheData()->DelStat(nowcache);
  }
  S3FS_MALLOCTRIM(0);

  return 0;
}

static int s3fs_utimens_nocopy(const char* path, const struct timespec ts[2])
{
  int result;
  string strpath;
  string newpath;
  string nowcache;
  headers_t meta;
  struct stat stbuf;
  int nDirType = DIRTYPE_UNKNOWN;

  FPRNN("[path=%s][mtime=%s]", path, str(ts[1].tv_sec).c_str());

  if(0 == strcmp(path, "/")){
    DPRNNN("Could not change mtime for maount point.");
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
    result = chk_dir_object_type(path, newpath, strpath, nowcache, &meta, &nDirType);
  }else{
    strpath  = path;
    nowcache = strpath;
    result   = get_object_attribute(strpath.c_str(), NULL, &meta);
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

    // Change date
    meta["x-amz-meta-mtime"] = str(ts[1].tv_sec);

    // open & load
    FdEntity* ent;
    if(NULL == (ent = get_local_fent(strpath.c_str(), true))){
      DPRN("could not open and read file(%s)", strpath.c_str());
      return -EIO;
    }

    // set mtime
    if(0 != (result = ent->SetMtime(ts[1].tv_sec))){
      DPRN("could not set mtime to file(%s): result=%d", strpath.c_str(), result);
      FdManager::get()->Close(ent);
      return result;
    }

    // upload
    if(0 != (result = ent->Flush(meta, false, true))){
      DPRN("could not upload file(%s): result=%d", strpath.c_str(), result);
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

  FPRN("[path=%s][size=%jd]", path, (intmax_t)size);

  if(0 != (result = check_parent_object_access(path, X_OK))){
    return result;
  }
  if(0 != (result = check_object_access(path, W_OK, NULL))){
    return result;
  }

  // Get file information
  if(0 == (result = get_object_attribute(path, NULL, &meta))){
    // Exists -> Get file(with size)
    if(NULL == (ent = FdManager::get()->Open(path, size, -1, false, true))){
      DPRN("could not open file(%s): errno=%d", path, errno);
      return -EIO;
    }
    if(0 != (result = ent->Load(0, size))){
      DPRN("could not download file(%s): result=%d", path, result);
      FdManager::get()->Close(ent);
      return result;
    }

  }else{
    // Not found -> Make tmpfile(with size)
    if(NULL == (ent = FdManager::get()->Open(path, size, -1, true, true))){
      DPRN("could not open file(%s): errno=%d", path, errno);
      return -EIO;
    }
  }

  // upload
  if(0 != (result = ent->Flush(meta, false, true))){
    DPRN("could not upload file(%s): result=%d", path, result);
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
  headers_t meta;
  struct stat st;

  FPRN("[path=%s][flags=%d]", path, fi->flags);

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
    st.st_size = 0;
  }
  if(!S_ISREG(st.st_mode) || S_ISLNK(st.st_mode)){
    st.st_mtime = -1;
  }

  FdEntity* ent;
  if(NULL == (ent = FdManager::get()->Open(path, st.st_size, st.st_mtime, false, true))){
    return -EIO;
  }
  fi->fh = ent->GetFd();
  S3FS_MALLOCTRIM(0);

  return 0;
}

static int s3fs_read(const char* path, char* buf, size_t size, off_t offset, struct fuse_file_info* fi)
{
  ssize_t res;

  FPRNINFO("[path=%s][size=%zu][offset=%jd][fd=%llu]", path, size, (intmax_t)offset, (unsigned long long)(fi->fh));

  FdEntity* ent;
  if(NULL == (ent = FdManager::get()->ExistOpen(path))){
    DPRN("could not find opened fd(%s)", path);
    return -EIO;
  }
  if(ent->GetFd() != static_cast<int>(fi->fh)){
    DPRNNN("Warning - different fd(%d - %llu)", ent->GetFd(), (unsigned long long)(fi->fh));
  }

  // check real file size
  off_t realsize = 0;
  if(!ent->GetSize(realsize) || 0 >= realsize){
    DPRNINFO("file size is 0, so break to read.");
    FdManager::get()->Close(ent);
    return 0;
  }

  if(0 > (res = ent->Read(buf, offset, size, false))){
    DPRN("failed to read file(%s). result=%zd", path, res);
  }
  FdManager::get()->Close(ent);

  return static_cast<int>(res);
}

static int s3fs_write(const char* path, const char* buf, size_t size, off_t offset, struct fuse_file_info* fi)
{
  ssize_t res;

  FPRNINFO("[path=%s][size=%zu][offset=%jd][fd=%llu]", path, size, (intmax_t)offset, (unsigned long long)(fi->fh));

  FdEntity* ent;
  if(NULL == (ent = FdManager::get()->ExistOpen(path))){
    DPRN("could not find opened fd(%s)", path);
    return -EIO;
  }
  if(ent->GetFd() != static_cast<int>(fi->fh)){
    DPRNNN("Warning - different fd(%d - %llu)", ent->GetFd(), (unsigned long long)(fi->fh));
  }
  if(0 > (res = ent->Write(buf, offset, size))){
    DPRN("failed to write file(%s). result=%zd", path, res);
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

  FPRN("[path=%s][fd=%llu]", path, (unsigned long long)(fi->fh));

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
  if(NULL != (ent = FdManager::get()->ExistOpen(path))){
    headers_t meta;
    if(0 != (result = get_object_attribute(path, NULL, &meta))){
      FdManager::get()->Close(ent);
      return result;
    }

    // If both mtime are not same, force to change mtime based on fd.
    time_t ent_mtime;
    if(ent->GetMtime(ent_mtime)){
      if(str(ent_mtime) != meta["x-amz-meta-mtime"]){
        meta["x-amz-meta-mtime"] = str(ent_mtime);
      }
    }
    result = ent->Flush(meta, true, false);
    FdManager::get()->Close(ent);
  }
  S3FS_MALLOCTRIM(0);

  return result;
}

static int s3fs_release(const char* path, struct fuse_file_info* fi)
{
  FPRN("[path=%s][fd=%llu]", path, (unsigned long long)(fi->fh));

  // [NOTICE]
  // At first, we remove stats cache.
  // Because fuse does not wait for responce from "release" function. :-(
  // And fuse runs next command before this function returns.
  // Thus we call deleting stats function ASSAP.
  //
  if((fi->flags & O_RDWR) || (fi->flags & O_WRONLY)){
    StatCache::getStatCacheData()->DelStat(path);
  }

  FdEntity* ent;
  if(NULL == (ent = FdManager::get()->GetFdEntity(path))){
    DPRN("could not find fd(file=%s)", path);
    return -EIO;
  }
  if(ent->GetFd() != static_cast<int>(fi->fh)){
    DPRNNN("Warning - different fd(%d - %llu)", ent->GetFd(), (unsigned long long)(fi->fh));
  }
  FdManager::get()->Close(ent);

  // check - for debug
  if(debug){
    if(NULL != (ent = FdManager::get()->GetFdEntity(path))){
      DPRNNN("Warning - file(%s),fd(%d) is still opened.", path, ent->GetFd());
    }
  }
  S3FS_MALLOCTRIM(0);

  return 0;
}

static int s3fs_opendir(const char* path, struct fuse_file_info* fi)
{
  int result;
  int mask = (O_RDONLY != (fi->flags & O_ACCMODE) ? W_OK : R_OK) | X_OK;

  FPRN("[path=%s][flags=%d]", path, fi->flags);

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
    DPRN("failed adding stat cache [path=%s]", saved_path.c_str());
    return false;
  }
  return true;
}

static S3fsCurl* multi_head_retry_callback(S3fsCurl* s3fscurl)
{
  if(!s3fscurl){
    return NULL;
  }
  if(s3fscurl->IsOverMultipartRetryCount()){
    DPRN("Over retry count(%d) limit(%s).", s3fscurl->GetMultipartRetryCount(), s3fscurl->GetSpacialSavedPath().c_str());
    return NULL;
  }

  S3fsCurl* newcurl = new S3fsCurl(s3fscurl->IsUseAhbe());
  string path       = s3fscurl->GetPath();
  string base_path  = s3fscurl->GetBasePath();
  string saved_path = s3fscurl->GetSpacialSavedPath();

  if(!newcurl->PreHeadRequest(path, base_path, saved_path)){
    DPRN("Could not duplicate curl object(%s).", saved_path.c_str());
    delete newcurl;
    return NULL;
  }
  newcurl->SetMultipartRetryCount(s3fscurl->GetMultipartRetryCount() + 1);

  return newcurl;
}

static int readdir_multi_head(const char* path, S3ObjList& head, void* buf, fuse_fill_dir_t filler)
{
  S3fsMultiCurl curlmulti;
  s3obj_list_t  headlist;
  s3obj_list_t  fillerlist;
  int           result = 0;

  FPRNN("[path=%s][list=%zu]", path, headlist.size());

  // Make base path list.
  head.GetNameList(headlist, true, false);  // get name with "/".

  // Initialize S3fsMultiCurl
  curlmulti.SetSuccessCallback(multi_head_callback);
  curlmulti.SetRetryCallback(multi_head_retry_callback);

  // Loop
  while(0 < headlist.size()){
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

      S3fsCurl* s3fscurl = new S3fsCurl();
      if(!s3fscurl->PreHeadRequest(disppath, (*iter), disppath)){  // target path = cache key path.(ex "dir/")
        DPRNNN("Could not make curl object for head request(%s).", disppath.c_str());
        delete s3fscurl;
        continue;
      }

      if(!curlmulti.SetS3fsCurlObject(s3fscurl)){
        DPRNNN("Could not make curl object into multi curl(%s).", disppath.c_str());
        delete s3fscurl;
        continue;
      }
      cnt++;     // max request count within S3fsMultiCurl::GetMaxMultiRequest()
    }

    // Multi request
    if(0 != (result = curlmulti.Request())){
      DPRN("error occuered in multi request(errno=%d).", result); 
      break;
    }

    // populate fuse buffer
    // here is best posision, because a case is cache size < files in directory
    //
    for(iter = fillerlist.begin(); fillerlist.end() != iter; iter++){
      struct stat st;
      string bpath = mybasename((*iter));
      if(StatCache::getStatCacheData()->GetStat((*iter), &st)){
        filler(buf, bpath.c_str(), &st, 0);
      }else{
        FPRNNN("Could not find %s file in stat cache.", (*iter).c_str());
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
  s3obj_list_t headlist;
  int result;

  FPRN("[path=%s]", path);

  if(0 != (result = check_object_access(path, X_OK, NULL))){
    return result;
  }

  // get a list of all the objects
  if((result = list_bucket(path, head, "/")) != 0){
    DPRN("list_bucket returns error(%d).", result);
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
    DPRN("readdir_multi_head returns error(%d).", result);
  }
  S3FS_MALLOCTRIM(0);

  return result;
}

static int list_bucket(const char* path, S3ObjList& head, const char* delimiter)
{
  int       result; 
  string    s3_realpath;
  string    query;
  string    next_marker = "";
  bool      truncated = true;
  S3fsCurl  s3fscurl;
  xmlDocPtr doc;
  BodyData* body;

  FPRNN("[path=%s]", path);

  if(delimiter && 0 < strlen(delimiter)){
    query += "delimiter=";
    query += delimiter;
    query += "&";
  }
  query += "prefix=";

  s3_realpath = get_realpath(path);
  if(0 == s3_realpath.length() || '/' != s3_realpath[s3_realpath.length() - 1]){
    // last word must be "/"
    query += urlEncode(s3_realpath.substr(1) + "/");
  }else{
    query += urlEncode(s3_realpath.substr(1));
  }
  query += "&max-keys=1000";

  while(truncated){
    string each_query = query;
    if(next_marker != ""){
      each_query += "&marker=" + urlEncode(next_marker);
      next_marker = "";
    }
    // request
    if(0 != (result = s3fscurl.ListBucketRequest(path, each_query.c_str()))){
      DPRN("ListBucketRequest returns with error.");
      return result;
    }
    body = s3fscurl.GetBodyData();

    // xmlDocPtr
    if(NULL == (doc = xmlReadMemory(body->str(), static_cast<int>(body->size()), "", NULL, 0))){
      DPRN("xmlReadMemory returns with error.");
      return -1;
    }
    if(0 != append_objects_from_xml(path, doc, head)){
      DPRN("append_objects_from_xml returns with error.");
      xmlFreeDoc(doc);
      return -1;
    }
    if(true == (truncated = is_truncated(doc))){
      xmlChar*	tmpch = get_next_marker(doc);
      if(tmpch){
        next_marker = (char*)tmpch;
        xmlFree(tmpch);
      }else{
        DPRN("Could not find next marker, thus break loop.");
        truncated = false;
      }
    }
    S3FS_XMLFREEDOC(doc);

    // reset(initialize) curl object
    s3fscurl.DestroyCurlHandle();
  }
  S3FS_MALLOCTRIM(0);

  return 0;
}

const char* c_strErrorObjectName = "FILE or SUBDIR in DIR";

static int append_objects_from_xml_ex(const char* path, xmlDocPtr doc, xmlXPathContextPtr ctx, 
       const char* ex_contents, const char* ex_key, const char* ex_etag, int isCPrefix, S3ObjList& head)
{
  xmlXPathObjectPtr contents_xp;
  xmlNodeSetPtr content_nodes;

  if(NULL == (contents_xp = xmlXPathEvalExpression((xmlChar*)ex_contents, ctx))){
    DPRNNN("xmlXPathEvalExpression returns null.");
    return -1;
  }
  if(xmlXPathNodeSetIsEmpty(contents_xp->nodesetval)){
    DPRNNN("contents_xp->nodesetval is empty.");
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
      DPRNNN("key is null. but continue.");
      continue;
    }
    if(xmlXPathNodeSetIsEmpty(key->nodesetval)){
      DPRNNN("node is empty. but continue.");
      xmlXPathFreeObject(key);
      continue;
    }
    xmlNodeSetPtr key_nodes = key->nodesetval;
    char* name = get_object_name(doc, key_nodes->nodeTab[0]->xmlChildrenNode, path);

    if(!name){
      DPRNNN("name is something wrong. but continue.");

    }else if((const char*)name != c_strErrorObjectName){
      is_dir  = isCPrefix ? true : false;
      stretag = "";

      if(!isCPrefix && ex_etag){
        // Get ETag
        xmlXPathObjectPtr ETag;
        if(NULL != (ETag = xmlXPathEvalExpression((xmlChar*)ex_etag, ctx))){
          if(xmlXPathNodeSetIsEmpty(ETag->nodesetval)){
            DPRNNN("ETag->nodesetval is empty.");
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
        DPRN("insert_object returns with error.");
        xmlXPathFreeObject(key);
        xmlXPathFreeObject(contents_xp);
        free(name);
        S3FS_MALLOCTRIM(0);
        return -1;
      }
      free(name);
    }else{
      DPRNINFO("name is file or subdir in dir. but continue.");
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
    DPRN("append_objects_from_xml_ex returns with error.");
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
    DPRNNN("marker_xp->nodesetval is empty.");
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
//         NULL(a case of something error occured)
static char* get_object_name(xmlDocPtr doc, xmlNodePtr node, const char* path)
{
  // Get full path
  xmlChar* fullpath = xmlNodeListGetString(doc, node, 1);
  if(!fullpath){
    DPRN("could not get object full path name..");
    return NULL;
  }
  // basepath(path) is as same as fullpath.
  if(0 == strcmp((char*)fullpath, path)){
    xmlFree(fullpath);
    return (char*)c_strErrorObjectName;
  }

  // Make dir path and filename
  string   strfullpath= (char*)fullpath;
  string   strdirpath = mydirname(string((char*)fullpath));
  string   strmybpath = mybasename(string((char*)fullpath));
  const char* dirpath = strdirpath.c_str();
  const char* mybname = strmybpath.c_str();
  const char* basepath= (!path || '\0' == path[0] || '/' != path[0] ? path : &path[1]);
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

  FPRNN("[path=%s]", path);

  // getattr will prefix the path with the remote mountpoint
  if(0 != get_object_attribute("/", &stbuf, NULL)){
    return -1;
  }
  if(!S_ISDIR(stbuf.st_mode)){
    return -1;
  }
  return 0;
}

static void* s3fs_init(struct fuse_conn_info* conn)
{
  FPRN("init");
  LOWSYSLOGPRINT(LOG_ERR, "init $Rev$");

  // init curl
  if(!S3fsCurl::InitS3fsCurl("/etc/mime.types")){
    fprintf(stderr, "%s: Could not initiate curl library.\n", program_name.c_str());
    LOWSYSLOGPRINT(LOG_ERR, "Could not initiate curl library.");
    exit(EXIT_FAILURE);
  }

  // Check Bucket
  // If the network is up, check for valid credentials and if the bucket
  // exists. skip check if mounting a public bucket
  if(!S3fsCurl::IsPublicBucket()){
    int result;
    if(EXIT_SUCCESS != (result = s3fs_check_service())){
      exit(result);
    }
  }

  // Investigate system capabilities
  if((unsigned int)conn->capable & FUSE_CAP_ATOMIC_O_TRUNC){
     conn->want |= FUSE_CAP_ATOMIC_O_TRUNC;
  }
  // cache
  if(is_remove_cache && !FdManager::DeleteCacheDirectory()){
    DPRNINFO("Could not inilialize cache directory.");
  }
  return NULL;
}

static void s3fs_destroy(void*)
{
  DPRN("destroy");

  // Destory curl
  if(!S3fsCurl::DestroyS3fsCurl()){
    DPRN("Could not release curl library.");
  }
  // cache
  if(is_remove_cache && !FdManager::DeleteCacheDirectory()){
    DPRN("Could not remove cache directory.");
  }
}

static int s3fs_access(const char* path, int mask)
{
  FPRN("[path=%s][mask=%s%s%s%s]", path,
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
    DPRNNN("Could not find key(%s).", exp_key);
    return NULL;
  }
  if(xmlXPathNodeSetIsEmpty(exp->nodesetval)){
    DPRNNN("Key(%s) node is empty.", exp_key);
    S3FS_XMLXPATHFREEOBJECT(exp);
    return NULL;
  }
  // get exp_key value & set in struct
  exp_nodes = exp->nodesetval;
  if(NULL == (exp_value = xmlNodeListGetString(doc, exp_nodes->nodeTab[0]->xmlChildrenNode, 1))){
    DPRNNN("Key(%s) value is empty.", exp_key);
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

  if(0 < list.size()){
    printf("---------------------------------------------------------------\n");

    int cnt = 0;
    for(uncomp_mp_list_t::iterator iter = list.begin(); iter != list.end(); iter++, cnt++){
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

  if(0 >= list.size()){
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
  for(uncomp_mp_list_t::iterator iter = list.begin(); iter != list.end(); iter++){
    const char* tpath     = (*iter).key.c_str();
    string      upload_id = (*iter).id;

    if(0 != s3fscurl.AbortMultipartUpload(tpath, upload_id)){
      fprintf(stderr, "Failed to remove %s multipart uploading object.\n", tpath);
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
    DPRNNN("xmlXPathEvalExpression returns null.");
    return false;
  }
  if(xmlXPathNodeSetIsEmpty(upload_xp->nodesetval)){
    DPRNNN("upload_xp->nodesetval is empty.");
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

  // init curl
  if(!S3fsCurl::InitS3fsCurl("/etc/mime.types")){
    fprintf(stderr, "%s: Could not initiate curl library.\n", program_name.c_str());
    LOWSYSLOGPRINT(LOG_ERR, "Could not initiate curl library.");
    return EXIT_FAILURE;
  }

  printf("Utility Mode\n");

  S3fsCurl s3fscurl;
  string   body;
  int      result = EXIT_SUCCESS;
  if(0 != s3fscurl.MultipartListRequest(body)){
    fprintf(stderr, "%s: Could not get list multipart upload.\n", program_name.c_str());
    result = EXIT_FAILURE;
  }else{
    // perse result(uncomplete multipart upload information)
    FPRNINFO("response body = {\n%s\n}", body.c_str());

    xmlDocPtr doc;
    if(NULL == (doc = xmlReadMemory(body.c_str(), static_cast<int>(body.size()), "", NULL, 0))){
      DPRN("xmlReadMemory returns with error.");
      result = EXIT_FAILURE;

    }else{
      // make working uploads list
      uncomp_mp_list_t list;
      if(!get_uncomp_mp_list(doc, list)){
        DPRN("get_uncomp_mp_list returns with error.");
        result = EXIT_FAILURE;

      }else{
        // print list
        print_uncomp_mp_list(list);
        // remove
        if(!abort_uncomp_mp_list(list)){
          DPRN("something error occured in removing process.");
          result = EXIT_FAILURE;
        }
      }
      S3FS_XMLFREEDOC(doc);
    }
  }

  // Destory curl
  if(!S3fsCurl::DestroyS3fsCurl()){
    DPRN("Could not release curl library.");
  }
  return result;
}

static int s3fs_check_service(void)
{
  FPRN("check services.");

  // At first time for access S3, we check IAM role if it sets.
  if(!S3fsCurl::CheckIAMCredentialUpdate()){
    fprintf(stderr, "%s: Failed to check IAM role name(%s).\n", program_name.c_str(), S3fsCurl::GetIAMRole());
    return EXIT_FAILURE;
  }

  S3fsCurl s3fscurl;
  if(0 != s3fscurl.CheckBucket()){
    fprintf(stderr, "%s: Failed to access bucket.\n", program_name.c_str());
    return EXIT_FAILURE;
  }
  long responseCode = s3fscurl.GetLastResponseCode();

  if(responseCode == 403){
    fprintf(stderr, "%s: invalid credentials\n", program_name.c_str());
    return EXIT_FAILURE;
  }
  if(responseCode == 404){
    fprintf(stderr, "%s: bucket not found\n", program_name.c_str());
    return EXIT_FAILURE;
  }
  // unable to connect
  if(responseCode == CURLE_OPERATION_TIMEDOUT){
    return EXIT_SUCCESS;
  }
  if(responseCode != 200 && responseCode != 301){
    fprintf(stderr, "%s: unable to connect\n", program_name.c_str());
    return EXIT_FAILURE;
  }

  // make sure remote mountpath exists and is a directory
  if(mount_prefix.size() > 0){
    if(remote_mountpath_exists(mount_prefix.c_str()) != 0){
      fprintf(stderr, "%s: remote mountpath %s not found.\n", 
          program_name.c_str(), mount_prefix.c_str());
      return EXIT_FAILURE;
    }
  }
  S3FS_MALLOCTRIM(0);

  return EXIT_SUCCESS;
}

// Return:  1 - OK(could read and set accesskey etc.)
//          0 - NG(could not read)
//         -1 - Should shoutdown immidiatly
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
      if(line[0]=='#')
        continue;
      if(line.size() == 0)
        continue;

      first_pos = line.find_first_of(" \t");
      if(first_pos != string::npos){
        printf ("%s: invalid line in passwd file, found whitespace character\n", 
           program_name.c_str());
        return -1;
      }

      first_pos = line.find_first_of("[");
      if(first_pos != string::npos && first_pos == 0){
        printf ("%s: invalid line in passwd file, found a bracket \"[\" character\n", 
           program_name.c_str());
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
      fprintf(stderr, "%s: if one access key is specified, both keys need to be specified\n", program_name.c_str());
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
    fprintf (stderr, "%s: unexpected error from stat(%s, ) \n", 
        program_name.c_str(), passwd_file.c_str());
    return EXIT_FAILURE;
  }

  // return error if any file has others permissions 
  if( (info.st_mode & S_IROTH) ||
      (info.st_mode & S_IWOTH) || 
      (info.st_mode & S_IXOTH)) {
    fprintf (stderr, "%s: credentials file %s should not have others permissions\n", 
        program_name.c_str(), passwd_file.c_str());
    return EXIT_FAILURE;
  }

  // Any local file should not have any group permissions 
  // /etc/passwd-s3fs can have group permissions 
  if(passwd_file != "/etc/passwd-s3fs"){
    if( (info.st_mode & S_IRGRP) ||
        (info.st_mode & S_IWGRP) || 
        (info.st_mode & S_IXGRP)) {
      fprintf (stderr, "%s: credentials file %s should not have group permissions\n", 
        program_name.c_str(), passwd_file.c_str());
      return EXIT_FAILURE;
    }
  }else{
    // "/etc/passwd-s3fs" does not allow group write.
    if((info.st_mode & S_IWGRP)){
      fprintf (stderr, "%s: credentials file %s should not have group writable permissions\n", 
        program_name.c_str(), passwd_file.c_str());
      return EXIT_FAILURE;
    }
  }
  if((info.st_mode & S_IXUSR) || (info.st_mode & S_IXGRP)){
    fprintf (stderr, "%s: credentials file %s should not have executable permissions\n", 
      program_name.c_str(), passwd_file.c_str());
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
  bool aws_format;

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

      first_pos = line.find_first_of(" \t");
      if(first_pos != string::npos){
        printf ("%s: invalid line in passwd file, found whitespace character\n", 
           program_name.c_str());
        return EXIT_FAILURE;
      }

      first_pos = line.find_first_of("[");
      if(first_pos != string::npos && first_pos == 0){
        printf ("%s: invalid line in passwd file, found a bracket \"[\" character\n", 
           program_name.c_str());
        return EXIT_FAILURE;
      }

      first_pos = line.find_first_of(":");
      if(first_pos == string::npos){
        printf ("%s: invalid line in passwd file, no \":\" separator found\n", 
           program_name.c_str());
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
          printf ("%s: more than one default key pair found in passwd file\n", 
            program_name.c_str());
          return EXIT_FAILURE;
        }
        default_found = 1;
        field1.assign("");
        field2 = line.substr(0,first_pos);
        field3 = line.substr(first_pos + 1, string::npos);
        if(!S3fsCurl::SetAccessKey(field2.c_str(), field3.c_str())){
          fprintf(stderr, "%s: if one access key is specified, both keys need to be specified\n", program_name.c_str());
          return EXIT_FAILURE;
        }
      }

      // does the bucket we are mounting match this passwd file entry?
      // if so, use that key pair, otherwise use the default key, if found,
      // will be used
      if(field1.size() != 0 && field1 == bucket){
        if(!S3fsCurl::SetAccessKey(field2.c_str(), field3.c_str())){
          fprintf(stderr, "%s: if one access key is specified, both keys need to be specified\n", program_name.c_str());
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
      fprintf(stderr, "%s: specified passwd_file is not readable\n",
              program_name.c_str());
      return EXIT_FAILURE;
    }
  }

  // 3  - environment variables
  char* AWSACCESSKEYID     = getenv("AWSACCESSKEYID");
  char* AWSSECRETACCESSKEY = getenv("AWSSECRETACCESSKEY");
  if(AWSACCESSKEYID != NULL || AWSSECRETACCESSKEY != NULL){
    if( (AWSACCESSKEYID == NULL && AWSSECRETACCESSKEY != NULL) ||
        (AWSACCESSKEYID != NULL && AWSSECRETACCESSKEY == NULL) ){

      fprintf(stderr, "%s: if environment variable AWSACCESSKEYID is set then AWSSECRETACCESSKEY must be set too\n",
              program_name.c_str());
      return EXIT_FAILURE;
    }
    if(!S3fsCurl::SetAccessKey(AWSACCESSKEYID, AWSSECRETACCESSKEY)){
      fprintf(stderr, "%s: if one access key is specified, both keys need to be specified\n", program_name.c_str());
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
        fprintf(stderr, "%s: AWS_CREDENTIAL_FILE: \"%s\" is not readable\n",
                program_name.c_str(), passwd_file.c_str());
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
  
  fprintf(stderr, "%s: could not determine how to establish security credentials\n",
           program_name.c_str());
  return EXIT_FAILURE;
}

//
// Check & Set attributes for mount point.
//
static int set_moutpoint_attribute(struct stat& mpst)
{
  mp_uid  = geteuid();
  mp_gid  = getegid();
  mp_mode = S_IFDIR | (allow_other ? (S_IRWXU | S_IRWXG | S_IRWXO) : S_IRWXU);

  FPRNNN("PROC(uid=%u, gid=%u) - MountPoint(uid=%u, gid=%u, mode=%04o)",
         (unsigned int)mp_uid, (unsigned int)mp_gid, (unsigned int)(mpst.st_uid), (unsigned int)(mpst.st_gid), mpst.st_mode);

  // check owner
  if(0 == mp_uid || mpst.st_uid == mp_uid){
    return true;
  }
  // check group permission
  if(mpst.st_gid == mp_gid || 1 == is_uid_inculde_group(mp_uid, mpst.st_gid)){
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

// This is repeatedly called by the fuse option parser
// if the key is equal to FUSE_OPT_KEY_OPT, it's an option passed in prefixed by 
// '-' or '--' e.g.: -f -d -ousecache=/tmp
//
// if the key is equal to FUSE_OPT_KEY_NONOPT, it's either the bucket name 
//  or the mountpoint. The bucket name will always come before the mountpoint
static int my_fuse_opt_proc(void* data, const char* arg, int key, struct fuse_args* outargs)
{
  if(key == FUSE_OPT_KEY_NONOPT){
    // the first NONOPT option is the bucket name
    if(bucket.size() == 0){
      // extract remote mount path
      char *bucket_name = (char*)arg;
      if(strstr(arg, ":")){
        bucket = strtok(bucket_name, ":");
        char* pmount_prefix = strtok(NULL, ":");
        if(pmount_prefix){
          if(0 == strlen(pmount_prefix) || '/' != pmount_prefix[0]){
            fprintf(stderr, "%s: path(%s) must be prefix \"/\".\n", program_name.c_str(), pmount_prefix);
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

    // the second NONPOT option is the mountpoint(not utility mode)
    if(0 == mountpoint.size() && 0 == utility_mode){
      // save the mountpoint and do some basic error checking
      mountpoint = arg;
      struct stat stbuf;

      if(stat(arg, &stbuf) == -1){
        fprintf(stderr, "%s: unable to access MOUNTPOINT %s: %s\n", 
            program_name.c_str(), mountpoint.c_str(), strerror(errno));
        return -1;
      }
      if(!(S_ISDIR(stbuf.st_mode))){
        fprintf(stderr, "%s: MOUNTPOINT: %s is not a directory\n", 
                program_name.c_str(), mountpoint.c_str());
        return -1;
      }
      if(!set_moutpoint_attribute(stbuf)){
        fprintf(stderr, "%s: MOUNTPOINT: %s permission denied.\n", 
                program_name.c_str(), mountpoint.c_str());
        return -1;
      }

      if(!nonempty){
        struct dirent *ent;
        DIR *dp = opendir(mountpoint.c_str());
        if(dp == NULL){
          fprintf(stderr, "%s: failed to open MOUNTPOINT: %s: %s\n", 
                program_name.c_str(), mountpoint.c_str(), strerror(errno));
          return -1;
        }
        while((ent = readdir(dp)) != NULL){
          if(strcmp(ent->d_name, ".") != 0 && strcmp(ent->d_name, "..") != 0){
            closedir(dp);
            fprintf(stderr, "%s: MOUNTPOINT directory %s is not empty.\n"
                            "%s: if you are sure this is safe, can use the 'nonempty' mount option.\n", 
                            program_name.c_str(), mountpoint.c_str(), program_name.c_str());
            return -1;
          }
        }
        closedir(dp);
      }
      return 1;
    }

    // Unknow option
    if(0 == utility_mode){
      fprintf(stderr, "%s: specified unknown third optioni(%s).\n", program_name.c_str(), arg);
    }else{
      fprintf(stderr, "%s: specified unknown second optioni(%s).\n"
                      "%s: you don't need to specify second option(mountpoint) for utility mode(-u).\n",
                      program_name.c_str(), arg, program_name.c_str());
    }
    return -1;

  }else if(key == FUSE_OPT_KEY_OPT){
    if(0 == STR2NCMP(arg, "uid=")){
      s3fs_uid = get_uid(strchr(arg, '=') + sizeof(char));
      if(0 != geteuid() && 0 == s3fs_uid){
        fprintf(stderr, "%s: root user can only specify uid=0.\n", program_name.c_str());
        return -1;
      }
      is_s3fs_uid = true;
      return 1; // continue for fuse option
    }
    if(0 == STR2NCMP(arg, "gid=")){
      s3fs_gid = get_gid(strchr(arg, '=') + sizeof(char));
      if(0 != getegid() && 0 == s3fs_gid){
        fprintf(stderr, "%s: root user can only specify gid=0.\n", program_name.c_str());
        return -1;
      }
      is_s3fs_gid = true;
      return 1; // continue for fuse option
    }
    if(0 == STR2NCMP(arg, "umask=")){
      s3fs_umask = get_mode(strchr(arg, '=') + sizeof(char));
      s3fs_umask &= (S_IRWXU | S_IRWXG | S_IRWXO);
      is_s3fs_umask = true;
      return 1; // continue for fuse option
    }
    if(0 == strcmp(arg, "allow_other")){
      allow_other = true;
      return 1; // continue for fuse option
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
      FdManager::SetCacheDir(strchr(arg, '=') + sizeof(char));
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
    if(0 == strcmp(arg, "use_rrs") || 0 == STR2NCMP(arg, "use_rrs=")){
      off_t rrs = 1;
      // for an old format.
      if(0 == STR2NCMP(arg, "use_rrs=")){
        rrs = s3fs_strtoofft(strchr(arg, '=') + sizeof(char));
      }
      if(0 == rrs){
        S3fsCurl::SetUseRrs(false);
      }else if(1 == rrs){
        if(S3fsCurl::GetUseSse()){
          fprintf(stderr, "%s: use_rrs option could not be specified with use_sse.\n", program_name.c_str());
          return -1;
        }
        S3fsCurl::SetUseRrs(true);
      }else{
        fprintf(stderr, "%s: poorly formed argument to option: use_rrs\n", program_name.c_str());
        return -1;
      }
      return 0;
    }
    if(0 == strcmp(arg, "use_sse") || 0 == STR2NCMP(arg, "use_sse=")){
      off_t sse = 1;
      // for an old format.
      if(0 == STR2NCMP(arg, "use_sse=")){
        sse = s3fs_strtoofft(strchr(arg, '=') + sizeof(char));
      }
      if(0 == sse){
        S3fsCurl::SetUseSse(false);
      }else if(1 == sse){
        if(S3fsCurl::GetUseRrs()){
          fprintf(stderr, "%s: use_sse option could not be specified with use_rrs.\n", program_name.c_str());
          return -1;
        }
        S3fsCurl::SetUseSse(true);
      }else{
        fprintf(stderr, "%s: poorly formed argument to option: use_sse\n", program_name.c_str());
        return -1;
      }
      return 0;
    }
    if(0 == STR2NCMP(arg, "ssl_verify_hostname=")){
      long sslvh = static_cast<long>(s3fs_strtoofft(strchr(arg, '=') + sizeof(char)));
      if(-1 == S3fsCurl::SetSslVerifyHostname(sslvh)){
        fprintf(stderr, "%s: poorly formed argument to option: ssl_verify_hostname\n", 
                program_name.c_str());
        return -1;
      }
      return 0;
    }
    if(0 == STR2NCMP(arg, "passwd_file=")){
      passwd_file = strchr(arg, '=') + sizeof(char);
      return 0;
    }
    if(0 == STR2NCMP(arg, "iam_role=")){
      const char* role = strchr(arg, '=') + sizeof(char);
      S3fsCurl::SetIAMRole(role);
      return 0;
    }
    if(0 == STR2NCMP(arg, "public_bucket=")){
      off_t pubbucket = s3fs_strtoofft(strchr(arg, '=') + sizeof(char));
      if(1 == pubbucket){
        S3fsCurl::SetPublicBucket(true);
      }else if(0 == pubbucket){
        S3fsCurl::SetPublicBucket(false);
      }else{
        fprintf(stderr, "%s: poorly formed argument to option: public_bucket\n", 
           program_name.c_str());
        return -1;
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
        fprintf(stderr, "%s: argument should be over 1: parallel_count\n", 
           program_name.c_str());
        return -1;
      }
      S3fsCurl::SetMaxParallelCount(maxpara);

      if(FdManager::GetPageSize() < static_cast<size_t>(S3fsCurl::GetMultipartSize() * S3fsCurl::GetMaxParallelCount())){
        FdManager::SetPageSize(static_cast<size_t>(S3fsCurl::GetMultipartSize() * S3fsCurl::GetMaxParallelCount()));
      }
      return 0;
    }
    if(0 == STR2NCMP(arg, "fd_page_size=")){
      size_t pagesize = static_cast<size_t>(s3fs_strtoofft(strchr(arg, '=') + sizeof(char)));
      if(pagesize < static_cast<size_t>(S3fsCurl::GetMultipartSize() * S3fsCurl::GetMaxParallelCount())){
        fprintf(stderr, "%s: argument should be over 1MB: fd_page_size\n", 
           program_name.c_str());
        return -1;
      }
      FdManager::SetPageSize(pagesize);
      return 0;
    }
    if(0 == STR2NCMP(arg, "multipart_size=")){
      off_t size = static_cast<off_t>(s3fs_strtoofft(strchr(arg, '=') + sizeof(char)));
      if(!S3fsCurl::SetMultipartSize(size)){
        fprintf(stderr, "%s: multipart_size option could not be specified over 10(MB)\n", program_name.c_str());
        return -1;
      }
      if(FdManager::GetPageSize() < static_cast<size_t>(S3fsCurl::GetMultipartSize() * S3fsCurl::GetMaxParallelCount())){
        FdManager::SetPageSize(static_cast<size_t>(S3fsCurl::GetMultipartSize() * S3fsCurl::GetMaxParallelCount()));
      }
      return 0;
    }
    if(0 == STR2NCMP(arg, "ahbe_conf=")){
      string ahbe_conf = strchr(arg, '=') + sizeof(char);
      if(!AdditionalHeader::get()->Load(ahbe_conf.c_str())){
        fprintf(stderr, "%s: failed to load ahbe_conf file(%s).\n", 
           program_name.c_str(), ahbe_conf.c_str());
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

    // debug option
    //
    // The first -d (or --debug) enables s3fs debug
    // the second -d option is passed to fuse to turn on its
    // debug output
    if(0 == strcmp(arg, "-d") || 0 == strcmp(arg, "--debug")){
      if(!debug){
        debug = true;
        return 0;
      }else{
        // fuse doesn't understand "--debug", but it 
        // understands -d, but we can't pass -d back
        // to fuse, in this case just ignore the
        // second --debug if is was provided.  If we
        // do not ignore this, fuse emits an error
        if(strcmp(arg, "--debug") == 0){
          return 0;
        }
      }
    }
    // for deep debugging message
    if(0 == strcmp(arg, "f2")){
      foreground2 = true;
      return 0;
    }
    if(0 == strcmp(arg, "curldbg")){
      S3fsCurl::SetVerbose(true);
      return 0;
    }

    if(0 == STR2NCMP(arg, "accessKeyId=")){
      fprintf(stderr, "%s: option accessKeyId is no longer supported\n", 
              program_name.c_str());
      return -1;
    }
    if(0 == STR2NCMP(arg, "secretAccessKey=")){
      fprintf(stderr, "%s: option secretAccessKey is no longer supported\n", 
              program_name.c_str());
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

  // init xml2
  xmlInitParser();
  LIBXML_TEST_VERSION

  // get progam name - emulate basename 
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

  // clear this structure
  memset(&s3fs_oper, 0, sizeof(s3fs_oper));

  // This is the fuse-style parser for the arguments
  // after which the bucket name and mountpoint names
  // should have been set
  struct fuse_args custom_args = FUSE_ARGS_INIT(argc, argv);
  if(0 != fuse_opt_parse(&custom_args, NULL, NULL, my_fuse_opt_proc)){
    exit(EXIT_FAILURE);
  }

  // The first plain argument is the bucket
  if(bucket.size() == 0){
    fprintf(stderr, "%s: missing BUCKET argument\n", program_name.c_str());
    show_usage();
    exit(EXIT_FAILURE);
  }

  // bucket names cannot contain upper case characters
  if(lower(bucket) != bucket){
    fprintf(stderr, "%s: BUCKET %s, upper case characters are not supported\n",
      program_name.c_str(), bucket.c_str());
    exit(EXIT_FAILURE);
  }

  // check bucket name for illegal characters
  found = bucket.find_first_of("/:\\;!@#$%^&*?|+=");
  if(found != string::npos){
    fprintf(stderr, "%s: BUCKET %s -- bucket name contains an illegal character\n",
      program_name.c_str(), bucket.c_str());
    exit(EXIT_FAILURE);
  }

  // The second plain argument is the mountpoint
  // if the option was given, we all ready checked for a
  // readable, non-empty directory, this checks determines
  // if the mountpoint option was ever supplied
  if(utility_mode == 0){
    if(mountpoint.size() == 0){
      fprintf(stderr, "%s: missing MOUNTPOINT argument\n", program_name.c_str());
      show_usage();
      exit(EXIT_FAILURE);
    }
  }

  // error checking of command line arguments for compatability
  if(S3fsCurl::IsPublicBucket() && S3fsCurl::IsSetAccessKeyId()){
    fprintf(stderr, "%s: specifying both public_bucket and the access keys options is invalid\n",
      program_name.c_str());
    exit(EXIT_FAILURE);
  }
  if(passwd_file.size() > 0 && S3fsCurl::IsSetAccessKeyId()){
    fprintf(stderr, "%s: specifying both passwd_file and the access keys options is invalid\n",
      program_name.c_str());
    exit(EXIT_FAILURE);
  }
  if(!S3fsCurl::IsPublicBucket()){
    if(EXIT_SUCCESS != get_access_keys()){
      exit(EXIT_FAILURE);
    }
    if(!S3fsCurl::IsSetAccessKeyId()){
      fprintf(stderr, "%s: could not establish security credentials, check documentation\n",
        program_name.c_str());
      exit(EXIT_FAILURE);
    }
    // More error checking on the access key pair can be done
    // like checking for appropriate lengths and characters  
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
        fprintf(stderr, "%s: Using https and a bucket name with periods is unsupported.\n",
          program_name.c_str());
        exit(1);
      }
    }
  }
  */

  if(utility_mode){
    exit(s3fs_utility_mode());
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
  s3fs_oper.release   = s3fs_release;
  s3fs_oper.opendir   = s3fs_opendir;
  s3fs_oper.readdir   = s3fs_readdir;
  s3fs_oper.init      = s3fs_init;
  s3fs_oper.destroy   = s3fs_destroy;
  s3fs_oper.access    = s3fs_access;
  s3fs_oper.create    = s3fs_create;

  // init NSS
  S3FS_INIT_NSS();

  // now passing things off to fuse, fuse will finish evaluating the command line args
  fuse_res = fuse_main(custom_args.argc, custom_args.argv, &s3fs_oper, NULL);
  fuse_opt_free_args(&custom_args);

  // cleanup NSS
  S3FS_CLEANUP_NSS();
  // cleanup xml2
  xmlCleanupParser();
  S3FS_MALLOCTRIM(0);

  exit(fuse_res);
}

