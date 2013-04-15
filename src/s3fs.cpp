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
#include <dirent.h>
#include <errno.h>
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

#include "common.h"
#include "s3fs.h"
#include "curl.h"
#include "cache.h"
#include "string_util.h"
#include "s3fs_util.h"

using namespace std;

//-------------------------------------------------------------------
// Typedef
//-------------------------------------------------------------------
struct file_part {
  char path[17];
  std::string etag;
  bool uploaded;

  file_part() : uploaded(false) {}
};

typedef std::map<int, int>         s3fs_descriptors_t;
typedef std::map<std::string, int> s3fs_pathtofd_t;

//-------------------------------------------------------------------
// Global valiables
//-------------------------------------------------------------------
bool debug                        = 0;
bool foreground                   = 0;
int retries                       = 2;
long connect_timeout              = 10;
time_t readwrite_timeout          = 30;
std::string AWSAccessKeyId;
std::string AWSSecretAccessKey;
std::string program_name;
std::string ssl_verify_hostname   = "1";
std::string service_path          = "/";
std::string host                  = "http://s3.amazonaws.com";
std::string bucket                = "";
std::string public_bucket;

//-------------------------------------------------------------------
// Static valiables
//-------------------------------------------------------------------
static mode_t root_mode           = 0;
static std::string mountpoint;
static std::string passwd_file    = "";
static bool service_validated     = false;
static bool utility_mode          = false;
static bool nomultipart           = false;
static bool noxmlns               = false;
static bool nocopyapi             = false;
static bool norenameapi           = false;

// if .size()==0 then local file cache is disabled
static std::string use_cache;
static std::string use_rrs;

// TODO(apetresc): make this an enum
// private, public-read, public-read-write, authenticated-read
static std::string default_acl("private");

// file discripter
static pthread_mutex_t *mutex_buf = NULL;
static pthread_mutex_t s3fs_descriptors_lock;
static s3fs_descriptors_t s3fs_descriptors;      // fd -> flags
static s3fs_pathtofd_t s3fs_pathtofd;            // path -> fd

//-------------------------------------------------------------------
// Static functions : prototype
//-------------------------------------------------------------------
static int get_object_attribute(const char *path, struct stat *pstbuf, headers_t* pmeta = NULL, bool overcheck = true);
static int check_object_access(const char *path, int mask, struct stat* pstbuf);
static int check_object_owner(const char *path, struct stat* pstbuf);
static int check_parent_object_access(const char *path, int mask);
static int list_bucket(const char *path, struct s3_object **head, const char* delimiter);
static bool is_truncated(const char *xml);
static int append_objects_from_xml_ex(const char* path, xmlDocPtr doc, xmlXPathContextPtr ctx, 
              const char* ex_contents, const char* ex_key, const char* ex_etag, int isCPrefix, struct s3_object **head);
static int append_objects_from_xml(const char* path, const char *xml, struct s3_object **head);
static bool GetXmlNsUrl(xmlDocPtr doc, string& nsurl);
static xmlChar* get_base_exp(const char* xml, const char* exp);
static xmlChar* get_prefix(const char *xml);
static xmlChar* get_next_marker(const char *xml);
static char *get_object_name(xmlDocPtr doc, xmlNodePtr node, const char* path);

static int put_headers(const char *path, headers_t meta);
static int put_multipart_headers(const char *path, headers_t meta);
static int complete_multipart_upload(const char *path, std::string upload_id, std::vector <file_part> parts);
static std::string initiate_multipart_upload(const char *path, off_t size, headers_t meta);
static std::string upload_part(const char *path, const char *source, int part_number, string upload_id);
static std::string copy_part(const char *from, const char *to, int part_number, std::string upload_id, headers_t meta);
static int list_multipart_uploads(void);

// fuse interface functions
static int s3fs_getattr(const char *path, struct stat *stbuf);
static int s3fs_readlink(const char *path, char *buf, size_t size);
static int s3fs_mknod(const char* path, mode_t mode, dev_t rdev);
static int s3fs_mkdir(const char *path, mode_t mode);
static int s3fs_unlink(const char *path);
static int s3fs_rmdir(const char *path);
static int s3fs_symlink(const char *from, const char *to);
static int s3fs_rename(const char *from, const char *to);
static int s3fs_link(const char *from, const char *to);
static int s3fs_chmod(const char *path, mode_t mode);
static int s3fs_chown(const char *path, uid_t uid, gid_t gid);
static int s3fs_truncate(const char *path, off_t size);
static int s3fs_open(const char *path, struct fuse_file_info *fi);
static int s3fs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi);
static int s3fs_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi);
static int s3fs_statfs(const char *path, struct statvfs *stbuf);
static int s3fs_flush(const char *path, struct fuse_file_info *fi);
static int s3fs_release(const char *path, struct fuse_file_info *fi);
static int s3fs_opendir(const char *path, struct fuse_file_info *fi);
static int s3fs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi);
static int s3fs_access(const char *path, int mask);
static int s3fs_utimens(const char *path, const struct timespec ts[2]);
static int remote_mountpath_exists(const char *path);
static void* s3fs_init(struct fuse_conn_info *conn);
static void s3fs_destroy(void*);


//-------------------------------------------------------------------
// Functions
//-------------------------------------------------------------------
//
// Get object attributes with stat cache.
// This function is base for s3fs_getattr().
//
static int get_object_attribute(const char *path, struct stat *pstbuf, headers_t* pmeta, bool overcheck)
{
  int          result = -1;
  struct stat  tmpstbuf;
  struct stat* pstat = pstbuf ? pstbuf : &tmpstbuf;
  headers_t    tmpHead;
  headers_t*   pheader = pmeta ? pmeta : &tmpHead;
  string       strpath;

//FGPRINT("   get_object_attribute[path=%s]\n", path);

  memset(pstat, 0, sizeof(struct stat));
  if(strcmp(path, "/") == 0) {
    pstat->st_nlink = 1; // see fuse faq
    pstat->st_mode  = root_mode | S_IFDIR;
    return 0;
  }

  strpath = path;
  if(StatCache::getStatCacheData()->GetStat(strpath, pstat, pheader, overcheck)){
    return 0;
  }

  // At first, check "object/".
  if(overcheck && 0 < strpath.length() && '/' != strpath[strpath.length() - 1]){
    strpath += "/";
    string s3_realpath = get_realpath(strpath.c_str());
    result = curl_get_headers(s3_realpath.c_str(), (*pheader));
  }
  if(0 != result){
    strpath = path;
    string s3_realpath = get_realpath(strpath.c_str());
    if(0 != (result = curl_get_headers(s3_realpath.c_str(), (*pheader)))){
      return result;
    }
  }

  // add into stat cache
  if(!StatCache::getStatCacheData()->AddStat(strpath, (*pheader))){
    FGPRINT("   get_object_attribute: failed adding stat cache [path=%s]\n", strpath.c_str());
    return -ENOENT;
  }
  if(!StatCache::getStatCacheData()->GetStat(strpath, pstat, pheader, overcheck)){
    FGPRINT("   get_object_attribute: failed getting added stat cache [path=%s]\n", strpath.c_str());
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
// stat:   NULL or the pointer of struct stat.
//
static int check_object_access(const char *path, int mask, struct stat* pstbuf)
{
  int result;
  struct stat st;
  struct stat* pst = (pstbuf ? pstbuf : &st);
  struct fuse_context* pcxt;

//FGPRINT("  check_object_access[path=%s]\n", path);

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
  if(F_OK == mask){
    // if there is a file, always return allowed.
    return 0;
  }

  // compare file mode and uid/gid + mask.
  mode_t mode = pst->st_mode;
  mode_t base_mask = 0;
  if(pcxt->uid == pst->st_uid){
    base_mask = S_IRWXU;
  }else if(pcxt->gid == pst->st_gid){
    base_mask = S_IRWXG;
  }else{
    if(1 == is_uid_inculde_group(pcxt->uid, pst->st_gid)){
      base_mask = S_IRWXG;
    }else{
      base_mask = S_IRWXO;
    }
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

static int check_object_owner(const char *path, struct stat* pstbuf)
{
  int result;
  struct stat st;
  struct stat* pst = (pstbuf ? pstbuf : &st);
  struct fuse_context* pcxt;

//FGPRINT("  check_object_owner[path=%s]\n", path);

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
  if(pcxt->uid == pst->st_uid){
    return 0;
  }
  return -EPERM;
}

//
// Check accessing the parent directories of the object by uid and gid.
//
static int check_parent_object_access(const char *path, int mask)
{
  string parent;
  int result;

//FGPRINT("  check_parent_object_access[path=%s]\n", path);

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

// Get fd in mapping data by path
static int get_opened_fd(const char* path)
{
  int fd = -1;

  pthread_mutex_lock( &s3fs_descriptors_lock );
  if(s3fs_pathtofd.find(string(path)) != s3fs_pathtofd.end()){
    fd = s3fs_pathtofd[string(path)];
    FGPRINT("  get_opened_fd: found fd [path=%s] [fd=%d]\n", path, fd);
  }
  pthread_mutex_unlock( &s3fs_descriptors_lock );

  return fd;
}

static int get_local_fd(const char* path) {
  int fd = -1;
  int result;
  struct stat st;
  CURL *curl = NULL;
  string url;
  string resource;
  string local_md5;
  string baseName = mybasename(path);
  string resolved_path(use_cache + "/" + bucket);
  string cache_path(resolved_path + path);
  headers_t responseHeaders;

  FGPRINT("   get_local_fd[path=%s]\n", path);

  string s3_realpath = get_realpath(path);
  resource = urlEncode(service_path + bucket + s3_realpath);
  url = host + resource;

  if(0 != (result = get_object_attribute(path, NULL, &responseHeaders))){
    return result;
  }

  if(use_cache.size() > 0) {
    fd = open(cache_path.c_str(), O_RDWR); // ### TODO should really somehow obey flags here
    if(fd != -1) {
      if((fstat(fd, &st)) == -1) {
        close(fd);
        YIKES(-errno);
      }

      // if the local and remote mtime/size
      // do not match we have an invalid cache entry
      if(str(st.st_size) != responseHeaders["Content-Length"] || 
        (str(st.st_mtime) != responseHeaders["x-amz-meta-mtime"])) {
        if(close(fd) == -1){
          YIKES(-errno);
        }
        fd = -1;
      }
    }
  }

  // need to download?
  if(fd == -1) {
    mode_t mode = get_mode(responseHeaders["x-amz-meta-mode"].c_str());

    if(use_cache.size() > 0) {
      // only download files, not folders
      if (S_ISREG(mode)) {
        mkdirp(resolved_path + mydirname(path), 0777);
        fd = open(cache_path.c_str(), O_CREAT|O_RDWR|O_TRUNC, mode);
      } else {
        // its a folder; do *not* create anything in local cache... 
        // TODO: do this in a better way)
        fd = fileno(tmpfile());
      }
    } else {
      fd = fileno(tmpfile());
    }

    if(fd == -1)
      YIKES(-errno);

    FILE *f = fdopen(fd, "w+");
    if(f == 0){
      close(fd);
      YIKES(-errno);
    }

    FGPRINT("      downloading[path=%s][fd=%d]\n", path, fd);
    SYSLOGDBG("LOCAL FD");

    auto_curl_slist headers;
    string date = get_date();
    string my_url = prepare_url(url.c_str());
    headers.append("Date: " + date);
    headers.append("Content-Type: ");
    if(public_bucket.substr(0,1) != "1") {
      headers.append("Authorization: AWS " + AWSAccessKeyId + ":" +
        calc_signature("GET", "", date, headers.get(), resource));
    }

    curl = create_curl_handle();
    curl_easy_setopt(curl, CURLOPT_FILE, f);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers.get());
    curl_easy_setopt(curl, CURLOPT_URL, my_url.c_str());

    result = my_curl_easy_perform(curl, NULL, NULL, f);
    if(result != 0) {
      destroy_curl_handle(curl);
      fclose(f);
      return -result;
    }

    // only one of these is needed...
    fflush(f);
    fsync(fd);

    if(fd == -1)
      YIKES(-errno);

    if(S_ISREG(mode) && !S_ISLNK(mode)) {
      // make the file's mtime match that of the file on s3
      // if fd is tmpfile, but we force tor set mtime.
      struct timeval tv[2];
      tv[0].tv_sec = get_mtime(responseHeaders["x-amz-meta-mtime"].c_str());
      tv[0].tv_usec= 0L;
      tv[1].tv_sec = tv[0].tv_sec;
      tv[1].tv_usec= 0L;
      if(-1 == futimes(fd, tv)){
        fclose(f);
        YIKES(-errno);
      }
    }
  }
  destroy_curl_handle(curl);

  return fd;
}

/**
 * create or update s3 meta
 * @return fuse return code
 */
static int put_headers(const char *path, headers_t meta) {
  int result;
  string s3_realpath;
  string url;
  string resource;
  struct stat buf;
  BodyData body;
  CURL *curl = NULL;

  FGPRINT("   put_headers[path=%s]\n", path);

  // files larger than 5GB must be modified via the multipart interface
  // *** If there is not target object(a case of move command),
  //     get_object_attribute() returns error with initilizing buf.
  get_object_attribute(path, &buf);

  if(buf.st_size >= FIVE_GB){
    return(put_multipart_headers(path, meta));
  }

  s3_realpath = get_realpath(path);
  resource = urlEncode(service_path + bucket + s3_realpath);
  url = host + resource;

  auto_curl_slist headers;
  string date = get_date();
  headers.append("Date: " + date);

  meta["x-amz-acl"] = default_acl;
  string ContentType = meta["Content-Type"];

  for (headers_t::iterator iter = meta.begin(); iter != meta.end(); ++iter) {
    string key = (*iter).first;
    string value = (*iter).second;
    if(key == "Content-Type"){
      headers.append(key + ":" + value);
    }else if(key.substr(0,9) == "x-amz-acl"){
      headers.append(key + ":" + value);
    }else if(key.substr(0,10) == "x-amz-meta"){
      headers.append(key + ":" + value);
    }else if(key == "x-amz-copy-source"){
      headers.append(key + ":" + value);
    }
  }

  if(use_rrs.substr(0,1) == "1")
    headers.append("x-amz-storage-class:REDUCED_REDUNDANCY");

  if(public_bucket.substr(0,1) != "1")
    headers.append("Authorization: AWS " + AWSAccessKeyId + ":" +
      calc_signature("PUT", ContentType, date, headers.get(), resource));

  curl = create_curl_handle();
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&body);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(curl, CURLOPT_UPLOAD, true); // HTTP PUT
  curl_easy_setopt(curl, CURLOPT_INFILESIZE, 0); // Content-Length
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers.get());

  FGPRINT("      copying [path=%s]\n", path);
  SYSLOGDBG("copy path=%s", path);

  string my_url = prepare_url(url.c_str());
  curl_easy_setopt(curl, CURLOPT_URL, my_url.c_str());

  result = my_curl_easy_perform(curl, &body);
  destroy_curl_handle(curl);
  if(result != 0)
    return result;

  // Update mtime in local file cache.
  if(meta.count("x-amz-meta-mtime") > 0){
    int fd;
    if(0 <= (fd = get_opened_fd(path))){
      // The file already is opened, so update fd before close(flush);
      struct timeval tv[2];
      memset(tv, 0, sizeof(struct timeval) * 2);
      tv[0].tv_sec = get_mtime(meta["x-amz-meta-mtime"].c_str());
      tv[1].tv_sec = tv[0].tv_sec;
      if(-1 == futimes(fd, tv)){
        YIKES(-errno);
      }
    }else if(use_cache.size() > 0){
      // Use local cache file.
      struct stat st;
      struct utimbuf n_mtime;
      string cache_path(use_cache + "/" + bucket + path);

      if((stat(cache_path.c_str(), &st)) == 0) {
        n_mtime.modtime = get_mtime(meta["x-amz-meta-mtime"].c_str());
        n_mtime.actime = n_mtime.modtime;
        if((utime(cache_path.c_str(), &n_mtime)) == -1) {
          YIKES(-errno);
        }
      }
    }
  }
  return 0;
}

static int put_multipart_headers(const char *path, headers_t meta) {
  int result;
  string s3_realpath;
  string url;
  string resource;
  string upload_id;
  struct stat buf;
  BodyData body;
  vector <file_part> parts;

  FGPRINT("   put_multipart_headers[path=%s]\n", path);

  s3_realpath = get_realpath(path);
  resource = urlEncode(service_path + bucket + s3_realpath);
  url = host + resource;

  // already checked by check_object_access(), so only get attr.
  if(0 != (result = get_object_attribute(path, &buf))){
    return result;
  }

  upload_id = initiate_multipart_upload(path, buf.st_size, meta);
  if(upload_id.size() == 0){
    return(-EIO);
  }

  off_t chunk = 0;
  off_t bytes_written = 0;
  off_t bytes_remaining = buf.st_size;
  while(bytes_remaining > 0) {
    file_part part;

    if(bytes_remaining > MAX_COPY_SOURCE_SIZE)
      chunk = MAX_COPY_SOURCE_SIZE;
    else
      chunk = bytes_remaining - 1;

    stringstream ss;
    ss << "bytes=" << bytes_written << "-" << (bytes_written + chunk);
    meta["x-amz-copy-source-range"] = ss.str();

    part.etag = copy_part(path, path, parts.size() + 1, upload_id, meta);
    parts.push_back(part);

    bytes_written += (chunk + 1);
    bytes_remaining = buf.st_size - bytes_written;
  }

  result = complete_multipart_upload(path, upload_id, parts);
  if(result != 0) {
    return -EIO;
  }

  // Update mtime in local file cache.
  if(meta.count("x-amz-meta-mtime") > 0 && use_cache.size() > 0) {
    struct stat st;
    struct utimbuf n_mtime;
    string cache_path(use_cache + "/" + bucket + path);

    if((stat(cache_path.c_str(), &st)) == 0) {
      n_mtime.modtime = get_mtime(meta["x-amz-meta-mtime"].c_str());
      n_mtime.actime = n_mtime.modtime;
      if((utime(cache_path.c_str(), &n_mtime)) == -1) {
        YIKES(-errno);
      }
    }
  }

  return 0;
}

static int put_local_fd_small_file(const char* path, headers_t meta, int fd) {
  string resource;
  string url;
  string s3_realpath;
  struct stat st;
  CURL *curl = NULL;

  FGPRINT("   put_local_fd_small_file[path=%s][fd=%d]\n", path, fd);

  if(fstat(fd, &st) == -1)
    YIKES(-errno);

  s3_realpath = get_realpath(path);
  resource = urlEncode(service_path + bucket + s3_realpath);
  url = host + resource;

  int result;
  BodyData body;
  auto_curl_slist headers;
  string date = get_date();

  curl = create_curl_handle();
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&body);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(curl, CURLOPT_UPLOAD, true); // HTTP PUT
  curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, static_cast<curl_off_t>(st.st_size)); // Content-Length

  FILE* f = fdopen(fd, "rb");
  if(f == 0){
    YIKES(-errno);
  }

  curl_easy_setopt(curl, CURLOPT_INFILE, f);

  string ContentType = meta["Content-Type"];
  headers.append("Date: " + date);
  meta["x-amz-acl"] = default_acl;

  for (headers_t::iterator iter = meta.begin(); iter != meta.end(); ++iter) {
    string key = (*iter).first;
    string value = (*iter).second;
    if (key == "Content-Type")
      headers.append(key + ":" + value);
    if (key.substr(0,9) == "x-amz-acl")
      headers.append(key + ":" + value);
    if (key.substr(0,10) == "x-amz-meta")
      headers.append(key + ":" + value);
  }

  if(use_rrs.substr(0,1) == "1")
    headers.append("x-amz-storage-class:REDUCED_REDUNDANCY");
  
  if(public_bucket.substr(0,1) != "1")
    headers.append("Authorization: AWS " + AWSAccessKeyId + ":" +
      calc_signature("PUT", ContentType, date, headers.get(), resource));

  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers.get());

  FGPRINT("    uploading[path=%s][fd=%d][size=%zd]\n", path, fd, st.st_size);

  string my_url = prepare_url(url.c_str());
  curl_easy_setopt(curl, CURLOPT_URL, my_url.c_str());

  result = my_curl_easy_perform(curl, &body, NULL, f);
  destroy_curl_handle(curl);
  if(result != 0)
    return result;

  return 0;
}

static int put_local_fd_big_file(const char* path, headers_t meta, int fd) {
  struct stat st;
  off_t lSize;
  int partfd = -1;
  FILE* pSourceFile;
  FILE* pPartFile;
  char *buffer;
  unsigned long lBufferSize = 0;
  size_t bytesRead;
  size_t bytesWritten;
  string uploadId;
  vector <file_part> parts;

  FGPRINT("   put_local_fd_big_file[path=%s][fd=%d]\n", path, fd);

  if(fstat(fd, &st) == -1)
    YIKES(-errno);

  uploadId = initiate_multipart_upload(path, st.st_size, meta);
  if(uploadId.size() == 0) {
    SYSLOGERR("Could not determine UploadId");
    return(-EIO);
  }

  // Open the source file
  pSourceFile = fdopen(fd, "rb");
  if(pSourceFile == NULL) {
    SYSLOGERR("%d###result=%d", __LINE__, errno);
    return(-errno);
  }

  // Source sucessfully opened, obtain file size:
  lSize = st.st_size;

  lBufferSize = 0;
 
  // cycle through open fd, pulling off 10MB chunks at a time
  while(lSize > 0) {
    file_part part;
    size_t totalSize;

    if(lSize >= MULTIPART_SIZE){
       lBufferSize = MULTIPART_SIZE;
    }else{
       lBufferSize = lSize;
    }
    lSize = lSize - lBufferSize;
      
    if((buffer = (char *) malloc(sizeof(char) * lBufferSize)) == NULL) {
      SYSLOGCRIT("Could not allocate memory for buffer\n");
      S3FS_FUSE_EXIT();
      return -ENOMEM;
    }

    // copy the file portion into the buffer:
    for(totalSize = 0; totalSize < lBufferSize; totalSize += bytesRead){
      bytesRead = fread(&buffer[totalSize], 1, (lBufferSize - totalSize), pSourceFile);
      if(bytesRead != (lBufferSize - totalSize)){
        int nError;
        if(0 != (nError = ferror(pSourceFile))){
          SYSLOGERR("%d ### read file error(%d): bytesRead:%zu does not match (lBufferSize - totalSize): %lu\n",
                      __LINE__, nError, bytesRead, (lBufferSize - totalSize));
          if(buffer){
            free(buffer);
          }
          return(-EIO);
        }
        if(feof(pSourceFile)){
          SYSLOGERR("%d ### read end of file: bytesRead:%zu does not match (lBufferSize - totalSize): %lu\n",
                      __LINE__, bytesRead, (lBufferSize - totalSize));
          if(buffer){
            free(buffer);
          }
          return(-EIO);
        }
      }
    }

    // create uniq temporary file
    strncpy(part.path, "/tmp/s3fs.XXXXXX", sizeof part.path);
    if((partfd = mkstemp(part.path)) == -1) {
      if(buffer){
        free(buffer);
      }
      YIKES(-errno);
    }

    // open a temporary file for upload
    if((pPartFile = fdopen(partfd, "wb")) == NULL) {
      SYSLOGERR("%d ### Could not open temporary file: errno %i\n", __LINE__, errno);
      close(partfd);
      if(buffer){
        free(buffer);
      }
      return(-errno);
    }

    // copy buffer to temporary file
    for(totalSize = 0; totalSize < lBufferSize; totalSize += bytesWritten){
      bytesWritten = fwrite(&buffer[totalSize], 1, (size_t)(lBufferSize - totalSize), pPartFile);
      if(bytesWritten != (lBufferSize - totalSize)){
        int nError;
        if(0 != (nError = ferror(pPartFile))){
          SYSLOGERR("%d ### write file error(%d): bytesWritten:%zu  does not match (lBufferSize - totalSize): %lu\n", 
                      __LINE__, nError, bytesWritten, (lBufferSize - totalSize));
          fclose(pPartFile);
          if(buffer){
            free(buffer);
          }
          return(-EIO);
        }
      }
    }

    fclose(pPartFile);
    if(buffer){
      free(buffer);  
    }
    part.etag = upload_part(path, part.path, parts.size() + 1, uploadId);

    // delete temporary part file
    if(remove(part.path) != 0){
      YIKES(-errno);
    }

    parts.push_back(part);
  } // while(lSize > 0)

  return complete_multipart_upload(path, uploadId, parts);
}

/**
 * create or update s3 object
 * @return fuse return code
 */
static int put_local_fd(const char* path, headers_t meta, int fd) {
  int result;
  struct stat st;

  FGPRINT("   put_local_fd[path=%s][fd=%d]\n", path, fd);

  if(fstat(fd, &st) == -1)
    YIKES(-errno);

  /*
   * Make decision to do multi upload (or not) based upon file size
   * 
   * According to the AWS spec:
   *  - 1 to 10,000 parts are allowed
   *  - minimum size of parts is 5MB (expect for the last part)
   * 
   * For our application, we will define part size to be 10MB (10 * 2^20 Bytes)
   * maximum file size will be ~64 GB - 2 ** 36 
   * 
   * Initially uploads will be done serially
   * 
   * If file is > 20MB, then multipart will kick in
   */
  if(st.st_size > 68719476735LL ) { // 64GB - 1
     // close f ?
     return -ENOTSUP;
  }

  if(st.st_size >= 20971520 && !nomultipart) { // 20MB
     // Additional time is needed for large files
     if(readwrite_timeout < 120)
       readwrite_timeout = 120;

     result = put_local_fd_big_file(path, meta, fd); 
  } else {
     result = put_local_fd_small_file(path, meta, fd); 
  }

  return result;
}

/*
 * initiate_multipart_upload
 *
 * Example :
 *   POST /example-object?uploads HTTP/1.1
 *   Host: example-bucket.s3.amazonaws.com
 *   Date: Mon, 1 Nov 2010 20:34:56 GMT
 *   Authorization: AWS VGhpcyBtZXNzYWdlIHNpZ25lZCBieSBlbHZpbmc=
 */
static string initiate_multipart_upload(const char *path, off_t size, headers_t meta) {
  CURL *curl = NULL;
  int result;
  string auth;
  string acl;
  string url;
  string my_url;
  string date;
  string raw_date;
  string resource;
  string upload_id = "";
  string ContentType;
  string s3_realpath;
  BodyData body;
  struct curl_slist *slist=NULL;

  FGPRINT("      initiate_multipart_upload [path=%s][size=%lu]\n", path, size);

  s3_realpath = get_realpath(path);
  resource = urlEncode(service_path + bucket + s3_realpath);
  resource.append("?uploads");
  url = host + resource;
  my_url = prepare_url(url.c_str());

  curl = create_curl_handle();
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&body);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(curl, CURLOPT_POST, true);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, 0);

  date.assign("Date: ");
  raw_date = get_date();
  date.append(raw_date);

  slist = curl_slist_append(slist, date.c_str());
  slist = curl_slist_append(slist, "Accept:");
  slist = curl_slist_append(slist, "Content-Length:");

  ContentType.assign("Content-Type: ");
  string ctype_data;
  ctype_data.assign(lookupMimeType(path));
  ContentType.append(ctype_data);
  slist = curl_slist_append(slist, ContentType.c_str());

  // x-amz headers: (a) alphabetical order and (b) no spaces after colon
  acl.assign("x-amz-acl:");
  acl.append(default_acl);
  slist = curl_slist_append(slist, acl.c_str());

  for(headers_t::iterator iter = meta.begin(); iter != meta.end(); ++iter) {
    string key = (*iter).first;
    string value = (*iter).second;

    if(key.substr(0,10) == "x-amz-meta") {
      string entry;
      entry.assign(key);
      entry.append(":");
      entry.append(value);
      slist = curl_slist_append(slist, entry.c_str());
    }
  }

  if(use_rrs.substr(0,1) == "1")
    slist = curl_slist_append(slist, "x-amz-storage-class:REDUCED_REDUNDANCY");

  if(public_bucket.substr(0,1) != "1") {
     auth.assign("Authorization: AWS ");
     auth.append(AWSAccessKeyId);
     auth.append(":");
     auth.append(calc_signature("POST", ctype_data, raw_date, slist, resource));
    slist = curl_slist_append(slist, auth.c_str());
  }
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);
  curl_easy_setopt(curl, CURLOPT_URL, my_url.c_str());

  result = my_curl_easy_perform(curl, &body);

  curl_slist_free_all(slist);
  destroy_curl_handle(curl);

  if(result != 0) {
    return upload_id;
  }

  // XML returns UploadId
  // Parse XML body for UploadId
  upload_id.clear();
  xmlDocPtr doc = xmlReadMemory(body.str(), body.size(), "", NULL, 0);
  if(doc != NULL && doc->children != NULL) {
    for(xmlNodePtr cur_node = doc->children->children;
         cur_node != NULL;
         cur_node = cur_node->next) {

      // string cur_node_name(reinterpret_cast<const char *>(cur_node->name));
      // printf("cur_node_name: %s\n", cur_node_name.c_str());

      if(cur_node->type == XML_ELEMENT_NODE) {
        string elementName = reinterpret_cast<const char*>(cur_node->name);
        // printf("elementName: %s\n", elementName.c_str());
        if(cur_node->children != NULL) {
          if(cur_node->children->type == XML_TEXT_NODE) {
            if(elementName == "UploadId") {
              upload_id = reinterpret_cast<const char *>(cur_node->children->content);
            }
          }
        }
      } 
    } // for (xmlNodePtr cur_node = doc->children->children;
  } // if (doc != NULL && doc->children != NULL)
  xmlFreeDoc(doc);

  return upload_id;
}

static int complete_multipart_upload(const char *path, string upload_id,
                                     vector <file_part> parts) {
  CURL *curl = NULL;
  char *pData;
  int result;
  int i, j;
  string auth;
  string date;
  string raw_date;
  string url;
  string my_url;
  string resource;
  string postContent;
  string s3_realpath;
  BodyData body;
  struct WriteThis pooh;
  struct curl_slist *slist = NULL;

  FGPRINT("      complete_multipart_upload [path=%s]\n", path);

  // initialization of variables
  curl = NULL;

  postContent.clear();
  postContent.append("<CompleteMultipartUpload>\n");
  for(i = 0, j = parts.size(); i < j; i++) {
     postContent.append("  <Part>\n");
     postContent.append("    <PartNumber>");
     postContent.append(IntToStr(i+1));
     postContent.append("</PartNumber>\n");
     postContent.append("    <ETag>");
     postContent.append(parts[i].etag.insert(0, "\"").append("\""));
     postContent.append("</ETag>\n");
     postContent.append("  </Part>\n");
  }  
  postContent.append("</CompleteMultipartUpload>\n");

  if((pData = (char *)malloc(postContent.size() + 1)) == NULL)
    YIKES(-errno)

  pooh.readptr = pData;
  pooh.sizeleft = postContent.size();

  strcpy(pData, postContent.c_str());

  postContent.clear();

  s3_realpath = get_realpath(path);
  resource = urlEncode(service_path + bucket + s3_realpath);
  resource.append("?uploadId=");
  resource.append(upload_id);
  url = host + resource;
  my_url = prepare_url(url.c_str());

  curl = create_curl_handle();
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&body);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(curl, CURLOPT_POST, true);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (curl_off_t)pooh.sizeleft);
  curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_callback);
  curl_easy_setopt(curl, CURLOPT_READDATA, &pooh);

  date.assign("Date: ");
  raw_date = get_date();
  date.append(raw_date);
  slist = NULL;
  slist = curl_slist_append(slist, date.c_str());

  slist = curl_slist_append(slist, "Accept:");
  slist = curl_slist_append(slist, "Content-Type:");

  if(public_bucket.substr(0,1) != "1") {
    auth.assign("Authorization: AWS ");
    auth.append(AWSAccessKeyId);
    auth.append(":");
    auth.append(calc_signature("POST", "", raw_date, slist, resource));
    slist = curl_slist_append(slist, auth.c_str());
  }
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);
  curl_easy_setopt(curl, CURLOPT_URL, my_url.c_str());

  result = my_curl_easy_perform(curl, &body);

  curl_slist_free_all(slist);
  destroy_curl_handle(curl);
  free(pData);

  return result;
}

static string upload_part(const char *path, const char *source, int part_number, string upload_id) {
  int fd;
  CURL *curl = NULL;
  FILE *part_file;
  int result;
  string url;
  string my_url;
  string auth;
  string resource;
  string date;
  string raw_date;
  string ETag;
  string s3_realpath;
  struct stat st;
  BodyData body;
  BodyData header;
  struct curl_slist *slist = NULL;

  // Now upload the file as the nth part
  FGPRINT("      multipart upload [path=%s][part=%d]\n", path, part_number);

  // PUT /ObjectName?partNumber=PartNumber&uploadId=UploadId HTTP/1.1
  // Host: BucketName.s3.amazonaws.com
  // Date: date
  // Content-Length: Size
  // Authorization: Signature

  // PUT /my-movie.m2ts?partNumber=1&uploadId=VCVsb2FkIElEIGZvciBlbZZpbmcncyBteS1tb3ZpZS5tMnRzIHVwbG9hZR HTTP/1.1
  // Host: example-bucket.s3.amazonaws.com
  // Date:  Mon, 1 Nov 2010 20:34:56 GMT
  // Content-Length: 10485760
  // Content-MD5: pUNXr/BjKK5G2UKvaRRrOA==
  // Authorization: AWS VGhpcyBtZXNzYWdlIHNpZ25lZGGieSRlbHZpbmc=

  part_file = fopen(source, "rb");
  if(part_file == NULL) {
    SYSLOGERR("%d###result=%d", __LINE__, errno); \
    return "";
  }

  if(fstat(fileno(part_file), &st) == -1) {
    fclose(part_file);
    SYSLOGERR("%d###result=%d", __LINE__, errno); \
    return "";
  }

  s3_realpath = get_realpath(path);
  resource = urlEncode(service_path + bucket + s3_realpath);

  resource.append("?partNumber=");
  resource.append(IntToStr(part_number));
  resource.append("&uploadId=");
  resource.append(upload_id);
  url = host + resource;
  my_url = prepare_url(url.c_str());

  curl = create_curl_handle();
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&body);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(curl, CURLOPT_HEADERDATA, (void *)&header);
  curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(curl, CURLOPT_UPLOAD, true); // HTTP PUT
  curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, static_cast<curl_off_t>(st.st_size)); // Content-Length
  curl_easy_setopt(curl, CURLOPT_INFILE, part_file);

  date.assign("Date: ");
  raw_date = get_date();
  date.append(raw_date);
  slist = NULL;
  slist = curl_slist_append(slist, date.c_str());
  slist = curl_slist_append(slist, "Accept:");

  if(public_bucket.substr(0,1) != "1") {
    auth.assign("Authorization: AWS ");
    auth.append(AWSAccessKeyId);
    auth.append(":");
    auth.append(calc_signature("PUT", "", raw_date, slist, resource));
    slist = curl_slist_append(slist, auth.c_str());
  }
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);
  curl_easy_setopt(curl, CURLOPT_URL, my_url.c_str());

  result = my_curl_easy_perform(curl, &body, &header, part_file);
  curl_slist_free_all(slist);
  destroy_curl_handle(curl);
  fclose(part_file);

  if(result != 0) {
    return "";
  }

  // calculate local md5sum, if it matches the header
  // ETag value, the upload was successful.
  if((fd = open(source, O_RDONLY)) == -1) {
    SYSLOGERR("%d###result=%d", __LINE__, -fd);
    return "";
  }

  string md5 = md5sum(fd);
  close(fd);
  if(!md5.empty() && strstr(header.str(), md5.c_str())) {
    ETag.assign(md5);
  } else {
    return "";
  }

  return ETag;
}

static string copy_part(const char *from, const char *to, int part_number, string upload_id, headers_t meta) {
  CURL *curl = NULL;
  int result;
  string url;
  string my_url;
  string auth;
  string resource;
  string raw_date;
  string ETag;
  string s3_realpath;
  BodyData body;
  BodyData header;

  // Now copy the file as the nth part
  FGPRINT("copy_part [from=%s] [to=%s]\n", from, to);

  s3_realpath = get_realpath(to);
  resource = urlEncode(service_path + bucket + s3_realpath);

  resource.append("?partNumber=");
  resource.append(IntToStr(part_number));
  resource.append("&uploadId=");
  resource.append(upload_id);
  url = host + resource;
  my_url = prepare_url(url.c_str());

  auto_curl_slist headers;
  string date = get_date();
  headers.append("Date: " + date);

  string ContentType = meta["Content-Type"];
  meta["x-amz-acl"] = default_acl;

  for(headers_t::iterator iter = meta.begin(); iter != meta.end(); ++iter) {
    string key = (*iter).first;
    string value = (*iter).second;
    if (key == "Content-Type")
      headers.append(key + ":" + value);
    if (key == "x-amz-copy-source")
      headers.append(key + ":" + value);
    if (key == "x-amz-copy-source-range")
      headers.append(key + ":" + value);
  }

  if(use_rrs.substr(0,1) == "1")
    headers.append("x-amz-storage-class:REDUCED_REDUNDANCY");

  if(public_bucket.substr(0,1) != "1")
    headers.append("Authorization: AWS " + AWSAccessKeyId + ":" +
      calc_signature("PUT", ContentType, date, headers.get(), resource));

  curl = create_curl_handle();
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&body);
  curl_easy_setopt(curl, CURLOPT_HEADERDATA, (void *)&header);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(curl, CURLOPT_UPLOAD, true); // HTTP PUT
  curl_easy_setopt(curl, CURLOPT_INFILESIZE, 0); // Content-Length
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers.get());
  curl_easy_setopt(curl, CURLOPT_URL, my_url.c_str());

  result = my_curl_easy_perform(curl, &body, &header);
  destroy_curl_handle(curl);
  if(result != 0) {
    return "";
  }

  char* body_data = (char*)body.str();
  char* start_etag= strstr(body_data, "ETag");
  char* end_etag  = strstr(body_data, "/ETag>");
  start_etag += 11;
  ETag.assign(start_etag, (size_t)(end_etag - start_etag - 7));

  return ETag;
}

//
// List Multipart Uploads for bucket
//
static int list_multipart_uploads(void) {
  CURL *curl = NULL;
  string resource;
  string url;
  BodyData body;
  int result;
  string date;
  string raw_date;
  string auth;
  string my_url;
  struct curl_slist *slist=NULL;

  printf("List Multipart Uploads\n");
  resource = urlEncode(service_path + bucket + "/");
  resource.append("?uploads");
  url = host + resource;
  my_url = prepare_url(url.c_str());
  curl = create_curl_handle();
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&body);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);

  date.assign("Date: ");
  raw_date = get_date();
  date.append(raw_date);
  slist = curl_slist_append(slist, date.c_str());
  slist = curl_slist_append(slist, "Accept:");

  if (public_bucket.substr(0,1) != "1") {
     auth.assign("Authorization: AWS ");
     auth.append(AWSAccessKeyId);
     auth.append(":");
     auth.append(calc_signature("GET", "", raw_date, slist, resource));
    slist = curl_slist_append(slist, auth.c_str());
  }
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);
  curl_easy_setopt(curl, CURLOPT_URL, my_url.c_str());
  result = my_curl_easy_perform(curl, &body);
  curl_slist_free_all(slist);
  destroy_curl_handle(curl);

  if(result != 0) {
    return result;
  }
  if(body.size() > 0){
    printf("body.text:\n%s\n", body.str());
  }
  return 0;
}

static int s3fs_getattr(const char *path, struct stat *stbuf)
{
  int result;

  FGPRINT("s3fs_getattr[path=%s]\n", path);

  // check parent directory attribute.
  if(0 != (result = check_parent_object_access(path, X_OK))){
    return result;
  }
  return check_object_access(path, F_OK, stbuf);
}

static int s3fs_readlink(const char *path, char *buf, size_t size) {
  int fd = -1;
  if (size > 0) {
    --size; // reserve nil terminator

    FGPRINT("s3fs_readlink[path=%s]\n", path);

    fd = get_local_fd(path);
    if(fd < 0) {
      SYSLOGERR("line %d: get_local_fd: %d", __LINE__, -fd);
      return -EIO;
    }

    struct stat st;

    if(fstat(fd, &st) == -1) {
      SYSLOGERR("line %d: fstat: %d", __LINE__, -errno);
      if(fd > 0)
        close(fd);

      return -errno;
    }

    if(st.st_size < (off_t)size)
      size = st.st_size;

    if(pread(fd, buf, size, 0) == -1) {
      SYSLOGERR("line %d: pread: %d", __LINE__, -errno);
      if(fd > 0) 
        close(fd);

      return -errno;
    }

    buf[size] = 0;
  }

  if(fd > 0)
    close(fd);

  return 0;
}

// common function for creation of a plain object
static int create_file_object(const char *path, mode_t mode, uid_t uid, gid_t gid) {
  int result;
  string s3_realpath;
  CURL *curl = NULL;

  FGPRINT("   create_file_object[path=%s][mode=%d]\n", path, mode);

  s3_realpath = get_realpath(path);
  string resource = urlEncode(service_path + bucket + s3_realpath);
  string url = host + resource;

  string date = get_date();
  string my_url = prepare_url(url.c_str());
  auto_curl_slist headers;
  headers.append("Date: " + date);
  string contentType(lookupMimeType(path));
  headers.append("Content-Type: " + contentType);
  // x-amz headers: (a) alphabetical order and (b) no spaces after colon
  headers.append("x-amz-acl:" + default_acl);
  headers.append("x-amz-meta-gid:" + str(gid));
  headers.append("x-amz-meta-mode:" + str(mode));
  headers.append("x-amz-meta-mtime:" + str(time(NULL)));
  headers.append("x-amz-meta-uid:" + str(uid));
  if(public_bucket.substr(0,1) != "1")
    headers.append("Authorization: AWS " + AWSAccessKeyId + ":" +
      calc_signature("PUT", contentType, date, headers.get(), resource));

  curl = create_curl_handle();
  curl_easy_setopt(curl, CURLOPT_UPLOAD, true); // HTTP PUT
  curl_easy_setopt(curl, CURLOPT_INFILESIZE, 0); // Content-Length: 0
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers.get());
  curl_easy_setopt(curl, CURLOPT_URL, my_url.c_str());

  result = my_curl_easy_perform(curl);
  destroy_curl_handle(curl);

  if(result != 0)
    return result;

  return 0;
}

static int s3fs_mknod(const char *path, mode_t mode, dev_t rdev)
{
  FGPRINT("s3fs_mknod[path=%s][mode=%d]\n", path, mode);

  // Could not make block or character special files on S3,
  // always return a error.
  return -EPERM;
}

static int s3fs_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
  int result;
  headers_t meta;
  struct fuse_context* pcxt;

  FGPRINT("s3fs_create[path=%s][mode=%d][flags=%d]\n", path, mode, fi->flags);

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

  if(result != 0)
    return result;

  // object created, open it
  if((fi->fh = get_local_fd(path)) <= 0)
    return -EIO;

  // remember flags and headers...
  pthread_mutex_lock( &s3fs_descriptors_lock );
  s3fs_descriptors[fi->fh] = fi->flags;
  s3fs_pathtofd[string(path)] = fi->fh;
  pthread_mutex_unlock( &s3fs_descriptors_lock );

  return 0;
}

static int create_directory_object(const char *path, mode_t mode, time_t time, uid_t uid, gid_t gid)
{
  CURL *curl = NULL;
  int result;
  string s3_realpath;
  string url;
  string resource;
  string date = get_date();
  auto_curl_slist headers;

  FGPRINT(" create_directory_object[path=%s][mode=%d][time=%lu][uid=%d][gid=%d]\n", path, mode, time, uid, gid);

  s3_realpath = get_realpath(path);
  if('/' != s3_realpath[s3_realpath.length() - 1]){
    s3_realpath += "/";
  }
  resource = urlEncode(service_path + bucket + s3_realpath);
  url = host + resource;

  curl = create_curl_handle();
  curl_easy_setopt(curl, CURLOPT_UPLOAD, true); // HTTP PUT
  curl_easy_setopt(curl, CURLOPT_INFILESIZE, 0); // Content-Length: 0

  headers.append("Date: " + date);
  headers.append("Content-Type: application/x-directory");
  // x-amz headers: (a) alphabetical order and (b) no spaces after colon
  headers.append("x-amz-acl:" + default_acl);
  headers.append("x-amz-meta-gid:" + str(gid));
  headers.append("x-amz-meta-mode:" + str(mode));
  headers.append("x-amz-meta-mtime:" + str(time));
  headers.append("x-amz-meta-uid:" + str(uid));
  if (use_rrs.substr(0,1) == "1") {
    headers.append("x-amz-storage-class:REDUCED_REDUNDANCY");
  }
  if (public_bucket.substr(0,1) != "1") {
    headers.append("Authorization: AWS " + AWSAccessKeyId + ":" +
      calc_signature("PUT", "application/x-directory", date, headers.get(), resource));
  }
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers.get());

  string my_url = prepare_url(url.c_str());
  curl_easy_setopt(curl, CURLOPT_URL, my_url.c_str());

  result = my_curl_easy_perform(curl);
 
  destroy_curl_handle(curl);

  if(result != 0)
    return result;

  return 0;
}

static int s3fs_mkdir(const char *path, mode_t mode)
{
  int result;
  struct fuse_context* pcxt;

  FGPRINT("s3fs_mkdir[path=%s][mode=%d]\n", path, mode);

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

  return create_directory_object(path, mode, time(NULL), pcxt->uid, pcxt->gid);
}

static int s3fs_unlink(const char *path) {
  int result;
  string s3_realpath;

  FGPRINT("s3fs_unlink[path=%s]\n", path);

  if(0 != (result = check_parent_object_access(path, W_OK | X_OK))){
    return result;
  }

  s3_realpath = get_realpath(path);
  result = curl_delete(s3_realpath.c_str());
  StatCache::getStatCacheData()->DelStat(path);

  return result;
}

static int directory_empty(const char *path) {
  int result;
  struct s3_object *head = NULL;

  if((result = list_bucket(path, &head, "/")) != 0){
    FGPRINT(" directory_empty - list_bucket returns error.\n");
    return result;
  }
  if(head){
    free_object_list(head);
    return -ENOTEMPTY;
  }

  return 0;
}

static int s3fs_rmdir(const char *path) {
  int result;
  string s3_realpath;

  FGPRINT("s3fs_rmdir [path=%s]\n", path);

  if(0 != (result = check_parent_object_access(path, W_OK | X_OK))){
    return result;
  }

   // directory must be empty
   if(directory_empty(path) != 0)
     return -ENOTEMPTY;

  s3_realpath = get_realpath(path);
  if('/' != s3_realpath[s3_realpath.length() - 1]){
    s3_realpath += "/";
  }
  result = curl_delete(s3_realpath.c_str());
  StatCache::getStatCacheData()->DelStat(path);

  if(0 != result){
    return result;
  }

  // double check for old version(before 1.63)
  // The old version makes "dir" object, newer version makes "dir/".
  // A case, there is only "dir", the first removing object is "dir/".
  // Then "dir/" is not exists, but curl_delete returns 0.
  // So need to check "dir" and should be removed it.
  struct stat stbuf;
  if(0 != get_object_attribute(path, &stbuf, NULL, false)){
    // This case is 0 return.
    return 0;
  }
  if(S_ISDIR(stbuf.st_mode)){
    // Found "dir" object.
    result = curl_delete(path);
    StatCache::getStatCacheData()->DelStat(path);
  }

  return result;
}

static int s3fs_symlink(const char *from, const char *to) {
  int result;
  int fd = -1;
  struct fuse_context* pcxt;

  FGPRINT("s3fs_symlink[from=%s][to=%s]\n", from, to);

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

  fd = fileno(tmpfile());
  if(fd == -1) {
    SYSLOGERR("line %d: error: fileno(tmpfile()): %d", __LINE__, -errno);
    return -errno;
  }

  if(pwrite(fd, from, strlen(from), 0) == -1) {
    SYSLOGERR("line %d: error: pwrite: %d", __LINE__, -errno);
    if(fd > 0)
      close(fd);

    return -errno;
  }

  result = put_local_fd(to, headers, fd);
  if(result != 0) {
    if(fd > 0)
      close(fd);

    return result;
  }

  if(fd > 0)
    close(fd);

  return 0;
}

static int rename_object(const char *from, const char *to) {
  int result;
  string s3_realpath;
  headers_t meta;

  FGPRINT("rename_object [from=%s] [to=%s]\n", from , to);
  SYSLOGDBG("rename_object [from=%s] [to=%s]", from, to);

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

  meta["x-amz-copy-source"] = urlEncode("/" + bucket + s3_realpath);
  meta["Content-Type"] = lookupMimeType(to);
  meta["x-amz-metadata-directive"] = "REPLACE";

  if(0 != (result = put_headers(to, meta))){
    return result;
  }
  result = s3fs_unlink(from);

  return result;
}

static int rename_object_nocopy(const char *from, const char *to) {
  int       result;
  headers_t meta;
  int       fd;
  int       isclose = 1;

  FGPRINT("rename_object_nocopy [from=%s] [to=%s]\n", from , to);
  SYSLOGDBG("rename_object_nocopy [from=%s] [to=%s]", from, to);

  if(0 != (result = check_parent_object_access(to, W_OK | X_OK))){
    // not permmit writing "to" object parent dir.
    return result;
  }
  if(0 != (result = check_parent_object_access(from, W_OK | X_OK))){
    // not permmit removing "from" object parent dir.
    return result;
  }

  // Downloading
  if(0 > (fd = get_opened_fd(from))){
    if(0 > (fd = get_local_fd(from))){
      FGPRINT("  rename_object_nocopy line %d: get_local_fd result: %d\n", __LINE__, fd);
      SYSLOGERR("rename_object_nocopy line %d: get_local_fd result: %d", __LINE__, fd);
      return -EIO;
    }
  }else{
    isclose = 0;
  }

  // Get attributes
  if(0 != (result = get_object_attribute(from, NULL, &meta))){
    if(isclose){
      close(fd);
    }
    return result;
  }

  // Set header
  meta["Content-Type"] = lookupMimeType(to);

  // Re-uploading
  result = put_local_fd(to, meta, fd);
  if(isclose){
    close(fd);
  }
  if(0 != result){
    FGPRINT("  rename_object_nocopy line %d: put_local_fd result: %d\n", __LINE__, result);
    return result;
  }

  // Remove file
  result = s3fs_unlink(from);

  // Stats
  StatCache::getStatCacheData()->DelStat(to);
  StatCache::getStatCacheData()->DelStat(from);

  return result;
}

static int rename_large_object(const char *from, const char *to) {
  int result;
  string s3_realpath;
  struct stat buf;
  headers_t meta;
  string upload_id;
  vector <file_part> parts;

  FGPRINT("rename_large_object [from=%s] [to=%s]\n", from , to);
  SYSLOGDBG("rename_large_object [from=%s] [to=%s]", from, to);

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
  s3_realpath = get_realpath(from);

  meta["Content-Type"] = lookupMimeType(to);
  meta["x-amz-copy-source"] = urlEncode("/" + bucket + s3_realpath);

  upload_id = initiate_multipart_upload(to, buf.st_size, meta);
  if(upload_id.size() == 0)
    return(-EIO);

  off_t chunk = 0;
  off_t bytes_written = 0;
  off_t bytes_remaining = buf.st_size;
  while(bytes_remaining > 0) {
    file_part part;

    if(bytes_remaining > MAX_COPY_SOURCE_SIZE)
      chunk = MAX_COPY_SOURCE_SIZE;
    else
      chunk = bytes_remaining - 1;

    stringstream ss;
    ss << "bytes=" << bytes_written << "-" << (bytes_written + chunk);
    meta["x-amz-copy-source-range"] = ss.str();

    part.etag = copy_part(from, to, parts.size() + 1, upload_id, meta);
    parts.push_back(part);

    bytes_written += (chunk + 1);
    bytes_remaining = buf.st_size - bytes_written;
  }

  result = complete_multipart_upload(to, upload_id, parts);
  if(result != 0)
    return -EIO;

  return s3fs_unlink(from);
}

static int clone_directory_object(const char *from, const char *to)
{
  int result = -1;
  mode_t mode;
  time_t time;
  uid_t  uid;
  gid_t  gid;
  headers_t meta;

  FGPRINT("clone_directory_object [from=%s] [to=%s]\n", from, to);
  SYSLOGDBG("clone_directory_object [from=%s] [to=%s]", from, to);

  // get target's attributes
  if(0 != (result = get_object_attribute(from, NULL, &meta))){
    return result;
  }

  mode = get_mode(meta["x-amz-meta-mode"].c_str());
  time = get_mtime(meta["x-amz-meta-mtime"].c_str());
  uid  = get_uid(meta["x-amz-meta-uid"].c_str());
  gid  = get_gid(meta["x-amz-meta-gid"].c_str());
  result = create_directory_object(to, mode, time, uid, gid);

  return result;
}

static int rename_directory(const char *from, const char *to) {
  struct s3_object* lb_head    = NULL;
  struct s3_object* lb_headref = NULL;
  string strfrom  = from ? from : "";	// from is without "/".
  string strto    = to ? to : "";	// to is without "/" too.
  string basepath = strfrom + "/";
  MVNODE* mn_head = NULL;
  MVNODE* mn_tail = NULL;
  MVNODE* mn_cur;
  struct stat stbuf;
  int result;
  bool is_dir;
  bool is_nobase = false;

  FGPRINT("rename_directory[from=%s][to=%s]\n", from, to);
  SYSLOGDBG("rename_directory [from=%s] [to=%s]", from, to);

  //
  // Initiate and Add base directory into MVNODE struct.
  //
  is_dir = true;
  if(0 == get_object_attribute(basepath.c_str(), &stbuf, NULL, false)){
    // "from" diredtory is new version type("dir/").
    strfrom = basepath;
  }else{
    // "from" diredtory is old version type("dir").
    if(0 != get_object_attribute(strfrom.c_str(), &stbuf, NULL, false)){
      // "from" diredtory is not new and old version type.
      // This case is that object is made by s3cmd tool(etc).
      is_nobase = true;
    }
  }
  // "to" directory object is always "dir/".
  strto += "/";	

  if(!is_nobase){
    if(NULL == (add_mvnode(&mn_head, &mn_tail, strfrom.c_str(), strto.c_str(), is_dir))){
      return -ENOMEM;
    }
  }

  //
  // get a list of all the objects
  //
  // No delimiter is specified, the result(head) is all object keys.
  // (CommonPrefixes is empty, but all object is listed in Key.)
  if(0 != (result = list_bucket(basepath.c_str(), &lb_head, NULL))){
    FGPRINT(" rename_directory list_bucket returns error.\n");
    return result; 
  }
  for(lb_headref = lb_head; lb_headref; lb_headref = lb_headref->next){
    // make "from" and "to" object name.
    string from_name = basepath + lb_headref->name;
    string to_name   = strto + lb_headref->name;

    // Check subdirectory.
    StatCache::getStatCacheData()->HasStat(from_name, lb_headref->etag); // Check ETag
    if(0 != get_object_attribute(from_name.c_str(), &stbuf, NULL)){
      FGPRINT(" rename_directory - failed to get %s object attribute.\n", from_name.c_str());
      continue;
    }
    is_dir = S_ISDIR(stbuf.st_mode) ? true : false;
    
    // push this one onto the stack
    if(NULL == add_mvnode(&mn_head, &mn_tail, from_name.c_str(), to_name.c_str(), is_dir)){
      return -ENOMEM;
    }
  }
  if(lb_head){
    free_object_list(lb_head);
  }

  //
  // rename
  //
  // rename directory objects.
  for(mn_cur = mn_head; mn_cur; mn_cur = mn_cur->next){
    if(mn_cur->is_dir){
      if(0 != (result = clone_directory_object(mn_cur->old_path, mn_cur->new_path))){
        FGPRINT(" rename_directory - failed(%d) to rename %s directory object to %s.\n", result, mn_cur->old_path, mn_cur->new_path);
        SYSLOGERR("clone_directory_object returned an error(%d)", result);
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
        FGPRINT(" rename_directory - failed(%d) to rename %s object to %s.\n", result, mn_cur->old_path, mn_cur->new_path);
        SYSLOGERR("rename_object returned an error(%d)", result);
        free_mvnodes(mn_head);
        return -EIO;
      }
    }
  }

  // Iterate over old the directories, bottoms up and remove
  for(mn_cur = mn_tail; mn_cur; mn_cur = mn_cur->prev){
    if(mn_cur->is_dir){
      if(0 != (result = s3fs_rmdir(mn_cur->old_path))){
        FGPRINT(" rename_directory - failed(%d) to remove %s directory object.\n", result, mn_cur->old_path);
        SYSLOGERR("s3fs_rmdir returned an error(%d)", result);
        free_mvnodes(mn_head);
        return -EIO;
      }
    }
  }
  free_mvnodes(mn_head);

  return 0;
}

static int s3fs_rename(const char *from, const char *to) {
  struct stat buf;
  int result;

  FGPRINT("s3fs_rename [from=%s] [to=%s]\n", from, to);
  SYSLOGDBG("s3fs_rename [from=%s] [to=%s]", from, to);

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
  return result;
}

static int s3fs_link(const char *from, const char *to)
{
  FGPRINT("s3fs_link[from=%s][to=%s]\n", from, to);
  return -EPERM;
}

static int s3fs_chmod(const char *path, mode_t mode) {
  int result;
  string s3_realpath;
  string strpath;
  headers_t meta;
  struct stat stbuf;
  int nIsNewDirType = 1;

  FGPRINT("s3fs_chmod [path=%s] [mode=%d]\n", path, mode);

  if(0 != (result = check_parent_object_access(path, X_OK))){
    return result;
  }
  if(0 != (result = check_object_owner(path, &stbuf))){
    return result;
  }

  if(S_ISDIR(stbuf.st_mode)){
    result = -1;
    if(0 < strlen(path) && '/' != path[strlen(path) - 1]){
      strpath = path;
      strpath += "/";
      result = get_object_attribute(strpath.c_str(), NULL, &meta, false);
    }
    if(0 != result){
      // Need to chack old type directory("dir").
      strpath = path;
      result = get_object_attribute(strpath.c_str(), NULL, &meta, false);
      if(0 < strpath.length() && '/' == strpath[strpath.length() - 1]){
        nIsNewDirType = 0;
      }
    }
  }else{
    strpath = path;
    result = get_object_attribute(strpath.c_str(), NULL, &meta);
  }
  if(0 != result){
    return result;
  }
  s3_realpath = get_realpath(strpath.c_str());

  if(S_ISDIR(stbuf.st_mode) && 0 == nIsNewDirType){
    // directory object of old version
    // Need to remove old dir("dir") and make new dir("dir/")

    // At first, remove directory old object
    if(0 != (result = curl_delete(s3_realpath.c_str()))){
      return result;
    }
    StatCache::getStatCacheData()->DelStat(path);

    // Make new directory object("dir/")
    if(0 != (result = create_directory_object(path, mode, stbuf.st_mtime, stbuf.st_uid, stbuf.st_gid))){
      return result;
    }

  }else{
    // normal object or directory object of newer version
    meta["x-amz-meta-mode"] = str(mode);
    meta["x-amz-copy-source"] = urlEncode("/" + bucket + s3_realpath);
    meta["x-amz-metadata-directive"] = "REPLACE";

    if(put_headers(strpath.c_str(), meta) != 0){
      return -EIO;
    }
    StatCache::getStatCacheData()->DelStat(strpath);
  }

  return 0;
}

static int s3fs_chmod_nocopy(const char *path, mode_t mode) {
  int result;
  string s3_realpath;
  string strpath;
  headers_t meta;
  struct stat stbuf;
  int nIsNewDirType = 1;

  FGPRINT("s3fs_chmod_nocopy [path=%s] [mode=%d]\n", path, mode);

  if(0 != (result = check_parent_object_access(path, X_OK))){
    return result;
  }
  if(0 != (result = check_object_owner(path, &stbuf))){
    return result;
  }

  // Get attributes
  if(S_ISDIR(stbuf.st_mode)){
    result = -1;
    if(0 < strlen(path) && '/' != path[strlen(path) - 1]){
      strpath = path;
      strpath += "/";
      result = get_object_attribute(strpath.c_str(), NULL, &meta, false);
    }
    if(0 != result){
      // Need to chack old type directory("dir").
      strpath = path;
      result = get_object_attribute(strpath.c_str(), NULL, &meta, false);
      if(0 < strpath.length() && '/' == strpath[strpath.length() - 1]){
        nIsNewDirType = 0;
      }
    }
  }else{
    strpath = path;
    result = get_object_attribute(strpath.c_str(), NULL, &meta);
  }
  if(0 != result){
    return result;
  }
  s3_realpath = get_realpath(strpath.c_str());

  if(S_ISDIR(stbuf.st_mode)){
    if(0 == nIsNewDirType){
      // directory object of old version
      // Need to remove old dir("dir") and make new dir("dir/")

      // At first, remove directory old object
      if(0 != (result = curl_delete(s3_realpath.c_str()))){
        return result;
      }
      StatCache::getStatCacheData()->DelStat(strpath);

      // Make new directory object("dir/")
      if(0 != (result = create_directory_object(strpath.c_str(), mode, stbuf.st_mtime, stbuf.st_uid, stbuf.st_gid))){
        return result;
      }
    }else{
      // directory object of new version
      // Over put directory object.
      if(0 != (result = create_directory_object(strpath.c_str(), mode, stbuf.st_mtime, stbuf.st_uid, stbuf.st_gid))){
        return result;
      }
      StatCache::getStatCacheData()->DelStat(strpath);
    }

  }else{
    // normal object or directory object of newer version
    int fd;
    int isclose = 1;

    // Downloading
    if(0 > (fd = get_opened_fd(strpath.c_str()))){
      if(0 > (fd = get_local_fd(strpath.c_str()))){
        FGPRINT("  s3fs_chmod_nocopy line %d: get_local_fd result: %d\n", __LINE__, fd);
        SYSLOGERR("s3fs_chmod_nocopy line %d: get_local_fd result: %d", __LINE__, fd);
        return -EIO;
      }
    }else{
      isclose = 0;
    }

    // Change file mode
    meta["x-amz-meta-mode"] = str(mode);
    // Change local file mode
    if(-1 == fchmod(fd, mode)){
      if(isclose){
        close(fd);
      }
      FGPRINT("  s3fs_chmod_nocopy line %d: fchmod(fd=%d) error(%d)\n", __LINE__, fd, errno);
      SYSLOGERR("s3fs_chmod_nocopy line %d: fchmod(fd=%d) error(%d)", __LINE__, fd, errno);
      return -errno;
    }

    // Re-uploading
    if(0 != (result = put_local_fd(strpath.c_str(), meta, fd))){
      FGPRINT("  s3fs_chmod_nocopy line %d: put_local_fd result: %d\n", __LINE__, result);
    }
    if(isclose){
      close(fd);
    }
    StatCache::getStatCacheData()->DelStat(strpath);
  }

  return result;
}

static int s3fs_chown(const char *path, uid_t uid, gid_t gid) {
  int result;
  string s3_realpath;
  string strpath;
  headers_t meta;
  struct stat stbuf;
  int nIsNewDirType = 1;

  FGPRINT("s3fs_chown [path=%s] [uid=%d] [gid=%d]\n", path, uid, gid);

  if(0 != (result = check_parent_object_access(path, X_OK))){
    return result;
  }     
  if(0 != (result = check_object_owner(path, &stbuf))){
    return result;
  }

  if(S_ISDIR(stbuf.st_mode)){
    result = -1;
    if(0 < strlen(path) && '/' != path[strlen(path) - 1]){
      strpath = path;
      strpath += "/";
      result = get_object_attribute(strpath.c_str(), NULL, &meta, false);
    }
    if(0 != result){
      // Need to chack old type directory("dir").
      strpath = path;
      result = get_object_attribute(strpath.c_str(), NULL, &meta, false);
      if(0 < strpath.length() && '/' == strpath[strpath.length() - 1]){
        nIsNewDirType = 0;
      }
    }
  }else{
    strpath = path;
    result = get_object_attribute(strpath.c_str(), NULL, &meta);
  }
  if(0 != result){
    return result;
  }
  s3_realpath = get_realpath(strpath.c_str());

  struct passwd* pwdata= getpwuid(uid);
  struct group* grdata = getgrgid(gid);
  if(pwdata){
    uid = pwdata->pw_uid;
  }
  if(grdata){
    gid = grdata->gr_gid;
  }

  if(S_ISDIR(stbuf.st_mode) && 0 == nIsNewDirType){
    // directory object of old version
    // Need to remove old dir("dir") and make new dir("dir/")

    // At first, remove directory old object
    if(0 != (result = curl_delete(s3_realpath.c_str()))){
      return result;
    }
    StatCache::getStatCacheData()->DelStat(strpath);

    // Make new directory object("dir/")
    if(0 != (result = create_directory_object(strpath.c_str(), stbuf.st_mode, stbuf.st_mtime, uid, gid))){
      return result;
    }
  }else{
    meta["x-amz-meta-uid"] = str(uid);
    meta["x-amz-meta-gid"] = str(gid);
    meta["x-amz-copy-source"] = urlEncode("/" + bucket + s3_realpath);
    meta["x-amz-metadata-directive"] = "REPLACE";

    if(put_headers(strpath.c_str(), meta) != 0){
      return -EIO;
    }
    StatCache::getStatCacheData()->DelStat(strpath);
  }

  return 0;
}

static int s3fs_chown_nocopy(const char *path, uid_t uid, gid_t gid) {
  int result;
  string s3_realpath;
  string strpath;
  headers_t meta;
  struct stat stbuf;
  int nIsNewDirType = 1;

  FGPRINT("s3fs_chown_nocopy [path=%s] [uid=%d] [gid=%d]\n", path, uid, gid);

  if(0 != (result = check_parent_object_access(path, X_OK))){
    return result;
  }     
  if(0 != (result = check_object_owner(path, &stbuf))){
    return result;
  }

  // Get attributes
  if(S_ISDIR(stbuf.st_mode)){
    result = -1;
    if(0 < strlen(path) && '/' != path[strlen(path) - 1]){
      strpath = path;
      strpath += "/";
      result = get_object_attribute(strpath.c_str(), NULL, &meta, false);
    }
    if(0 != result){
      // Need to chack old type directory("dir").
      strpath = path;
      result = get_object_attribute(strpath.c_str(), NULL, &meta, false);
      if(0 < strpath.length() && '/' == strpath[strpath.length() - 1]){
        nIsNewDirType = 0;
      }
    }
  }else{
    strpath = path;
    result = get_object_attribute(strpath.c_str(), NULL, &meta);
  }
  if(0 != result){
    return result;
  }
  s3_realpath = get_realpath(strpath.c_str());

  struct passwd* pwdata= getpwuid(uid);
  struct group* grdata = getgrgid(gid);
  if(pwdata){
    uid = pwdata->pw_uid;
  }
  if(grdata){
    gid = grdata->gr_gid;
  }

  if(S_ISDIR(stbuf.st_mode)){
    if(0 == nIsNewDirType){
      // directory object of old version
      // Need to remove old dir("dir") and make new dir("dir/")

      // At first, remove directory old object
      if(0 != (result = curl_delete(s3_realpath.c_str()))){
        return result;
      }
      StatCache::getStatCacheData()->DelStat(strpath);

      // Make new directory object("dir/")
      if(0 != (result = create_directory_object(strpath.c_str(), stbuf.st_mode, stbuf.st_mtime, uid, gid))){
        return result;
      }
    }else{
      // directory object of new version
      // Over put directory object.
      if(0 != (result = create_directory_object(strpath.c_str(), stbuf.st_mode, stbuf.st_mtime, uid, gid))){
        return result;
      }
      StatCache::getStatCacheData()->DelStat(strpath);
    }
  }else{
    // normal object or directory object of newer version
    int fd;
    int isclose = 1;

    // Downloading
    if(0 > (fd = get_opened_fd(strpath.c_str()))){
      if(0 > (fd = get_local_fd(strpath.c_str()))){
        FGPRINT("  s3fs_chown_nocopy line %d: get_local_fd result: %d\n", __LINE__, fd);
        SYSLOGERR("s3fs_chown_nocopy line %d: get_local_fd result: %d", __LINE__, fd);
        return -EIO;
      }
    }else{
      isclose = 0;
    }

    // Change owner
    meta["x-amz-meta-uid"] = str(uid);
    meta["x-amz-meta-gid"] = str(gid);

    // Change local file owner
    if(-1 == fchown(fd, uid, gid)){
      if(isclose){
        close(fd);
      }
      FGPRINT("  s3fs_chown_nocopy line %d: fchown(fd=%d, uid=%d, gid=%d) is error(%d)\n", __LINE__, fd, (int)uid, (int)gid, errno);
      SYSLOGERR("s3fs_chown_nocopy line %d: fchown(fd=%d, uid=%d, gid=%d) is error(%d)", __LINE__, fd, (int)uid, (int)gid, errno);
      return -errno;
    }

    // Re-uploading
    if(0 != (result = put_local_fd(strpath.c_str(), meta, fd))){
      FGPRINT("  s3fs_chown_nocopy line %d: put_local_fd result: %d\n", __LINE__, result);
    }
    if(isclose){
      close(fd);
    }
    StatCache::getStatCacheData()->DelStat(strpath);
  }

  return result;
}

static int s3fs_truncate(const char *path, off_t size) {
  int fd = -1;
  int result;
  headers_t meta;
  int isclose = 1;

  FGPRINT("s3fs_truncate[path=%s][size=%zd]\n", path, size);

  if(0 != (result = check_parent_object_access(path, X_OK))){
    return result;
  }     
  if(0 != (result = check_object_access(path, W_OK, NULL))){
    return result;
  }

  // Get file information
  if(0 == (result = get_object_attribute(path, NULL, &meta))){
    // Exists -> Get file
    if(0 > (fd = get_opened_fd(path))){
      if(0 > (fd = get_local_fd(path))){
        FGPRINT("  s3fs_truncate line %d: get_local_fd result: %d\n", __LINE__, fd);
        SYSLOGERR("s3fs_truncate line %d: get_local_fd result: %d", __LINE__, fd);
        return -EIO;
      }
    }else{
      isclose = 0;
    }
  }else{
    // Not found -> Make tmpfile
    if(-1 == (fd = fileno(tmpfile()))){
      SYSLOGERR("error: line %d: %d", __LINE__, -errno);
      return -errno;
    }
  }

  // Truncate
  if(0 != ftruncate(fd, size) || 0 != fsync(fd)){
    FGPRINT("  s3fs_truncate line %d: ftruncate or fsync returned err(%d)\n", __LINE__, errno);
    SYSLOGERR("s3fs_truncate line %d: ftruncate or fsync returned err(%d)", __LINE__, errno);
    if(isclose){
      close(fd);
    }
    return -errno;
  }

  // Re-uploading
  if(0 != (result = put_local_fd(path, meta, fd))){
    FGPRINT("  s3fs_truncate line %d: put_local_fd result: %d\n", __LINE__, result);
  }
  if(isclose){
    close(fd);
  }
  StatCache::getStatCacheData()->DelStat(path);

  return result;
}

static int s3fs_open(const char *path, struct fuse_file_info *fi) {
  int result;
  headers_t meta;

  FGPRINT("s3fs_open[path=%s][flags=%d]\n", path, fi->flags);

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

  // Go do the truncation if called for
  if((unsigned int)fi->flags & O_TRUNC) {
     result = s3fs_truncate(path, 0);
     if(result != 0)
        return result;
  }

  if((fi->fh = get_local_fd(path)) <= 0)
    return -EIO;

  // remember flags and headers...
  pthread_mutex_lock( &s3fs_descriptors_lock );
  s3fs_descriptors[fi->fh] = fi->flags;
  s3fs_pathtofd[string(path)] = fi->fh;
  pthread_mutex_unlock( &s3fs_descriptors_lock );

  return 0;
}

static int s3fs_read(
    const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
  int res;

  FGPRINT("s3fs_read[path=%s]\n", path);

  res = pread(fi->fh, buf, size, offset);
  if(res == -1)
    YIKES(-errno);

  return res;
}

static int s3fs_write(
    const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
  int res = pwrite(fi->fh, buf, size, offset);

  // Commented - This message is output too much
//FGPRINT("s3fs_write[path=%s]\n", path);

  if(res == -1)
    YIKES(-errno);

  return res;
}

static int s3fs_statfs(const char *path, struct statvfs *stbuf) {
  // 256T
  stbuf->f_bsize  = 0X1000000;
  stbuf->f_blocks = 0X1000000;
  stbuf->f_bfree  = 0x1000000;
  stbuf->f_bavail = 0x1000000;
  stbuf->f_namemax = NAME_MAX;
  return 0;
}

static int get_flags(int fd) {
  int flags;
  pthread_mutex_lock( &s3fs_descriptors_lock );
  flags = s3fs_descriptors[fd];
  pthread_mutex_unlock( &s3fs_descriptors_lock );
  return flags;
}

static int s3fs_flush(const char *path, struct fuse_file_info *fi) {
  int flags;
  int result;
  int fd = fi->fh;

  FGPRINT("s3fs_flush[path=%s][fd=%d]\n", path, fd);

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

  // NOTE- fi->flags is not available here
  flags = get_flags(fd);
  if(O_RDONLY != (flags & O_ACCMODE)) {
    headers_t meta;
    if(0 != (result = get_object_attribute(path, NULL, &meta))){
      return result;
    }

    // if the cached file matches the remote file skip uploading
    struct stat st;
    if((fstat(fd, &st)) == -1)
      YIKES(-errno);

    if(str(st.st_size) == meta["Content-Length"] &&
      (str(st.st_mtime) == meta["x-amz-meta-mtime"])) {
      return result;
    }

    // If both mtime are not same, force to change mtime based on fd.
    if(str(st.st_mtime) != meta["x-amz-meta-mtime"]){
      meta["x-amz-meta-mtime"] = str(st.st_mtime);
    }

    return put_local_fd(path, meta, fd);
  }

  return 0;
}

static int s3fs_release(const char *path, struct fuse_file_info *fi)
{
  FGPRINT("s3fs_release[path=%s][fd=%ld]\n", path, fi->fh);

  // clear file discriptor mapping.
  s3fs_pathtofd_t::iterator it;
  pthread_mutex_lock( &s3fs_descriptors_lock );
  if(s3fs_pathtofd.end() != (it = s3fs_pathtofd.find(string(path)))){
    if(fi->fh == (uint)s3fs_pathtofd[string(path)]){
      s3fs_pathtofd.erase(it);
    }else{
      FGPRINT("s3fs_release line %d: file discriptor is not same(%d : %d)\n", __LINE__, (int)fi->fh, s3fs_pathtofd[string(path)]);
    }
  }
  pthread_mutex_unlock( &s3fs_descriptors_lock );

  if(close(fi->fh) == -1){
    YIKES(-errno);
  }
  if((fi->flags & O_RDWR) || (fi->flags & O_WRONLY)){
    StatCache::getStatCacheData()->DelStat(path);
  }

  return 0;
}

static int s3fs_opendir(const char *path, struct fuse_file_info *fi)
{
  int result;
  int mask = (O_RDONLY != (fi->flags & O_ACCMODE) ? W_OK : R_OK) | X_OK;

  FGPRINT("s3fs_opendir [path=%s][flags=%d]\n", path, fi->flags);

  if(0 == (result = check_object_access(path, mask, NULL))){
    result = check_parent_object_access(path, mask);
  }
  return result;
}

static int s3fs_readdir(
    const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi) {
  CURLM *mh;
  CURLMsg *msg;
  CURLMcode curlm_code;
  int n_reqs;
  int remaining_messages;
  struct s3_object *head    = NULL;
  struct s3_object *headref = NULL;
  auto_head curl_map;

  FGPRINT("s3fs_readdir[path=%s]\n", path);

  int result;
  if(0 != (result = check_object_access(path, X_OK, NULL))){
    return result;
  }

  // get a list of all the objects
  if((result = list_bucket(path, &head, "/")) != 0){
    FGPRINT(" s3fs_readdir list_bucket returns error.\n");
    return result;
  }

  // force to add "." and ".." name.
  filler(buf, ".", 0, 0);
  filler(buf, "..", 0, 0);
  if(!head){
    return 0;
  }

  // populate fuse buffer
  for(headref = head; headref; headref = headref->next){
    int nLen = strlen(headref->name);
    if(2 <= nLen && '/' == headref->name[nLen - 1]){
      // cut for last '/' charactor
      char* ptmp = strdup(headref->name);
      ptmp[nLen - 1] = '\0';
      filler(buf, ptmp, 0, 0);
      free(ptmp);
    }else{
      filler(buf, headref->name, 0, 0);
    }
  }
  headref = head;

  // populate the multi interface with an initial set of requests
  n_reqs = 0;
  mh = curl_multi_init();
  int still_running = 0;

  do{
    // Add curl handle to multi session.
    while(n_reqs < MAX_REQUESTS && head != NULL) {
      string fullpath = path;
      if(strcmp(path, "/") != 0){
        fullpath += "/" + string(head->name);
      }else{
        fullpath += string(head->name);
      }
      if(StatCache::getStatCacheData()->HasStat(fullpath, head->etag)) {
        head = head->next;
        continue;
      }

      // file not cached, prepare a call to get_headers
      head_data request_data;
      request_data.path = fullpath;
      CURL *curl_handle = create_head_handle(&request_data);
      curl_map.get()[curl_handle] = request_data;

      // add this handle to the multi handle
      n_reqs++;
      curlm_code = curl_multi_add_handle(mh, curl_handle);
      if(curlm_code != CURLM_OK) {
        SYSLOGERR("readdir: curl_multi_add_handle code: %d msg: %s", 
            curlm_code, curl_multi_strerror(curlm_code));

        curl_multi_cleanup(mh);
        free_object_list(headref);
        return -EIO;
      }
      // go to the next object.
      head = head->next;
    }

    // Start making requests and check running.
    still_running = 0;
    do {
      curlm_code = curl_multi_perform(mh, &still_running);
    } while(curlm_code == CURLM_CALL_MULTI_PERFORM);

    if(curlm_code != CURLM_OK) {
      SYSLOGERR("readdir: curl_multi_perform code: %d msg: %s", 
          curlm_code, curl_multi_strerror(curlm_code));
    }

    // Set timer when still running
    if(still_running) {
      fd_set r_fd;
      fd_set w_fd;
      fd_set e_fd;
      FD_ZERO(&r_fd);
      FD_ZERO(&w_fd);
      FD_ZERO(&e_fd);

      long milliseconds;
      curlm_code = curl_multi_timeout(mh, &milliseconds);
      if(curlm_code != CURLM_OK) {
        SYSLOGERR("readdir: curl_multi_perform code: %d msg: %s", 
            curlm_code, curl_multi_strerror(curlm_code));
      }

      if(milliseconds < 0)
        milliseconds = 50;
      if(milliseconds > 0) {
        struct timeval timeout;
        timeout.tv_sec  = 1000 * milliseconds / 1000000;
        timeout.tv_usec = 1000 * milliseconds % 1000000;

        int max_fd;
        curlm_code = curl_multi_fdset(mh, &r_fd, &w_fd, &e_fd, &max_fd);
        if(curlm_code != CURLM_OK) {
          SYSLOGERR("readdir: curl_multi_fdset code: %d msg: %s", 
              curlm_code, curl_multi_strerror(curlm_code));

          curl_multi_cleanup(mh);
          free_object_list(headref);
          return -EIO;
        }

        if(select(max_fd + 1, &r_fd, &w_fd, &e_fd, &timeout) == -1){
          curl_multi_cleanup(mh);
          free_object_list(headref);
          YIKES(-errno);
        }
      }
    }

    // Read the result
    while((msg = curl_multi_info_read(mh, &remaining_messages))) {
      if(msg->msg != CURLMSG_DONE) {
        SYSLOGERR("readdir: curl_multi_add_handle code: %d msg: %s", 
            curlm_code, curl_multi_strerror(curlm_code));

        curl_multi_cleanup(mh);
        free_object_list(headref);
        return -EIO;
      }

      CURLcode code = msg->data.result;
      if(code != 0) {
        SYSLOGERR("s3fs_readdir: remaining_msgs: %i code: %d  msg: %s", 
            remaining_messages, code, curl_easy_strerror(code));

        curl_multi_cleanup(mh);
        free_object_list(headref);
        return -EIO;
      }

      CURL *curl_handle = msg->easy_handle;
      head_data response= curl_map.get()[curl_handle];
      long responseCode = -1;
      if(CURLE_OK != curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &responseCode) || 400 <= responseCode){
        curl_multi_remove_handle(mh, curl_handle);
        curl_map.remove(curl_handle);
        n_reqs--;
        continue;
      }

      // add into stat cache
      if(!StatCache::getStatCacheData()->AddStat(response.path, (*response.responseHeaders))){
        FGPRINT("s3fs_readdir: failed adding stat cache [path=%s]\n", response.path.c_str());
      }

      // cleanup
      curl_multi_remove_handle(mh, curl_handle);
      curl_map.remove(curl_handle);
      n_reqs--;
    }
  }while(still_running || head);

  curl_multi_cleanup(mh);
  free_object_list(headref);

  return 0;
}

static int list_bucket(const char *path, struct s3_object **head, const char* delimiter) {
  CURL *curl;
  int result; 
  string s3_realpath;
  BodyData body;
  bool truncated = true;
  string next_marker = "";

  FGPRINT("list_bucket [path=%s]\n", path);

  s3_realpath = get_realpath(path);
  string resource = urlEncode(service_path + bucket); // this is what gets signed
  string query;
  if(delimiter && 0 < strlen(delimiter)){
    query += "delimiter=";
    query += delimiter;
    query += "&";
  }
  query += "prefix=";

  if(0 == s3_realpath.length() || '/' != s3_realpath[s3_realpath.length() - 1]){
    // last word must be "/"
    query += urlEncode(s3_realpath.substr(1) + "/");
  }else{
    query += urlEncode(s3_realpath.substr(1));
  }
  query += "&max-keys=1000";

  while(truncated) {
    string url = host + resource + "?" + query;

    if(next_marker != ""){
      url += "&marker=" + urlEncode(next_marker);
      next_marker = "";
    }

    string my_url = prepare_url(url.c_str());

    auto_curl_slist headers;
    string date = get_date();
    headers.append("Date: " + date);
    headers.append("ContentType: ");
    if(public_bucket.substr(0,1) != "1") {
      headers.append("Authorization: AWS " + AWSAccessKeyId + ":" +
        calc_signature("GET", "", date, headers.get(), resource + "/"));
    }

    curl = create_curl_handle();
    curl_easy_setopt(curl, CURLOPT_URL, my_url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *) &body);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers.get());

    result = my_curl_easy_perform(curl, &body);
    destroy_curl_handle(curl);

    if(result != 0) {
      FGPRINT("  list_bucket my_curl_easy_perform returns with error.\n");
      return result;
    }
    if((append_objects_from_xml(path, body.str(), head)) != 0) {
      FGPRINT("  list_bucket append_objects_from_xml returns with error.\n");
      return -1;
    }

    truncated = is_truncated(body.str());
    if(truncated){
      xmlChar*	tmpch = get_next_marker(body.str());
      if(tmpch){
        next_marker = (char*)tmpch;
        xmlFree(tmpch);
      }
    }
    body.Clear();
  }

  return 0;
}

const char* c_strErrorObjectName = "FILE or SUBDIR in DIR";

static int append_objects_from_xml_ex(const char* path, xmlDocPtr doc, xmlXPathContextPtr ctx, 
       const char* ex_contents, const char* ex_key, const char* ex_etag, int isCPrefix, struct s3_object **head)
{
  xmlXPathObjectPtr contents_xp;
  xmlNodeSetPtr content_nodes;

  contents_xp = xmlXPathEvalExpression((xmlChar*)ex_contents, ctx);
  content_nodes = contents_xp->nodesetval;

  int i;
  for(i = 0; i < content_nodes->nodeNr; i++) {
    ctx->node = content_nodes->nodeTab[i];

    // object name
    xmlXPathObjectPtr key = xmlXPathEvalExpression((xmlChar*)ex_key, ctx);
    xmlNodeSetPtr key_nodes = key->nodesetval;
    char *name = get_object_name(doc, key_nodes->nodeTab[0]->xmlChildrenNode, path);

    if(!name){
      FGPRINT("  append_objects_from_xml_ex name is something wrong. but continue.\n");

    }else if((const char*)name != c_strErrorObjectName){
      string stretag = "";
      string objname = name;
      free(name);
      if(isCPrefix){
        objname += "/";
      }
      if(!isCPrefix && ex_etag){
        // Get ETag
        xmlXPathObjectPtr ETag   = xmlXPathEvalExpression((xmlChar*)ex_etag, ctx);
        xmlNodeSetPtr etag_nodes = ETag->nodesetval;
        xmlChar* petag           = xmlNodeListGetString(doc, etag_nodes->nodeTab[0]->xmlChildrenNode, 1);
        stretag                  = (char*)petag;
        xmlFree(petag);
        xmlXPathFreeObject(ETag);
      }
      if(0 != insert_object(objname.c_str(), (0 < stretag.length() ? stretag.c_str() : NULL), head)){
        FGPRINT("  append_objects_from_xml_ex insert_object returns with error.\n");
        xmlXPathFreeObject(key);
        xmlXPathFreeObject(contents_xp);
        return -1;
      }
    }else{
      //FGPRINT("append_objects_from_xml_ex name is file or subdir in dir. but continue.\n");
    }
    xmlXPathFreeObject(key);
  }
  xmlXPathFreeObject(contents_xp);

  return 0;
}

static bool GetXmlNsUrl(xmlDocPtr doc, string& nsurl)
{
  bool result = false;

  if(!doc){
    return result;
  }
  xmlNodePtr pRootNode = xmlDocGetRootElement(doc);
  if(pRootNode){
    xmlNsPtr* nslist = xmlGetNsList(doc, pRootNode);
    if(nslist && nslist[0]){
      if(nslist[0]->href){
        nsurl  = (const char*)(nslist[0]->href);
        result = true;
      }
      xmlFree(nslist);
    }
  }
  return result;
}

static int append_objects_from_xml(const char* path, const char *xml, struct s3_object **head) {
  xmlDocPtr doc;
  xmlXPathContextPtr ctx;
  string xmlnsurl;
  string ex_contents = "//";
  string ex_key      = "";
  string ex_cprefix  = "//";
  string ex_prefix   = "";
  string ex_etag     = "";

  // If there is not <Prefix>, use path instead of it.
  xmlChar* pprefix = get_prefix(xml);
  string prefix = (pprefix ? (char*)pprefix : path ? path : "");
  xmlFree(pprefix);

  doc = xmlReadMemory(xml, strlen(xml), "", NULL, 0);
  if(doc == NULL){
    FGPRINT("  append_objects_from_xml xmlReadMemory returns with error.\n");
    return -1;
  }
  ctx = xmlXPathNewContext(doc);

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
    FGPRINT("  append_objects_from_xml append_objects_from_xml_ex returns with error.\n");
    xmlXPathFreeContext(ctx);
    xmlFreeDoc(doc);
    return -1;
  }
  xmlXPathFreeContext(ctx);
  xmlFreeDoc(doc);

  return 0;
}

static xmlChar* get_base_exp(const char* xml, const char* exp) {
  xmlDocPtr doc;
  xmlXPathContextPtr ctx;
  xmlXPathObjectPtr marker_xp;
  xmlNodeSetPtr nodes;
  xmlChar* result;
  string xmlnsurl;
  string exp_string = "//";

  doc = xmlReadMemory(xml, strlen(xml), "", NULL, 0);
  ctx = xmlXPathNewContext(doc);

  if(!noxmlns && GetXmlNsUrl(doc, xmlnsurl)){
    xmlXPathRegisterNs(ctx, (xmlChar*)"s3", (xmlChar*)xmlnsurl.c_str());
    exp_string += "s3:";
  }
  exp_string += exp;

  marker_xp = xmlXPathEvalExpression((xmlChar *)exp_string.c_str(), ctx);
  nodes = marker_xp->nodesetval;

  if(nodes->nodeNr < 1)
    return NULL;

  result = xmlNodeListGetString(doc, nodes->nodeTab[0]->xmlChildrenNode, 1);

  xmlXPathFreeObject(marker_xp);
  xmlXPathFreeContext(ctx);
  xmlFreeDoc(doc);

  return result;
}

static xmlChar* get_prefix(const char *xml) {
  return get_base_exp(xml, "Prefix");
}

static xmlChar* get_next_marker(const char *xml) {
  return get_base_exp(xml, "NextMarker");
}

static bool is_truncated(const char *xml) {
  if(strstr(xml, "<IsTruncated>true</IsTruncated>"))
    return true;

  return false;
}

// return: the pointer to object name on allocated memory.
//         the pointer to "c_strErrorObjectName".(not allocated)
//         NULL(a case of something error occured)
static char *get_object_name(xmlDocPtr doc, xmlNodePtr node, const char* path)
{
  // Get full path
  xmlChar*    fullpath= xmlNodeListGetString(doc, node, 1);
  if(!fullpath){
    FGPRINT("  get_object_name could not get object full path name..\n");
    return NULL;
  }
  // basepath(path) is as same as fullpath.
  if(0 == strcmp((char*)fullpath, path)){
    xmlFree(fullpath);
    return (char*)c_strErrorObjectName;
  }

  // Make dir path and filename
  string   strfullpath= (char*)fullpath;
  string   strdirpath = mydirname((char*)fullpath);
  string   strmybpath = mybasename((char*)fullpath);
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

static int remote_mountpath_exists(const char *path) {
  struct stat stbuf;

  FGPRINT("remote_mountpath_exists [path=%s]\n", path);

  // getattr will prefix the path with the remote mountpoint
  if(0 != get_object_attribute("", &stbuf, NULL)){
    return -1;
  }
  if(!S_ISDIR(stbuf.st_mode)){
    return -1;
  }
  return 0;
}

/**
 * OpenSSL locking function.
 *
 * @param    mode    lock mode
 * @param    n        lock number
 * @param    file    source file name
 * @param    line    source file line number
 * @return    none
 */
static void locking_function(int mode, int n, const char *file, int line) {
  if(mode & CRYPTO_LOCK)
    pthread_mutex_lock(&mutex_buf[n]);
  else
    pthread_mutex_unlock(&mutex_buf[n]);
}

// OpenSSL uniq thread id function.
static unsigned long id_function(void) {
  return((unsigned long) pthread_self());
}

static void* s3fs_init(struct fuse_conn_info *conn)
{
  SYSLOGINFO("init $Rev$");
  FGPRINT("s3fs_init\n");

  // openssl
  mutex_buf = static_cast<pthread_mutex_t*>(malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t)));
  for (int i = 0; i < CRYPTO_num_locks(); i++){
    pthread_mutex_init(&mutex_buf[i], NULL);
  }
  CRYPTO_set_locking_callback(locking_function);
  CRYPTO_set_id_callback(id_function);
  curl_global_init(CURL_GLOBAL_ALL);
  pthread_mutex_init(&s3fs_descriptors_lock, NULL);
  init_curl_handles_mutex();
  InitMimeType("/etc/mime.types");

  // Investigate system capabilities
  if((unsigned int)conn->capable & FUSE_CAP_ATOMIC_O_TRUNC){
     conn->want |= FUSE_CAP_ATOMIC_O_TRUNC;
  }
  return 0;
}

static void s3fs_destroy(void*)
{
  SYSLOGDBG("destroy");
  FGPRINT("s3fs_destroy\n");

  // openssl
  CRYPTO_set_id_callback(NULL);
  CRYPTO_set_locking_callback(NULL);
  for(int i = 0; i < CRYPTO_num_locks(); i++){
    pthread_mutex_destroy(&mutex_buf[i]);
  }
  free(mutex_buf);
  mutex_buf = NULL;
  curl_global_cleanup();
  pthread_mutex_destroy(&s3fs_descriptors_lock);
  destroy_curl_handles_mutex();
}

static int s3fs_access(const char *path, int mask)
{
  FGPRINT("s3fs_access[path=%s][mask=%s%s%s%s]\n", path,
          ((mask & R_OK) == R_OK) ? "R_OK " : "",
          ((mask & W_OK) == W_OK) ? "W_OK " : "",
          ((mask & X_OK) == X_OK) ? "X_OK " : "",
          (mask == F_OK) ? "F_OK" : "");

    return check_object_access(path, mask, NULL);
}

static int s3fs_utimens(const char *path, const struct timespec ts[2]) {
  int result;
  string s3_realpath;
  string strpath;
  headers_t meta;
  struct stat stbuf;
  int nIsNewDirType = 1;

  FGPRINT("s3fs_utimens[path=%s][mtime=%zd]\n", path, ts[1].tv_sec);

  if(0 != (result = check_parent_object_access(path, X_OK))){
    return result;
  }
  if(0 != (result = check_object_owner(path, &stbuf))){
    return result;
  }

  if(S_ISDIR(stbuf.st_mode)){
    result = -1;
    if(0 < strlen(path) && '/' != path[strlen(path) - 1]){
      strpath = path;
      strpath += "/";
      result = get_object_attribute(strpath.c_str(), NULL, &meta, false);
    }
    if(0 != result){
      // Need to chack old type directory("dir").
      strpath = path;
      result = get_object_attribute(strpath.c_str(), NULL, &meta, false);
      if(0 < strpath.length() && '/' == strpath[strpath.length() - 1]){
        nIsNewDirType = 0;
      }
    }
  }else{
    strpath = path;
    result = get_object_attribute(strpath.c_str(), NULL, &meta);
  }
  if(0 != result){
    return result;
  }
  s3_realpath = get_realpath(strpath.c_str());

  if(S_ISDIR(stbuf.st_mode) && 0 == nIsNewDirType){
    // directory object of old version
    // Need to remove old dir("dir") and make new dir("dir/")

    // At first, remove directory old object
    if(0 != (result = curl_delete(s3_realpath.c_str()))){
      return result;
    }
    StatCache::getStatCacheData()->DelStat(strpath);

    // Make new directory object("dir/")
    if(0 != (result = create_directory_object(strpath.c_str(), stbuf.st_mode, ts[1].tv_sec, stbuf.st_uid, stbuf.st_gid))){
      return result;
    }
  }else{
    meta["x-amz-meta-mtime"] = str(ts[1].tv_sec);
    meta["x-amz-copy-source"] = urlEncode("/" + bucket + s3_realpath);
    meta["x-amz-metadata-directive"] = "REPLACE";

    if(put_headers(strpath.c_str(), meta) != 0){
      return -EIO;
    }
    StatCache::getStatCacheData()->DelStat(strpath);
  }

  return 0;
}

static int s3fs_utimens_nocopy(const char *path, const struct timespec ts[2]) {
  int result;
  string s3_realpath;
  string strpath;
  headers_t meta;
  struct stat stbuf;
  int nIsNewDirType = 1;

  FGPRINT("s3fs_utimens_nocopy [path=%s][mtime=%s]\n", path, str(ts[1].tv_sec).c_str());

  if(0 != (result = check_parent_object_access(path, X_OK))){
    return result;
  }
  if(0 != (result = check_object_owner(path, &stbuf))){
    return result;
  }

  // Get attributes
  if(S_ISDIR(stbuf.st_mode)){
    result = -1;
    if(0 < strlen(path) && '/' != path[strlen(path) - 1]){
      strpath = path;
      strpath += "/";
      result = get_object_attribute(strpath.c_str(), NULL, &meta, false);
    }
    if(0 != result){
      // Need to chack old type directory("dir").
      strpath = path;
      result = get_object_attribute(strpath.c_str(), NULL, &meta, false);
      if(0 < strpath.length() && '/' == strpath[strpath.length() - 1]){
        nIsNewDirType = 0;
      }
    }
  }else{
    strpath = path;
    result = get_object_attribute(strpath.c_str(), NULL, &meta);
  }
  if(0 != result){
    return result;
  }
  s3_realpath = get_realpath(strpath.c_str());

  if(S_ISDIR(stbuf.st_mode)){
    if(0 == nIsNewDirType){
      // directory object of old version
      // Need to remove old dir("dir") and make new dir("dir/")

      // At first, remove directory old object
      if(0 != (result = curl_delete(s3_realpath.c_str()))){
        return result;
      }
      StatCache::getStatCacheData()->DelStat(strpath);

      // Make new directory object("dir/")
      if(0 != (result = create_directory_object(strpath.c_str(), stbuf.st_mode, ts[1].tv_sec, stbuf.st_uid, stbuf.st_gid))){
        return result;
      }
    }else{
      // directory object of new version
      // Over put directory object.
      if(0 != (result = create_directory_object(strpath.c_str(), stbuf.st_mode, ts[1].tv_sec, stbuf.st_uid, stbuf.st_gid))){
        return result;
      }
      StatCache::getStatCacheData()->DelStat(strpath);
    }
  }else{
    // normal object or directory object of newer version
    int fd;
    int isclose = 1;
    struct timeval tv[2];

    // Downloading
    if(0 > (fd = get_opened_fd(strpath.c_str()))){
      if(0 > (fd = get_local_fd(strpath.c_str()))){
        FGPRINT("  s3fs_utimens_nocopy line %d: get_local_fd result: %d\n", __LINE__, fd);
        SYSLOGERR("s3fs_utimens_nocopy line %d: get_local_fd result: %d", __LINE__, fd);
        return -EIO;
      }
    }else{
      isclose = 0;
    }

    // Change date
    meta["x-amz-meta-mtime"] = str(ts[1].tv_sec);

    // Change local file date
    TIMESPEC_TO_TIMEVAL(&tv[0], &ts[0]);
    TIMESPEC_TO_TIMEVAL(&tv[1], &ts[1]);
    if(-1 == futimes(fd, tv)){
      if(isclose){
        close(fd);
      }
      FGPRINT("  s3fs_utimens_nocopy line %d: futimes(fd=%d, ...) is error(%d)\n", __LINE__, fd, errno);
      SYSLOGERR("s3fs_utimens_nocopy line %d: futimes(fd=%d, ...) is error(%d)", __LINE__, fd, errno);
      return -errno;
    }

    // Re-uploading
    if(0 != (result = put_local_fd(strpath.c_str(), meta, fd))){
      FGPRINT("  s3fs_utimens_nocopy line %d: put_local_fd result: %d\n", __LINE__, result);
    }
    if(isclose){
      close(fd);
    }
    StatCache::getStatCacheData()->DelStat(strpath);
  }

  return result;
}

static int s3fs_check_service(void) {
  CURL *curl = NULL;
  int result = CURLE_OK;
  CURLcode responseCode;
  BodyData body;

  FGPRINT("s3fs_check_service\n");

  string resource = urlEncode(service_path + bucket);
  string url = host + resource;

  auto_curl_slist headers;
  string date = get_date();
  headers.append("Date: " + date);
  if (public_bucket.substr(0,1) != "1") {
    headers.append("Authorization: AWS " + AWSAccessKeyId + ":" +
      calc_signature("GET", "", date, headers.get(), resource));
  } else {
     return EXIT_SUCCESS;
  }

  curl = create_curl_handle();
  curl_easy_setopt(curl, CURLOPT_FAILONERROR, true);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&body);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers.get());
  result = my_curl_easy_perform(curl, &body);

  // connect either successful or too many timeouts
  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &responseCode);

  if(responseCode == 403) {
    destroy_curl_handle(curl);
    fprintf(stderr, "%s: invalid credentials\n", program_name.c_str());
    return EXIT_FAILURE;
  }

  if(responseCode == 404) {
    destroy_curl_handle(curl);
    fprintf(stderr, "%s: bucket not found\n", program_name.c_str());
    return EXIT_FAILURE;
  }

  // unable to connect
  if(responseCode == CURLE_OPERATION_TIMEDOUT) {
    destroy_curl_handle(curl);
    return EXIT_SUCCESS;
  }

  if(responseCode != 200 && responseCode != 301) {
    SYSLOGDBG("responseCode: %i\n", (int)responseCode);
    destroy_curl_handle(curl);
    fprintf(stderr, "%s: unable to connect\n", program_name.c_str());
    return EXIT_FAILURE;
  }

  // make sure remote mountpath exists and is a directory
  if(mount_prefix.size() > 0) {
    if(remote_mountpath_exists(mount_prefix.c_str()) != 0) {
      fprintf(stderr, "%s: remote mountpath %s not found.\n", 
          program_name.c_str(), mount_prefix.c_str());

      destroy_curl_handle(curl);
      return EXIT_FAILURE;
    }
  }

  // success
  service_validated = true;
  destroy_curl_handle(curl);

  return EXIT_SUCCESS;
}

// Return:  1 - OK(could read and set accesskey etc.)
//          0 - NG(could not read)
//         -1 - Should shoutdown immidiatly
static int check_for_aws_format (void) {
  size_t first_pos = string::npos;
  string line;
  bool got_access_key_id_line = 0;
  bool got_secret_key_line = 0;
  string str1 ("AWSAccessKeyId=");
  string str2 ("AWSSecretKey=");
  size_t found;


  ifstream PF(passwd_file.c_str());
  if (PF.good()) {
    while (getline(PF, line)) {
      if(line[0]=='#')
        continue;
      if(line.size() == 0)
        continue;

      first_pos = line.find_first_of(" \t");
      if (first_pos != string::npos) {
        printf ("%s: invalid line in passwd file, found whitespace character\n", 
           program_name.c_str());
        return -1;
      }

      first_pos = line.find_first_of("[");
      if (first_pos != string::npos && first_pos == 0) {
        printf ("%s: invalid line in passwd file, found a bracket \"[\" character\n", 
           program_name.c_str());
        return -1;
      }

      found = line.find(str1);
      if (found != string::npos) {
         first_pos = line.find_first_of("=");
         AWSAccessKeyId = line.substr(first_pos + 1, string::npos);
         got_access_key_id_line = 1;
         continue;
      }

      found = line.find(str2);
      if (found != string::npos) {
         first_pos = line.find_first_of("=");
         AWSSecretAccessKey = line.substr(first_pos + 1, string::npos);
         got_secret_key_line = 1;
         continue;
      }
    }
  }

  if(got_access_key_id_line && got_secret_key_line)
     return 1;
  else
     return 0;
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
static int check_passwd_file_perms (void) {
  struct stat info;

  // let's get the file info
  if (stat(passwd_file.c_str(), &info) != 0) {
    fprintf (stderr, "%s: unexpected error from stat(%s, ) \n", 
        program_name.c_str(), passwd_file.c_str());
    return EXIT_FAILURE;
  } 

  // return error if any file has others permissions 
  if ((info.st_mode & S_IROTH) ||
      (info.st_mode & S_IWOTH) || 
      (info.st_mode & S_IXOTH))  {
    fprintf (stderr, "%s: credentials file %s should not have others permissions\n", 
        program_name.c_str(), passwd_file.c_str());
    return EXIT_FAILURE;
  }

  // Any local file should not have any group permissions 
  // /etc/passwd-s3fs can have group permissions 
  if (passwd_file != "/etc/passwd-s3fs") {
    if ((info.st_mode & S_IRGRP) ||
        (info.st_mode & S_IWGRP) || 
        (info.st_mode & S_IXGRP))  {
      fprintf (stderr, "%s: credentials file %s should not have group permissions\n", 
        program_name.c_str(), passwd_file.c_str());
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
static int read_passwd_file (void) {
  string line;
  string field1, field2, field3;
  size_t first_pos = string::npos;
  size_t last_pos = string::npos;
  bool default_found = 0;
  bool aws_format;

  // if you got here, the password file
  // exists and is readable by the
  // current user, check for permissions
  check_passwd_file_perms();

  aws_format = check_for_aws_format();
  if(1 == aws_format){
     return EXIT_SUCCESS;
  }else if(-1 == aws_format){
     return EXIT_FAILURE;
  }

  ifstream PF(passwd_file.c_str());
  if (PF.good()) {
    while (getline(PF, line)) {
      if (line[0]=='#') {
        continue;
      }
      if (line.size() == 0) {
        continue;
      }

      first_pos = line.find_first_of(" \t");
      if (first_pos != string::npos) {
        printf ("%s: invalid line in passwd file, found whitespace character\n", 
           program_name.c_str());
        return EXIT_FAILURE;
      }

      first_pos = line.find_first_of("[");
      if (first_pos != string::npos && first_pos == 0) {
        printf ("%s: invalid line in passwd file, found a bracket \"[\" character\n", 
           program_name.c_str());
        return EXIT_FAILURE;
      }

      first_pos = line.find_first_of(":");
      if (first_pos == string::npos) {
        printf ("%s: invalid line in passwd file, no \":\" separator found\n", 
           program_name.c_str());
        return EXIT_FAILURE;
      }
      last_pos = line.find_last_of(":");

      if (first_pos != last_pos) {
        // bucket specified
        field1 = line.substr(0,first_pos);
        field2 = line.substr(first_pos + 1, last_pos - first_pos - 1);
        field3 = line.substr(last_pos + 1, string::npos);
      } else {
        // no bucket specified - original style - found default key
        if (default_found == 1) {
          printf ("%s: more than one default key pair found in passwd file\n", 
            program_name.c_str());
          return EXIT_FAILURE;
        }
        default_found = 1;
        field1.assign("");
        field2 = line.substr(0,first_pos);
        field3 = line.substr(first_pos + 1, string::npos);
        AWSAccessKeyId = field2;
        AWSSecretAccessKey = field3;
      }

      // does the bucket we are mounting match this passwd file entry?
      // if so, use that key pair, otherwise use the default key, if found,
      // will be used
      if (field1.size() != 0 && field1 == bucket) {
         AWSAccessKeyId = field2;
         AWSSecretAccessKey = field3;
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
static int get_access_keys (void) {

  // should be redundant
  if (public_bucket.substr(0,1) == "1") {
     return EXIT_SUCCESS;
  }

  // 1 - keys specified on the command line
  if (AWSAccessKeyId.size() > 0 && AWSSecretAccessKey.size() > 0) {
     return EXIT_SUCCESS;
  }

  // 2 - was specified on the command line
  if (passwd_file.size() > 0) {
    ifstream PF(passwd_file.c_str());
    if (PF.good()) {
       PF.close();
       return read_passwd_file();
    } else {
      fprintf(stderr, "%s: specified passwd_file is not readable\n",
              program_name.c_str());
      return EXIT_FAILURE;
    }
  }

  // 3  - environment variables
  char * AWSACCESSKEYID;
  char * AWSSECRETACCESSKEY;

  AWSACCESSKEYID     = getenv("AWSACCESSKEYID");
  AWSSECRETACCESSKEY = getenv("AWSSECRETACCESSKEY");
  if (AWSACCESSKEYID != NULL || AWSSECRETACCESSKEY != NULL) {
    if ((AWSACCESSKEYID == NULL && AWSSECRETACCESSKEY != NULL) ||
        (AWSACCESSKEYID != NULL && AWSSECRETACCESSKEY == NULL) ){

      fprintf(stderr, "%s: if environment variable AWSACCESSKEYID is set then AWSSECRETACCESSKEY must be set too\n",
              program_name.c_str());
      return EXIT_FAILURE;
    }
    AWSAccessKeyId.assign(AWSACCESSKEYID);
    AWSSecretAccessKey.assign(AWSSECRETACCESSKEY);
    return EXIT_SUCCESS;
  }

  // 3a - from the AWS_CREDENTIAL_FILE environment variable
  char * AWS_CREDENTIAL_FILE;
  AWS_CREDENTIAL_FILE = getenv("AWS_CREDENTIAL_FILE");
  if (AWS_CREDENTIAL_FILE != NULL) {
    passwd_file.assign(AWS_CREDENTIAL_FILE);
    if (passwd_file.size() > 0) {
      ifstream PF(passwd_file.c_str());
      if (PF.good()) {
         PF.close();
         return read_passwd_file();
      } else {
        fprintf(stderr, "%s: AWS_CREDENTIAL_FILE: \"%s\" is not readable\n",
                program_name.c_str(), passwd_file.c_str());
        return EXIT_FAILURE;
      }
    }
  }

  // 4 - from the default location in the users home directory
  char * HOME;
  HOME = getenv ("HOME");
  if (HOME != NULL) {
     passwd_file.assign(HOME);
     passwd_file.append("/.passwd-s3fs");
     ifstream PF(passwd_file.c_str());
     if (PF.good()) {
       PF.close();
       if(EXIT_SUCCESS != read_passwd_file()){
         return EXIT_FAILURE;
       }
       // It is possible that the user's file was there but
       // contained no key pairs i.e. commented out
       // in that case, go look in the final location
       if (AWSAccessKeyId.size() > 0 && AWSSecretAccessKey.size() > 0) {
          return EXIT_SUCCESS;
       }
     }
   }

  // 5 - from the system default location
  passwd_file.assign("/etc/passwd-s3fs"); 
  ifstream PF(passwd_file.c_str());
  if (PF.good()) {
    PF.close();
    return read_passwd_file();
  }
  
  fprintf(stderr, "%s: could not determine how to establish security credentials\n",
           program_name.c_str());
  return EXIT_FAILURE;
}

// This is repeatedly called by the fuse option parser
// if the key is equal to FUSE_OPT_KEY_OPT, it's an option passed in prefixed by 
// '-' or '--' e.g.: -f -d -ousecache=/tmp
//
// if the key is equal to FUSE_OPT_KEY_NONOPT, it's either the bucket name 
//  or the mountpoint. The bucket name will always come before the mountpoint
static int my_fuse_opt_proc(void *data, const char *arg, int key, struct fuse_args *outargs) {
  if(key == FUSE_OPT_KEY_NONOPT) {
    // the first NONOPT option is the bucket name
    if(bucket.size() == 0) {
      // extract remote mount path
      char *bucket_name = (char*)arg;
      if(strstr(arg, ":")){
        bucket = strtok(bucket_name, ":");
        char* pmount_prefix = strtok(NULL, ":");
        if(pmount_prefix){
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

    // save the mountpoint and do some basic error checking
    mountpoint = arg;
    struct stat stbuf;

    if(stat(arg, &stbuf) == -1) {
      fprintf(stderr, "%s: unable to access MOUNTPOINT %s: %s\n", 
          program_name.c_str(), mountpoint.c_str(), strerror(errno));
      return -1;
    }

    root_mode = stbuf.st_mode; // save mode for later usage
    
    if(!(S_ISDIR(stbuf.st_mode ))) {
      fprintf(stderr, "%s: MOUNTPOINT: %s is not a directory\n", 
              program_name.c_str(), mountpoint.c_str());
      return -1;
    } 

    struct dirent *ent;
    DIR *dp = opendir(mountpoint.c_str());
    if(dp == NULL) {
      fprintf(stderr, "%s: failed to open MOUNTPOINT: %s: %s\n", 
              program_name.c_str(), mountpoint.c_str(), strerror(errno));
      return -1;
    }

    while((ent = readdir(dp)) != NULL) {
      if(strcmp(ent->d_name, ".") != 0 && strcmp(ent->d_name, "..") != 0) {
        closedir(dp);
        fprintf(stderr, "%s: MOUNTPOINT directory %s is not empty\n", 
                program_name.c_str(), mountpoint.c_str());
        return -1;
      }
    }

    closedir(dp);
  }

  if (key == FUSE_OPT_KEY_OPT) {
    if (strstr(arg, "default_acl=") != 0) {
      default_acl = strchr(arg, '=') + 1;
      return 0;
    }
    if (strstr(arg, "retries=") != 0) {
      retries = atoi(strchr(arg, '=') + 1);
      return 0;
    }
    if (strstr(arg, "use_cache=") != 0) {
      use_cache = strchr(arg, '=') + 1;
      return 0;
    }

    if(strstr(arg, "nomultipart") != 0) {
      nomultipart = true;
      return 0;
    }
    
    if (strstr(arg, "use_rrs=") != 0) {
      use_rrs = strchr(arg, '=') + 1;
      if (strcmp(use_rrs.c_str(), "1") == 0 || 
          strcmp(use_rrs.c_str(), "")  == 0 ) {
        return 0;
      } else {
         fprintf(stderr, "%s: poorly formed argument to option: use_rrs\n", 
                 program_name.c_str());
         return -1;
      }
    }
    if (strstr(arg, "ssl_verify_hostname=") != 0) {
      ssl_verify_hostname = strchr(arg, '=') + 1;
      if (strcmp(ssl_verify_hostname.c_str(), "1") == 0 || 
          strcmp(ssl_verify_hostname.c_str(), "0") == 0 ) { 
        return 0;
      } else {
         fprintf(stderr, "%s: poorly formed argument to option: ssl_verify_hostname\n", 
                 program_name.c_str());
         return -1;
      }
    }
    if (strstr(arg, "passwd_file=") != 0) {
      passwd_file = strchr(arg, '=') + 1;
      return 0;
    }
    if (strstr(arg, "public_bucket=") != 0) {
      public_bucket = strchr(arg, '=') + 1;
      if (strcmp(public_bucket.c_str(), "1") == 0 || 
          strcmp(public_bucket.c_str(), "")  == 0 ) {
        return 0;
      } else {
         fprintf(stderr, "%s: poorly formed argument to option: public_bucket\n", 
                 program_name.c_str());
         return -1;
      }
    }
    if (strstr(arg, "host=") != 0) {
      host = strchr(arg, '=') + 1;
      return 0;
     }
    if (strstr(arg, "servicepath=") != 0) {
      service_path = strchr(arg, '=') + 1;
      return 0;
    }
    if (strstr(arg, "connect_timeout=") != 0) {
      connect_timeout = strtol(strchr(arg, '=') + 1, 0, 10);
      return 0;
    }
    if (strstr(arg, "readwrite_timeout=") != 0) {
      readwrite_timeout = strtoul(strchr(arg, '=') + 1, 0, 10);
      return 0;
    }
    if (strstr(arg, "max_stat_cache_size=") != 0) {
      unsigned long cache_size = strtoul(strchr(arg, '=') + 1, 0, 10);
      StatCache::getStatCacheData()->SetCacheSize(cache_size);
      return 0;
    }
    if (strstr(arg, "stat_cache_expire=") != 0) {
      time_t expr_time = strtoul(strchr(arg, '=') + 1, 0, 10);
      StatCache::getStatCacheData()->SetExpireTime(expr_time);
      return 0;
    }
    if(strstr(arg, "noxmlns") != 0) {
      noxmlns = true;
      return 0;
    }
    if(strstr(arg, "nocopyapi") != 0) {
      nocopyapi = true;
      return 0;
    }
    if(strstr(arg, "norenameapi") != 0) {
      norenameapi = true;
      return 0;
    }
    if (strstr(arg, "url=") != 0) {
      host = strchr(arg, '=') + 1;
      // strip the trailing '/', if any, off the end of the host
      // string
      size_t found, length;
      found = host.find_last_of('/');
      length = host.length();
      while ( found == (length - 1) && length > 0 ) {
         host.erase(found);
         found = host.find_last_of('/');
         length = host.length();
      }
      return 0;
    }

    // debug option
    //
    // The first -d (or --debug) enables s3fs debug
    // the second -d option is passed to fuse to turn on its
    // debug output
    if ( (strcmp(arg, "-d") == 0) || (strcmp(arg, "--debug") == 0) ) {
      if (!debug) {
        debug = 1;
        return 0;
      } else {
         // fuse doesn't understand "--debug", but it 
         // understands -d, but we can't pass -d back
         // to fuse, in this case just ignore the
         // second --debug if is was provided.  If we
         // do not ignore this, fuse emits an error
         if(strcmp(arg, "--debug") == 0) {
            return 0;
         } 
      }
    }

    if (strstr(arg, "accessKeyId=") != 0) {
      fprintf(stderr, "%s: option accessKeyId is no longer supported\n", 
              program_name.c_str());
      return -1;
    }
    if (strstr(arg, "secretAccessKey=") != 0) {
      fprintf(stderr, "%s: option secretAccessKey is no longer supported\n", 
              program_name.c_str());
      return -1;
    }
  }

  return 1;
}

int main(int argc, char *argv[]) {
  int ch;
  int fuse_res;
  int option_index = 0; 
  struct fuse_operations s3fs_oper;

  static const struct option long_opts[] = {
    {"help",    no_argument, NULL, 'h'},
    {"version", no_argument, 0,     0},
    {"debug",   no_argument, NULL, 'd'},
    {0, 0, 0, 0}};

   // get progam name - emulate basename 
   size_t found = string::npos;
   program_name.assign(argv[0]);
   found = program_name.find_last_of("/");
   if(found != string::npos) {
      program_name.replace(0, found+1, "");
   }

   while ((ch = getopt_long(argc, argv, "dho:fsu", long_opts, &option_index)) != -1) {
     switch (ch) {
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
       foreground = 1;
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
  if (bucket.size() == 0) {
    fprintf(stderr, "%s: missing BUCKET argument\n", program_name.c_str());
    show_usage();
    exit(EXIT_FAILURE);
  }

  // bucket names cannot contain upper case characters
  if (lower(bucket) != bucket) {
    fprintf(stderr, "%s: BUCKET %s, upper case characters are not supported\n",
      program_name.c_str(), bucket.c_str());
    exit(EXIT_FAILURE);
  }

  // check bucket name for illegal characters
  found = bucket.find_first_of("/:\\;!@#$%^&*?|+=");
  if(found != string::npos) {
    fprintf(stderr, "%s: BUCKET %s -- bucket name contains an illegal character\n",
      program_name.c_str(), bucket.c_str());
    exit(EXIT_FAILURE);
  }

  // The second plain argument is the mountpoint
  // if the option was given, we all ready checked for a
  // readable, non-empty directory, this checks determines
  // if the mountpoint option was ever supplied
  if (utility_mode == 0) {
    if (mountpoint.size() == 0) {
      fprintf(stderr, "%s: missing MOUNTPOINT argument\n", program_name.c_str());
      show_usage();
      exit(EXIT_FAILURE);
    }
  }

  // error checking of command line arguments for compatability
  if ((AWSSecretAccessKey.size() > 0 && AWSAccessKeyId.size() == 0) ||
      (AWSSecretAccessKey.size() == 0 && AWSAccessKeyId.size() > 0)) {
    fprintf(stderr, "%s: if one access key is specified, both keys need to be specified\n",
      program_name.c_str());
    exit(EXIT_FAILURE);
  }

  if (public_bucket.substr(0,1) == "1" && 
       (AWSSecretAccessKey.size() > 0 || AWSAccessKeyId.size() > 0)) {
    fprintf(stderr, "%s: specifying both public_bucket and the access keys options is invalid\n",
      program_name.c_str());
    exit(EXIT_FAILURE);
  }

  if (passwd_file.size() > 0 && 
       (AWSSecretAccessKey.size() > 0 || AWSAccessKeyId.size() > 0)) {
    fprintf(stderr, "%s: specifying both passwd_file and the access keys options is invalid\n",
      program_name.c_str());
    exit(EXIT_FAILURE);
  }
  
  if (public_bucket.substr(0,1) != "1") {
     if(EXIT_SUCCESS != get_access_keys()){
        exit(EXIT_FAILURE);
     }
     if(AWSSecretAccessKey.size() == 0 || AWSAccessKeyId.size() == 0) {
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
  if (ssl_verify_hostname.substr(0,1) == "1") {
    found = bucket.find_first_of(".");
    if(found != string::npos) {
      found = host.find("https:");
      if(found != string::npos) {
        fprintf(stderr, "%s: Using https and a bucket name with periods is unsupported.\n",
          program_name.c_str());
        exit(1);
      }
    }
  }
  */

  // Does the bucket exist?
  // if the network is up, check for valid credentials and if the bucket
  // exists. skip check if mounting a public bucket
  if(public_bucket.substr(0,1) != "1"){
     int result;
     if(EXIT_SUCCESS != (result = s3fs_check_service())){
       exit(result);
     }
  }

  if (utility_mode) {
     printf("Utility Mode\n");
     int result;
     result = list_multipart_uploads();
     exit(EXIT_SUCCESS);
  }

  s3fs_oper.getattr = s3fs_getattr;
  s3fs_oper.readlink = s3fs_readlink;
  s3fs_oper.mknod = s3fs_mknod;
  s3fs_oper.mkdir = s3fs_mkdir;
  s3fs_oper.unlink = s3fs_unlink;
  s3fs_oper.rmdir = s3fs_rmdir;
  s3fs_oper.symlink = s3fs_symlink;
  s3fs_oper.rename = s3fs_rename;
  s3fs_oper.link = s3fs_link;
  if(!nocopyapi){
    s3fs_oper.chmod = s3fs_chmod;
    s3fs_oper.chown = s3fs_chown;
    s3fs_oper.utimens = s3fs_utimens;
  }else{
    s3fs_oper.chmod = s3fs_chmod_nocopy;
    s3fs_oper.chown = s3fs_chown_nocopy;
    s3fs_oper.utimens = s3fs_utimens_nocopy;
  }
  s3fs_oper.truncate = s3fs_truncate;
  s3fs_oper.open = s3fs_open;
  s3fs_oper.read = s3fs_read;
  s3fs_oper.write = s3fs_write;
  s3fs_oper.statfs = s3fs_statfs;
  s3fs_oper.flush = s3fs_flush;
  s3fs_oper.release = s3fs_release;
  s3fs_oper.opendir = s3fs_opendir;
  s3fs_oper.readdir = s3fs_readdir;
  s3fs_oper.init = s3fs_init;
  s3fs_oper.destroy = s3fs_destroy;
  s3fs_oper.access = s3fs_access;
  s3fs_oper.create = s3fs_create;

  // now passing things off to fuse, fuse will finish evaluating the command line args
  fuse_res = fuse_main(custom_args.argc, custom_args.argv, &s3fs_oper, NULL);
  fuse_opt_free_args(&custom_args);

  exit(fuse_res);
}

