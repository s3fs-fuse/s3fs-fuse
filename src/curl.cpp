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
#include <ctime>
#include <cstring>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include <dirent.h>
#include <cerrno>
#include <syslog.h>
#include <pthread.h>
#include <cassert>
#include <curl/curl.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <map>
#include <algorithm>
#include <list>
#include <vector>

#include "common.h"
#include "curl.h"
#include "string_util.h"
#include "s3fs.h"
#include "s3fs_util.h"
#include "s3fs_auth.h"
#include "addhead.h"
#include "fdcache.h"
#include "psemaphore.h"

using namespace std;

static const std::string empty_payload_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

//-------------------------------------------------------------------
// Utilities
//-------------------------------------------------------------------
// [TODO]
// This function uses temporary file, but should not use it.
// For not using it, we implement function in each auth file(openssl, nss. gnutls).
//
static bool make_md5_from_binary(const char* pstr, size_t length, string& md5)
{
  if(!pstr || '\0' == pstr[0]){
    S3FS_PRN_ERR("Parameter is wrong.");
    return false;
  }
  FILE* fp;
  if(NULL == (fp = tmpfile())){
    S3FS_PRN_ERR("Could not make tmpfile.");
    return false;
  }
  if(length != fwrite(pstr, sizeof(char), length, fp)){
    S3FS_PRN_ERR("Failed to write tmpfile.");
    fclose(fp);
    return false;
  }
  int fd;
  if(0 != fflush(fp) || 0 != fseek(fp, 0L, SEEK_SET) || -1 == (fd = fileno(fp))){
    S3FS_PRN_ERR("Failed to make MD5.");
    fclose(fp);
    return false;
  }
  // base64 md5
  md5 = s3fs_get_content_md5(fd);
  if(0 == md5.length()){
    S3FS_PRN_ERR("Failed to make MD5.");
    fclose(fp);
    return false;
  }
  fclose(fp);
  return true;
}

static string url_to_host(const std::string &url)
{
  S3FS_PRN_INFO3("url is %s", url.c_str());

  static const string http = "http://";
  static const string https = "https://";
  std::string hostname;

  if (url.compare(0, http.size(), http) == 0) {
    hostname = url.substr(http.size());
  } else if (url.compare(0, https.size(), https) == 0) {
    hostname = url.substr(https.size());
  } else {
    S3FS_PRN_EXIT("url does not begin with http:// or https://");
    abort();
  }

  size_t idx;
  if ((idx = hostname.find('/')) != string::npos) {
    return hostname.substr(0, idx);
  } else {
    return hostname;
  }
}

static string get_bucket_host()
{
  if(!pathrequeststyle){
    return bucket + "." + url_to_host(host);
  }
  return url_to_host(host);
}

// compare ETag ignoring quotes
static bool etag_equals(std::string s1, std::string s2) {
  if(s1.length() > 1 && s1[0] == '\"' && s1[s1.length() - 1] == '\"'){
	s1 = s1.substr(1, s1.size() - 2);
  }
  if(s2.length() > 1 && s2[0] == '\"' && s2[s2.length() - 1] == '\"'){
	s2 = s2.substr(1, s2.size() - 2);
  }
  return s1 == s2;
}

#if 0 // noused
static string tolower_header_name(const char* head)
{
  string::size_type pos;
  string            name = head;
  string            value("");
  if(string::npos != (pos = name.find(':'))){
    value= name.substr(pos);
    name = name.substr(0, pos);
  }
  name = lower(name);
  name += value;
  return name;
}
#endif

//-------------------------------------------------------------------
// Class BodyData
//-------------------------------------------------------------------
static const int BODYDATA_RESIZE_APPEND_MIN = 1024;
static const int BODYDATA_RESIZE_APPEND_MID = 1024 * 1024;
static const int BODYDATA_RESIZE_APPEND_MAX = 10 * 1024 * 1024;

static size_t adjust_block(size_t bytes, size_t block) { return ((bytes / block) + ((bytes % block) ? 1 : 0)) * block; }

bool BodyData::Resize(size_t addbytes)
{
  if(IsSafeSize(addbytes)){
    return true;
  }

  // New size
  size_t need_size = adjust_block((lastpos + addbytes + 1) - bufsize, sizeof(off_t));

  if(BODYDATA_RESIZE_APPEND_MAX < bufsize){
    need_size = (BODYDATA_RESIZE_APPEND_MAX < need_size ? need_size : BODYDATA_RESIZE_APPEND_MAX);
  }else if(BODYDATA_RESIZE_APPEND_MID < bufsize){
    need_size = (BODYDATA_RESIZE_APPEND_MID < need_size ? need_size : BODYDATA_RESIZE_APPEND_MID);
  }else if(BODYDATA_RESIZE_APPEND_MIN < bufsize){
    need_size = ((bufsize * 2) < need_size ? need_size : (bufsize * 2));
  }else{
    need_size = (BODYDATA_RESIZE_APPEND_MIN < need_size ? need_size : BODYDATA_RESIZE_APPEND_MIN);
  }
  // realloc
  char* newtext;
  if(NULL == (newtext = (char*)realloc(text, (bufsize + need_size)))){
    S3FS_PRN_CRIT("not enough memory (realloc returned NULL)");
    free(text);
    text = NULL;
    return false;
  }
  text     = newtext;
  bufsize += need_size;

  return true;
}

void BodyData::Clear()
{
  if(text){
    free(text);
    text = NULL;
  }
  lastpos = 0;
  bufsize = 0;
}

bool BodyData::Append(void* ptr, size_t bytes)
{
  if(!ptr){
    return false;
  }
  if(0 == bytes){
    return true;
  }
  if(!Resize(bytes)){
    return false;
  }
  memcpy(&text[lastpos], ptr, bytes);
  lastpos += bytes;
  text[lastpos] = '\0';

  return true;
}

const char* BodyData::str() const
{
  if(!text){
    static const char* strnull = "";
    return strnull;
  }
  return text;
}

//-------------------------------------------------------------------
// Class CurlHandlerPool
//-------------------------------------------------------------------
bool CurlHandlerPool::Init()
{
  pthread_mutexattr_t attr;
  pthread_mutexattr_init(&attr);
#if S3FS_PTHREAD_ERRORCHECK
  pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK);
#endif
  if (0 != pthread_mutex_init(&mLock, &attr)) {
    S3FS_PRN_ERR("Init curl handlers lock failed");
    return false;
  }

  for(int cnt = 0; cnt < mMaxHandlers; ++cnt){
    CURL* hCurl = curl_easy_init();
    if(!hCurl){
      S3FS_PRN_ERR("Init curl handlers pool failed");
      Destroy();
      return false;
    }
    mPool.push_back(hCurl);
  }

  return true;
}

bool CurlHandlerPool::Destroy()
{
  while(!mPool.empty()){
    CURL* hCurl = mPool.back();
    mPool.pop_back();
    if(hCurl){
      curl_easy_cleanup(hCurl);
    }
  }
  if (0 != pthread_mutex_destroy(&mLock)) {
    S3FS_PRN_ERR("Destroy curl handlers lock failed");
    return false;
  }

  return true;
}

CURL* CurlHandlerPool::GetHandler(bool only_pool)
{
  CURL* hCurl = NULL;
  {
    AutoLock lock(&mLock);

    if(!mPool.empty()){
      hCurl = mPool.back();
      mPool.pop_back();
      S3FS_PRN_DBG("Get handler from pool: rest = %d", static_cast<int>(mPool.size()));
    }
  }
  if(only_pool){
    return hCurl;
  }
  if(!hCurl){
    S3FS_PRN_INFO("Pool empty: force to create new handler");
    hCurl = curl_easy_init();
  }
  return hCurl;
}

void CurlHandlerPool::ReturnHandler(CURL* hCurl, bool restore_pool)
{
  if(!hCurl){
    return;
  }

  if(restore_pool){
    AutoLock lock(&mLock);

    S3FS_PRN_DBG("Return handler to pool");
    mPool.push_back(hCurl);

    while(mMaxHandlers <= static_cast<int>(mPool.size())){
      CURL* hOldCurl = mPool.front();
      mPool.pop_front();
      if(hOldCurl){
        S3FS_PRN_INFO("Pool full: destroy the oldest handler");
        curl_easy_cleanup(hOldCurl);
      }
    }
  }else{
    S3FS_PRN_INFO("Pool full: destroy the handler");
    curl_easy_cleanup(hCurl);
  }
}

//-------------------------------------------------------------------
// Class S3fsCurl
//-------------------------------------------------------------------
static const int MULTIPART_SIZE = 10 * 1024 * 1024;
// constant must be at least 512 MB to copy the maximum 5 TB object size
// TODO: scale part size with object size
static const int MAX_MULTI_COPY_SOURCE_SIZE = 512 * 1024 * 1024;

static const int IAM_EXPIRE_MERGIN = 20 * 60;  // update timing
static const std::string ECS_IAM_ENV_VAR = "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI";
static const std::string IAMCRED_ACCESSKEYID = "AccessKeyId";
static const std::string IAMCRED_SECRETACCESSKEY = "SecretAccessKey";
static const std::string IAMCRED_ROLEARN = "RoleArn";

static const long S3FSCURL_RESPONSECODE_NOTSET      = -1;
static const long S3FSCURL_RESPONSECODE_FATAL_ERROR = -2;
static const int  S3FSCURL_PERFORM_RESULT_NOTSET    = 1;

// [NOTICE]
// This symbol is for libcurl under 7.23.0
#ifndef CURLSHE_NOT_BUILT_IN
#define CURLSHE_NOT_BUILT_IN        5
#endif

pthread_mutex_t  S3fsCurl::curl_handles_lock;
pthread_mutex_t  S3fsCurl::curl_share_lock[SHARE_MUTEX_MAX];
bool             S3fsCurl::is_initglobal_done  = false;
CurlHandlerPool* S3fsCurl::sCurlPool           = NULL;
int              S3fsCurl::sCurlPoolSize       = 32;
CURLSH*          S3fsCurl::hCurlShare          = NULL;
bool             S3fsCurl::is_cert_check       = true; // default
bool             S3fsCurl::is_dns_cache        = true; // default
bool             S3fsCurl::is_ssl_session_cache= true; // default
long             S3fsCurl::connect_timeout     = 300;  // default
time_t           S3fsCurl::readwrite_timeout   = 120;  // default
int              S3fsCurl::retries             = 5;    // default
bool             S3fsCurl::is_public_bucket    = false;
acl_t            S3fsCurl::default_acl         = PRIVATE;
storage_class_t  S3fsCurl::storage_class       = STANDARD;
sseckeylist_t    S3fsCurl::sseckeys;
std::string      S3fsCurl::ssekmsid;
sse_type_t       S3fsCurl::ssetype             = SSE_DISABLE;
bool             S3fsCurl::is_content_md5      = false;
bool             S3fsCurl::is_verbose          = false;
string           S3fsCurl::AWSAccessKeyId;
string           S3fsCurl::AWSSecretAccessKey;
string           S3fsCurl::AWSAccessToken;
time_t           S3fsCurl::AWSAccessTokenExpire= 0;
bool             S3fsCurl::is_ecs              = false;
bool             S3fsCurl::is_ibm_iam_auth     = false;
string           S3fsCurl::IAM_cred_url        = "http://169.254.169.254/latest/meta-data/iam/security-credentials/";
size_t           S3fsCurl::IAM_field_count     = 4;
string           S3fsCurl::IAM_token_field     = "Token";
string           S3fsCurl::IAM_expiry_field    = "Expiration";
string           S3fsCurl::IAM_role;
long             S3fsCurl::ssl_verify_hostname = 1;    // default(original code...)
curltime_t       S3fsCurl::curl_times;
curlprogress_t   S3fsCurl::curl_progress;
string           S3fsCurl::curl_ca_bundle;
mimes_t          S3fsCurl::mimeTypes;
string           S3fsCurl::userAgent;
int              S3fsCurl::max_parallel_cnt    = 5;              // default
int              S3fsCurl::max_multireq        = 20;             // default
off_t            S3fsCurl::multipart_size      = MULTIPART_SIZE; // default
bool             S3fsCurl::is_sigv4            = true;           // default
bool             S3fsCurl::is_ua               = true;           // default
bool             S3fsCurl::is_use_session_token = false;         // default

//-------------------------------------------------------------------
// Class methods for S3fsCurl
//-------------------------------------------------------------------
bool S3fsCurl::InitS3fsCurl(const char* MimeFile)
{
  pthread_mutexattr_t attr;
  pthread_mutexattr_init(&attr);
#if S3FS_PTHREAD_ERRORCHECK
  pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK);
#endif
  if(0 != pthread_mutex_init(&S3fsCurl::curl_handles_lock, &attr)){
    return false;
  }
  if(0 != pthread_mutex_init(&S3fsCurl::curl_share_lock[SHARE_MUTEX_DNS], &attr)){
    return false;
  }
  if(0 != pthread_mutex_init(&S3fsCurl::curl_share_lock[SHARE_MUTEX_SSL_SESSION], &attr)){
    return false;
  }
  if(!S3fsCurl::InitMimeType(MimeFile)){
    return false;
  }
  if(!S3fsCurl::InitGlobalCurl()){
    return false;
  }
  if(!S3fsCurl::InitShareCurl()){
    return false;
  }
  if(!S3fsCurl::InitCryptMutex()){
    return false;
  }
  // [NOTE]
  // sCurlPoolSize must be over parallel(or multireq) count.
  //
  if(sCurlPoolSize < std::max(GetMaxParallelCount(), GetMaxMultiRequest())){
    sCurlPoolSize = std::max(GetMaxParallelCount(), GetMaxMultiRequest());
  }
  sCurlPool = new CurlHandlerPool(sCurlPoolSize);
  if (!sCurlPool->Init()) {
    return false;
  }
  return true;
}

bool S3fsCurl::DestroyS3fsCurl()
{
  bool result = true;

  if(!S3fsCurl::DestroyCryptMutex()){
    result = false;
  }
  if(!sCurlPool->Destroy()){
    result = false;
  }
  delete sCurlPool;
  sCurlPool = NULL;
  if(!S3fsCurl::DestroyShareCurl()){
    result = false;
  }
  if(!S3fsCurl::DestroyGlobalCurl()){
    result = false;
  }
  if(0 != pthread_mutex_destroy(&S3fsCurl::curl_share_lock[SHARE_MUTEX_DNS])){
    result = false;
  }
  if(0 != pthread_mutex_destroy(&S3fsCurl::curl_share_lock[SHARE_MUTEX_SSL_SESSION])){
    result = false;
  }
  if(0 != pthread_mutex_destroy(&S3fsCurl::curl_handles_lock)){
    result = false;
  }
  return result;
}

bool S3fsCurl::InitGlobalCurl()
{
  if(S3fsCurl::is_initglobal_done){
    return false;
  }
  if(CURLE_OK != curl_global_init(CURL_GLOBAL_ALL)){
    S3FS_PRN_ERR("init_curl_global_all returns error.");
    return false;
  }
  S3fsCurl::is_initglobal_done = true;
  return true;
}

bool S3fsCurl::DestroyGlobalCurl()
{
  if(!S3fsCurl::is_initglobal_done){
    return false;
  }
  curl_global_cleanup();
  S3fsCurl::is_initglobal_done = false;
  return true;
}

bool S3fsCurl::InitShareCurl()
{
  CURLSHcode nSHCode;

  if(!S3fsCurl::is_dns_cache && !S3fsCurl::is_ssl_session_cache){
    S3FS_PRN_INFO("Curl does not share DNS data.");
    return true;
  }
  if(S3fsCurl::hCurlShare){
    S3FS_PRN_WARN("already initiated.");
    return false;
  }
  if(NULL == (S3fsCurl::hCurlShare = curl_share_init())){
    S3FS_PRN_ERR("curl_share_init failed");
    return false;
  }
  if(CURLSHE_OK != (nSHCode = curl_share_setopt(S3fsCurl::hCurlShare, CURLSHOPT_LOCKFUNC, S3fsCurl::LockCurlShare))){
    S3FS_PRN_ERR("curl_share_setopt(LOCKFUNC) returns %d(%s)", nSHCode, curl_share_strerror(nSHCode));
    return false;
  }
  if(CURLSHE_OK != (nSHCode = curl_share_setopt(S3fsCurl::hCurlShare, CURLSHOPT_UNLOCKFUNC, S3fsCurl::UnlockCurlShare))){
    S3FS_PRN_ERR("curl_share_setopt(UNLOCKFUNC) returns %d(%s)", nSHCode, curl_share_strerror(nSHCode));
    return false;
  }
  if(S3fsCurl::is_dns_cache){
    nSHCode = curl_share_setopt(S3fsCurl::hCurlShare, CURLSHOPT_SHARE, CURL_LOCK_DATA_DNS);
    if(CURLSHE_OK != nSHCode && CURLSHE_BAD_OPTION != nSHCode && CURLSHE_NOT_BUILT_IN != nSHCode){
      S3FS_PRN_ERR("curl_share_setopt(DNS) returns %d(%s)", nSHCode, curl_share_strerror(nSHCode));
      return false;
    }else if(CURLSHE_BAD_OPTION == nSHCode || CURLSHE_NOT_BUILT_IN == nSHCode){
      S3FS_PRN_WARN("curl_share_setopt(DNS) returns %d(%s), but continue without shared dns data.", nSHCode, curl_share_strerror(nSHCode));
    }
  }
  if(S3fsCurl::is_ssl_session_cache){
    nSHCode = curl_share_setopt(S3fsCurl::hCurlShare, CURLSHOPT_SHARE, CURL_LOCK_DATA_SSL_SESSION);
    if(CURLSHE_OK != nSHCode && CURLSHE_BAD_OPTION != nSHCode && CURLSHE_NOT_BUILT_IN != nSHCode){
      S3FS_PRN_ERR("curl_share_setopt(SSL SESSION) returns %d(%s)", nSHCode, curl_share_strerror(nSHCode));
      return false;
    }else if(CURLSHE_BAD_OPTION == nSHCode || CURLSHE_NOT_BUILT_IN == nSHCode){
      S3FS_PRN_WARN("curl_share_setopt(SSL SESSION) returns %d(%s), but continue without shared ssl session data.", nSHCode, curl_share_strerror(nSHCode));
    }
  }
  if(CURLSHE_OK != (nSHCode = curl_share_setopt(S3fsCurl::hCurlShare, CURLSHOPT_USERDATA, (void*)&S3fsCurl::curl_share_lock[0]))){
    S3FS_PRN_ERR("curl_share_setopt(USERDATA) returns %d(%s)", nSHCode, curl_share_strerror(nSHCode));
    return false;
  }
  return true;
}

bool S3fsCurl::DestroyShareCurl()
{
  if(!S3fsCurl::hCurlShare){
    if(!S3fsCurl::is_dns_cache && !S3fsCurl::is_ssl_session_cache){
      return true;
    }
    S3FS_PRN_WARN("already destroy share curl.");
    return false;
  }
  if(CURLSHE_OK != curl_share_cleanup(S3fsCurl::hCurlShare)){
    return false;
  }
  S3fsCurl::hCurlShare = NULL;
  return true;
}

void S3fsCurl::LockCurlShare(CURL* handle, curl_lock_data nLockData, curl_lock_access laccess, void* useptr)
{
  if(!hCurlShare){
    return;
  }
  pthread_mutex_t* lockmutex = static_cast<pthread_mutex_t*>(useptr);
  if(CURL_LOCK_DATA_DNS == nLockData){
    pthread_mutex_lock(&lockmutex[SHARE_MUTEX_DNS]);
  }else if(CURL_LOCK_DATA_SSL_SESSION == nLockData){
    pthread_mutex_lock(&lockmutex[SHARE_MUTEX_SSL_SESSION]);
  }
}

void S3fsCurl::UnlockCurlShare(CURL* handle, curl_lock_data nLockData, void* useptr)
{
  if(!hCurlShare){
    return;
  }
  pthread_mutex_t* lockmutex = static_cast<pthread_mutex_t*>(useptr);
  if(CURL_LOCK_DATA_DNS == nLockData){
    pthread_mutex_unlock(&lockmutex[SHARE_MUTEX_DNS]);
  }else if(CURL_LOCK_DATA_SSL_SESSION == nLockData){
    pthread_mutex_unlock(&lockmutex[SHARE_MUTEX_SSL_SESSION]);
  }
}

bool S3fsCurl::InitCryptMutex()
{
  return s3fs_init_crypt_mutex();
}

bool S3fsCurl::DestroyCryptMutex()
{
  return s3fs_destroy_crypt_mutex();
}

// homegrown timeout mechanism
int S3fsCurl::CurlProgress(void *clientp, double dltotal, double dlnow, double ultotal, double ulnow)
{
  CURL* curl = static_cast<CURL*>(clientp);
  time_t now = time(0);
  progress_t p(dlnow, ulnow);

  AutoLock lock(&S3fsCurl::curl_handles_lock);

  // any progress?
  if(p != S3fsCurl::curl_progress[curl]){
    // yes!
    S3fsCurl::curl_times[curl]    = now;
    S3fsCurl::curl_progress[curl] = p;
  }else{
    // timeout?
    if(now - S3fsCurl::curl_times[curl] > readwrite_timeout){
      S3FS_PRN_ERR("timeout now: %lld, curl_times[curl]: %lld, readwrite_timeout: %lld",
                      static_cast<long long>(now), static_cast<long long>((S3fsCurl::curl_times[curl])), static_cast<long long>(readwrite_timeout));
      return CURLE_ABORTED_BY_CALLBACK;
    }
  }

  return 0;
}

bool S3fsCurl::InitMimeType(const char* MimeFile)
{
  if(!MimeFile){
    MimeFile = "/etc/mime.types";  // default
  }

  string line;
  ifstream MT(MimeFile);
  if(MT.good()){
    while(getline(MT, line)){
      if(line[0]=='#'){
        continue;
      }
      if(line.empty()){
        continue;
      }

      istringstream tmp(line);
      string mimeType;
      tmp >> mimeType;
      while(tmp){
        string ext;
        tmp >> ext;
        if(ext.empty()){
          continue;
        }
        S3fsCurl::mimeTypes[ext] = mimeType;
      }
    }
  }
  return true;
}

void S3fsCurl::InitUserAgent()
{
  if(S3fsCurl::userAgent.empty()){
    S3fsCurl::userAgent =  "s3fs/";
    S3fsCurl::userAgent += VERSION;
    S3fsCurl::userAgent += " (commit hash ";
    S3fsCurl::userAgent += COMMIT_HASH_VAL;
    S3fsCurl::userAgent += "; ";
    S3fsCurl::userAgent += s3fs_crypt_lib_name();
    S3fsCurl::userAgent += ")";
    S3fsCurl::userAgent += instance_name;
  }
}

//
// @param s e.g., "index.html"
// @return e.g., "text/html"
//
string S3fsCurl::LookupMimeType(const string& name)
{
  string result("application/octet-stream");
  string::size_type last_pos = name.find_last_of('.');
  string::size_type first_pos = name.find_first_of('.');
  string prefix, ext, ext2;

  // No dots in name, just return
  if(last_pos == string::npos){
    return result;
  }
  // extract the last extension
  ext = name.substr(1+last_pos, string::npos);

  if (last_pos != string::npos) {
     // one dot was found, now look for another
     if (first_pos != string::npos && first_pos < last_pos) {
        prefix = name.substr(0, last_pos);
        // Now get the second to last file extension
        string::size_type next_pos = prefix.find_last_of('.');
        if (next_pos != string::npos) {
           ext2 = prefix.substr(1+next_pos, string::npos);
        }
     }
  }

  // if we get here, then we have an extension (ext)
  mimes_t::const_iterator iter = S3fsCurl::mimeTypes.find(ext);
  // if the last extension matches a mimeType, then return
  // that mime type
  if (iter != S3fsCurl::mimeTypes.end()) {
    result = (*iter).second;
    return result;
  }

  // return with the default result if there isn't a second extension
  if(first_pos == last_pos){
     return result;
  }

  // Didn't find a mime-type for the first extension
  // Look for second extension in mimeTypes, return if found
  iter = S3fsCurl::mimeTypes.find(ext2);
  if (iter != S3fsCurl::mimeTypes.end()) {
     result = (*iter).second;
     return result;
  }

  // neither the last extension nor the second-to-last extension
  // matched a mimeType, return the default mime type 
  return result;
}

bool S3fsCurl::LocateBundle()
{
  // See if environment variable CURL_CA_BUNDLE is set
  // if so, check it, if it is a good path, then set the
  // curl_ca_bundle variable to it
  if(S3fsCurl::curl_ca_bundle.empty()){
    char* CURL_CA_BUNDLE = getenv("CURL_CA_BUNDLE");
    if(CURL_CA_BUNDLE != NULL)  {
      // check for existence and readability of the file
      ifstream BF(CURL_CA_BUNDLE);
      if(!BF.good()){
        S3FS_PRN_ERR("%s: file specified by CURL_CA_BUNDLE environment variable is not readable", program_name.c_str());
        return false;
      }
      BF.close();
      S3fsCurl::curl_ca_bundle.assign(CURL_CA_BUNDLE); 
      return true;
    }
  }else{
    // Already set ca bundle variable
    return true;
  }

  // not set via environment variable, look in likely locations

  ///////////////////////////////////////////
  // following comment from curl's (7.21.2) acinclude.m4 file
  ///////////////////////////////////////////
  // dnl CURL_CHECK_CA_BUNDLE
  // dnl -------------------------------------------------
  // dnl Check if a default ca-bundle should be used
  // dnl
  // dnl regarding the paths this will scan:
  // dnl /etc/ssl/certs/ca-certificates.crt Debian systems
  // dnl /etc/pki/tls/certs/ca-bundle.crt Redhat and Mandriva
  // dnl /usr/share/ssl/certs/ca-bundle.crt old(er) Redhat
  // dnl /usr/local/share/certs/ca-root.crt FreeBSD
  // dnl /etc/ssl/cert.pem OpenBSD
  // dnl /etc/ssl/certs/ (ca path) SUSE
  ///////////////////////////////////////////
  // Within CURL the above path should have been checked
  // according to the OS. Thus, although we do not need
  // to check files here, we will only examine some files.
  //
  ifstream BF("/etc/pki/tls/certs/ca-bundle.crt"); 
  if(BF.good()){
    BF.close();
    S3fsCurl::curl_ca_bundle.assign("/etc/pki/tls/certs/ca-bundle.crt"); 
  }else{
    BF.open("/etc/ssl/certs/ca-certificates.crt");
    if(BF.good()){
      BF.close();
      S3fsCurl::curl_ca_bundle.assign("/etc/ssl/certs/ca-certificates.crt");
    }else{
      BF.open("/usr/share/ssl/certs/ca-bundle.crt");
      if(BF.good()){
        BF.close();
        S3fsCurl::curl_ca_bundle.assign("/usr/share/ssl/certs/ca-bundle.crt");
      }else{
        BF.open("/usr/local/share/certs/ca-root.crt");
        if(BF.good()){
          BF.close();
          S3fsCurl::curl_ca_bundle.assign("/usr/share/ssl/certs/ca-bundle.crt");
        }else{
          S3FS_PRN_ERR("%s: /.../ca-bundle.crt is not readable", program_name.c_str());
          return false;
        }
      }
    }
  }
  return true;
}

size_t S3fsCurl::WriteMemoryCallback(void* ptr, size_t blockSize, size_t numBlocks, void* data)
{
  BodyData* body  = static_cast<BodyData*>(data);

  if(!body->Append(ptr, blockSize, numBlocks)){
    S3FS_PRN_CRIT("BodyData.Append() returned false.");
    S3FS_FUSE_EXIT();
    return -1;
  }
  return (blockSize * numBlocks);
}

size_t S3fsCurl::ReadCallback(void* ptr, size_t size, size_t nmemb, void* userp)
{
  S3fsCurl* pCurl = reinterpret_cast<S3fsCurl*>(userp);

  if(1 > (size * nmemb)){
    return 0;
  }
  if(0 >= pCurl->postdata_remaining){
    return 0;
  }
  int copysize = std::min((int)(size * nmemb), pCurl->postdata_remaining);
  memcpy(ptr, pCurl->postdata, copysize);

  pCurl->postdata_remaining = (pCurl->postdata_remaining > copysize ? (pCurl->postdata_remaining - copysize) : 0);
  pCurl->postdata          += static_cast<size_t>(copysize);

  return copysize;
}

size_t S3fsCurl::HeaderCallback(void* data, size_t blockSize, size_t numBlocks, void* userPtr)
{
  headers_t* headers = reinterpret_cast<headers_t*>(userPtr);
  string header(reinterpret_cast<char*>(data), blockSize * numBlocks);
  string key;
  istringstream ss(header);

  if(getline(ss, key, ':')){
    // Force to lower, only "x-amz"
    string lkey = key;
    transform(lkey.begin(), lkey.end(), lkey.begin(), static_cast<int (*)(int)>(std::tolower));
    if(lkey.compare(0, 5, "x-amz") == 0){
      key = lkey;
    }
    string value;
    getline(ss, value);
    (*headers)[key] = trim(value);
  }
  return blockSize * numBlocks;
}

size_t S3fsCurl::UploadReadCallback(void* ptr, size_t size, size_t nmemb, void* userp)
{
  S3fsCurl* pCurl = reinterpret_cast<S3fsCurl*>(userp);

  if(1 > (size * nmemb)){
    return 0;
  }
  if(-1 == pCurl->partdata.fd || 0 >= pCurl->partdata.size){
    return 0;
  }
  // read size
  ssize_t copysize = (size * nmemb) < (size_t)pCurl->partdata.size ? (size * nmemb) : (size_t)pCurl->partdata.size;
  ssize_t readbytes;
  ssize_t totalread;
  // read and set
  for(totalread = 0, readbytes = 0; totalread < copysize; totalread += readbytes){
    readbytes = pread(pCurl->partdata.fd, &((char*)ptr)[totalread], (copysize - totalread), pCurl->partdata.startpos + totalread);
    if(0 == readbytes){
      // eof
      break;
    }else if(-1 == readbytes){
      // error
      S3FS_PRN_ERR("read file error(%d).", errno);
      return 0;
    }
  }
  pCurl->partdata.startpos += totalread;
  pCurl->partdata.size     -= totalread;

  return totalread;
}

size_t S3fsCurl::DownloadWriteCallback(void* ptr, size_t size, size_t nmemb, void* userp)
{
  S3fsCurl* pCurl = reinterpret_cast<S3fsCurl*>(userp);

  if(1 > (size * nmemb)){
    return 0;
  }
  if(-1 == pCurl->partdata.fd || 0 >= pCurl->partdata.size){
    return 0;
  }

  // write size
  ssize_t copysize = (size * nmemb) < (size_t)pCurl->partdata.size ? (size * nmemb) : (size_t)pCurl->partdata.size;
  ssize_t writebytes;
  ssize_t totalwrite;

  // write
  for(totalwrite = 0, writebytes = 0; totalwrite < copysize; totalwrite += writebytes){
    writebytes = pwrite(pCurl->partdata.fd, &((char*)ptr)[totalwrite], (copysize - totalwrite), pCurl->partdata.startpos + totalwrite);
    if(0 == writebytes){
      // eof?
      break;
    }else if(-1 == writebytes){
      // error
      S3FS_PRN_ERR("write file error(%d).", errno);
      return 0;
    }
  }
  pCurl->partdata.startpos += totalwrite;
  pCurl->partdata.size     -= totalwrite;

  return totalwrite;
}

bool S3fsCurl::SetCheckCertificate(bool isCertCheck) {
    bool old = S3fsCurl::is_cert_check;
    S3fsCurl::is_cert_check = isCertCheck;
    return old;
}

bool S3fsCurl::SetDnsCache(bool isCache)
{
  bool old = S3fsCurl::is_dns_cache;
  S3fsCurl::is_dns_cache = isCache;
  return old;
}

bool S3fsCurl::SetSslSessionCache(bool isCache)
{
  bool old = S3fsCurl::is_ssl_session_cache;
  S3fsCurl::is_ssl_session_cache = isCache;
  return old;
}

long S3fsCurl::SetConnectTimeout(long timeout)
{
  long old = S3fsCurl::connect_timeout;
  S3fsCurl::connect_timeout = timeout;
  return old;
}

time_t S3fsCurl::SetReadwriteTimeout(time_t timeout)
{
  time_t old = S3fsCurl::readwrite_timeout;
  S3fsCurl::readwrite_timeout = timeout;
  return old;
}

int S3fsCurl::SetRetries(int count)
{
  int old = S3fsCurl::retries;
  S3fsCurl::retries = count;
  return old;
}

bool S3fsCurl::SetPublicBucket(bool flag)
{
  bool old = S3fsCurl::is_public_bucket;
  S3fsCurl::is_public_bucket = flag;
  return old;
}

acl_t S3fsCurl::SetDefaultAcl(acl_t acl)
{
  acl_t old = S3fsCurl::default_acl;
  S3fsCurl::default_acl = acl;
  return old;
}

acl_t S3fsCurl::GetDefaultAcl()
{
  return S3fsCurl::default_acl;
}

storage_class_t S3fsCurl::SetStorageClass(storage_class_t storage_class)
{
  storage_class_t old = S3fsCurl::storage_class;
  S3fsCurl::storage_class = storage_class;
  return old;
}

bool S3fsCurl::PushbackSseKeys(string& onekey)
{
  onekey = trim(onekey);
  if(onekey.empty()){
    return false;
  }
  if('#' == onekey[0]){
    return false;
  }
  // make base64 if the key is short enough, otherwise assume it is already so
  string base64_key;
  string raw_key;
  if(onekey.length() > 256 / 8){
    char* p_key;
    size_t keylength;

    if(NULL != (p_key = (char *)s3fs_decode64(onekey.c_str(), &keylength))) {
      raw_key = string(p_key, keylength);
      base64_key = onekey;
      delete[] p_key;
    } else {
      S3FS_PRN_ERR("Failed to convert base64 to SSE-C key %s", onekey.c_str());
      return false;
    }
  } else {
    char* pbase64_key;

    if(NULL != (pbase64_key = s3fs_base64((unsigned char*)onekey.c_str(), onekey.length()))) {
      raw_key = onekey;
      base64_key = pbase64_key;
      delete[] pbase64_key;
    } else {
      S3FS_PRN_ERR("Failed to convert base64 from SSE-C key %s", onekey.c_str());
      return false;
    }
  }

  // make MD5
  string strMd5;
  if(!make_md5_from_binary(raw_key.c_str(), raw_key.length(), strMd5)){
    S3FS_PRN_ERR("Could not make MD5 from SSE-C keys(%s).", raw_key.c_str());
    return false;
  }
  // mapped MD5 = SSE Key
  sseckeymap_t md5map;
  md5map.clear();
  md5map[strMd5] = base64_key;
  S3fsCurl::sseckeys.push_back(md5map);
  return true;
}

sse_type_t S3fsCurl::SetSseType(sse_type_t type)
{
  sse_type_t    old = S3fsCurl::ssetype;
  S3fsCurl::ssetype = type;
  return old;
}

bool S3fsCurl::SetSseCKeys(const char* filepath)
{
  if(!filepath){
    S3FS_PRN_ERR("SSE-C keys filepath is empty.");
    return false;
  }
  struct stat st;
  if(0 != stat(filepath, &st)){
    S3FS_PRN_ERR("could not open use_sse keys file(%s).", filepath);
    return false;
  }
  if(st.st_mode & (S_IXUSR | S_IRWXG | S_IRWXO)){
    S3FS_PRN_ERR("use_sse keys file %s should be 0600 permissions.", filepath);
    return false;
  }

  S3fsCurl::sseckeys.clear();

  ifstream ssefs(filepath);
  if(!ssefs.good()){
    S3FS_PRN_ERR("Could not open SSE-C keys file(%s).", filepath);
    return false;
  }

  string   line;
  while(getline(ssefs, line)){
    S3fsCurl::PushbackSseKeys(line);
  }
  if(S3fsCurl::sseckeys.empty()){
    S3FS_PRN_ERR("There is no SSE Key in file(%s).", filepath);
    return false;
  }
  return true;
}

bool S3fsCurl::SetSseKmsid(const char* kmsid)
{
  if(!kmsid || '\0' == kmsid[0]){
    S3FS_PRN_ERR("SSE-KMS kms id is empty.");
    return false;
  }
  S3fsCurl::ssekmsid = kmsid;
  return true;
}

// [NOTE]
// Because SSE is set by some options and environment, 
// this function check the integrity of the SSE data finally.
bool S3fsCurl::FinalCheckSse()
{
  if(SSE_DISABLE == S3fsCurl::ssetype){
    S3fsCurl::ssekmsid.erase();
  }else if(SSE_S3 == S3fsCurl::ssetype){
    S3fsCurl::ssekmsid.erase();
  }else if(SSE_C == S3fsCurl::ssetype){
    if(S3fsCurl::sseckeys.empty()){
      S3FS_PRN_ERR("sse type is SSE-C, but there is no custom key.");
      return false;
    }
    S3fsCurl::ssekmsid.erase();
  }else if(SSE_KMS == S3fsCurl::ssetype){
    if(S3fsCurl::ssekmsid.empty()){
      S3FS_PRN_ERR("sse type is SSE-KMS, but there is no specified kms id.");
      return false;
    }
    if(!S3fsCurl::IsSignatureV4()){
      S3FS_PRN_ERR("sse type is SSE-KMS, but signature type is not v4. SSE-KMS require signature v4.");
      return false;
    }
  }else{
    S3FS_PRN_ERR("sse type is unknown(%d).", S3fsCurl::ssetype);
    return false;
  }
  return true;
}
                                                                                                                                                   
bool S3fsCurl::LoadEnvSseCKeys()
{
  char* envkeys = getenv("AWSSSECKEYS");
  if(NULL == envkeys){
    // nothing to do
    return true;
  }
  S3fsCurl::sseckeys.clear();

  istringstream fullkeys(envkeys);
  string        onekey;
  while(getline(fullkeys, onekey, ':')){
    S3fsCurl::PushbackSseKeys(onekey);
  }
  if(S3fsCurl::sseckeys.empty()){
    S3FS_PRN_ERR("There is no SSE Key in environment(AWSSSECKEYS=%s).", envkeys);
    return false;
  }
  return true;
}

bool S3fsCurl::LoadEnvSseKmsid()
{
  char* envkmsid = getenv("AWSSSEKMSID");
  if(NULL == envkmsid){
    // nothing to do
    return true;
  }
  return S3fsCurl::SetSseKmsid(envkmsid);
}

//
// If md5 is empty, returns first(current) sse key.
//
bool S3fsCurl::GetSseKey(string& md5, string& ssekey)
{
  for(sseckeylist_t::const_iterator iter = S3fsCurl::sseckeys.begin(); iter != S3fsCurl::sseckeys.end(); ++iter){
    if(0 == md5.length() || md5 == (*iter).begin()->first){
      md5    = iter->begin()->first;
      ssekey = iter->begin()->second;
      return true;
    }
  }
  return false;
}

bool S3fsCurl::GetSseKeyMd5(int pos, string& md5)
{
  if(pos < 0){
    return false;
  }
  if(S3fsCurl::sseckeys.size() <= static_cast<size_t>(pos)){
    return false;
  }
  int cnt = 0;
  for(sseckeylist_t::const_iterator iter = S3fsCurl::sseckeys.begin(); iter != S3fsCurl::sseckeys.end(); ++iter, ++cnt){
    if(pos == cnt){
      md5 = iter->begin()->first;
      return true;
    }
  }
  return false;
}

int S3fsCurl::GetSseKeyCount()
{
  return S3fsCurl::sseckeys.size();
}

bool S3fsCurl::SetContentMd5(bool flag)
{
  bool old = S3fsCurl::is_content_md5;
  S3fsCurl::is_content_md5 = flag;
  return old;
}

bool S3fsCurl::SetVerbose(bool flag)
{
  bool old = S3fsCurl::is_verbose;
  S3fsCurl::is_verbose = flag;
  return old;
}

bool S3fsCurl::SetAccessKey(const char* AccessKeyId, const char* SecretAccessKey)
{
  if((!S3fsCurl::is_ibm_iam_auth && (!AccessKeyId || '\0' == AccessKeyId[0])) || !SecretAccessKey || '\0' == SecretAccessKey[0]){
    return false;
  }
  AWSAccessKeyId     = AccessKeyId;
  AWSSecretAccessKey = SecretAccessKey;
  return true;
}

bool S3fsCurl::SetAccessKeyWithSessionToken(const char* AccessKeyId, const char* SecretAccessKey, const char* SessionToken)
{
  bool access_key_is_empty = !AccessKeyId || '\0' == AccessKeyId[0];
  bool secret_access_key_is_empty = !SecretAccessKey || '\0' == SecretAccessKey[0];
  bool session_token_is_empty = !SessionToken || '\0' == SessionToken[0];
  if((!S3fsCurl::is_ibm_iam_auth && access_key_is_empty) || secret_access_key_is_empty || session_token_is_empty){
    return false;
  }
  AWSAccessKeyId     = AccessKeyId;
  AWSSecretAccessKey = SecretAccessKey;
  AWSAccessToken     = SessionToken;
  S3fsCurl::is_use_session_token = true;
  return true;
}

long S3fsCurl::SetSslVerifyHostname(long value)
{
  if(0 != value && 1 != value){
    return -1;
  }
  long old = S3fsCurl::ssl_verify_hostname;
  S3fsCurl::ssl_verify_hostname = value;
  return old;
}

bool S3fsCurl::SetIsIBMIAMAuth(bool flag)
{
  bool old = S3fsCurl::is_ibm_iam_auth;
  S3fsCurl::is_ibm_iam_auth = flag;
  return old;
}

bool S3fsCurl::SetIsECS(bool flag)
{
  bool old = S3fsCurl::is_ecs;
  S3fsCurl::is_ecs = flag;
  return old;
}

string S3fsCurl::SetIAMRole(const char* role)
{
  string old = S3fsCurl::IAM_role;
  S3fsCurl::IAM_role = role ? role : "";
  return old;
}

size_t S3fsCurl::SetIAMFieldCount(size_t field_count)
{
  size_t old = S3fsCurl::IAM_field_count;
  S3fsCurl::IAM_field_count = field_count;
  return old;
}

string S3fsCurl::SetIAMCredentialsURL(const char* url)
{
  string old = S3fsCurl::IAM_cred_url;
  S3fsCurl::IAM_cred_url = url ? url : "";
  return old;
}

string S3fsCurl::SetIAMTokenField(const char* token_field)
{
  string old = S3fsCurl::IAM_token_field;
  S3fsCurl::IAM_token_field = token_field ? token_field : "";
  return old;
}

string S3fsCurl::SetIAMExpiryField(const char* expiry_field)
{
  string old = S3fsCurl::IAM_expiry_field;
  S3fsCurl::IAM_expiry_field = expiry_field ? expiry_field : "";
  return old;
}

bool S3fsCurl::SetMultipartSize(off_t size)
{
  size = size * 1024 * 1024;
  if(size < MIN_MULTIPART_SIZE){
    return false;
  }
  S3fsCurl::multipart_size = size;
  return true;
}

int S3fsCurl::SetMaxParallelCount(int value)
{
  int old = S3fsCurl::max_parallel_cnt;
  S3fsCurl::max_parallel_cnt = value;
  return old;
}

int S3fsCurl::SetMaxMultiRequest(int max)
{
  int old = S3fsCurl::max_multireq;
  S3fsCurl::max_multireq = max;
  return old;
}

bool S3fsCurl::UploadMultipartPostCallback(S3fsCurl* s3fscurl)
{
  if(!s3fscurl){
    return false;
  }

  return s3fscurl->UploadMultipartPostComplete();
}

bool S3fsCurl::MixMultipartPostCallback(S3fsCurl* s3fscurl)
{
  if(!s3fscurl){
    return false;
  }

  return s3fscurl->MixMultipartPostComplete();
}

S3fsCurl* S3fsCurl::UploadMultipartPostRetryCallback(S3fsCurl* s3fscurl)
{
  if(!s3fscurl){
    return NULL;
  }
  // parse and get part_num, upload_id.
  string upload_id;
  string part_num_str;
  int    part_num;
  if(!get_keyword_value(s3fscurl->url, "uploadId", upload_id)){
    return NULL;
  }
  if(!get_keyword_value(s3fscurl->url, "partNumber", part_num_str)){
    return NULL;
  }
  part_num = s3fs_strtoofft(part_num_str.c_str(), /*base=*/ 10);

  if(s3fscurl->retry_count >= S3fsCurl::retries){
    S3FS_PRN_ERR("Over retry count(%d) limit(%s:%d).", s3fscurl->retry_count, s3fscurl->path.c_str(), part_num);
    return NULL;
  }

  // duplicate request
  S3fsCurl* newcurl            = new S3fsCurl(s3fscurl->IsUseAhbe());
  newcurl->partdata.etaglist   = s3fscurl->partdata.etaglist;
  newcurl->partdata.etagpos    = s3fscurl->partdata.etagpos;
  newcurl->partdata.fd         = s3fscurl->partdata.fd;
  newcurl->partdata.startpos   = s3fscurl->b_partdata_startpos;
  newcurl->partdata.size       = s3fscurl->b_partdata_size;
  newcurl->b_partdata_startpos = s3fscurl->b_partdata_startpos;
  newcurl->b_partdata_size     = s3fscurl->b_partdata_size;
  newcurl->retry_count         = s3fscurl->retry_count + 1;
  newcurl->op                  = s3fscurl->op;
  newcurl->type                = s3fscurl->type;

  // setup new curl object
  if(0 != newcurl->UploadMultipartPostSetup(s3fscurl->path.c_str(), part_num, upload_id)){
    S3FS_PRN_ERR("Could not duplicate curl object(%s:%d).", s3fscurl->path.c_str(), part_num);
    delete newcurl;
    return NULL;
  }
  return newcurl;
}

S3fsCurl* S3fsCurl::CopyMultipartPostRetryCallback(S3fsCurl* s3fscurl)
{
  if(!s3fscurl){
    return NULL;
  }
  // parse and get part_num, upload_id.
  string upload_id;
  string part_num_str;
  int    part_num;
  if(!get_keyword_value(s3fscurl->url, "uploadId", upload_id)){
    return NULL;
  }
  if(!get_keyword_value(s3fscurl->url, "partNumber", part_num_str)){
    return NULL;
  }
  part_num = s3fs_strtoofft(part_num_str.c_str(), /*base=*/ 10);

  if(s3fscurl->retry_count >= S3fsCurl::retries){
    S3FS_PRN_ERR("Over retry count(%d) limit(%s:%d).", s3fscurl->retry_count, s3fscurl->path.c_str(), part_num);
    return NULL;
  }

  // duplicate request
  S3fsCurl* newcurl            = new S3fsCurl(s3fscurl->IsUseAhbe());
  newcurl->partdata.etaglist   = s3fscurl->partdata.etaglist;
  newcurl->partdata.etagpos    = s3fscurl->partdata.etagpos;
  newcurl->b_from              = s3fscurl->b_from;
  newcurl->b_meta              = s3fscurl->b_meta;
  newcurl->retry_count         = s3fscurl->retry_count + 1;
  newcurl->op                  = s3fscurl->op;
  newcurl->type                = s3fscurl->type;

  // setup new curl object
  if(0 != newcurl->CopyMultipartPostSetup(s3fscurl->b_from.c_str(), s3fscurl->path.c_str(), part_num, upload_id, s3fscurl->b_meta)){
    S3FS_PRN_ERR("Could not duplicate curl object(%s:%d).", s3fscurl->path.c_str(), part_num);
    delete newcurl;
    return NULL;
  }
  return newcurl;
}

S3fsCurl* S3fsCurl::MixMultipartPostRetryCallback(S3fsCurl* s3fscurl)
{
  if(!s3fscurl){
    return NULL;
  }

  S3fsCurl* pcurl;
  if(-1 == s3fscurl->partdata.fd){
    pcurl = S3fsCurl::CopyMultipartPostRetryCallback(s3fscurl);
  }else{
    pcurl = S3fsCurl::UploadMultipartPostRetryCallback(s3fscurl);
  }
  return pcurl;
}

int S3fsCurl::ParallelMultipartUploadRequest(const char* tpath, headers_t& meta, int fd)
{
  int            result;
  string         upload_id;
  struct stat    st;
  int            fd2;
  etaglist_t     list;
  off_t          remaining_bytes;
  S3fsCurl       s3fscurl(true);

  S3FS_PRN_INFO3("[tpath=%s][fd=%d]", SAFESTRPTR(tpath), fd);

  // duplicate fd
  if(-1 == (fd2 = dup(fd)) || 0 != lseek(fd2, 0, SEEK_SET)){
    S3FS_PRN_ERR("Could not duplicate file descriptor(errno=%d)", errno);
    if(-1 != fd2){
      close(fd2);
    }
    return -errno;
  }
  if(-1 == fstat(fd2, &st)){
    S3FS_PRN_ERR("Invalid file descriptor(errno=%d)", errno);
    close(fd2);
    return -errno;
  }

  if(0 != (result = s3fscurl.PreMultipartPostRequest(tpath, meta, upload_id, false))){
    close(fd2);
    return result;
  }
  s3fscurl.DestroyCurlHandle();

  // Initialize S3fsMultiCurl
  S3fsMultiCurl curlmulti(GetMaxParallelCount());
  curlmulti.SetSuccessCallback(S3fsCurl::UploadMultipartPostCallback);
  curlmulti.SetRetryCallback(S3fsCurl::UploadMultipartPostRetryCallback);

  // cycle through open fd, pulling off 10MB chunks at a time
  for(remaining_bytes = st.st_size; 0 < remaining_bytes; ){
    off_t chunk = remaining_bytes > S3fsCurl::multipart_size ? S3fsCurl::multipart_size : remaining_bytes;

    // s3fscurl sub object
    S3fsCurl* s3fscurl_para            = new S3fsCurl(true);
    s3fscurl_para->partdata.fd         = fd2;
    s3fscurl_para->partdata.startpos   = st.st_size - remaining_bytes;
    s3fscurl_para->partdata.size       = chunk;
    s3fscurl_para->b_partdata_startpos = s3fscurl_para->partdata.startpos;
    s3fscurl_para->b_partdata_size     = s3fscurl_para->partdata.size;
    s3fscurl_para->partdata.add_etag_list(&list);

    // initiate upload part for parallel
    if(0 != (result = s3fscurl_para->UploadMultipartPostSetup(tpath, list.size(), upload_id))){
      S3FS_PRN_ERR("failed uploading part setup(%d)", result);
      close(fd2);
      delete s3fscurl_para;
      return result;
    }

    // set into parallel object
    if(!curlmulti.SetS3fsCurlObject(s3fscurl_para)){
      S3FS_PRN_ERR("Could not make curl object into multi curl(%s).", tpath);
      close(fd2);
      delete s3fscurl_para;
      return -1;
    }

    remaining_bytes -= chunk;
  }

  // Multi request
  if(0 != (result = curlmulti.Request())){
    S3FS_PRN_ERR("error occurred in multi request(errno=%d).", result);

    S3fsCurl s3fscurl_abort(true);
    int result2 = s3fscurl_abort.AbortMultipartUpload(tpath, upload_id);
    s3fscurl_abort.DestroyCurlHandle();
    if(result2 != 0){
      S3FS_PRN_ERR("error aborting multipart upload(errno=%d).", result2);
    }

    return result;
  }

  close(fd2);

  if(0 != (result = s3fscurl.CompleteMultipartPostRequest(tpath, upload_id, list))){
    return result;
  }
  return 0;
}

int S3fsCurl::ParallelMixMultipartUploadRequest(const char* tpath, headers_t& meta, int fd, const PageList& pagelist)
{
  int            result;
  string         upload_id;
  struct stat    st;
  int            fd2;
  etaglist_t     list;
  S3fsCurl       s3fscurl(true);

  S3FS_PRN_INFO3("[tpath=%s][fd=%d]", SAFESTRPTR(tpath), fd);

  // get upload mixed page list
  fdpage_list_t fdplist;
  if(!pagelist.GetMultipartSizeList(fdplist, S3fsCurl::multipart_size)){
    return -1;
  }

  // duplicate fd
  if(-1 == (fd2 = dup(fd)) || 0 != lseek(fd2, 0, SEEK_SET)){
    S3FS_PRN_ERR("Could not duplicate file descriptor(errno=%d)", errno);
    PageList::FreeList(fdplist);
    if(-1 != fd2){
      close(fd2);
    }
    return -errno;
  }
  if(-1 == fstat(fd2, &st)){
    S3FS_PRN_ERR("Invalid file descriptor(errno=%d)", errno);
    PageList::FreeList(fdplist);
    close(fd2);
    return -errno;
  }

  if(0 != (result = s3fscurl.PreMultipartPostRequest(tpath, meta, upload_id, true))){
    PageList::FreeList(fdplist);
    close(fd2);
    return result;
  }
  s3fscurl.DestroyCurlHandle();

  // for copy multipart
  string srcresource;
  string srcurl;
  MakeUrlResource(get_realpath(tpath).c_str(), srcresource, srcurl);
  meta["Content-Type"]      = S3fsCurl::LookupMimeType(string(tpath));
  meta["x-amz-copy-source"] = srcresource;

  // Initialize S3fsMultiCurl
  S3fsMultiCurl curlmulti(GetMaxParallelCount());
  curlmulti.SetSuccessCallback(S3fsCurl::MixMultipartPostCallback);
  curlmulti.SetRetryCallback(S3fsCurl::MixMultipartPostRetryCallback);

  for(fdpage_list_t::const_iterator iter = fdplist.begin(); iter != fdplist.end(); ++iter){
    // s3fscurl sub object
    S3fsCurl* s3fscurl_para              = new S3fsCurl(true);

    if(iter->modified){
      // Multipart upload
      s3fscurl_para->partdata.fd         = fd2;
      s3fscurl_para->partdata.startpos   = iter->offset;
      s3fscurl_para->partdata.size       = iter->bytes;
      s3fscurl_para->b_partdata_startpos = s3fscurl_para->partdata.startpos;
      s3fscurl_para->b_partdata_size     = s3fscurl_para->partdata.size;
      s3fscurl_para->partdata.add_etag_list(&list);

      S3FS_PRN_INFO3("Upload Part [tpath=%s][start=%jd][size=%jd][part=%jd]", SAFESTRPTR(tpath), (intmax_t)(iter->offset), (intmax_t)(iter->bytes), (intmax_t)(list.size()));

      // initiate upload part for parallel
      if(0 != (result = s3fscurl_para->UploadMultipartPostSetup(tpath, list.size(), upload_id))){
        S3FS_PRN_ERR("failed uploading part setup(%d)", result);
        PageList::FreeList(fdplist);
        close(fd2);
        delete s3fscurl_para;
        return result;
      }
    }else{
      // Multipart copy
      ostringstream  strrange;
      strrange << "bytes=" << iter->offset << "-" << (iter->offset + iter->bytes - 1);
      meta["x-amz-copy-source-range"] = strrange.str();
      strrange.str("");
      strrange.clear(stringstream::goodbit);

      s3fscurl_para->b_from   = SAFESTRPTR(tpath);
      s3fscurl_para->b_meta   = meta;
      s3fscurl_para->partdata.add_etag_list(&list);

      S3FS_PRN_INFO3("Copy Part [tpath=%s][start=%jd][size=%jd][part=%jd]", SAFESTRPTR(tpath), (intmax_t)(iter->offset), (intmax_t)(iter->bytes), (intmax_t)(list.size()));

      // initiate upload part for parallel
      if(0 != (result = s3fscurl_para->CopyMultipartPostSetup(tpath, tpath, list.size(), upload_id, meta))){
        S3FS_PRN_ERR("failed uploading part setup(%d)", result);
        close(fd2);
        delete s3fscurl_para;
        return result;
      }
    }

    // set into parallel object
    if(!curlmulti.SetS3fsCurlObject(s3fscurl_para)){
      S3FS_PRN_ERR("Could not make curl object into multi curl(%s).", tpath);
      PageList::FreeList(fdplist);
      close(fd2);
      delete s3fscurl_para;
      return -1;
    }
  }
  PageList::FreeList(fdplist);

  // Multi request
  if(0 != (result = curlmulti.Request())){
    S3FS_PRN_ERR("error occurred in multi request(errno=%d).", result);

    S3fsCurl s3fscurl_abort(true);
    int result2 = s3fscurl_abort.AbortMultipartUpload(tpath, upload_id);
    s3fscurl_abort.DestroyCurlHandle();
    if(result2 != 0){
      S3FS_PRN_ERR("error aborting multipart upload(errno=%d).", result2);
    }
    close(fd2);
    return result;
  }
  close(fd2);

  if(0 != (result = s3fscurl.CompleteMultipartPostRequest(tpath, upload_id, list))){
    return result;
  }
  return 0;
}

S3fsCurl* S3fsCurl::ParallelGetObjectRetryCallback(S3fsCurl* s3fscurl)
{
  int result;

  if(!s3fscurl){
    return NULL;
  }
  if(s3fscurl->retry_count >= S3fsCurl::retries){
    S3FS_PRN_ERR("Over retry count(%d) limit(%s).", s3fscurl->retry_count, s3fscurl->path.c_str());
    return NULL;
  }

  // duplicate request(setup new curl object)
  S3fsCurl* newcurl = new S3fsCurl(s3fscurl->IsUseAhbe());
  if(0 != (result = newcurl->PreGetObjectRequest(s3fscurl->path.c_str(), s3fscurl->partdata.fd,
     s3fscurl->partdata.startpos, s3fscurl->partdata.size, s3fscurl->b_ssetype, s3fscurl->b_ssevalue)))
  {
    S3FS_PRN_ERR("failed downloading part setup(%d)", result);
    delete newcurl;
    return NULL;;
  }
  newcurl->retry_count = s3fscurl->retry_count + 1;

  return newcurl;
}

int S3fsCurl::ParallelGetObjectRequest(const char* tpath, int fd, off_t start, ssize_t size)
{
  S3FS_PRN_INFO3("[tpath=%s][fd=%d]", SAFESTRPTR(tpath), fd);

  sse_type_t ssetype;
  string     ssevalue;
  if(!get_object_sse_type(tpath, ssetype, ssevalue)){
    S3FS_PRN_WARN("Failed to get SSE type for file(%s).", SAFESTRPTR(tpath));
  }
  int        result = 0;
  ssize_t    remaining_bytes;

  // cycle through open fd, pulling off 10MB chunks at a time
  for(remaining_bytes = size; 0 < remaining_bytes; ){
    S3fsMultiCurl curlmulti(GetMaxParallelCount());
    int           para_cnt;
    off_t         chunk;

    // Initialize S3fsMultiCurl
    //curlmulti.SetSuccessCallback(NULL);   // not need to set success callback
    curlmulti.SetRetryCallback(S3fsCurl::ParallelGetObjectRetryCallback);

    // Loop for setup parallel upload(multipart) request.
    for(para_cnt = 0; para_cnt < S3fsCurl::max_parallel_cnt && 0 < remaining_bytes; para_cnt++, remaining_bytes -= chunk){
      // chunk size
      chunk = remaining_bytes > S3fsCurl::multipart_size ? S3fsCurl::multipart_size : remaining_bytes;

      // s3fscurl sub object
      S3fsCurl* s3fscurl_para = new S3fsCurl();
      if(0 != (result = s3fscurl_para->PreGetObjectRequest(tpath, fd, (start + size - remaining_bytes), chunk, ssetype, ssevalue))){
        S3FS_PRN_ERR("failed downloading part setup(%d)", result);
        delete s3fscurl_para;
        return result;
      }

      // set into parallel object
      if(!curlmulti.SetS3fsCurlObject(s3fscurl_para)){
        S3FS_PRN_ERR("Could not make curl object into multi curl(%s).", tpath);
        delete s3fscurl_para;
        return -1;
      }
    }

    // Multi request
    if(0 != (result = curlmulti.Request())){
      S3FS_PRN_ERR("error occurred in multi request(errno=%d).", result);
      break;
    }

    // reinit for loop.
    curlmulti.Clear();
  }
  return result;
}

bool S3fsCurl::UploadMultipartPostSetCurlOpts(S3fsCurl* s3fscurl)
{
  if(!s3fscurl){
    return false;
  }
  if(!s3fscurl->CreateCurlHandle()){
    return false;
  }
  curl_easy_setopt(s3fscurl->hCurl, CURLOPT_URL, s3fscurl->url.c_str());
  curl_easy_setopt(s3fscurl->hCurl, CURLOPT_UPLOAD, true);              // HTTP PUT
  curl_easy_setopt(s3fscurl->hCurl, CURLOPT_WRITEDATA, (void*)(&s3fscurl->bodydata));
  curl_easy_setopt(s3fscurl->hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(s3fscurl->hCurl, CURLOPT_HEADERDATA, (void*)&(s3fscurl->responseHeaders));
  curl_easy_setopt(s3fscurl->hCurl, CURLOPT_HEADERFUNCTION, HeaderCallback);
  curl_easy_setopt(s3fscurl->hCurl, CURLOPT_INFILESIZE_LARGE, static_cast<curl_off_t>(s3fscurl->partdata.size)); // Content-Length
  curl_easy_setopt(s3fscurl->hCurl, CURLOPT_READFUNCTION, UploadReadCallback);
  curl_easy_setopt(s3fscurl->hCurl, CURLOPT_READDATA, (void*)s3fscurl);
  S3fsCurl::AddUserAgent(s3fscurl->hCurl);                            // put User-Agent

  return true;
}

bool S3fsCurl::CopyMultipartPostSetCurlOpts(S3fsCurl* s3fscurl)
{
  if(!s3fscurl){
    return false;
  }
  if(!s3fscurl->CreateCurlHandle()){
    return false;
  }

  curl_easy_setopt(s3fscurl->hCurl, CURLOPT_URL, s3fscurl->url.c_str());
  curl_easy_setopt(s3fscurl->hCurl, CURLOPT_UPLOAD, true);                // HTTP PUT
  curl_easy_setopt(s3fscurl->hCurl, CURLOPT_WRITEDATA, (void*)(&s3fscurl->bodydata));
  curl_easy_setopt(s3fscurl->hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(s3fscurl->hCurl, CURLOPT_HEADERDATA, (void*)(&s3fscurl->headdata));
  curl_easy_setopt(s3fscurl->hCurl, CURLOPT_HEADERFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(s3fscurl->hCurl, CURLOPT_INFILESIZE, 0);               // Content-Length
  S3fsCurl::AddUserAgent(s3fscurl->hCurl);                                // put User-Agent

  return true;
}

bool S3fsCurl::PreGetObjectRequestSetCurlOpts(S3fsCurl* s3fscurl)
{
  if(!s3fscurl){
    return false;
  }
  if(!s3fscurl->CreateCurlHandle()){
    return false;
  }

  curl_easy_setopt(s3fscurl->hCurl, CURLOPT_URL, s3fscurl->url.c_str());
  curl_easy_setopt(s3fscurl->hCurl, CURLOPT_WRITEFUNCTION, DownloadWriteCallback);
  curl_easy_setopt(s3fscurl->hCurl, CURLOPT_WRITEDATA, (void*)s3fscurl);
  S3fsCurl::AddUserAgent(s3fscurl->hCurl);        // put User-Agent

  return true;
}

bool S3fsCurl::PreHeadRequestSetCurlOpts(S3fsCurl* s3fscurl)
{
  if(!s3fscurl){
    return false;
  }
  if(!s3fscurl->CreateCurlHandle()){
    return false;
  }

  curl_easy_setopt(s3fscurl->hCurl, CURLOPT_URL, s3fscurl->url.c_str());
  curl_easy_setopt(s3fscurl->hCurl, CURLOPT_NOBODY, true);   // HEAD
  curl_easy_setopt(s3fscurl->hCurl, CURLOPT_FILETIME, true); // Last-Modified

  // responseHeaders
  curl_easy_setopt(s3fscurl->hCurl, CURLOPT_HEADERDATA, (void*)&(s3fscurl->responseHeaders));
  curl_easy_setopt(s3fscurl->hCurl, CURLOPT_HEADERFUNCTION, HeaderCallback);
  S3fsCurl::AddUserAgent(s3fscurl->hCurl);                   // put User-Agent

  return true;
}

bool S3fsCurl::ParseIAMCredentialResponse(const char* response, iamcredmap_t& keyval)
{
  if(!response){
    return false;
  }
  istringstream sscred(response);
  string        oneline;
  keyval.clear();
  while(getline(sscred, oneline, ',')){
    string::size_type pos;
    string            key;
    string            val;
    if(string::npos != (pos = oneline.find(IAMCRED_ACCESSKEYID))){
      key = IAMCRED_ACCESSKEYID;
    }else if(string::npos != (pos = oneline.find(IAMCRED_SECRETACCESSKEY))){
      key = IAMCRED_SECRETACCESSKEY;
    }else if(string::npos != (pos = oneline.find(S3fsCurl::IAM_token_field))){
      key = S3fsCurl::IAM_token_field;
    }else if(string::npos != (pos = oneline.find(S3fsCurl::IAM_expiry_field))){
      key = S3fsCurl::IAM_expiry_field;
    }else if(string::npos != (pos = oneline.find(IAMCRED_ROLEARN))){
      key = IAMCRED_ROLEARN;
    }else{
      continue;
    }
    if(string::npos == (pos = oneline.find(':', pos + key.length()))){
      continue;
    }

    if(S3fsCurl::is_ibm_iam_auth && key == S3fsCurl::IAM_expiry_field){
      // parse integer value
      if(string::npos == (pos = oneline.find_first_of("0123456789", pos))){
        continue;
      }
      oneline = oneline.substr(pos);
      if(string::npos == (pos = oneline.find_last_of("0123456789"))){
        continue;
      }
      val = oneline.substr(0, pos+1);
    }else{
      // parse string value (starts and ends with quotes)
      if(string::npos == (pos = oneline.find('\"', pos))){
        continue;
      }
      oneline = oneline.substr(pos + sizeof(char));
      if(string::npos == (pos = oneline.find('\"'))){
        continue;
      }
      val = oneline.substr(0, pos);
    }
    keyval[key] = val;
  }
  return true;
}

bool S3fsCurl::SetIAMCredentials(const char* response)
{
  S3FS_PRN_INFO3("IAM credential response = \"%s\"", response);

  iamcredmap_t keyval;

  if(!ParseIAMCredentialResponse(response, keyval)){
    return false;
  }

  if(S3fsCurl::IAM_field_count != keyval.size()){
    return false;
  }

  S3fsCurl::AWSAccessToken       = keyval[string(S3fsCurl::IAM_token_field)];

  if(S3fsCurl::is_ibm_iam_auth){
    S3fsCurl::AWSAccessTokenExpire = s3fs_strtoofft(keyval[string(S3fsCurl::IAM_expiry_field)].c_str(), /*base=*/ 10);
  }else{
    S3fsCurl::AWSAccessKeyId       = keyval[string(IAMCRED_ACCESSKEYID)];
    S3fsCurl::AWSSecretAccessKey   = keyval[string(IAMCRED_SECRETACCESSKEY)];
    S3fsCurl::AWSAccessTokenExpire = cvtIAMExpireStringToTime(keyval[S3fsCurl::IAM_expiry_field].c_str());
  }

  return true;
}

bool S3fsCurl::CheckIAMCredentialUpdate()
{
  if(S3fsCurl::IAM_role.empty() && !S3fsCurl::is_ecs && !S3fsCurl::is_ibm_iam_auth){
    return true;
  }
  if(time(NULL) + IAM_EXPIRE_MERGIN <= S3fsCurl::AWSAccessTokenExpire){
    return true;
  }
  // update
  S3fsCurl s3fscurl;
  if(0 != s3fscurl.GetIAMCredentials()){
    return false;
  }
  return true;
}

bool S3fsCurl::ParseIAMRoleFromMetaDataResponse(const char* response, string& rolename)
{
  if(!response){
    return false;
  }
  // [NOTE]
  // expected following strings.
  // 
  // myrolename
  //
  istringstream ssrole(response);
  string        oneline;
  if (getline(ssrole, oneline, '\n')){
    rolename = oneline;
    return !rolename.empty();
  }
  return false;
}

bool S3fsCurl::SetIAMRoleFromMetaData(const char* response)
{
  S3FS_PRN_INFO3("IAM role name response = \"%s\"", response);

  string rolename;

  if(!S3fsCurl::ParseIAMRoleFromMetaDataResponse(response, rolename)){
    return false;
  }

  SetIAMRole(rolename.c_str());
  return true;
}

bool S3fsCurl::AddUserAgent(CURL* hCurl)
{
  if(!hCurl){
    return false;
  }
  if(S3fsCurl::IsUserAgentFlag()){
    curl_easy_setopt(hCurl, CURLOPT_USERAGENT, S3fsCurl::userAgent.c_str());
  }
  return true;
}

int S3fsCurl::CurlDebugFunc(CURL* hcurl, curl_infotype type, char* data, size_t size, void* userptr)
{
  if(!hcurl){
    // something wrong...
    return 0;
  }
  switch(type){
    case CURLINFO_TEXT:
      // Swap tab indentation with spaces so it stays pretty in syslog
      int indent;
      indent = 0;
      while (*data == '\t' && size > 0) {
        indent += 4;
        size--;
        data++;
      }
      S3FS_PRN_CURL("* %*s%.*s", indent, "", (int)size, data);
      break;
    case CURLINFO_HEADER_IN:
    case CURLINFO_HEADER_OUT:
      size_t remaining;
      char* p;

      // Print each line individually for tidy output
      remaining = size;
      p = data;
      do {
        char* eol = (char*)memchr(p, '\n', remaining);
        int newline = 0;
        if (eol == NULL) {
          eol = (char*)memchr(p, '\r', remaining);
        } else {
          if (eol > p && *(eol - 1) == '\r') {
            newline++;
          }
          newline++;
          eol++;
        }
        size_t length = eol - p;
        S3FS_PRN_CURL("%c %.*s", CURLINFO_HEADER_IN == type ? '<' : '>', (int)length - newline, p);
        remaining -= length;
        p = eol;
      } while (p != NULL && remaining > 0);
      break;
    case CURLINFO_DATA_IN:
    case CURLINFO_DATA_OUT:
    case CURLINFO_SSL_DATA_IN:
    case CURLINFO_SSL_DATA_OUT:
      // not put
      break;
    default:
      // why
      break;
  }
  return 0;
}

//-------------------------------------------------------------------
// Methods for S3fsCurl
//-------------------------------------------------------------------
S3fsCurl::S3fsCurl(bool ahbe) : 
    hCurl(NULL), type(REQTYPE_UNSET), path(""), base_path(""), saved_path(""), url(""), requestHeaders(NULL),
    LastResponseCode(S3FSCURL_RESPONSECODE_NOTSET), postdata(NULL), postdata_remaining(0), is_use_ahbe(ahbe),
    retry_count(0), b_infile(NULL), b_postdata(NULL), b_postdata_remaining(0), b_partdata_startpos(0), b_partdata_size(0),
    b_ssekey_pos(-1), b_ssevalue(""), b_ssetype(SSE_DISABLE), op(""), query_string(""),
    sem(NULL), completed_tids_lock(NULL), completed_tids(NULL), fpLazySetup(NULL)
{
}

S3fsCurl::~S3fsCurl()
{
  DestroyCurlHandle();
}

bool S3fsCurl::ResetHandle()
{
  static volatile bool run_once = false;  // emit older curl warnings only once
  curl_easy_reset(hCurl);
  curl_easy_setopt(hCurl, CURLOPT_NOSIGNAL, 1);
  curl_easy_setopt(hCurl, CURLOPT_FOLLOWLOCATION, true);
  curl_easy_setopt(hCurl, CURLOPT_CONNECTTIMEOUT, S3fsCurl::connect_timeout);
  curl_easy_setopt(hCurl, CURLOPT_NOPROGRESS, 0);
  curl_easy_setopt(hCurl, CURLOPT_PROGRESSFUNCTION, S3fsCurl::CurlProgress);
  curl_easy_setopt(hCurl, CURLOPT_PROGRESSDATA, hCurl);
  // curl_easy_setopt(hCurl, CURLOPT_FORBID_REUSE, 1);
  if(CURLE_OK != curl_easy_setopt(hCurl, S3FS_CURLOPT_TCP_KEEPALIVE, 1) && !run_once){
    S3FS_PRN_WARN("The CURLOPT_TCP_KEEPALIVE option could not be set. For maximize performance you need to enable this option and you should use libcurl 7.25.0 or later.");
  }
  if(CURLE_OK != curl_easy_setopt(hCurl, S3FS_CURLOPT_SSL_ENABLE_ALPN, 0) && !run_once){
    S3FS_PRN_WARN("The CURLOPT_SSL_ENABLE_ALPN option could not be unset. S3 server does not support ALPN, then this option should be disabled to maximize performance. you need to use libcurl 7.36.0 or later.");
  }
  if(CURLE_OK != curl_easy_setopt(hCurl, S3FS_CURLOPT_KEEP_SENDING_ON_ERROR, 1) && !run_once){
    S3FS_PRN_WARN("The S3FS_CURLOPT_KEEP_SENDING_ON_ERROR option could not be set. For maximize performance you need to enable this option and you should use libcurl 7.51.0 or later.");
  }
  run_once = true;

  if(type != REQTYPE_IAMCRED && type != REQTYPE_IAMROLE){
    // REQTYPE_IAMCRED and REQTYPE_IAMROLE are always HTTP
    if(0 == S3fsCurl::ssl_verify_hostname){
      curl_easy_setopt(hCurl, CURLOPT_SSL_VERIFYHOST, 0);
    }
    if(!S3fsCurl::curl_ca_bundle.empty()){
      curl_easy_setopt(hCurl, CURLOPT_CAINFO, S3fsCurl::curl_ca_bundle.c_str());
    }
  }
  if((S3fsCurl::is_dns_cache || S3fsCurl::is_ssl_session_cache) && S3fsCurl::hCurlShare){
    curl_easy_setopt(hCurl, CURLOPT_SHARE, S3fsCurl::hCurlShare);
  }
  if(!S3fsCurl::is_cert_check) {
    S3FS_PRN_DBG("'no_check_certificate' option in effect.");
    S3FS_PRN_DBG("The server certificate won't be checked against the available certificate authorities.");
    curl_easy_setopt(hCurl, CURLOPT_SSL_VERIFYPEER, false);
  }
  if(S3fsCurl::is_verbose){
    curl_easy_setopt(hCurl, CURLOPT_VERBOSE, true);
    if(!foreground){
      curl_easy_setopt(hCurl, CURLOPT_DEBUGFUNCTION, S3fsCurl::CurlDebugFunc);
    }
  }
  if(!cipher_suites.empty()) {
    curl_easy_setopt(hCurl, CURLOPT_SSL_CIPHER_LIST, cipher_suites.c_str());
  }

  S3fsCurl::curl_times[hCurl]    = time(0);
  S3fsCurl::curl_progress[hCurl] = progress_t(-1, -1);

  return true;
}

bool S3fsCurl::CreateCurlHandle(bool only_pool, bool remake)
{
  AutoLock lock(&S3fsCurl::curl_handles_lock);

  if(hCurl && remake){
    if(!DestroyCurlHandle(false)){
      S3FS_PRN_ERR("could not destroy handle.");
      return false;
    }
    S3FS_PRN_INFO3("already has handle, so destroyed it or restored it to pool.");
  }

  if(!hCurl){
    if(NULL == (hCurl = sCurlPool->GetHandler(only_pool))){
      if(!only_pool){
        S3FS_PRN_ERR("Failed to create handle.");
        return false;
      }else{
        // [NOTE]
        // Further initialization processing is left to lazy processing to be executed later.
        // (Currently we do not use only_pool=true, but this code is remained for the future)
        return true;
      }
    }
  }

  ResetHandle();

  return true;
}

bool S3fsCurl::DestroyCurlHandle(bool restore_pool, bool clear_internal_data)
{
  // [NOTE]
  // If type is REQTYPE_IAMCRED or REQTYPE_IAMROLE, do not clear type.
  // Because that type only uses HTTP protocol, then the special
  // logic in ResetHandle function.
  //
  if(type != REQTYPE_IAMCRED && type != REQTYPE_IAMROLE){
    type = REQTYPE_UNSET;
  }

  if(clear_internal_data){
    ClearInternalData();
  }

  if(hCurl){
    AutoLock lock(&S3fsCurl::curl_handles_lock);

    S3fsCurl::curl_times.erase(hCurl);
    S3fsCurl::curl_progress.erase(hCurl);
    sCurlPool->ReturnHandler(hCurl, restore_pool);
    hCurl = NULL;
  }else{
    return false;
  }
  return true;
}

bool S3fsCurl::ClearInternalData()
{
  // Always clear internal data
  //
  type        = REQTYPE_UNSET;
  path        = "";
  base_path   = "";
  saved_path  = "";
  url         = "";
  op          = "";
  query_string= "";
  if(requestHeaders){
    curl_slist_free_all(requestHeaders);
    requestHeaders = NULL;
  }
  responseHeaders.clear();
  bodydata.Clear();
  headdata.Clear();
  LastResponseCode     = S3FSCURL_RESPONSECODE_NOTSET;
  postdata             = NULL;
  postdata_remaining   = 0;
  retry_count          = 0;
  b_infile             = NULL;
  b_postdata           = NULL;
  b_postdata_remaining = 0;
  b_partdata_startpos  = 0;
  b_partdata_size      = 0;
  partdata.clear();

  fpLazySetup          = NULL;

  S3FS_MALLOCTRIM(0);

  return true;
}

bool S3fsCurl::SetUseAhbe(bool ahbe)
{
  bool old = is_use_ahbe;
  is_use_ahbe = ahbe;
  return old;
}

bool S3fsCurl::GetResponseCode(long& responseCode, bool from_curl_handle)
{
  responseCode = -1;

  if(!from_curl_handle){
    responseCode = LastResponseCode;
  }else{
    if(!hCurl){
      return false;
    }
    if(CURLE_OK != curl_easy_getinfo(hCurl, CURLINFO_RESPONSE_CODE, &LastResponseCode)){
      return false;
    }
    responseCode = LastResponseCode;
  }
  return true;
}

//
// Reset all options for retrying
//
bool S3fsCurl::RemakeHandle()
{
  S3FS_PRN_INFO3("Retry request. [type=%d][url=%s][path=%s]", type, url.c_str(), path.c_str());

  if(REQTYPE_UNSET == type){
    return false;
  }

  // rewind file
  struct stat st;
  if(b_infile){
    rewind(b_infile);
    if(-1 == fstat(fileno(b_infile), &st)){
      S3FS_PRN_WARN("Could not get file stat(fd=%d)", fileno(b_infile));
      return false;
    }
  }

  // reinitialize internal data
  responseHeaders.clear();
  bodydata.Clear();
  headdata.Clear();
  LastResponseCode   = S3FSCURL_RESPONSECODE_NOTSET;

  // count up(only use for multipart)
  retry_count++;

  // set from backup
  postdata           = b_postdata;
  postdata_remaining = b_postdata_remaining;
  partdata.startpos  = b_partdata_startpos;
  partdata.size      = b_partdata_size;

  // reset handle
  ResetHandle();

  // set options
  switch(type){
    case REQTYPE_DELETE:
      curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
      curl_easy_setopt(hCurl, CURLOPT_CUSTOMREQUEST, "DELETE");
      break;

    case REQTYPE_HEAD:
      curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
      curl_easy_setopt(hCurl, CURLOPT_NOBODY, true);
      curl_easy_setopt(hCurl, CURLOPT_FILETIME, true);
      // responseHeaders
      curl_easy_setopt(hCurl, CURLOPT_HEADERDATA, (void*)&responseHeaders);
      curl_easy_setopt(hCurl, CURLOPT_HEADERFUNCTION, HeaderCallback);
      break;

    case REQTYPE_PUTHEAD:
      curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
      curl_easy_setopt(hCurl, CURLOPT_UPLOAD, true);
      curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, (void*)&bodydata);
      curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
      curl_easy_setopt(hCurl, CURLOPT_INFILESIZE, 0);
      break;

    case REQTYPE_PUT:
      curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
      curl_easy_setopt(hCurl, CURLOPT_UPLOAD, true);
      curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, (void*)&bodydata);
      curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
      if(b_infile){
        curl_easy_setopt(hCurl, CURLOPT_INFILESIZE_LARGE, static_cast<curl_off_t>(st.st_size));
        curl_easy_setopt(hCurl, CURLOPT_INFILE, b_infile);
      }else{
        curl_easy_setopt(hCurl, CURLOPT_INFILESIZE, 0);
      }
      break;

    case REQTYPE_GET:
      curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
      curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, S3fsCurl::DownloadWriteCallback);
      curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, (void*)this);
      break;

    case REQTYPE_CHKBUCKET:
      curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
      curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, (void*)&bodydata);
      curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
      break;

    case REQTYPE_LISTBUCKET:
      curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
      curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, (void*)&bodydata);
      curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
      break;

    case REQTYPE_PREMULTIPOST:
      curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
      curl_easy_setopt(hCurl, CURLOPT_POST, true);
      curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, (void*)&bodydata);
      curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
      curl_easy_setopt(hCurl, CURLOPT_POSTFIELDSIZE, 0);
      break;

    case REQTYPE_COMPLETEMULTIPOST:
      curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
      curl_easy_setopt(hCurl, CURLOPT_POST, true);
      curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, (void*)&bodydata);
      curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
      curl_easy_setopt(hCurl, CURLOPT_POSTFIELDSIZE, static_cast<curl_off_t>(postdata_remaining));
      curl_easy_setopt(hCurl, CURLOPT_READDATA, (void*)this);
      curl_easy_setopt(hCurl, CURLOPT_READFUNCTION, S3fsCurl::ReadCallback);
      break;

    case REQTYPE_UPLOADMULTIPOST:
      curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
      curl_easy_setopt(hCurl, CURLOPT_UPLOAD, true);
      curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, (void*)&bodydata);
      curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
      curl_easy_setopt(hCurl, CURLOPT_HEADERDATA, (void*)&responseHeaders);
      curl_easy_setopt(hCurl, CURLOPT_HEADERFUNCTION, HeaderCallback);
      curl_easy_setopt(hCurl, CURLOPT_INFILESIZE_LARGE, static_cast<curl_off_t>(partdata.size));
      curl_easy_setopt(hCurl, CURLOPT_READFUNCTION, S3fsCurl::UploadReadCallback);
      curl_easy_setopt(hCurl, CURLOPT_READDATA, (void*)this);
      break;

    case REQTYPE_COPYMULTIPOST:
      curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
      curl_easy_setopt(hCurl, CURLOPT_UPLOAD, true);
      curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, (void*)&bodydata);
      curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
      curl_easy_setopt(hCurl, CURLOPT_HEADERDATA, (void*)&headdata);
      curl_easy_setopt(hCurl, CURLOPT_HEADERFUNCTION, WriteMemoryCallback);
      curl_easy_setopt(hCurl, CURLOPT_INFILESIZE, 0);
      break;

    case REQTYPE_MULTILIST:
      curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
      curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, (void*)&bodydata);
      curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
      break;

    case REQTYPE_IAMCRED:
      curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
      curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, (void*)&bodydata);
      curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
      if(S3fsCurl::is_ibm_iam_auth){
        curl_easy_setopt(hCurl, CURLOPT_POST, true);
        curl_easy_setopt(hCurl, CURLOPT_POSTFIELDSIZE, static_cast<curl_off_t>(postdata_remaining));
        curl_easy_setopt(hCurl, CURLOPT_READDATA, (void*)this);
        curl_easy_setopt(hCurl, CURLOPT_READFUNCTION, S3fsCurl::ReadCallback);
      }
      break;

    case REQTYPE_ABORTMULTIUPLOAD:
      curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
      curl_easy_setopt(hCurl, CURLOPT_CUSTOMREQUEST, "DELETE");
      break;

    case REQTYPE_IAMROLE:
      curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
      curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, (void*)&bodydata);
      curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
      break;

    default:
      S3FS_PRN_ERR("request type is unknown(%d)", type);
      return false;
  }
  S3fsCurl::AddUserAgent(hCurl);        // put User-Agent

  return true;
}

//
// returns curl return code
//
int S3fsCurl::RequestPerform()
{
  if(IS_S3FS_LOG_DBG()){
    char* ptr_url = NULL;
    curl_easy_getinfo(hCurl, CURLINFO_EFFECTIVE_URL , &ptr_url);
    S3FS_PRN_DBG("connecting to URL %s", SAFESTRPTR(ptr_url));
  }

  LastResponseCode  = S3FSCURL_RESPONSECODE_NOTSET;
  long responseCode;
  int result        = S3FSCURL_PERFORM_RESULT_NOTSET;

  insertAuthHeaders();
  curl_easy_setopt(hCurl, CURLOPT_HTTPHEADER, requestHeaders);

  // 1 attempt + retries...
  for(int retrycnt = 0; S3FSCURL_PERFORM_RESULT_NOTSET == result && retrycnt < S3fsCurl::retries; ++retrycnt){
    // Reset response code
    responseCode = S3FSCURL_RESPONSECODE_NOTSET;

    // Requests
    CURLcode curlCode = curl_easy_perform(hCurl);

    // Check result
    switch(curlCode){
      case CURLE_OK:
        // Need to look at the HTTP response code
        if(0 != curl_easy_getinfo(hCurl, CURLINFO_RESPONSE_CODE, &responseCode)){
          S3FS_PRN_ERR("curl_easy_getinfo failed while trying to retrieve HTTP response code");
          responseCode = S3FSCURL_RESPONSECODE_FATAL_ERROR;
          result       = -EIO;
          break;
        }
        if(responseCode >= 200 && responseCode < 300){
          S3FS_PRN_INFO3("HTTP response code %ld", responseCode);
          result = 0;
          break;
        }

        // Service response codes which are >= 300 && < 500
        switch(responseCode){
          case 301:
          case 307:
            S3FS_PRN_ERR("HTTP response code 301(Moved Permanently: also happens when bucket's region is incorrect), returning EIO. Body Text: %s", bodydata.str());
            S3FS_PRN_ERR("The options of url and endpoint may be useful for solving, please try to use both options.");
            result = -EIO;
            break;

          case 400:
            S3FS_PRN_ERR("HTTP response code %ld, returning EIO. Body Text: %s", responseCode, bodydata.str());
            result = -EIO;
            break;

          case 403:
            S3FS_PRN_ERR("HTTP response code %ld, returning EPERM. Body Text: %s", responseCode, bodydata.str());
            result = -EPERM;
            break;

          case 404:
            S3FS_PRN_INFO3("HTTP response code 404 was returned, returning ENOENT");
            S3FS_PRN_DBG("Body Text: %s", bodydata.str());
            result = -ENOENT;
            break;

          case 501:
            S3FS_PRN_INFO3("HTTP response code 501 was returned, returning ENOTSUP");
            S3FS_PRN_DBG("Body Text: %s", bodydata.str());
            result = -ENOTSUP;
            break;

          case 503:
            S3FS_PRN_INFO3("HTTP response code 503 was returned, slowing down");
            S3FS_PRN_DBG("Body Text: %s", bodydata.str());
            sleep(4 << retry_count);
            break;

          default:
            S3FS_PRN_ERR("HTTP response code %ld, returning EIO. Body Text: %s", responseCode, bodydata.str());
            result = -EIO;
            break;
        }
        break;

      case CURLE_WRITE_ERROR:
        S3FS_PRN_ERR("### CURLE_WRITE_ERROR");
        sleep(2);
        break; 

      case CURLE_OPERATION_TIMEDOUT:
        S3FS_PRN_ERR("### CURLE_OPERATION_TIMEDOUT");
        sleep(2);
        break; 

      case CURLE_COULDNT_RESOLVE_HOST:
        S3FS_PRN_ERR("### CURLE_COULDNT_RESOLVE_HOST");
        sleep(2);
        break; 

      case CURLE_COULDNT_CONNECT:
        S3FS_PRN_ERR("### CURLE_COULDNT_CONNECT");
        sleep(4);
        break; 

      case CURLE_GOT_NOTHING:
        S3FS_PRN_ERR("### CURLE_GOT_NOTHING");
        sleep(4);
        break; 

      case CURLE_ABORTED_BY_CALLBACK:
        S3FS_PRN_ERR("### CURLE_ABORTED_BY_CALLBACK");
        sleep(4);
        S3fsCurl::curl_times[hCurl] = time(0);
        break; 

      case CURLE_PARTIAL_FILE:
        S3FS_PRN_ERR("### CURLE_PARTIAL_FILE");
        sleep(4);
        break; 

      case CURLE_SEND_ERROR:
        S3FS_PRN_ERR("### CURLE_SEND_ERROR");
        sleep(2);
        break;

      case CURLE_RECV_ERROR:
        S3FS_PRN_ERR("### CURLE_RECV_ERROR");
        sleep(2);
        break;

      case CURLE_SSL_CONNECT_ERROR:
        S3FS_PRN_ERR("### CURLE_SSL_CONNECT_ERROR");
        sleep(2);
        break;

      case CURLE_SSL_CACERT:
        S3FS_PRN_ERR("### CURLE_SSL_CACERT");

        // try to locate cert, if successful, then set the
        // option and continue
        if(S3fsCurl::curl_ca_bundle.empty()){
          if(!S3fsCurl::LocateBundle()){
            S3FS_PRN_ERR("could not get CURL_CA_BUNDLE.");
            result = -EIO;
          }
          // retry with CAINFO
        }else{
          S3FS_PRN_ERR("curlCode: %d  msg: %s", curlCode, curl_easy_strerror(curlCode));
          result = -EIO;
        }
        break;

#ifdef CURLE_PEER_FAILED_VERIFICATION
      case CURLE_PEER_FAILED_VERIFICATION:
        S3FS_PRN_ERR("### CURLE_PEER_FAILED_VERIFICATION");

        first_pos = bucket.find_first_of(".");
        if(first_pos != string::npos){
          S3FS_PRN_INFO("curl returned a CURL_PEER_FAILED_VERIFICATION error");
          S3FS_PRN_INFO("security issue found: buckets with periods in their name are incompatible with http");
          S3FS_PRN_INFO("This check can be over-ridden by using the -o ssl_verify_hostname=0");
          S3FS_PRN_INFO("The certificate will still be checked but the hostname will not be verified.");
          S3FS_PRN_INFO("A more secure method would be to use a bucket name without periods.");
        }else{
          S3FS_PRN_INFO("my_curl_easy_perform: curlCode: %d -- %s", curlCode, curl_easy_strerror(curlCode));
        }
        result = -EIO;
        break;
#endif

      // This should be invalid since curl option HTTP FAILONERROR is now off
      case CURLE_HTTP_RETURNED_ERROR:
        S3FS_PRN_ERR("### CURLE_HTTP_RETURNED_ERROR");

        if(0 != curl_easy_getinfo(hCurl, CURLINFO_RESPONSE_CODE, &responseCode)){
          result = -EIO;
        }else{
          S3FS_PRN_INFO3("HTTP response code =%ld", responseCode);

          // Let's try to retrieve the 
          if(404 == responseCode){
            result = -ENOENT;
          }else if(500 > responseCode){
            result = -EIO;
          }
        }
        break;

      // Unknown CURL return code
      default:
        S3FS_PRN_ERR("###curlCode: %d  msg: %s", curlCode, curl_easy_strerror(curlCode));
        result = -EIO;
        break;
    }

    if(S3FSCURL_PERFORM_RESULT_NOTSET == result){
      S3FS_PRN_INFO("### retrying...");

      if(!RemakeHandle()){
        S3FS_PRN_INFO("Failed to reset handle and internal data for retrying.");
        result = -EIO;
        break;
      }
    }
  }

  // set last response code
  if(S3FSCURL_RESPONSECODE_NOTSET == responseCode){
    LastResponseCode = S3FSCURL_RESPONSECODE_FATAL_ERROR;
  }else{
    LastResponseCode = responseCode;
  }

  if(S3FSCURL_PERFORM_RESULT_NOTSET == result){
    S3FS_PRN_ERR("### giving up");
    result = -EIO;
  }
  return result;
}

//
// Returns the Amazon AWS signature for the given parameters.
//
// @param method e.g., "GET"
// @param content_type e.g., "application/x-directory"
// @param date e.g., get_date_rfc850()
// @param resource e.g., "/pub"
//
string S3fsCurl::CalcSignatureV2(const string& method, const string& strMD5, const string& content_type, const string& date, const string& resource)
{
  string Signature;
  string StringToSign;

  if(!S3fsCurl::IAM_role.empty() || S3fsCurl::is_ecs || S3fsCurl::is_use_session_token){
    requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-security-token", S3fsCurl::AWSAccessToken.c_str());
  }

  StringToSign += method + "\n";
  StringToSign += strMD5 + "\n";        // md5
  StringToSign += content_type + "\n";
  StringToSign += date + "\n";
  StringToSign += get_canonical_headers(requestHeaders, true);
  StringToSign += resource;

  const void* key            = S3fsCurl::AWSSecretAccessKey.data();
  int key_len                = S3fsCurl::AWSSecretAccessKey.size();
  const unsigned char* sdata = reinterpret_cast<const unsigned char*>(StringToSign.data());
  int sdata_len              = StringToSign.size();
  unsigned char* md          = NULL;
  unsigned int md_len        = 0;;

  s3fs_HMAC(key, key_len, sdata, sdata_len, &md, &md_len);

  char* base64;
  if(NULL == (base64 = s3fs_base64(md, md_len))){
    delete[] md;
    return string("");  // ENOMEM
  }
  delete[] md;

  Signature = base64;
  delete[] base64;

  return Signature;
}

string S3fsCurl::CalcSignature(const string& method, const string& canonical_uri, const string& query_string, const string& strdate, const string& payload_hash, const string& date8601)
{
  string Signature, StringCQ, StringToSign;
  string uriencode;

  if(!S3fsCurl::IAM_role.empty()  || S3fsCurl::is_ecs || S3fsCurl::is_use_session_token){
    requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-security-token", S3fsCurl::AWSAccessToken.c_str());
  }

  uriencode = urlEncode(canonical_uri);
  StringCQ  = method + "\n";
  if(0 == strcmp(method.c_str(),"HEAD") || 0 == strcmp(method.c_str(),"PUT") || 0 == strcmp(method.c_str(),"DELETE")){
    StringCQ += uriencode + "\n";
  }else if (0 == strcmp(method.c_str(), "GET") && 0 == strcmp(uriencode.c_str(), "")) {
    StringCQ +="/\n";
  }else if (0 == strcmp(method.c_str(), "GET") && 0 == strncmp(uriencode.c_str(), "/", 1)) {
    StringCQ += uriencode +"\n";
  }else if (0 == strcmp(method.c_str(), "GET") && 0 != strncmp(uriencode.c_str(), "/", 1)) {
    StringCQ += "/\n" + urlEncode2(canonical_uri) +"\n";
  }else if (0 == strcmp(method.c_str(), "POST")) {
    StringCQ += uriencode + "\n";
  }
  StringCQ += urlEncode2(query_string) + "\n";
  StringCQ += get_canonical_headers(requestHeaders) + "\n";
  StringCQ += get_sorted_header_keys(requestHeaders) + "\n";
  StringCQ += payload_hash;

  char          kSecret[128];
  unsigned char *kDate, *kRegion, *kService, *kSigning, *sRequest               = NULL;
  unsigned int  kDate_len,kRegion_len, kService_len, kSigning_len, sRequest_len = 0;
  char          hexsRequest[64 + 1];
  int           kSecret_len = snprintf(kSecret, sizeof(kSecret), "AWS4%s", S3fsCurl::AWSSecretAccessKey.c_str());
  unsigned int  cnt;

  s3fs_HMAC256(kSecret, kSecret_len, reinterpret_cast<const unsigned char*>(strdate.data()), strdate.size(), &kDate, &kDate_len);
  s3fs_HMAC256(kDate, kDate_len, reinterpret_cast<const unsigned char*>(endpoint.c_str()), endpoint.size(), &kRegion, &kRegion_len);
  s3fs_HMAC256(kRegion, kRegion_len, reinterpret_cast<const unsigned char*>("s3"), sizeof("s3") - 1, &kService, &kService_len);
  s3fs_HMAC256(kService, kService_len, reinterpret_cast<const unsigned char*>("aws4_request"), sizeof("aws4_request") - 1, &kSigning, &kSigning_len);
  delete[] kDate;
  delete[] kRegion;
  delete[] kService;

  const unsigned char* cRequest     = reinterpret_cast<const unsigned char*>(StringCQ.c_str());
  unsigned int         cRequest_len = StringCQ.size();
  s3fs_sha256(cRequest, cRequest_len, &sRequest, &sRequest_len);
  for(cnt = 0; cnt < sRequest_len; cnt++){
    sprintf(&hexsRequest[cnt * 2], "%02x", sRequest[cnt]);
  }
  delete[] sRequest;

  StringToSign  = "AWS4-HMAC-SHA256\n";
  StringToSign += date8601 + "\n";
  StringToSign += strdate + "/" + endpoint + "/s3/aws4_request\n";
  StringToSign += hexsRequest;

  const unsigned char* cscope     = reinterpret_cast<const unsigned char*>(StringToSign.c_str());
  unsigned int         cscope_len = StringToSign.size();
  unsigned char*       md         = NULL;
  unsigned int         md_len     = 0;

  s3fs_HMAC256(kSigning, kSigning_len, cscope, cscope_len, &md, &md_len);
  char *hexSig = new char[2 * md_len + 1];
  for(cnt = 0; cnt < md_len; cnt++){
    sprintf(&hexSig[cnt * 2], "%02x", md[cnt]);
  }
  delete[] kSigning;
  delete[] md;

  Signature = hexSig;
  delete[] hexSig;

  return Signature;
}

void S3fsCurl::insertV4Headers()
{
  string server_path = type == REQTYPE_LISTBUCKET ? "/" : path;
  string payload_hash;
  switch (type) {
    case REQTYPE_PUT:
      payload_hash = s3fs_sha256sum(b_infile == NULL ? -1 : fileno(b_infile), 0, -1);
      break;

    case REQTYPE_COMPLETEMULTIPOST:
    {
      unsigned int         cRequest_len = strlen(reinterpret_cast<const char *>(b_postdata));
      unsigned char*       sRequest     = NULL;
      unsigned int         sRequest_len = 0;
      char                 hexsRequest[64 + 1];
      unsigned int         cnt;
      s3fs_sha256(b_postdata, cRequest_len, &sRequest, &sRequest_len);
      for(cnt = 0; cnt < sRequest_len; cnt++){
        sprintf(&hexsRequest[cnt * 2], "%02x", sRequest[cnt]);
      }
      delete[] sRequest;
      payload_hash.assign(hexsRequest, &hexsRequest[sRequest_len * 2]);
      break;
    }

    case REQTYPE_UPLOADMULTIPOST:
      payload_hash = s3fs_sha256sum(partdata.fd, partdata.startpos, partdata.size);
      break;
    default:
      break;
  }

  S3FS_PRN_INFO3("computing signature [%s] [%s] [%s] [%s]", op.c_str(), server_path.c_str(), query_string.c_str(), payload_hash.c_str());
  string strdate;
  string date8601;
  get_date_sigv3(strdate, date8601);

  string contentSHA256 = payload_hash.empty() ? empty_payload_hash : payload_hash;
  const std::string realpath = pathrequeststyle ? "/" + bucket + server_path : server_path;

  //string canonical_headers, signed_headers;
  requestHeaders = curl_slist_sort_insert(requestHeaders, "host", get_bucket_host().c_str());
  requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-content-sha256", contentSHA256.c_str());
  requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-date", date8601.c_str());
	
  if(!S3fsCurl::IsPublicBucket()){
    string Signature = CalcSignature(op, realpath, query_string + (type == REQTYPE_PREMULTIPOST || type == REQTYPE_MULTILIST ? "=" : ""), strdate, contentSHA256, date8601);
    string auth = "AWS4-HMAC-SHA256 Credential=" + AWSAccessKeyId + "/" + strdate + "/" + endpoint +
        "/s3/aws4_request, SignedHeaders=" + get_sorted_header_keys(requestHeaders) + ", Signature=" + Signature;
    requestHeaders = curl_slist_sort_insert(requestHeaders, "Authorization", auth.c_str());
  }
}

void S3fsCurl::insertV2Headers()
{
  string resource;
  string turl;
  string server_path = type == REQTYPE_LISTBUCKET ? "/" : path;
  MakeUrlResource(server_path.c_str(), resource, turl);
  if(!query_string.empty() && type != REQTYPE_LISTBUCKET){
    resource += "?" + query_string;
  }

  string date    = get_date_rfc850();
  requestHeaders = curl_slist_sort_insert(requestHeaders, "Date", date.c_str());
  if(op != "PUT" && op != "POST"){
      requestHeaders = curl_slist_sort_insert(requestHeaders, "Content-Type", NULL);
  }

  if(!S3fsCurl::IsPublicBucket()){
    string Signature = CalcSignatureV2(op, get_header_value(requestHeaders, "Content-MD5"), get_header_value(requestHeaders, "Content-Type"), date, resource);
    requestHeaders   = curl_slist_sort_insert(requestHeaders, "Authorization", string("AWS " + AWSAccessKeyId + ":" + Signature).c_str());
  }
}

void S3fsCurl::insertIBMIAMHeaders()
{
  requestHeaders = curl_slist_sort_insert(requestHeaders, "Authorization", ("Bearer " + S3fsCurl::AWSAccessToken).c_str());

  if(op == "PUT" && path == mount_prefix + "/"){
    // ibm-service-instance-id header is required for bucket creation requests
    requestHeaders = curl_slist_sort_insert(requestHeaders, "ibm-service-instance-id", S3fsCurl::AWSAccessKeyId.c_str());
  }
}

void S3fsCurl::insertAuthHeaders()
{
  if(!S3fsCurl::CheckIAMCredentialUpdate()){
    S3FS_PRN_ERR("An error occurred in checking IAM credential.");
    return; // do not insert auth headers on error
  }

  if(S3fsCurl::is_ibm_iam_auth){
    insertIBMIAMHeaders();
  }else if(!S3fsCurl::is_sigv4){
    insertV2Headers();
  }else{
    insertV4Headers();
  }
}

int S3fsCurl::DeleteRequest(const char* tpath)
{
  S3FS_PRN_INFO3("[tpath=%s]", SAFESTRPTR(tpath));

  if(!tpath){
    return -1;
  }
  if(!CreateCurlHandle()){
    return -1;
  }
  string resource;
  string turl;
  MakeUrlResource(get_realpath(tpath).c_str(), resource, turl);

  url             = prepare_url(turl.c_str());
  path            = get_realpath(tpath);
  requestHeaders  = NULL;
  responseHeaders.clear();

  op = "DELETE";
  type = REQTYPE_DELETE;

  curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(hCurl, CURLOPT_CUSTOMREQUEST, "DELETE");
  S3fsCurl::AddUserAgent(hCurl);        // put User-Agent

  return RequestPerform();
}

//
// Get AccessKeyId/SecretAccessKey/AccessToken/Expiration by IAM role,
// and Set these value to class variable.
//
int S3fsCurl::GetIAMCredentials()
{
  if (!S3fsCurl::is_ecs && !S3fsCurl::is_ibm_iam_auth) {
    S3FS_PRN_INFO3("[IAM role=%s]", S3fsCurl::IAM_role.c_str());

    if(S3fsCurl::IAM_role.empty()) {
      S3FS_PRN_ERR("IAM role name is empty.");
      return -EIO;
    }
  }

  // at first set type for handle
  type = REQTYPE_IAMCRED;

  if(!CreateCurlHandle()){
    return -EIO;
  }

  // url
  if (is_ecs) {
    url = string(S3fsCurl::IAM_cred_url) + std::getenv(ECS_IAM_ENV_VAR.c_str());
  }
  else {
    url = string(S3fsCurl::IAM_cred_url) + S3fsCurl::IAM_role;
  }

  requestHeaders  = NULL;
  responseHeaders.clear();
  bodydata.Clear();
  string postContent;

  if(S3fsCurl::is_ibm_iam_auth){
    url = string(S3fsCurl::IAM_cred_url);

    // make contents
    postContent += "grant_type=urn:ibm:params:oauth:grant-type:apikey";
    postContent += "&response_type=cloud_iam";
    postContent += "&apikey=" + S3fsCurl::AWSSecretAccessKey;

    // set postdata
    postdata             = reinterpret_cast<const unsigned char*>(postContent.c_str());
    b_postdata           = postdata;
    postdata_remaining   = postContent.size(); // without null
    b_postdata_remaining = postdata_remaining;

    requestHeaders = curl_slist_sort_insert(requestHeaders, "Authorization", "Basic Yng6Yng=");

    curl_easy_setopt(hCurl, CURLOPT_POST, true);              // POST
    curl_easy_setopt(hCurl, CURLOPT_POSTFIELDSIZE, static_cast<curl_off_t>(postdata_remaining));
    curl_easy_setopt(hCurl, CURLOPT_READDATA, (void*)this);
    curl_easy_setopt(hCurl, CURLOPT_READFUNCTION, S3fsCurl::ReadCallback);
  }

  curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, (void*)&bodydata);
  curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  S3fsCurl::AddUserAgent(hCurl);        // put User-Agent

  int result = RequestPerform();

  // analyzing response
  if(0 == result && !S3fsCurl::SetIAMCredentials(bodydata.str())){
    S3FS_PRN_ERR("Something error occurred, could not get IAM credential.");
    result = -EIO;
  }
  bodydata.Clear();

  return result;
}

//
// Get IAM role name automatically.
//
bool S3fsCurl::LoadIAMRoleFromMetaData()
{
  S3FS_PRN_INFO3("Get IAM Role name");

  // at first set type for handle
  type = REQTYPE_IAMROLE;

  if(!CreateCurlHandle()){
    return false;
  }

  // url
  url             = string(S3fsCurl::IAM_cred_url);
  requestHeaders  = NULL;
  responseHeaders.clear();
  bodydata.Clear();

  curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, (void*)&bodydata);
  curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  S3fsCurl::AddUserAgent(hCurl);        // put User-Agent

  int result = RequestPerform();

  // analyzing response
  if(0 == result && !S3fsCurl::SetIAMRoleFromMetaData(bodydata.str())){
    S3FS_PRN_ERR("Something error occurred, could not get IAM role name.");
    result = -EIO;
  }
  bodydata.Clear();

  return (0 == result);
}

bool S3fsCurl::AddSseRequestHead(sse_type_t ssetype, string& ssevalue, bool is_only_c, bool is_copy)
{
  if(SSE_S3 == ssetype){
    if(!is_only_c){
      requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-server-side-encryption", "AES256");
    }
  }else if(SSE_C == ssetype){
    string sseckey;
    if(S3fsCurl::GetSseKey(ssevalue, sseckey)){
      if(is_copy){
        requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-copy-source-server-side-encryption-customer-algorithm", "AES256");
        requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-copy-source-server-side-encryption-customer-key",       sseckey.c_str());
        requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-copy-source-server-side-encryption-customer-key-md5",   ssevalue.c_str());
      }else{
        requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-server-side-encryption-customer-algorithm", "AES256");
        requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-server-side-encryption-customer-key",       sseckey.c_str());
        requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-server-side-encryption-customer-key-md5",   ssevalue.c_str());
      }
    }else{
      S3FS_PRN_WARN("Failed to insert SSE-C header.");
    }

  }else if(SSE_KMS == ssetype){
    if(!is_only_c){
      if(ssevalue.empty()){
        ssevalue = S3fsCurl::GetSseKmsId();
      }
      requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-server-side-encryption", "aws:kms");
      requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-server-side-encryption-aws-kms-key-id", ssevalue.c_str());
    }
  }
  return true;
}

//
// tpath :      target path for head request
// bpath :      saved into base_path
// savedpath :  saved into saved_path
// ssekey_pos : -1    means "not" SSE-C type
//              0 - X means SSE-C type and position for SSE-C key(0 is latest key)
//
bool S3fsCurl::PreHeadRequest(const char* tpath, const char* bpath, const char* savedpath, int ssekey_pos)
{
  S3FS_PRN_INFO3("[tpath=%s][bpath=%s][save=%s][sseckeypos=%d]", SAFESTRPTR(tpath), SAFESTRPTR(bpath), SAFESTRPTR(savedpath), ssekey_pos);

  if(!tpath){
    return false;
  }
  string resource;
  string turl;
  MakeUrlResource(get_realpath(tpath).c_str(), resource, turl);

  // libcurl 7.17 does deep copy of url, deep copy "stable" url
  url             = prepare_url(turl.c_str());
  path            = get_realpath(tpath);
  base_path       = SAFESTRPTR(bpath);
  saved_path      = SAFESTRPTR(savedpath);
  requestHeaders  = NULL;
  responseHeaders.clear();

  // requestHeaders
  if(0 <= ssekey_pos){
    string md5;
    if(!S3fsCurl::GetSseKeyMd5(ssekey_pos, md5) || !AddSseRequestHead(SSE_C, md5, true, false)){
      S3FS_PRN_ERR("Failed to set SSE-C headers for sse-c key pos(%d)(=md5(%s)).", ssekey_pos, md5.c_str());
      return false;
    }
  }
  b_ssekey_pos = ssekey_pos;

  op = "HEAD";
  type = REQTYPE_HEAD;

  // set lazy function
  fpLazySetup = PreHeadRequestSetCurlOpts;

  return true;
}

int S3fsCurl::HeadRequest(const char* tpath, headers_t& meta)
{
  int result = -1;

  S3FS_PRN_INFO3("[tpath=%s]", SAFESTRPTR(tpath));

  // At first, try to get without SSE-C headers
  if(!PreHeadRequest(tpath) || !fpLazySetup || !fpLazySetup(this) || 0 != (result = RequestPerform())){
    // If has SSE-C keys, try to get with all SSE-C keys.
    for(int pos = 0; static_cast<size_t>(pos) < S3fsCurl::sseckeys.size(); pos++){
      if(!DestroyCurlHandle()){
        break;
      }
      if(!PreHeadRequest(tpath, NULL, NULL, pos)){
        break;
      }
      if(!fpLazySetup || !fpLazySetup(this)){
        S3FS_PRN_ERR("Failed to lazy setup in single head request.");
        break;
      }
      if(0 == (result = RequestPerform())){
        break;
      }
    }
    if(0 != result){
      DestroyCurlHandle();  // not check result.
      return result;
    }
  }

  // file exists in s3
  // fixme: clean this up.
  meta.clear();
  for(headers_t::iterator iter = responseHeaders.begin(); iter != responseHeaders.end(); ++iter){
    string key   = lower(iter->first);
    string value = iter->second;
    if(key == "content-type"){
      meta[iter->first] = value;
    }else if(key == "content-length"){
      meta[iter->first] = value;
    }else if(key == "etag"){
      meta[iter->first] = value;
    }else if(key == "last-modified"){
      meta[iter->first] = value;
    }else if(key.substr(0, 5) == "x-amz"){
      meta[key] = value;		// key is lower case for "x-amz"
    }
  }
  return 0;
}

int S3fsCurl::PutHeadRequest(const char* tpath, headers_t& meta, bool is_copy)
{
  S3FS_PRN_INFO3("[tpath=%s]", SAFESTRPTR(tpath));

  if(!tpath){
    return -1;
  }
  if(!CreateCurlHandle()){
    return -1;
  }
  string resource;
  string turl;
  MakeUrlResource(get_realpath(tpath).c_str(), resource, turl);

  url             = prepare_url(turl.c_str());
  path            = get_realpath(tpath);
  requestHeaders  = NULL;
  responseHeaders.clear();
  bodydata.Clear();

  string contype       = S3fsCurl::LookupMimeType(string(tpath));
  requestHeaders = curl_slist_sort_insert(requestHeaders, "Content-Type", contype.c_str());

  // Make request headers
  for(headers_t::iterator iter = meta.begin(); iter != meta.end(); ++iter){
    string key   = lower(iter->first);
    string value = iter->second;
    if(key.substr(0, 9) == "x-amz-acl"){
      // not set value, but after set it.
    }else if(key.substr(0, 10) == "x-amz-meta"){
      requestHeaders = curl_slist_sort_insert(requestHeaders, iter->first.c_str(), value.c_str());
    }else if(key == "x-amz-copy-source"){
      requestHeaders = curl_slist_sort_insert(requestHeaders, iter->first.c_str(), value.c_str());
    }else if(key == "x-amz-server-side-encryption" && value != "aws:kms"){
      // Only copy mode.
      if(is_copy && !AddSseRequestHead(SSE_S3, value, false, true)){
        S3FS_PRN_WARN("Failed to insert SSE-S3 header.");
      }
    }else if(key == "x-amz-server-side-encryption-aws-kms-key-id"){
      // Only copy mode.
      if(is_copy && !value.empty() && !AddSseRequestHead(SSE_KMS, value, false, true)){
        S3FS_PRN_WARN("Failed to insert SSE-KMS header.");
      }
    }else if(key == "x-amz-server-side-encryption-customer-key-md5"){
      // Only copy mode.
      if(is_copy){
        if(!AddSseRequestHead(SSE_C, value, true, true) || !AddSseRequestHead(SSE_C, value, true, false)){
          S3FS_PRN_WARN("Failed to insert SSE-C header.");
        }
      }
    }
  }

  // "x-amz-acl", storage class, sse
  if(S3fsCurl::default_acl != PRIVATE){
    requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-acl", acl_to_string(S3fsCurl::default_acl));
  }
  if(REDUCED_REDUNDANCY == GetStorageClass()){
    requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-storage-class", "REDUCED_REDUNDANCY");
  } else if(STANDARD_IA == GetStorageClass()){
    requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-storage-class", "STANDARD_IA");
  } else if(ONEZONE_IA == GetStorageClass()){
    requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-storage-class", "ONEZONE_IA");
  }
  // SSE
  if(!is_copy){
    string ssevalue;
    if(!AddSseRequestHead(S3fsCurl::GetSseType(), ssevalue, false, false)){
      S3FS_PRN_WARN("Failed to set SSE header, but continue...");
    }
  }
  if(is_use_ahbe){
    // set additional header by ahbe conf
    requestHeaders = AdditionalHeader::get()->AddHeader(requestHeaders, tpath);
  }

  op = "PUT";
  type = REQTYPE_PUTHEAD;

  // setopt
  curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(hCurl, CURLOPT_UPLOAD, true);                // HTTP PUT
  curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, (void*)&bodydata);
  curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(hCurl, CURLOPT_INFILESIZE, 0);               // Content-Length
  S3fsCurl::AddUserAgent(hCurl);                                // put User-Agent

  S3FS_PRN_INFO3("copying... [path=%s]", tpath);

  int result = RequestPerform();
  if(0 == result){
    // PUT returns 200 status code with something error, thus
    // we need to check body.
    //
    // example error body:
    //     <?xml version="1.0" encoding="UTF-8"?>
    //     <Error>
    //       <Code>AccessDenied</Code>
    //       <Message>Access Denied</Message>
    //       <RequestId>E4CA6F6767D6685C</RequestId>
    //       <HostId>BHzLOATeDuvN8Es1wI8IcERq4kl4dc2A9tOB8Yqr39Ys6fl7N4EJ8sjGiVvu6wLP</HostId>
    //     </Error>
    //
    const char* pstrbody = bodydata.str();
    if(!pstrbody || NULL != strcasestr(pstrbody, "<Error>")){
      S3FS_PRN_ERR("PutHeadRequest get 200 status response, but it included error body(or NULL). The request failed during copying the object in S3.");
      S3FS_PRN_DBG("PutHeadRequest Response Body : %s", (pstrbody ? pstrbody : "(null)"));
      result = -EIO;
    }
  }
  bodydata.Clear();

  return result;
}

int S3fsCurl::PutRequest(const char* tpath, headers_t& meta, int fd)
{
  struct stat st;
  FILE*       file = NULL;

  S3FS_PRN_INFO3("[tpath=%s]", SAFESTRPTR(tpath));

  if(!tpath){
    return -1;
  }
  if(-1 != fd){
    // duplicate fd
    int fd2;
    if(-1 == (fd2 = dup(fd)) || -1 == fstat(fd2, &st) || 0 != lseek(fd2, 0, SEEK_SET) || NULL == (file = fdopen(fd2, "rb"))){
      S3FS_PRN_ERR("Could not duplicate file descriptor(errno=%d)", errno);
      if(-1 != fd2){
        close(fd2);
      }
      return -errno;
    }
    b_infile = file;
  }else{
    // This case is creating zero byte object.(calling by create_file_object())
    S3FS_PRN_INFO3("create zero byte file object.");
  }

  if(!CreateCurlHandle()){
    if(file){
      fclose(file);
    }
    return -1;
  }
  string resource;
  string turl;
  MakeUrlResource(get_realpath(tpath).c_str(), resource, turl);

  url             = prepare_url(turl.c_str());
  path            = get_realpath(tpath);
  requestHeaders  = NULL;
  responseHeaders.clear();
  bodydata.Clear();

  // Make request headers
  string strMD5;
  if(-1 != fd && S3fsCurl::is_content_md5){
    strMD5         = s3fs_get_content_md5(fd);
    requestHeaders = curl_slist_sort_insert(requestHeaders, "Content-MD5", strMD5.c_str());
  }

  string contype       = S3fsCurl::LookupMimeType(string(tpath));
  requestHeaders = curl_slist_sort_insert(requestHeaders, "Content-Type", contype.c_str());

  for(headers_t::iterator iter = meta.begin(); iter != meta.end(); ++iter){
    string key   = lower(iter->first);
    string value = iter->second;
    if(key.substr(0, 9) == "x-amz-acl"){
      // not set value, but after set it.
    }else if(key.substr(0, 10) == "x-amz-meta"){
      requestHeaders = curl_slist_sort_insert(requestHeaders, iter->first.c_str(), value.c_str());
    }else if(key == "x-amz-server-side-encryption" && value != "aws:kms"){
      // skip this header, because this header is specified after logic.
    }else if(key == "x-amz-server-side-encryption-aws-kms-key-id"){
      // skip this header, because this header is specified after logic.
    }else if(key == "x-amz-server-side-encryption-customer-key-md5"){
      // skip this header, because this header is specified after logic.
    }
  }
  // "x-amz-acl", storage class, sse
  if(S3fsCurl::default_acl != PRIVATE){
    requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-acl", acl_to_string(S3fsCurl::default_acl));
  }
  if(REDUCED_REDUNDANCY == GetStorageClass()){
    requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-storage-class", "REDUCED_REDUNDANCY");
  } else if(STANDARD_IA == GetStorageClass()){
    requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-storage-class", "STANDARD_IA");
  } else if(ONEZONE_IA == GetStorageClass()){
    requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-storage-class", "ONEZONE_IA");
  }
  // SSE
  string ssevalue;
  if(!AddSseRequestHead(S3fsCurl::GetSseType(), ssevalue, false, false)){
    S3FS_PRN_WARN("Failed to set SSE header, but continue...");
  }
  if(is_use_ahbe){
    // set additional header by ahbe conf
    requestHeaders = AdditionalHeader::get()->AddHeader(requestHeaders, tpath);
  }

  op = "PUT";
  type = REQTYPE_PUT;

  // setopt
  curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(hCurl, CURLOPT_UPLOAD, true);                // HTTP PUT
  curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, (void*)&bodydata);
  curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  if(file){
    curl_easy_setopt(hCurl, CURLOPT_INFILESIZE_LARGE, static_cast<curl_off_t>(st.st_size)); // Content-Length
    curl_easy_setopt(hCurl, CURLOPT_INFILE, file);
  }else{
    curl_easy_setopt(hCurl, CURLOPT_INFILESIZE, 0);             // Content-Length: 0
  }
  S3fsCurl::AddUserAgent(hCurl);                                // put User-Agent

  S3FS_PRN_INFO3("uploading... [path=%s][fd=%d][size=%lld]", tpath, fd, static_cast<long long int>(-1 != fd ? st.st_size : 0));

  int result = RequestPerform();
  bodydata.Clear();
  if(file){
    fclose(file);
  }

  return result;
}

int S3fsCurl::PreGetObjectRequest(const char* tpath, int fd, off_t start, ssize_t size, sse_type_t ssetype, string& ssevalue)
{
  S3FS_PRN_INFO3("[tpath=%s][start=%lld][size=%lld]", SAFESTRPTR(tpath), static_cast<long long>(start), static_cast<long long>(size));

  if(!tpath || -1 == fd || 0 > start || 0 > size){
    return -1;
  }

  string resource;
  string turl;
  MakeUrlResource(get_realpath(tpath).c_str(), resource, turl);

  url             = prepare_url(turl.c_str());
  path            = get_realpath(tpath);
  requestHeaders  = NULL;
  responseHeaders.clear();

  if(-1 != start && 0 < size){
    string range = "bytes=";
    range       += str(start);
    range       += "-";
    range       += str(start + size - 1);
    requestHeaders = curl_slist_sort_insert(requestHeaders, "Range", range.c_str());
  }
  // SSE
  if(!AddSseRequestHead(ssetype, ssevalue, true, false)){
    S3FS_PRN_WARN("Failed to set SSE header, but continue...");
  }

  op = "GET";
  type = REQTYPE_GET;

  // set lazy function
  fpLazySetup = PreGetObjectRequestSetCurlOpts;

  // set info for callback func.
  // (use only fd, startpos and size, other member is not used.)
  partdata.clear();
  partdata.fd         = fd;
  partdata.startpos   = start;
  partdata.size       = size;
  b_partdata_startpos = start;
  b_partdata_size     = size;
  b_ssetype           = ssetype;
  b_ssevalue          = ssevalue;
  b_ssekey_pos        = -1;         // not use this value for get object.

  return 0;
}

int S3fsCurl::GetObjectRequest(const char* tpath, int fd, off_t start, ssize_t size)
{
  int result;

  S3FS_PRN_INFO3("[tpath=%s][start=%lld][size=%lld]", SAFESTRPTR(tpath), static_cast<long long>(start), static_cast<long long>(size));

  if(!tpath){
    return -1;
  }
  sse_type_t ssetype;
  string     ssevalue;
  if(!get_object_sse_type(tpath, ssetype, ssevalue)){
    S3FS_PRN_WARN("Failed to get SSE type for file(%s).", SAFESTRPTR(tpath));
  }

  if(0 != (result = PreGetObjectRequest(tpath, fd, start, size, ssetype, ssevalue))){
    return result;
  }
  if(!fpLazySetup || !fpLazySetup(this)){
    S3FS_PRN_ERR("Failed to lazy setup in single get object request.");
    return -1;
  }

  S3FS_PRN_INFO3("downloading... [path=%s][fd=%d]", tpath, fd);

  result = RequestPerform();
  partdata.clear();

  return result;
}

int S3fsCurl::CheckBucket()
{
  S3FS_PRN_INFO3("check a bucket.");

  if(!CreateCurlHandle()){
    return -1;
  }
  string resource;
  string turl;
  MakeUrlResource(get_realpath("/").c_str(), resource, turl);

  url             = prepare_url(turl.c_str());
  path            = get_realpath("/");
  requestHeaders  = NULL;
  responseHeaders.clear();
  bodydata.Clear();

  op = "GET";
  type = REQTYPE_CHKBUCKET;

  // setopt
  curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, (void*)&bodydata);
  curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  S3fsCurl::AddUserAgent(hCurl);        // put User-Agent

  int result = RequestPerform();
  if (result != 0) {
    S3FS_PRN_ERR("Check bucket failed, S3 response: %s", bodydata.str());
  }
  return result;
}

int S3fsCurl::ListBucketRequest(const char* tpath, const char* query)
{
  S3FS_PRN_INFO3("[tpath=%s]", SAFESTRPTR(tpath));

  if(!tpath){
    return -1;
  }
  if(!CreateCurlHandle()){
    return -1;
  }
  string resource;
  string turl;
  MakeUrlResource("", resource, turl);    // NOTICE: path is "".
  if(query){
    turl += "?";
    turl += query;
    query_string = query;
  }

  url             = prepare_url(turl.c_str());
  path            = get_realpath(tpath);
  requestHeaders  = NULL;
  responseHeaders.clear();
  bodydata.Clear();

  op = "GET";
  type = REQTYPE_LISTBUCKET;

  // setopt
  curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, (void*)&bodydata);
  curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  S3fsCurl::AddUserAgent(hCurl);        // put User-Agent

  return RequestPerform();
}

//
// Initialize multipart upload
//
// Example :
//   POST /example-object?uploads HTTP/1.1
//   Host: example-bucket.s3.amazonaws.com
//   Date: Mon, 1 Nov 2010 20:34:56 GMT
//   Authorization: AWS VGhpcyBtZXNzYWdlIHNpZ25lZCBieSBlbHZpbmc=
//
int S3fsCurl::PreMultipartPostRequest(const char* tpath, headers_t& meta, string& upload_id, bool is_copy)
{
  S3FS_PRN_INFO3("[tpath=%s]", SAFESTRPTR(tpath));

  if(!tpath){
    return -1;
  }
  if(!CreateCurlHandle()){
    return -1;
  }
  string resource;
  string turl;
  MakeUrlResource(get_realpath(tpath).c_str(), resource, turl);

  query_string   = "uploads";
  turl          += "?" + query_string;
  url            = prepare_url(turl.c_str());
  path           = get_realpath(tpath);
  requestHeaders = NULL;
  bodydata.Clear();
  responseHeaders.clear();

  string contype = S3fsCurl::LookupMimeType(string(tpath));

  for(headers_t::iterator iter = meta.begin(); iter != meta.end(); ++iter){
    string key   = lower(iter->first);
    string value = iter->second;
    if(key.substr(0, 9) == "x-amz-acl"){
      // not set value, but after set it.
    }else if(key.substr(0, 10) == "x-amz-meta"){
      requestHeaders = curl_slist_sort_insert(requestHeaders, iter->first.c_str(), value.c_str());
    }else if(key == "x-amz-server-side-encryption" && value != "aws:kms"){
      // Only copy mode.
      if(is_copy && !AddSseRequestHead(SSE_S3, value, false, true)){
        S3FS_PRN_WARN("Failed to insert SSE-S3 header.");
      }
    }else if(key == "x-amz-server-side-encryption-aws-kms-key-id"){
      // Only copy mode.
      if(is_copy && !value.empty() && !AddSseRequestHead(SSE_KMS, value, false, true)){
        S3FS_PRN_WARN("Failed to insert SSE-KMS header.");
      }
    }else if(key == "x-amz-server-side-encryption-customer-key-md5"){
      // Only copy mode.
      if(is_copy){
        if(!AddSseRequestHead(SSE_C, value, true, true) || !AddSseRequestHead(SSE_C, value, true, false)){
          S3FS_PRN_WARN("Failed to insert SSE-C header.");
        }
      }
    }
  }
  // "x-amz-acl", storage class, sse
  if(S3fsCurl::default_acl != PRIVATE){
    requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-acl", acl_to_string(S3fsCurl::default_acl));
  }
  if(REDUCED_REDUNDANCY == GetStorageClass()){
    requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-storage-class", "REDUCED_REDUNDANCY");
  } else if(STANDARD_IA == GetStorageClass()){
    requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-storage-class", "STANDARD_IA");
  } else if(ONEZONE_IA == GetStorageClass()){
    requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-storage-class", "ONEZONE_IA");
  }
  // SSE
  if(!is_copy){
    string ssevalue;
    if(!AddSseRequestHead(S3fsCurl::GetSseType(), ssevalue, false, false)){
      S3FS_PRN_WARN("Failed to set SSE header, but continue...");
    }
  }
  if(is_use_ahbe){
    // set additional header by ahbe conf
    requestHeaders = AdditionalHeader::get()->AddHeader(requestHeaders, tpath);
  }

  requestHeaders = curl_slist_sort_insert(requestHeaders, "Accept", NULL);
  requestHeaders = curl_slist_sort_insert(requestHeaders, "Content-Length", NULL);
  requestHeaders = curl_slist_sort_insert(requestHeaders, "Content-Type", contype.c_str());

  op = "POST";
  type = REQTYPE_PREMULTIPOST;

  // setopt
  curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(hCurl, CURLOPT_POST, true);              // POST
  curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, (void*)&bodydata);
  curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(hCurl, CURLOPT_POSTFIELDSIZE, 0);
  S3fsCurl::AddUserAgent(hCurl);                            // put User-Agent

  // request
  int result;
  if(0 != (result = RequestPerform())){
    bodydata.Clear();
    return result;
  }

  if(!simple_parse_xml(bodydata.str(), bodydata.size(), "UploadId", upload_id)){
    bodydata.Clear();
    return -1;
  }

  bodydata.Clear();
  return 0;
}

int S3fsCurl::CompleteMultipartPostRequest(const char* tpath, const string& upload_id, etaglist_t& parts)
{
  S3FS_PRN_INFO3("[tpath=%s][parts=%zu]", SAFESTRPTR(tpath), parts.size());

  if(!tpath){
    return -1;
  }

  // make contents
  string postContent;
  postContent += "<CompleteMultipartUpload>\n";
  for(int cnt = 0; cnt < (int)parts.size(); cnt++){
    if(0 == parts[cnt].length()){
      S3FS_PRN_ERR("%d file part is not finished uploading.", cnt + 1);
      return -1;
    }
    postContent += "<Part>\n";
    postContent += "  <PartNumber>" + str(cnt + 1) + "</PartNumber>\n";
    postContent += "  <ETag>" + parts[cnt] + "</ETag>\n";
    postContent += "</Part>\n";
  }  
  postContent += "</CompleteMultipartUpload>\n";

  // set postdata
  postdata             = reinterpret_cast<const unsigned char*>(postContent.c_str());
  b_postdata           = postdata;
  postdata_remaining   = postContent.size(); // without null
  b_postdata_remaining = postdata_remaining;

  if(!CreateCurlHandle()){
    return -1;
  }
  string resource;
  string turl;
  MakeUrlResource(get_realpath(tpath).c_str(), resource, turl);

  query_string         = "uploadId=" + upload_id;
  turl                += "?" + query_string;
  url                  = prepare_url(turl.c_str());
  path                 = get_realpath(tpath);
  requestHeaders       = NULL;
  bodydata.Clear();
  responseHeaders.clear();
  string contype       = S3fsCurl::LookupMimeType(string(tpath));

  requestHeaders = curl_slist_sort_insert(requestHeaders, "Accept", NULL);
  requestHeaders = curl_slist_sort_insert(requestHeaders, "Content-Type", contype.c_str());

  op = "POST";
  type = REQTYPE_COMPLETEMULTIPOST;

  // setopt
  curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(hCurl, CURLOPT_POST, true);              // POST
  curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, (void*)&bodydata);
  curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(hCurl, CURLOPT_POSTFIELDSIZE, static_cast<curl_off_t>(postdata_remaining));
  curl_easy_setopt(hCurl, CURLOPT_READDATA, (void*)this);
  curl_easy_setopt(hCurl, CURLOPT_READFUNCTION, S3fsCurl::ReadCallback);
  S3fsCurl::AddUserAgent(hCurl);                            // put User-Agent

  // request
  int result = RequestPerform();
  bodydata.Clear();
  postdata = NULL;

  return result;
}

int S3fsCurl::MultipartListRequest(string& body)
{
  S3FS_PRN_INFO3("list request(multipart)");

  if(!CreateCurlHandle()){
    return -1;
  }
  string resource;
  string turl;
  path            = get_realpath("/");
  MakeUrlResource(path.c_str(), resource, turl);

  query_string    = "uploads";
  turl           += "?" + query_string;
  url             = prepare_url(turl.c_str());
  requestHeaders  = NULL;
  responseHeaders.clear();
  bodydata.Clear();

  requestHeaders = curl_slist_sort_insert(requestHeaders, "Accept", NULL);

  op = "GET";
  type = REQTYPE_MULTILIST;

  // setopt
  curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, (void*)&bodydata);
  curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  S3fsCurl::AddUserAgent(hCurl);        // put User-Agent

  int result;
  if(0 == (result = RequestPerform()) && 0 < bodydata.size()){
    body = bodydata.str();
  }else{
    body = "";
  }
  bodydata.Clear();

  return result;
}

int S3fsCurl::AbortMultipartUpload(const char* tpath, const string& upload_id)
{
  S3FS_PRN_INFO3("[tpath=%s]", SAFESTRPTR(tpath));

  if(!tpath){
    return -1;
  }
  if(!CreateCurlHandle()){
    return -1;
  }
  string resource;
  string turl;
  MakeUrlResource(get_realpath(tpath).c_str(), resource, turl);

  query_string    = "uploadId=" + upload_id;
  turl           += "?" + query_string;
  url             = prepare_url(turl.c_str());
  path            = get_realpath(tpath);
  requestHeaders  = NULL;
  responseHeaders.clear();

  op = "DELETE";
  type = REQTYPE_ABORTMULTIUPLOAD;

  curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(hCurl, CURLOPT_CUSTOMREQUEST, "DELETE");
  S3fsCurl::AddUserAgent(hCurl);        // put User-Agent

  return RequestPerform();
}

//
// PUT /ObjectName?partNumber=PartNumber&uploadId=UploadId HTTP/1.1
// Host: BucketName.s3.amazonaws.com
// Date: date
// Content-Length: Size
// Authorization: Signature
//
// PUT /my-movie.m2ts?partNumber=1&uploadId=VCVsb2FkIElEIGZvciBlbZZpbmcncyBteS1tb3ZpZS5tMnRzIHVwbG9hZR HTTP/1.1
// Host: example-bucket.s3.amazonaws.com
// Date:  Mon, 1 Nov 2010 20:34:56 GMT
// Content-Length: 10485760
// Content-MD5: pUNXr/BjKK5G2UKvaRRrOA==
// Authorization: AWS VGhpcyBtZXNzYWdlIHNpZ25lZGGieSRlbHZpbmc=
//

int S3fsCurl::UploadMultipartPostSetup(const char* tpath, int part_num, const string& upload_id)
{
  S3FS_PRN_INFO3("[tpath=%s][start=%lld][size=%lld][part=%d]", SAFESTRPTR(tpath), static_cast<long long int>(partdata.startpos), static_cast<long long int>(partdata.size), part_num);

  if(-1 == partdata.fd || -1 == partdata.startpos || -1 == partdata.size){
    return -1;
  }

  requestHeaders = NULL;

  // make md5 and file pointer
  if(S3fsCurl::is_content_md5){
    unsigned char *md5raw = s3fs_md5hexsum(partdata.fd, partdata.startpos, partdata.size);
    if(md5raw == NULL){
      S3FS_PRN_ERR("Could not make md5 for file(part %d)", part_num);
      return -1;
    }
    partdata.etag = s3fs_hex(md5raw, get_md5_digest_length());
    char* md5base64p = s3fs_base64(md5raw, get_md5_digest_length());
    requestHeaders = curl_slist_sort_insert(requestHeaders, "Content-MD5", md5base64p);
    delete[] md5base64p;
    delete[] md5raw;
  }

  // make request
  query_string        = "partNumber=" + str(part_num) + "&uploadId=" + upload_id;
  string urlargs      = "?" + query_string;
  string resource;
  string turl;
  MakeUrlResource(get_realpath(tpath).c_str(), resource, turl);

  turl              += urlargs;
  url                = prepare_url(turl.c_str());
  path               = get_realpath(tpath);
  bodydata.Clear();
  headdata.Clear();
  responseHeaders.clear();

  // SSE
  if(SSE_C == S3fsCurl::GetSseType()){
    string ssevalue;
    if(!AddSseRequestHead(S3fsCurl::GetSseType(), ssevalue, false, false)){
      S3FS_PRN_WARN("Failed to set SSE header, but continue...");
    }
  }

  requestHeaders = curl_slist_sort_insert(requestHeaders, "Accept", NULL);

  op = "PUT";
  type = REQTYPE_UPLOADMULTIPOST;

  // set lazy function
  fpLazySetup = UploadMultipartPostSetCurlOpts;

  return 0;
}

int S3fsCurl::UploadMultipartPostRequest(const char* tpath, int part_num, const string& upload_id)
{
  int result;

  S3FS_PRN_INFO3("[tpath=%s][start=%lld][size=%lld][part=%d]", SAFESTRPTR(tpath), static_cast<long long int>(partdata.startpos), static_cast<long long int>(partdata.size), part_num);

  // setup
  if(0 != (result = S3fsCurl::UploadMultipartPostSetup(tpath, part_num, upload_id))){
    return result;
  }

  if(!fpLazySetup || !fpLazySetup(this)){
    S3FS_PRN_ERR("Failed to lazy setup in multipart upload post request.");
    return -1;
  }

  // request
  if(0 == (result = RequestPerform())){
    // UploadMultipartPostComplete returns true on success -> convert to 0
    result = !UploadMultipartPostComplete();
  }

  // closing
  bodydata.Clear();
  headdata.Clear();

  return result;
}

int S3fsCurl::CopyMultipartPostSetup(const char* from, const char* to, int part_num, const string& upload_id, headers_t& meta)
{
  S3FS_PRN_INFO3("[from=%s][to=%s][part=%d]", SAFESTRPTR(from), SAFESTRPTR(to), part_num);

  if(!from || !to){
    return -1;
  }
  query_string       = "partNumber=" + str(part_num) + "&uploadId=" + upload_id;
  string urlargs     = "?" + query_string;
  string resource;
  string turl;
  MakeUrlResource(get_realpath(to).c_str(), resource, turl);

  turl           += urlargs;
  url             = prepare_url(turl.c_str());
  path            = get_realpath(to);
  requestHeaders  = NULL;
  responseHeaders.clear();
  bodydata.Clear();
  headdata.Clear();

  string contype       = S3fsCurl::LookupMimeType(string(to));
  requestHeaders = curl_slist_sort_insert(requestHeaders, "Content-Type", contype.c_str());

  // Make request headers
  for(headers_t::iterator iter = meta.begin(); iter != meta.end(); ++iter){
    string key   = lower(iter->first);
    string value = iter->second;
    if(key == "x-amz-copy-source"){
      requestHeaders = curl_slist_sort_insert(requestHeaders, iter->first.c_str(), value.c_str());
    }else if(key == "x-amz-copy-source-range"){
      requestHeaders = curl_slist_sort_insert(requestHeaders, iter->first.c_str(), value.c_str());
    }
    // NOTICE: x-amz-acl, x-amz-server-side-encryption is not set!
  }

  op = "PUT";
  type = REQTYPE_COPYMULTIPOST;

  // set lazy function
  fpLazySetup = CopyMultipartPostSetCurlOpts;

  // request
  S3FS_PRN_INFO3("copying... [from=%s][to=%s][part=%d]", from, to, part_num);

  return 0;
}

bool S3fsCurl::UploadMultipartPostComplete()
{
  headers_t::iterator it = responseHeaders.find("ETag");
  if (it == responseHeaders.end()) {
    return false;
  }

  // check etag(md5);
  //
  // The ETAG when using SSE_C and SSE_KMS does not reflect the MD5 we sent  
  // SSE_C: https://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectPUT.html
  // SSE_KMS is ignored in the above, but in the following it states the same in the highlights:  
  // https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingKMSEncryption.html
  //
  if(S3fsCurl::is_content_md5 && SSE_C != S3fsCurl::GetSseType() && SSE_KMS != S3fsCurl::GetSseType()){
    if(!etag_equals(it->second, partdata.etag)){
      return false;
    }
  }
  partdata.etaglist->at(partdata.etagpos).assign(it->second);
  partdata.uploaded = true;

  return true;
}

bool S3fsCurl::CopyMultipartPostCallback(S3fsCurl* s3fscurl)
{
  if(!s3fscurl){
    return false;
  }

  return s3fscurl->CopyMultipartPostComplete();
}

bool S3fsCurl::CopyMultipartPostComplete()
{
  std::string etag;
  partdata.uploaded = simple_parse_xml(bodydata.str(), bodydata.size(), "ETag", etag);
  if(etag.size() >= 2 && *etag.begin() == '"' && *etag.rbegin() == '"'){
    etag.assign(etag.substr(1, etag.size() - 2));
  }
  partdata.etaglist->at(partdata.etagpos).assign(etag);

  bodydata.Clear();
  headdata.Clear();

  return true;
}

bool S3fsCurl::MixMultipartPostComplete()
{
  bool result;
  if(-1 == partdata.fd){
    result = CopyMultipartPostComplete();
  }else{
    result = UploadMultipartPostComplete();
  }
  return result;
}

int S3fsCurl::MultipartHeadRequest(const char* tpath, off_t size, headers_t& meta, bool is_copy)
{
  int            result;
  string         upload_id;
  off_t          chunk;
  off_t          bytes_remaining;
  etaglist_t     list;
  ostringstream  strrange;

  S3FS_PRN_INFO3("[tpath=%s]", SAFESTRPTR(tpath));

  if(0 != (result = PreMultipartPostRequest(tpath, meta, upload_id, is_copy))){
    return result;
  }
  DestroyCurlHandle();

  // Initialize S3fsMultiCurl
  S3fsMultiCurl curlmulti(GetMaxParallelCount());
  curlmulti.SetSuccessCallback(S3fsCurl::CopyMultipartPostCallback);
  curlmulti.SetRetryCallback(S3fsCurl::CopyMultipartPostRetryCallback);

  for(bytes_remaining = size, chunk = 0; 0 < bytes_remaining; bytes_remaining -= chunk){
    chunk = bytes_remaining > MAX_MULTI_COPY_SOURCE_SIZE ? MAX_MULTI_COPY_SOURCE_SIZE : bytes_remaining;

    strrange << "bytes=" << (size - bytes_remaining) << "-" << (size - bytes_remaining + chunk - 1);
    meta["x-amz-copy-source-range"] = strrange.str();
    strrange.str("");
    strrange.clear(stringstream::goodbit);

    // s3fscurl sub object
    S3fsCurl* s3fscurl_para = new S3fsCurl(true);
    s3fscurl_para->b_from   = SAFESTRPTR(tpath);
    s3fscurl_para->b_meta   = meta;
    s3fscurl_para->partdata.add_etag_list(&list);

    // initiate upload part for parallel
    if(0 != (result = s3fscurl_para->CopyMultipartPostSetup(tpath, tpath, list.size(), upload_id, meta))){
      S3FS_PRN_ERR("failed uploading part setup(%d)", result);
      delete s3fscurl_para;
      return result;
    }

    // set into parallel object
    if(!curlmulti.SetS3fsCurlObject(s3fscurl_para)){
      S3FS_PRN_ERR("Could not make curl object into multi curl(%s).", tpath);
      delete s3fscurl_para;
      return -1;
    }
  }

  // Multi request
  if(0 != (result = curlmulti.Request())){
    S3FS_PRN_ERR("error occurred in multi request(errno=%d).", result);

    S3fsCurl s3fscurl_abort(true);
    int result2 = s3fscurl_abort.AbortMultipartUpload(tpath, upload_id);
    s3fscurl_abort.DestroyCurlHandle();
    if(result2 != 0){
      S3FS_PRN_ERR("error aborting multipart upload(errno=%d).", result2);
    }

    return result;
  }

  if(0 != (result = CompleteMultipartPostRequest(tpath, upload_id, list))){
    return result;
  }
  return 0;
}

int S3fsCurl::MultipartUploadRequest(const char* tpath, headers_t& meta, int fd, bool is_copy)
{
  int            result;
  string         upload_id;
  struct stat    st;
  int            fd2;
  etaglist_t     list;
  off_t          remaining_bytes;
  off_t          chunk;

  S3FS_PRN_INFO3("[tpath=%s][fd=%d]", SAFESTRPTR(tpath), fd);

  // duplicate fd
  if(-1 == (fd2 = dup(fd)) || 0 != lseek(fd2, 0, SEEK_SET)){
    S3FS_PRN_ERR("Could not duplicate file descriptor(errno=%d)", errno);
    if(-1 != fd2){
      close(fd2);
    }
    return -errno;
  }
  if(-1 == fstat(fd2, &st)){
    S3FS_PRN_ERR("Invalid file descriptor(errno=%d)", errno);
    close(fd2);
    return -errno;
  }

  if(0 != (result = PreMultipartPostRequest(tpath, meta, upload_id, is_copy))){
    close(fd2);
    return result;
  }
  DestroyCurlHandle();

  // cycle through open fd, pulling off 10MB chunks at a time
  for(remaining_bytes = st.st_size; 0 < remaining_bytes; remaining_bytes -= chunk){
    // chunk size
    chunk = remaining_bytes > S3fsCurl::multipart_size ? S3fsCurl::multipart_size : remaining_bytes;

    // set
    partdata.fd         = fd2;
    partdata.startpos   = st.st_size - remaining_bytes;
    partdata.size       = chunk;
    b_partdata_startpos = partdata.startpos;
    b_partdata_size     = partdata.size;
    partdata.add_etag_list(&list);

    // upload part
    if(0 != (result = UploadMultipartPostRequest(tpath, list.size(), upload_id))){
      S3FS_PRN_ERR("failed uploading part(%d)", result);
      close(fd2);
      return result;
    }
    DestroyCurlHandle();
  }
  close(fd2);

  if(0 != (result = CompleteMultipartPostRequest(tpath, upload_id, list))){
    return result;
  }
  return 0;
}

int S3fsCurl::MultipartUploadRequest(const string& upload_id, const char* tpath, int fd, off_t offset, off_t size, etaglist_t& list)
{
  S3FS_PRN_INFO3("[upload_id=%s][tpath=%s][fd=%d][offset=%lld][size=%lld]", upload_id.c_str(), SAFESTRPTR(tpath), fd, static_cast<long long int>(offset), static_cast<long long int>(size));

  // duplicate fd
  int fd2;
  if(-1 == (fd2 = dup(fd)) || 0 != lseek(fd2, 0, SEEK_SET)){
    S3FS_PRN_ERR("Could not duplicate file descriptor(errno=%d)", errno);
    if(-1 != fd2){
      close(fd2);
    }
    return -errno;
  }

  // set
  partdata.fd         = fd2;
  partdata.startpos   = offset;
  partdata.size       = size;
  b_partdata_startpos = partdata.startpos;
  b_partdata_size     = partdata.size;
  partdata.add_etag_list(&list);

  // upload part
  int   result;
  if(0 != (result = UploadMultipartPostRequest(tpath, list.size(), upload_id))){
    S3FS_PRN_ERR("failed uploading part(%d)", result);
    close(fd2);
    return result;
  }
  DestroyCurlHandle();
  close(fd2);

  return 0;
}

int S3fsCurl::MultipartRenameRequest(const char* from, const char* to, headers_t& meta, off_t size)
{
  int            result;
  string         upload_id;
  off_t          chunk;
  off_t          bytes_remaining;
  etaglist_t     list;
  ostringstream  strrange;

  S3FS_PRN_INFO3("[from=%s][to=%s]", SAFESTRPTR(from), SAFESTRPTR(to));

  string srcresource;
  string srcurl;
  MakeUrlResource(get_realpath(from).c_str(), srcresource, srcurl);

  meta["Content-Type"]      = S3fsCurl::LookupMimeType(string(to));
  meta["x-amz-copy-source"] = srcresource;

  if(0 != (result = PreMultipartPostRequest(to, meta, upload_id, true))){
    return result;
  }
  DestroyCurlHandle();

  // Initialize S3fsMultiCurl
  S3fsMultiCurl curlmulti(GetMaxParallelCount());
  curlmulti.SetSuccessCallback(S3fsCurl::CopyMultipartPostCallback);
  curlmulti.SetRetryCallback(S3fsCurl::CopyMultipartPostRetryCallback);

  for(bytes_remaining = size, chunk = 0; 0 < bytes_remaining; bytes_remaining -= chunk){
    chunk = bytes_remaining > MAX_MULTI_COPY_SOURCE_SIZE ? MAX_MULTI_COPY_SOURCE_SIZE : bytes_remaining;

    strrange << "bytes=" << (size - bytes_remaining) << "-" << (size - bytes_remaining + chunk - 1);
    meta["x-amz-copy-source-range"] = strrange.str();
    strrange.str("");
    strrange.clear(stringstream::goodbit);

    // s3fscurl sub object
    S3fsCurl* s3fscurl_para = new S3fsCurl(true);
    s3fscurl_para->b_from   = SAFESTRPTR(from);
    s3fscurl_para->b_meta   = meta;
    s3fscurl_para->partdata.add_etag_list(&list);

    // initiate upload part for parallel
    if(0 != (result = s3fscurl_para->CopyMultipartPostSetup(from, to, list.size(), upload_id, meta))){
      S3FS_PRN_ERR("failed uploading part setup(%d)", result);
      delete s3fscurl_para;
      return result;
    }

    // set into parallel object
    if(!curlmulti.SetS3fsCurlObject(s3fscurl_para)){
      S3FS_PRN_ERR("Could not make curl object into multi curl(%s).", to);
      delete s3fscurl_para;
      return -1;
    }
  }

  // Multi request
  if(0 != (result = curlmulti.Request())){
    S3FS_PRN_ERR("error occurred in multi request(errno=%d).", result);

    S3fsCurl s3fscurl_abort(true);
    int result2 = s3fscurl_abort.AbortMultipartUpload(to, upload_id);
    s3fscurl_abort.DestroyCurlHandle();
    if(result2 != 0){
      S3FS_PRN_ERR("error aborting multipart upload(errno=%d).", result2);
    }

    return result;
  }

  if(0 != (result = CompleteMultipartPostRequest(to, upload_id, list))){
    return result;
  }
  return 0;
}

//-------------------------------------------------------------------
// method for S3fsMultiCurl 
//-------------------------------------------------------------------
S3fsMultiCurl::S3fsMultiCurl(int maxParallelism)
  : maxParallelism(maxParallelism)
  , SuccessCallback(NULL)
  , RetryCallback(NULL)
{
  int res;
  pthread_mutexattr_t attr;
  pthread_mutexattr_init(&attr);
#if S3FS_PTHREAD_ERRORCHECK
  pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK);
#endif
  if (0 != (res = pthread_mutex_init(&completed_tids_lock, &attr))) {
    S3FS_PRN_ERR("could not initialize completed_tids_lock: %i", res);
  }
}

S3fsMultiCurl::~S3fsMultiCurl()
{
  Clear();
  int res;
  if(0 != (res = pthread_mutex_destroy(&completed_tids_lock))){
    S3FS_PRN_ERR("could not destroy completed_tids_lock: %i", res);
  }
}

bool S3fsMultiCurl::ClearEx(bool is_all)
{
  s3fscurllist_t::iterator iter;
  for(iter = clist_req.begin(); iter != clist_req.end(); ++iter){
    S3fsCurl* s3fscurl = *iter;
    if(s3fscurl){
      s3fscurl->DestroyCurlHandle();
      delete s3fscurl;  // with destroy curl handle.
    }
  }
  clist_req.clear();

  if(is_all){
    for(iter = clist_all.begin(); iter != clist_all.end(); ++iter){
      S3fsCurl* s3fscurl = *iter;
      s3fscurl->DestroyCurlHandle();
      delete s3fscurl;
    }
    clist_all.clear();
  }

  S3FS_MALLOCTRIM(0);

  return true;
}

S3fsMultiSuccessCallback S3fsMultiCurl::SetSuccessCallback(S3fsMultiSuccessCallback function)
{
  S3fsMultiSuccessCallback old = SuccessCallback;
  SuccessCallback = function;
  return old;
}
  
S3fsMultiRetryCallback S3fsMultiCurl::SetRetryCallback(S3fsMultiRetryCallback function)
{
  S3fsMultiRetryCallback old = RetryCallback;
  RetryCallback = function;
  return old;
}
  
bool S3fsMultiCurl::SetS3fsCurlObject(S3fsCurl* s3fscurl)
{
  if(!s3fscurl){
    return false;
  }
  clist_all.push_back(s3fscurl);

  return true;
}

int S3fsMultiCurl::MultiPerform()
{
  std::vector<pthread_t>   threads;
  bool                     success = true;
  bool                     isMultiHead = false;
  Semaphore                sem(GetMaxParallelism());
  int                      rc;

  for(s3fscurllist_t::iterator iter = clist_req.begin(); iter != clist_req.end(); ++iter) {
    pthread_t   thread;
    S3fsCurl*   s3fscurl = *iter;
    s3fscurl->sem = &sem;
    s3fscurl->completed_tids_lock = &completed_tids_lock;
    s3fscurl->completed_tids = &completed_tids;

    sem.wait();

    {
      AutoLock lock(&completed_tids_lock);
      for(std::vector<pthread_t>::iterator it = completed_tids.begin(); it != completed_tids.end(); ++it){
        void*   retval;

        rc = pthread_join(*it, &retval);
        if (rc) {
          success = false;
          S3FS_PRN_ERR("failed pthread_join - rc(%d) %s", rc, strerror(rc));
        } else {
          int int_retval = (int)(intptr_t)(retval);
          if (int_retval && !(int_retval == -ENOENT && isMultiHead)) {
            S3FS_PRN_WARN("thread failed - rc(%d)", int_retval);
          }
        }
      }
      completed_tids.clear();
    }

    isMultiHead |= s3fscurl->GetOp() == "HEAD";

    rc = pthread_create(&thread, NULL, S3fsMultiCurl::RequestPerformWrapper, static_cast<void*>(s3fscurl));
    if (rc != 0) {
      success = false;
      S3FS_PRN_ERR("failed pthread_create - rc(%d)", rc);
      break;
    }

    threads.push_back(thread);
  }

  for(int i = 0; i < sem.get_value(); ++i){
    sem.wait();
  }

  AutoLock lock(&completed_tids_lock);
  for (std::vector<pthread_t>::iterator titer = completed_tids.begin(); titer != completed_tids.end(); ++titer) {
    void*   retval;

    rc = pthread_join(*titer, &retval);
    if (rc) {
      success = false;
      S3FS_PRN_ERR("failed pthread_join - rc(%d)", rc);
    } else {
      int int_retval = (int)(intptr_t)(retval);
      if (int_retval && !(int_retval == -ENOENT && isMultiHead)) {
        S3FS_PRN_WARN("thread failed - rc(%d)", int_retval);
      }
    }
  }
  completed_tids.clear();

  return success ? 0 : -EIO;
}

int S3fsMultiCurl::MultiRead()
{
  int result = 0;

  for(s3fscurllist_t::iterator iter = clist_req.begin(); iter != clist_req.end(); ){
    S3fsCurl* s3fscurl = *iter;

    bool isRetry = false;
    bool isPostpone = false;
    long responseCode = S3FSCURL_RESPONSECODE_NOTSET;
    if(s3fscurl->GetResponseCode(responseCode, false)){
      if(S3FSCURL_RESPONSECODE_NOTSET == responseCode){
        // This is a case where the processing result has not yet been updated (should be very rare).
        isPostpone = true;
      }else if(400 > responseCode){
        // add into stat cache
        if(SuccessCallback && !SuccessCallback(s3fscurl)){
          S3FS_PRN_WARN("error from callback function(%s).", s3fscurl->url.c_str());
        }
      }else if(400 == responseCode){
        // as possibly in multipart
        S3FS_PRN_WARN("failed a request(%ld: %s)", responseCode, s3fscurl->url.c_str());
        isRetry = true;
      }else if(404 == responseCode){
        // not found
        // HEAD requests on readdir_multi_head can return 404
        if(s3fscurl->GetOp() != "HEAD"){
          S3FS_PRN_WARN("failed a request(%ld: %s)", responseCode, s3fscurl->url.c_str());
        }
      }else if(500 == responseCode){
        // case of all other result, do retry.(11/13/2013)
        // because it was found that s3fs got 500 error from S3, but could success
        // to retry it.
        S3FS_PRN_WARN("failed a request(%ld: %s)", responseCode, s3fscurl->url.c_str());
        isRetry = true;
      }else{
        // Retry in other case.
        S3FS_PRN_WARN("failed a request(%ld: %s)", responseCode, s3fscurl->url.c_str());
        isRetry = true;
      }
    }else{
      S3FS_PRN_ERR("failed a request(Unknown response code: %s)", s3fscurl->url.c_str());
    }

    if(isPostpone){
      clist_req.erase(iter);
      clist_req.push_back(s3fscurl);    // Re-evaluate at the end
      iter = clist_req.begin();
    }else{
      if(!isRetry || 0 != result){
        // If an EIO error has already occurred, it will be terminated
        // immediately even if retry processing is required. 
        s3fscurl->DestroyCurlHandle();
        delete s3fscurl;
      }else{
        S3fsCurl* retrycurl = NULL;

        // For retry
        if(RetryCallback){
          retrycurl = RetryCallback(s3fscurl);
          if(NULL != retrycurl){
            clist_all.push_back(retrycurl);
          }else{
            // set EIO and wait for other parts.
            result = -EIO;
          }
        }
        if(s3fscurl != retrycurl){
          s3fscurl->DestroyCurlHandle();
          delete s3fscurl;
        }
      }
      iter = clist_req.erase(iter);
    }
  }
  clist_req.clear();

  if(0 != result){
    // If an EIO error has already occurred, clear all retry objects.
    for(s3fscurllist_t::iterator iter = clist_all.begin(); iter != clist_all.end(); ++iter){
      S3fsCurl* s3fscurl = *iter;
      s3fscurl->DestroyCurlHandle();
      delete s3fscurl;
    }
    clist_all.clear();
  }
  return result;
}

int S3fsMultiCurl::Request()
{
  S3FS_PRN_INFO3("[count=%zu]", clist_all.size());

  // Make request list.
  //
  // Send multi request loop( with retry )
  // (When many request is sends, sometimes gets "Couldn't connect to server")
  //
  while(!clist_all.empty()){
    // set curl handle to multi handle
    int                      result;
    s3fscurllist_t::iterator iter;
    for(iter = clist_all.begin(); iter != clist_all.end(); ++iter){
      S3fsCurl* s3fscurl = *iter;
      clist_req.push_back(s3fscurl);
    }
    clist_all.clear();

    // Send multi request.
    if(0 != (result = MultiPerform())){
      Clear();
      return result;
    }

    // Read the result
    if(0 != (result = MultiRead())){
      Clear();
      return result;
    }

    // Cleanup curl handle in multi handle
    ClearEx(false);
  }
  return 0;
}

// thread function for performing an S3fsCurl request
//
void* S3fsMultiCurl::RequestPerformWrapper(void* arg)
{
  S3fsCurl* s3fscurl= static_cast<S3fsCurl*>(arg);
  void*     result  = NULL;
  if(s3fscurl && s3fscurl->fpLazySetup){
    if(!s3fscurl->fpLazySetup(s3fscurl)){
      S3FS_PRN_ERR("Failed to lazy setup, then respond EIO.");
      result  = (void*)(intptr_t)(-EIO);
    }
  }

  if(!result){
    result = (void*)(intptr_t)(s3fscurl->RequestPerform());
    s3fscurl->DestroyCurlHandle(true, false);
  }

  AutoLock  lock(s3fscurl->completed_tids_lock);
  s3fscurl->completed_tids->push_back(pthread_self());
  s3fscurl->sem->post();

  return result;
}

//-------------------------------------------------------------------
// Utility functions
//-------------------------------------------------------------------
//
// curl_slist_sort_insert
// This function is like curl_slist_append function, but this adds data by a-sorting.
// Because AWS signature needs sorted header.
//
struct curl_slist* curl_slist_sort_insert(struct curl_slist* list, const char* data)
{
  if(!data){
    return list;
  }
  string strkey = data;
  string strval;

  string::size_type pos = strkey.find(':', 0);
  if(string::npos != pos){
    strval = strkey.substr(pos + 1);
    strkey = strkey.substr(0, pos);
  }

  return curl_slist_sort_insert(list, strkey.c_str(), strval.c_str());
}

struct curl_slist* curl_slist_sort_insert(struct curl_slist* list, const char* key, const char* value)
{
  struct curl_slist* curpos;
  struct curl_slist* lastpos;
  struct curl_slist* new_item;

  if(!key){
    return list;
  }
  if(NULL == (new_item = reinterpret_cast<struct curl_slist*>(malloc(sizeof(struct curl_slist))))){
    return list;
  }

  // key & value are trimmed and lower (only key)
  string strkey = trim(string(key));
  string strval = trim(string(value ? value : ""));
  string strnew = key + string(": ") + strval;
  if(NULL == (new_item->data = strdup(strnew.c_str()))){
    free(new_item);
    return list;
  }
  new_item->next = NULL;

  for(lastpos = NULL, curpos = list; curpos; lastpos = curpos, curpos = curpos->next){
    string strcur = curpos->data;
    size_t pos;
    if(string::npos != (pos = strcur.find(':', 0))){
      strcur = strcur.substr(0, pos);
    }

    int result = strcasecmp(strkey.c_str(), strcur.c_str());
    if(0 == result){
      // same data, so replace it.
      if(lastpos){
        lastpos->next = new_item;
      }else{
        list = new_item;
      }
      new_item->next = curpos->next;
      free(curpos->data);
      free(curpos);
      break;

    }else if(0 > result){
      // add data before curpos.
      if(lastpos){
        lastpos->next = new_item;
      }else{
        list = new_item;
      }
      new_item->next = curpos;
      break;
    }
  }

  if(!curpos){
    // append to last pos
    if(lastpos){
      lastpos->next = new_item;
    }else{
      // a case of list is null
      list = new_item;
    }
  }

  return list;
}

string get_sorted_header_keys(const struct curl_slist* list)
{
  string sorted_headers;

  if(!list){
    return sorted_headers;
  }

  for( ; list; list = list->next){
    string strkey = list->data;
    size_t pos;
    if(string::npos != (pos = strkey.find(':', 0))){
      if (trim(strkey.substr(pos + 1)).empty()) {
        // skip empty-value headers (as they are discarded by libcurl)
        continue;
      }
      strkey = strkey.substr(0, pos);
    }
    if(0 < sorted_headers.length()){
      sorted_headers += ";";
    }
    sorted_headers += lower(strkey);
  }

  return sorted_headers;
}

string get_header_value(const struct curl_slist* list, const string &key)
{
  if(!list){
    return "";
  }

  for( ; list; list = list->next){
    string strkey = list->data;
    size_t pos;
    if(string::npos != (pos = strkey.find(':', 0))){
      if(0 == strcasecmp(trim(strkey.substr(0, pos)).c_str(), key.c_str())){
        return trim(strkey.substr(pos+1));
      }
    }
  }

  return "";
}

string get_canonical_headers(const struct curl_slist* list)
{
  string canonical_headers;

  if(!list){
    canonical_headers = "\n";
    return canonical_headers;
  }

  for( ; list; list = list->next){
    string strhead = list->data;
    size_t pos;
    if(string::npos != (pos = strhead.find(':', 0))){
      string strkey = trim(lower(strhead.substr(0, pos)));
      string strval = trim(strhead.substr(pos + 1));
      if (strval.empty()) {
        // skip empty-value headers (as they are discarded by libcurl)
        continue;
      }
      strhead       = strkey.append(":").append(strval);
    }else{
      strhead       = trim(lower(strhead));
    }
    canonical_headers += strhead;
    canonical_headers += "\n";
  }
  return canonical_headers;
}

string get_canonical_headers(const struct curl_slist* list, bool only_amz)
{
  string canonical_headers;

  if(!list){
    canonical_headers = "\n";
    return canonical_headers;
  }

  for( ; list; list = list->next){
    string strhead = list->data;
    size_t pos;
    if(string::npos != (pos = strhead.find(':', 0))){
      string strkey = trim(lower(strhead.substr(0, pos)));
      string strval = trim(strhead.substr(pos + 1));
      if (strval.empty()) {
        // skip empty-value headers (as they are discarded by libcurl)
        continue;
      }
      strhead       = strkey.append(":").append(strval);
    }else{
      strhead       = trim(lower(strhead));
    }
    if(only_amz && strhead.substr(0, 5) != "x-amz"){
      continue;
    }
    canonical_headers += strhead;
    canonical_headers += "\n";
  }
  return canonical_headers;
}

// function for using global values
bool MakeUrlResource(const char* realpath, string& resourcepath, string& url)
{
  if(!realpath){
    return false;
  }
  resourcepath = urlEncode(service_path + bucket + realpath);
  url          = host + resourcepath;
  return true;
}

string prepare_url(const char* url)
{
  S3FS_PRN_INFO3("URL is %s", url);

  string uri;
  string hostname;
  string path;
  string url_str = string(url);
  string token = string("/") + bucket;
  int bucket_pos = url_str.find(token);
  int bucket_length = token.size();
  int uri_length = 0;

  if(!strncasecmp(url_str.c_str(), "https://", 8)){
    uri_length = 8;
  } else if(!strncasecmp(url_str.c_str(), "http://", 7)) {
    uri_length = 7;
  }
  uri  = url_str.substr(0, uri_length);

  if(!pathrequeststyle){
    hostname = bucket + "." + url_str.substr(uri_length, bucket_pos - uri_length);
    path = url_str.substr((bucket_pos + bucket_length));
  }else{
    hostname = url_str.substr(uri_length, bucket_pos - uri_length);
    string part = url_str.substr((bucket_pos + bucket_length));
    if('/' != part[0]){
      part = "/" + part;
    }
    path = "/" + bucket + part;
  }

  url_str = uri + hostname + path;

  S3FS_PRN_INFO3("URL changed is %s", url_str.c_str());

  return url_str;
}

const char *acl_to_string(acl_t acl)
{
  switch(acl){
  case PRIVATE:
    return "private";
  case PUBLIC_READ:
    return "public-read";
  case PUBLIC_READ_WRITE:
    return "public-read-write";
  case AWS_EXEC_READ:
    return "aws-exec-read";
  case AUTHENTICATED_READ:
    return "authenticated-read";
  case BUCKET_OWNER_READ:
    return "bucket-owner-read";
  case BUCKET_OWNER_FULL_CONTROL:
    return "bucket-owner-full-control";
  case LOG_DELIVERY_WRITE:
    return "log-delivery-write";
  case INVALID_ACL:
    return NULL;
  }
  abort();
}

acl_t string_to_acl(const char *acl)
{
  if(0 == strcmp(acl, "private")){
    return PRIVATE;
  }else if(0 == strcmp(acl, "public-read")){
    return PUBLIC_READ;
  }else if(0 == strcmp(acl, "public-read-write")){
    return PUBLIC_READ_WRITE;
  }else if(0 == strcmp(acl, "aws-exec-read")){
    return AWS_EXEC_READ;
  }else if(0 == strcmp(acl, "authenticated-read")){
    return AUTHENTICATED_READ;
  }else if(0 == strcmp(acl, "bucket-owner-read")){
    return BUCKET_OWNER_READ;
  }else if(0 == strcmp(acl, "bucket-owner-full-control")){
    return BUCKET_OWNER_FULL_CONTROL;
  }else if(0 == strcmp(acl, "log-delivery-write")){
    return LOG_DELIVERY_WRITE;
  }else{
    return INVALID_ACL;
  }
}

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: noet sw=4 ts=4 fdm=marker
* vim<600: noet sw=4 ts=4
*/
