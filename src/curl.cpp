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
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <syslog.h>
#include <pthread.h>
#include <assert.h>
#include <curl/curl.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include <libxml/tree.h>
#include <iostream>
#include <fstream>
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

using namespace std;

static const std::string empty_payload_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

//-------------------------------------------------------------------
// Utilities
//-------------------------------------------------------------------
// [TODO]
// This function uses tempolary file, but should not use it.
// For not using it, we implement function in each auth file(openssl, nss. gnutls).
//
static bool make_md5_from_string(const char* pstr, string& md5)
{
  if(!pstr || '\0' == pstr[0]){
    DPRN("Parameter is wrong.");
    return false;
  }
  FILE* fp;
  if(NULL == (fp = tmpfile())){
    FPRN("Could not make tmpfile.");
    return false;
  }
  size_t length = strlen(pstr);
  if(length != fwrite(pstr, sizeof(char), length, fp)){
    FPRN("Failed to write tmpfile.");
    fclose(fp);
    return false;
  }
  int fd;
  if(0 != fflush(fp) || 0 != fseek(fp, 0L, SEEK_SET) || -1 == (fd = fileno(fp))){
    FPRN("Failed to make MD5.");
    fclose(fp);
    return false;
  }
  // base64 md5
  md5 = s3fs_get_content_md5(fd);
  if(0 == md5.length()){
    FPRN("Failed to make MD5.");
    fclose(fp);
    return false;
  }
  fclose(fp);
  return true;
}

static string url_to_host(const std::string &url)
{
    DPRNNN("url is %s", url.c_str());

    static const string http = "http://";
    static const string https = "https://";
    std::string host;

    if (url.compare(0, http.size(), http) == 0) {
        host = url.substr(http.size());
    } else if (url.compare(0, https.size(), https) == 0) {
        host = url.substr(https.size());
    } else {
        assert(!"url does not begin with http:// or https://");
    }

    size_t idx;

    if ((idx = host.find(':')) != string::npos || (idx = host.find('/')) != string::npos) {
        return host.substr(0, idx);
    } else {
        return host;
    }
}

static string get_bucket_host()
{
  if(!pathrequeststyle){
    return bucket + "." + url_to_host(host);
  }
  return url_to_host(host) + "/" + bucket;
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
#define BODYDATA_RESIZE_APPEND_MIN  (1 * 1024)         // 1KB
#define BODYDATA_RESIZE_APPEND_MID  (1 * 1024 * 1024)  // 1MB
#define BODYDATA_RESIZE_APPEND_MAX  (10 * 1024 * 1024) // 10MB
#define	AJUST_BLOCK(bytes, block)   (((bytes / block) + ((bytes % block) ? 1 : 0)) * block)

bool BodyData::Resize(size_t addbytes)
{
  if(IsSafeSize(addbytes)){
    return true;
  }

  // New size
  size_t need_size = AJUST_BLOCK((lastpos + addbytes + 1) - bufsize, sizeof(off_t));

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
    DPRNCRIT("not enough memory (realloc returned NULL)");
    free(text);
    text = NULL;
    return false;
  }
  text     = newtext;
  bufsize += need_size;

  return true;
}

void BodyData::Clear(void)
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

const char* BodyData::str(void) const
{
  static const char* strnull = "";
  if(!text){
    return strnull;
  }
  return text;
}

//-------------------------------------------------------------------
// Class S3fsCurl
//-------------------------------------------------------------------
#define MULTIPART_SIZE              10485760          // 10MB
#define MAX_MULTI_COPY_SOURCE_SIZE  524288000         // 500MB

#define	IAM_EXPIRE_MERGIN           (20 * 60)         // update timming
#define	IAM_CRED_URL                "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
#define IAMCRED_ACCESSKEYID         "AccessKeyId"
#define IAMCRED_SECRETACCESSKEY     "SecretAccessKey"
#define IAMCRED_ACCESSTOKEN         "Token"
#define IAMCRED_EXPIRATION          "Expiration"
#define IAMCRED_KEYCOUNT            4

// [NOTICE]
// This symbol is for libcurl under 7.23.0
#ifndef CURLSHE_NOT_BUILT_IN
#define CURLSHE_NOT_BUILT_IN        5
#endif

pthread_mutex_t  S3fsCurl::curl_handles_lock;
pthread_mutex_t  S3fsCurl::curl_share_lock[SHARE_MUTEX_MAX];
bool             S3fsCurl::is_initglobal_done  = false;
CURLSH*          S3fsCurl::hCurlShare          = NULL;
bool             S3fsCurl::is_cert_check       = true; // default
bool             S3fsCurl::is_dns_cache        = true; // default
bool             S3fsCurl::is_ssl_session_cache= true; // default
long             S3fsCurl::connect_timeout     = 300;  // default
time_t           S3fsCurl::readwrite_timeout   = 60;   // default
int              S3fsCurl::retries             = 3;    // default
bool             S3fsCurl::is_public_bucket    = false;
string           S3fsCurl::default_acl         = "private";
bool             S3fsCurl::is_use_rrs          = false;
sseckeylist_t    S3fsCurl::sseckeys;
bool             S3fsCurl::is_use_sse          = false;
bool             S3fsCurl::is_content_md5      = false;
bool             S3fsCurl::is_verbose          = false;
string           S3fsCurl::AWSAccessKeyId;
string           S3fsCurl::AWSSecretAccessKey;
string           S3fsCurl::AWSAccessToken;
time_t           S3fsCurl::AWSAccessTokenExpire= 0;
string           S3fsCurl::IAM_role;
long             S3fsCurl::ssl_verify_hostname = 1;    // default(original code...)
curltime_t       S3fsCurl::curl_times;
curlprogress_t   S3fsCurl::curl_progress;
string           S3fsCurl::curl_ca_bundle;
mimes_t          S3fsCurl::mimeTypes;
int              S3fsCurl::max_parallel_cnt    = 5;              // default
off_t            S3fsCurl::multipart_size      = MULTIPART_SIZE; // default
bool             S3fsCurl::is_sigv4            = true;           // default

//-------------------------------------------------------------------
// Class methods for S3fsCurl
//-------------------------------------------------------------------
bool S3fsCurl::InitS3fsCurl(const char* MimeFile)
{
  if(0 != pthread_mutex_init(&S3fsCurl::curl_handles_lock, NULL)){
    return false;
  }
  if(0 != pthread_mutex_init(&S3fsCurl::curl_share_lock[SHARE_MUTEX_DNS], NULL)){
    return false;
  }
  if(0 != pthread_mutex_init(&S3fsCurl::curl_share_lock[SHARE_MUTEX_SSL_SESSION], NULL)){
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
  return true;
}

bool S3fsCurl::DestroyS3fsCurl(void)
{
  int result = true;

  if(!S3fsCurl::DestroyCryptMutex()){
    result = false;
  }
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

bool S3fsCurl::InitGlobalCurl(void)
{
  if(S3fsCurl::is_initglobal_done){
    return false;
  }
  if(CURLE_OK != curl_global_init(CURL_GLOBAL_ALL)){
    DPRN("init_curl_global_all returns error.");
    return false;
  }
  S3fsCurl::is_initglobal_done = true;
  return true;
}

bool S3fsCurl::DestroyGlobalCurl(void)
{
  if(!S3fsCurl::is_initglobal_done){
    return false;
  }
  curl_global_cleanup();
  S3fsCurl::is_initglobal_done = false;
  return true;
}

bool S3fsCurl::InitShareCurl(void)
{
  CURLSHcode nSHCode;

  if(!S3fsCurl::is_dns_cache && !S3fsCurl::is_ssl_session_cache){
    DPRN("Curl does not share DNS data.");
    return true;
  }
  if(S3fsCurl::hCurlShare){
    DPRN("already initiated.");
    return false;
  }
  if(NULL == (S3fsCurl::hCurlShare = curl_share_init())){
    DPRN("curl_share_init failed");
    return false;
  }
  if(CURLSHE_OK != (nSHCode = curl_share_setopt(S3fsCurl::hCurlShare, CURLSHOPT_LOCKFUNC, S3fsCurl::LockCurlShare))){
    DPRN("curl_share_setopt(LOCKFUNC) returns %d(%s)", nSHCode, curl_share_strerror(nSHCode));
    return false;
  }
  if(CURLSHE_OK != (nSHCode = curl_share_setopt(S3fsCurl::hCurlShare, CURLSHOPT_UNLOCKFUNC, S3fsCurl::UnlockCurlShare))){
    DPRN("curl_share_setopt(UNLOCKFUNC) returns %d(%s)", nSHCode, curl_share_strerror(nSHCode));
    return false;
  }
  if(S3fsCurl::is_dns_cache){
    nSHCode = curl_share_setopt(S3fsCurl::hCurlShare, CURLSHOPT_SHARE, CURL_LOCK_DATA_DNS);
    if(CURLSHE_OK != nSHCode && CURLSHE_BAD_OPTION != nSHCode && CURLSHE_NOT_BUILT_IN != nSHCode){
      DPRN("curl_share_setopt(DNS) returns %d(%s)", nSHCode, curl_share_strerror(nSHCode));
      return false;
    }else if(CURLSHE_BAD_OPTION == nSHCode || CURLSHE_NOT_BUILT_IN == nSHCode){
      DPRN("curl_share_setopt(DNS) returns %d(%s), but continue without shared dns data.", nSHCode, curl_share_strerror(nSHCode));
    }
  }
  if(S3fsCurl::is_ssl_session_cache){
    nSHCode = curl_share_setopt(S3fsCurl::hCurlShare, CURLSHOPT_SHARE, CURL_LOCK_DATA_SSL_SESSION);
    if(CURLSHE_OK != nSHCode && CURLSHE_BAD_OPTION != nSHCode && CURLSHE_NOT_BUILT_IN != nSHCode){
      DPRN("curl_share_setopt(SSL SESSION) returns %d(%s)", nSHCode, curl_share_strerror(nSHCode));
      return false;
    }else if(CURLSHE_BAD_OPTION == nSHCode || CURLSHE_NOT_BUILT_IN == nSHCode){
      DPRN("curl_share_setopt(SSL SESSION) returns %d(%s), but continue without shared ssl session data.", nSHCode, curl_share_strerror(nSHCode));
    }
  }
  if(CURLSHE_OK != (nSHCode = curl_share_setopt(S3fsCurl::hCurlShare, CURLSHOPT_USERDATA, (void*)&S3fsCurl::curl_share_lock[0]))){
    DPRN("curl_share_setopt(USERDATA) returns %d(%s)", nSHCode, curl_share_strerror(nSHCode));
    return false;
  }
  return true;
}

bool S3fsCurl::DestroyShareCurl(void)
{
  if(!S3fsCurl::hCurlShare){
    if(!S3fsCurl::is_dns_cache && !S3fsCurl::is_ssl_session_cache){
      return true;
    }
    DPRN("already destroy share curl.");
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

bool S3fsCurl::InitCryptMutex(void)
{
  return s3fs_init_crypt_mutex();
}

bool S3fsCurl::DestroyCryptMutex(void)
{
  return s3fs_destroy_crypt_mutex();
}

// homegrown timeout mechanism
int S3fsCurl::CurlProgress(void *clientp, double dltotal, double dlnow, double ultotal, double ulnow)
{
  CURL* curl = static_cast<CURL*>(clientp);
  time_t now = time(0);
  progress_t p(dlnow, ulnow);

  pthread_mutex_lock(&S3fsCurl::curl_handles_lock);

  // any progress?
  if(p != S3fsCurl::curl_progress[curl]){
    // yes!
    S3fsCurl::curl_times[curl]    = now;
    S3fsCurl::curl_progress[curl] = p;
  }else{
    // timeout?
    if(now - S3fsCurl::curl_times[curl] > readwrite_timeout){
      pthread_mutex_unlock(&S3fsCurl::curl_handles_lock);
      DPRN("timeout now: %jd, curl_times[curl]: %jd, readwrite_timeout: %jd",
                      (intmax_t)now, (intmax_t)(S3fsCurl::curl_times[curl]), (intmax_t)readwrite_timeout);
      return CURLE_ABORTED_BY_CALLBACK;
    }
  }

  pthread_mutex_unlock(&S3fsCurl::curl_handles_lock);
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
      if(line.size() == 0){
        continue;
      }

      stringstream tmp(line);
      string mimeType;
      tmp >> mimeType;
      while(tmp){
        string ext;
        tmp >> ext;
        if(ext.size() == 0){
          continue;
        }
        S3fsCurl::mimeTypes[ext] = mimeType;
      }
    }
  }
  return true;
}

//
// @param s e.g., "index.html"
// @return e.g., "text/html"
//
string S3fsCurl::LookupMimeType(string name)
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
  if(last_pos != string::npos){
    ext = name.substr(1+last_pos, string::npos);
  }
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

bool S3fsCurl::LocateBundle(void)
{
  // See if environment variable CURL_CA_BUNDLE is set
  // if so, check it, if it is a good path, then set the
  // curl_ca_bundle variable to it
  char *CURL_CA_BUNDLE; 

  if(0 == S3fsCurl::curl_ca_bundle.size()){
    CURL_CA_BUNDLE = getenv("CURL_CA_BUNDLE");
    if(CURL_CA_BUNDLE != NULL)  {
      // check for existence and readability of the file
      ifstream BF(CURL_CA_BUNDLE);
      if(!BF.good()){
        DPRN("%s: file specified by CURL_CA_BUNDLE environment variable is not readable", program_name.c_str());
        return false;
      }
      BF.close();
      S3fsCurl::curl_ca_bundle.assign(CURL_CA_BUNDLE); 
      return true;
    }
  }

  // not set via environment variable, look in likely locations

  ///////////////////////////////////////////
  // from curl's (7.21.2) acinclude.m4 file
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
  ifstream BF("/etc/pki/tls/certs/ca-bundle.crt"); 
  if(BF.good()){
     BF.close();
     S3fsCurl::curl_ca_bundle.assign("/etc/pki/tls/certs/ca-bundle.crt"); 
  }else{
    DPRN("%s: /etc/pki/tls/certs/ca-bundle.crt is not readable", program_name.c_str());
    return false;
  }
  return true;
}

size_t S3fsCurl::WriteMemoryCallback(void* ptr, size_t blockSize, size_t numBlocks, void* data)
{
  BodyData* body  = (BodyData*)data;

  if(!body->Append(ptr, blockSize, numBlocks)){
    DPRNCRIT("BodyData.Append() returned false.");
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
  stringstream ss(header);

  if(getline(ss, key, ':')){
    // Force to lower, only "x-amz"
    string lkey = key;
    transform(lkey.begin(), lkey.end(), lkey.begin(), static_cast<int (*)(int)>(std::tolower));
    if(lkey.substr(0, 5) == "x-amz"){
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
      DPRN("read file error(%d).", errno);
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
      DPRN("write file error(%d).", errno);
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

string S3fsCurl::SetDefaultAcl(const char* acl)
{
  string old = S3fsCurl::default_acl;
  S3fsCurl::default_acl = acl ? acl : "";
  return old;
}

bool S3fsCurl::SetUseRrs(bool flag)
{
  bool old = S3fsCurl::is_use_rrs;
  S3fsCurl::is_use_rrs = flag;
  return old;
}

bool S3fsCurl::PushbackSseKeys(string& onekey)
{
  onekey = trim(onekey);
  if(0 == onekey.size()){
    return false;
  }
  if('#' == onekey[0]){
    return false;
  }
  // make base64
  char* pbase64_key;
  if(NULL == (pbase64_key = s3fs_base64((unsigned char*)onekey.c_str(), onekey.length()))){
    FPRN("Failed to convert base64 from sse-c key %s", onekey.c_str());
    return false;
  }
  string base64_key = pbase64_key;
  free(pbase64_key);

  // make MD5
  string strMd5;
  if(!make_md5_from_string(onekey.c_str(), strMd5)){
    FPRN("Could not make MD5 from SSE-C keys(%s).", onekey.c_str());
    return false;
  }
  // mapped MD5 = SSE Key
  sseckeymap_t md5map;
  md5map.clear();
  md5map[strMd5] = base64_key;
  S3fsCurl::sseckeys.push_back(md5map);
  return true;
}

bool S3fsCurl::SetSseKeys(const char* filepath)
{
  if(!filepath){
    DPRN("SSE-C keys filepath is empty.");
    return false;
  }
  S3fsCurl::sseckeys.clear();

  ifstream ssefs(filepath);
  if(!ssefs.good()){
    FPRN("Could not open SSE-C keys file(%s).", filepath);
    return false;
  }

  string   line;
  while(getline(ssefs, line)){
    S3fsCurl::PushbackSseKeys(line);
  }
  if(0 == S3fsCurl::sseckeys.size()){
    FPRN("There is no SSE Key in file(%s).", filepath);
    return false;
  }
  return true;
}
                                                                                                                                                   
bool S3fsCurl::LoadEnvSseKeys(void)
{
  char* envkeys = getenv("AWSSSECKEYS");
  if(NULL == envkeys){
    return false;
  }
  S3fsCurl::sseckeys.clear();

  istringstream fullkeys(envkeys);
  string        onekey;
  while(getline(fullkeys, onekey, ':')){
    S3fsCurl::PushbackSseKeys(onekey);
  }
  if(0 == S3fsCurl::sseckeys.size()){
    FPRN("There is no SSE Key in environment(AWSSSECKEYS=%s).", envkeys);
    return false;
  }
  return true;
}

//
// If md5 is empty, returns first(current) sse key.
//
bool S3fsCurl::GetSseKey(string& md5, string& ssekey)
{
  for(sseckeylist_t::const_iterator iter = S3fsCurl::sseckeys.begin(); iter != S3fsCurl::sseckeys.end(); iter++){
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
  for(sseckeylist_t::const_iterator iter = S3fsCurl::sseckeys.begin(); iter != S3fsCurl::sseckeys.end(); iter++, cnt++){
    if(pos == cnt){
      md5 = iter->begin()->first;
      return true;
    }
  }
  return false;
}

int S3fsCurl::GetSseKeyCount(void)
{
  return S3fsCurl::sseckeys.size();
}

bool S3fsCurl::IsSseCustomMode(void)
{
  return (0 < S3fsCurl::sseckeys.size());
}

bool S3fsCurl::SetUseSse(bool flag)
{
  bool old = S3fsCurl::is_use_sse;
  S3fsCurl::is_use_sse = flag;
  return old;
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
  if(!AccessKeyId || '\0' == AccessKeyId[0] || !SecretAccessKey || '\0' == SecretAccessKey[0]){
    return false;
  }
  AWSAccessKeyId     = AccessKeyId;
  AWSSecretAccessKey = SecretAccessKey;
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

string S3fsCurl::SetIAMRole(const char* role)
{
  string old = S3fsCurl::IAM_role;
  S3fsCurl::IAM_role = role ? role : "";
  return old;
}

bool S3fsCurl::SetMultipartSize(off_t size)
{
  size = size * 1024 * 1024;
  if(size < MULTIPART_SIZE){
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

bool S3fsCurl::UploadMultipartPostCallback(S3fsCurl* s3fscurl)
{
  if(!s3fscurl){
    return false;
  }
  // check etag(md5);
  if(NULL == strstr(s3fscurl->headdata->str(), s3fscurl->partdata.etag.c_str())){
    return false;
  }
  s3fscurl->partdata.etaglist->at(s3fscurl->partdata.etagpos).assign(s3fscurl->partdata.etag);
  s3fscurl->partdata.uploaded = true;

  return true;
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
  part_num = atoi(part_num_str.c_str());

  if(s3fscurl->retry_count >= S3fsCurl::retries){
    DPRN("Over retry count(%d) limit(%s:%d).", s3fscurl->retry_count, s3fscurl->path.c_str(), part_num);
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

  // setup new curl object
  if(0 != newcurl->UploadMultipartPostSetup(s3fscurl->path.c_str(), part_num, upload_id)){
    DPRN("Could not duplicate curl object(%s:%d).", s3fscurl->path.c_str(), part_num);
    delete newcurl;
    return NULL;
  }
  return newcurl;
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

  FPRNNN("[tpath=%s][fd=%d]", SAFESTRPTR(tpath), fd);

  // duplicate fd
  if(-1 == (fd2 = dup(fd)) || 0 != lseek(fd2, 0, SEEK_SET)){
    DPRN("Could not duplicate file descriptor(errno=%d)", errno);
    if(-1 != fd2){
      close(fd2);
    }
    return -errno;
  }
  if(-1 == fstat(fd2, &st)){
    DPRN("Invalid file descriptor(errno=%d)", errno);
    close(fd2);
    return -errno;
  }

  if(0 != (result = s3fscurl.PreMultipartPostRequest(tpath, meta, upload_id, false))){
    close(fd2);
    return result;
  }
  s3fscurl.DestroyCurlHandle();

  // cycle through open fd, pulling off 10MB chunks at a time
  for(remaining_bytes = st.st_size; 0 < remaining_bytes; ){
    S3fsMultiCurl curlmulti;
    int           para_cnt;
    off_t         chunk;

    // Initialize S3fsMultiCurl
    curlmulti.SetSuccessCallback(S3fsCurl::UploadMultipartPostCallback);
    curlmulti.SetRetryCallback(S3fsCurl::UploadMultipartPostRetryCallback);

    // Loop for setup parallel upload(multipart) request.
    for(para_cnt = 0; para_cnt < S3fsCurl::max_parallel_cnt && 0 < remaining_bytes; para_cnt++, remaining_bytes -= chunk){
      // chunk size
      chunk = remaining_bytes > S3fsCurl::multipart_size ? S3fsCurl::multipart_size : remaining_bytes;

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
        DPRN("failed uploading part setup(%d)", result);
        close(fd2);
        delete s3fscurl_para;
        return result;
      }

      // set into parallel object
      if(!curlmulti.SetS3fsCurlObject(s3fscurl_para)){
        DPRN("Could not make curl object into multi curl(%s).", tpath);
        close(fd2);
        delete s3fscurl_para;
        return -1;
      }
    }

    // Multi request
    if(0 != (result = curlmulti.Request())){
      DPRN("error occuered in multi request(errno=%d).", result);
      break;
    }

    // reinit for loop.
    curlmulti.Clear();
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
    DPRN("Over retry count(%d) limit(%s).", s3fscurl->retry_count, s3fscurl->path.c_str());
    return NULL;
  }

  // duplicate request(setup new curl object)
  S3fsCurl* newcurl = new S3fsCurl(s3fscurl->IsUseAhbe());
  if(0 != (result = newcurl->PreGetObjectRequest(
           s3fscurl->path.c_str(), s3fscurl->partdata.fd, s3fscurl->partdata.startpos, s3fscurl->partdata.size, s3fscurl->b_ssekey_md5))){
    DPRN("failed downloading part setup(%d)", result);
    delete newcurl;
    return NULL;;
  }
  newcurl->retry_count = s3fscurl->retry_count + 1;

  return newcurl;
}

int S3fsCurl::ParallelGetObjectRequest(const char* tpath, int fd, off_t start, ssize_t size)
{
  FPRNNN("[tpath=%s][fd=%d]", SAFESTRPTR(tpath), fd);

  string sseckeymd5("");
  char*  psseckeymd5;
  if(NULL != (psseckeymd5 = get_object_sseckey_md5(tpath))){
    sseckeymd5 = psseckeymd5;
    free(psseckeymd5);
  }
  int     result = 0;
  ssize_t remaining_bytes;

  // cycle through open fd, pulling off 10MB chunks at a time
  for(remaining_bytes = size; 0 < remaining_bytes; ){
    S3fsMultiCurl curlmulti;
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
      if(0 != (result = s3fscurl_para->PreGetObjectRequest(tpath, fd, (start + size - remaining_bytes), chunk, sseckeymd5))){
        DPRN("failed downloading part setup(%d)", result);
        delete s3fscurl_para;
        return result;
      }

      // set into parallel object
      if(!curlmulti.SetS3fsCurlObject(s3fscurl_para)){
        DPRN("Could not make curl object into multi curl(%s).", tpath);
        delete s3fscurl_para;
        return -1;
      }
    }

    // Multi request
    if(0 != (result = curlmulti.Request())){
      DPRN("error occuered in multi request(errno=%d).", result);
      break;
    }

    // reinit for loop.
    curlmulti.Clear();
  }
  return result;
}

bool S3fsCurl::ParseIAMCredentialResponse(const char* response, iamcredmap_t& keyval)
{
  if(!response){
    return false;
  }
  istringstream sscred(response);
  string        oneline;
  keyval.clear();
  while(getline(sscred, oneline, '\n')){
    string::size_type pos;
    string            key;
    string            val;
    if(string::npos != (pos = oneline.find(IAMCRED_ACCESSKEYID))){
      key = IAMCRED_ACCESSKEYID;
    }else if(string::npos != (pos = oneline.find(IAMCRED_SECRETACCESSKEY))){
      key = IAMCRED_SECRETACCESSKEY;
    }else if(string::npos != (pos = oneline.find(IAMCRED_ACCESSTOKEN))){
      key = IAMCRED_ACCESSTOKEN;
    }else if(string::npos != (pos = oneline.find(IAMCRED_EXPIRATION))){
      key = IAMCRED_EXPIRATION;
    }else{
      continue;
    }
    if(string::npos == (pos = oneline.find(':', pos + key.length()))){
      continue;
    }
    if(string::npos == (pos = oneline.find('\"', pos))){
      continue;
    }
    oneline = oneline.substr(pos + sizeof(char));
    if(string::npos == (pos = oneline.find('\"'))){
      continue;
    }
    val = oneline.substr(0, pos);
    keyval[key] = val;
  }
  return true;
}

bool S3fsCurl::SetIAMCredentials(const char* response)
{
  FPRNINFO("IAM credential response = \"%s\"", response);

  iamcredmap_t keyval;

  if(!ParseIAMCredentialResponse(response, keyval)){
    return false;
  }
  if(IAMCRED_KEYCOUNT != keyval.size()){
    return false;
  }

  S3fsCurl::AWSAccessKeyId       = keyval[string(IAMCRED_ACCESSKEYID)];
  S3fsCurl::AWSSecretAccessKey   = keyval[string(IAMCRED_SECRETACCESSKEY)];
  S3fsCurl::AWSAccessToken       = keyval[string(IAMCRED_ACCESSTOKEN)];
  S3fsCurl::AWSAccessTokenExpire = cvtIAMExpireStringToTime(keyval[string(IAMCRED_EXPIRATION)].c_str());

  return true;
}

bool S3fsCurl::CheckIAMCredentialUpdate(void)
{
  if(0 == S3fsCurl::IAM_role.size()){
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

//-------------------------------------------------------------------
// Methods for S3fsCurl
//-------------------------------------------------------------------
S3fsCurl::S3fsCurl(bool ahbe) : 
    hCurl(NULL), path(""), base_path(""), saved_path(""), url(""), requestHeaders(NULL),
    bodydata(NULL), headdata(NULL), LastResponseCode(-1), postdata(NULL), postdata_remaining(0), is_use_ahbe(ahbe),
    retry_count(0), b_infile(NULL), b_postdata(NULL), b_postdata_remaining(0), b_partdata_startpos(0), b_partdata_size(0),
    b_ssekey_pos(-1), b_ssekey_md5("")
{
  type = REQTYPE_UNSET;
}

S3fsCurl::~S3fsCurl()
{
  DestroyCurlHandle();
}

bool S3fsCurl::ResetHandle(void)
{
  curl_easy_reset(hCurl);
  curl_easy_setopt(hCurl, CURLOPT_NOSIGNAL, 1);
  curl_easy_setopt(hCurl, CURLOPT_FOLLOWLOCATION, true);
  curl_easy_setopt(hCurl, CURLOPT_CONNECTTIMEOUT, S3fsCurl::connect_timeout);
  curl_easy_setopt(hCurl, CURLOPT_NOPROGRESS, 0);
  curl_easy_setopt(hCurl, CURLOPT_PROGRESSFUNCTION, S3fsCurl::CurlProgress);
  curl_easy_setopt(hCurl, CURLOPT_PROGRESSDATA, hCurl);
  // curl_easy_setopt(hCurl, CURLOPT_FORBID_REUSE, 1);

  if(type != REQTYPE_IAMCRED){
    // REQTYPE_IAMCRED is always HTTP
    if(0 == S3fsCurl::ssl_verify_hostname){
      curl_easy_setopt(hCurl, CURLOPT_SSL_VERIFYHOST, 0);
    }
    if(S3fsCurl::curl_ca_bundle.size() != 0){
      curl_easy_setopt(hCurl, CURLOPT_CAINFO, S3fsCurl::curl_ca_bundle.c_str());
    }
  }
  if((S3fsCurl::is_dns_cache || S3fsCurl::is_ssl_session_cache) && S3fsCurl::hCurlShare){
    curl_easy_setopt(hCurl, CURLOPT_SHARE, S3fsCurl::hCurlShare);
  }
  if(!S3fsCurl::is_cert_check) {
    DPRN("'no_check_certificate' option in effect.")
    DPRN("The server certificate won't be checked against the available certificate authorities.")
    curl_easy_setopt(hCurl, CURLOPT_SSL_VERIFYPEER, false);
  }
  if(S3fsCurl::is_verbose){
    curl_easy_setopt(hCurl, CURLOPT_VERBOSE, true);
  }

  S3fsCurl::curl_times[hCurl]    = time(0);
  S3fsCurl::curl_progress[hCurl] = progress_t(-1, -1);

  return true;
}

bool S3fsCurl::CreateCurlHandle(bool force)
{
  pthread_mutex_lock(&S3fsCurl::curl_handles_lock);

  if(hCurl){
    if(!force){
      DPRN("already create handle.");
      return false;
    }
    if(!DestroyCurlHandle()){
      DPRN("could not destroy handle.");
      return false;
    }
    DPRN("already has handle, so destroied it.");
  }

  if(NULL == (hCurl = curl_easy_init())){
    DPRN("Failed to create handle.");
    return false;
  }
  type = REQTYPE_UNSET;
  ResetHandle();

  pthread_mutex_unlock(&S3fsCurl::curl_handles_lock);

  return true;
}

bool S3fsCurl::DestroyCurlHandle(void)
{
  if(!hCurl){
    return false;
  }
  pthread_mutex_lock(&S3fsCurl::curl_handles_lock);

  S3fsCurl::curl_times.erase(hCurl);
  S3fsCurl::curl_progress.erase(hCurl);
  curl_easy_cleanup(hCurl);
  hCurl = NULL;
  ClearInternalData();

  pthread_mutex_unlock(&S3fsCurl::curl_handles_lock);
  return true;
}

bool S3fsCurl::ClearInternalData(void)
{
  if(hCurl){
    return false;
  }
  type      = REQTYPE_UNSET;
  path      = "";
  base_path = "";
  saved_path= "";
  url       = "";
  if(requestHeaders){
    curl_slist_free_all(requestHeaders);
    requestHeaders = NULL;
  }
  responseHeaders.clear();
  if(bodydata){
    delete bodydata;
    bodydata = NULL;
  }
  if(headdata){
    delete headdata;
    headdata = NULL;
  }
  LastResponseCode     = -1;
  postdata             = NULL;
  postdata_remaining   = 0;
  retry_count          = 0;
  b_infile             = NULL;
  b_postdata           = NULL;
  b_postdata_remaining = 0;
  b_partdata_startpos  = 0;
  b_partdata_size      = 0;
  partdata.clear();

  S3FS_MALLOCTRIM(0);

  return true;
}

bool S3fsCurl::SetUseAhbe(bool ahbe)
{
  bool old = is_use_ahbe;
  is_use_ahbe = ahbe;
  return old;
}

bool S3fsCurl::GetResponseCode(long& responseCode)
{
  if(!hCurl){
    return false;
  }
  responseCode = -1;
  if(CURLE_OK != curl_easy_getinfo(hCurl, CURLINFO_RESPONSE_CODE, &LastResponseCode)){
    return false;
  }
  responseCode = LastResponseCode;
  return true;
}

//
// Reset all options for retrying
//
bool S3fsCurl::RemakeHandle(void)
{
  DPRNNN("Retry request. [type=%d][url=%s][path=%s]", type, url.c_str(), path.c_str());

  if(REQTYPE_UNSET == type){
    return false;
  }

  // rewind file
  struct stat st;
  if(b_infile){
    rewind(b_infile);
    if(-1 == fstat(fileno(b_infile), &st)){
      DPRNNN("Could not get file stat(fd=%d)", fileno(b_infile));
      return false;
    }
  }

  // reinitialize internal data
  responseHeaders.clear();
  if(bodydata){
    bodydata->Clear();
  }
  if(headdata){
    headdata->Clear();
  }
  LastResponseCode   = -1;

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
      curl_easy_setopt(hCurl, CURLOPT_HTTPHEADER, requestHeaders);
      break;

    case REQTYPE_HEAD:
      curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
      curl_easy_setopt(hCurl, CURLOPT_NOBODY, true);
      curl_easy_setopt(hCurl, CURLOPT_FILETIME, true);
      curl_easy_setopt(hCurl, CURLOPT_HTTPHEADER, requestHeaders);
      // responseHeaders
      curl_easy_setopt(hCurl, CURLOPT_HEADERDATA, (void*)&responseHeaders);
      curl_easy_setopt(hCurl, CURLOPT_HEADERFUNCTION, HeaderCallback);
      break;

    case REQTYPE_PUTHEAD:
      curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
      curl_easy_setopt(hCurl, CURLOPT_UPLOAD, true);
      curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, (void*)bodydata);
      curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
      curl_easy_setopt(hCurl, CURLOPT_INFILESIZE, 0);
      curl_easy_setopt(hCurl, CURLOPT_HTTPHEADER, requestHeaders);
      break;

    case REQTYPE_PUT:
      curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
      curl_easy_setopt(hCurl, CURLOPT_UPLOAD, true);
      curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, (void*)bodydata);
      curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
      curl_easy_setopt(hCurl, CURLOPT_HTTPHEADER, requestHeaders);
      if(b_infile){
        curl_easy_setopt(hCurl, CURLOPT_INFILESIZE_LARGE, static_cast<curl_off_t>(st.st_size));
        curl_easy_setopt(hCurl, CURLOPT_INFILE, b_infile);
      }else{
        curl_easy_setopt(hCurl, CURLOPT_INFILESIZE, 0);
      }
      break;

    case REQTYPE_GET:
      curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
      curl_easy_setopt(hCurl, CURLOPT_HTTPHEADER, requestHeaders);
      curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, S3fsCurl::DownloadWriteCallback);
      curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, (void*)this);
      break;

    case REQTYPE_CHKBUCKET:
      curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
      curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, (void*)bodydata);
      curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
      curl_easy_setopt(hCurl, CURLOPT_HTTPHEADER, requestHeaders);
      break;

    case REQTYPE_LISTBUCKET:
      curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
      curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, (void*)bodydata);
      curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
      curl_easy_setopt(hCurl, CURLOPT_HTTPHEADER, requestHeaders);
      break;

    case REQTYPE_PREMULTIPOST:
      curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
      curl_easy_setopt(hCurl, CURLOPT_POST, true);
      curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, (void*)bodydata);
      curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
      curl_easy_setopt(hCurl, CURLOPT_POSTFIELDSIZE, 0);
      curl_easy_setopt(hCurl, CURLOPT_HTTPHEADER, requestHeaders);
      break;

    case REQTYPE_COMPLETEMULTIPOST:
      curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
      curl_easy_setopt(hCurl, CURLOPT_HTTPHEADER, requestHeaders);
      curl_easy_setopt(hCurl, CURLOPT_POST, true);
      curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, (void*)bodydata);
      curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
      curl_easy_setopt(hCurl, CURLOPT_POSTFIELDSIZE, static_cast<curl_off_t>(postdata_remaining));
      curl_easy_setopt(hCurl, CURLOPT_READDATA, (void*)this);
      curl_easy_setopt(hCurl, CURLOPT_READFUNCTION, S3fsCurl::ReadCallback);
      break;

    case REQTYPE_UPLOADMULTIPOST:
      curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
      curl_easy_setopt(hCurl, CURLOPT_UPLOAD, true);
      curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, (void*)bodydata);
      curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
      curl_easy_setopt(hCurl, CURLOPT_HEADERDATA, (void*)headdata);
      curl_easy_setopt(hCurl, CURLOPT_HEADERFUNCTION, WriteMemoryCallback);
      curl_easy_setopt(hCurl, CURLOPT_INFILESIZE_LARGE, static_cast<curl_off_t>(partdata.size));
      curl_easy_setopt(hCurl, CURLOPT_READFUNCTION, S3fsCurl::UploadReadCallback);
      curl_easy_setopt(hCurl, CURLOPT_READDATA, (void*)this);
      curl_easy_setopt(hCurl, CURLOPT_HTTPHEADER, requestHeaders);
      break;

    case REQTYPE_COPYMULTIPOST:
      curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
      curl_easy_setopt(hCurl, CURLOPT_UPLOAD, true);
      curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, (void*)bodydata);
      curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
      curl_easy_setopt(hCurl, CURLOPT_HEADERDATA, (void*)headdata);
      curl_easy_setopt(hCurl, CURLOPT_HEADERFUNCTION, WriteMemoryCallback);
      curl_easy_setopt(hCurl, CURLOPT_INFILESIZE, 0);
      curl_easy_setopt(hCurl, CURLOPT_HTTPHEADER, requestHeaders);
      break;

    case REQTYPE_MULTILIST:
      curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
      curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, (void*)bodydata);
      curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
      curl_easy_setopt(hCurl, CURLOPT_HTTPHEADER, requestHeaders);
      break;

    case REQTYPE_IAMCRED:
      curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
      curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, (void*)bodydata);
      curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
      break;

    case REQTYPE_ABORTMULTIUPLOAD:
      curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
      curl_easy_setopt(hCurl, CURLOPT_CUSTOMREQUEST, "DELETE");
      curl_easy_setopt(hCurl, CURLOPT_HTTPHEADER, requestHeaders);
      break;

    default:
      DPRNNN("request type is unknown(%d)", type);
      return false;
  }
  return true;
}

//
// returns curl return code
//
int S3fsCurl::RequestPerform(void)
{
  if(debug){
    char* ptr_url = NULL;
    curl_easy_getinfo(hCurl, CURLINFO_EFFECTIVE_URL , &ptr_url);
    DPRNNN("connecting to URL %s", SAFESTRPTR(ptr_url));
  }

  // 1 attempt + retries...
  for(int retrycnt = S3fsCurl::retries; 0 < retrycnt; retrycnt--){
    // Requests
    CURLcode curlCode = curl_easy_perform(hCurl);

    // Check result
    switch(curlCode){
      case CURLE_OK:
        // Need to look at the HTTP response code
        if(0 != curl_easy_getinfo(hCurl, CURLINFO_RESPONSE_CODE, &LastResponseCode)){
          DPRNNN("curl_easy_getinfo failed while trying to retrieve HTTP response code");
          return -EIO;
        }
        if(400 > LastResponseCode){
          DPRNNN("HTTP response code %ld", LastResponseCode);
          return 0;
        }
        if(500 <= LastResponseCode){
          DPRNNN("###HTTP response=%ld", LastResponseCode);
          sleep(4);
          break; 
        }

        // Service response codes which are >= 400 && < 500
        switch(LastResponseCode){
          case 400:
            DPRNNN("HTTP response code 400 was returned, returing EIO.");
            DPRNINFO("Body Text: %s", (bodydata ? bodydata->str() : ""));
            return -EIO;

          case 403:
            DPRNNN("HTTP response code 403 was returned, returning EPERM");
            DPRNINFO("Body Text: %s", (bodydata ? bodydata->str() : ""));
            return -EPERM;

          case 404:
            DPRNNN("HTTP response code 404 was returned, returning ENOENT");
            DPRNINFO("Body Text: %s", (bodydata ? bodydata->str() : ""));
            return -ENOENT;

          default:
            DPRNNN("HTTP response code = %ld, returning EIO", LastResponseCode);
            DPRNINFO("Body Text: %s", (bodydata ? bodydata->str() : ""));
            return -EIO;
        }
        break;

      case CURLE_WRITE_ERROR:
        DPRN("### CURLE_WRITE_ERROR");
        sleep(2);
        break; 

      case CURLE_OPERATION_TIMEDOUT:
        DPRN("### CURLE_OPERATION_TIMEDOUT");
        sleep(2);
        break; 

      case CURLE_COULDNT_RESOLVE_HOST:
        DPRN("### CURLE_COULDNT_RESOLVE_HOST");
        sleep(2);
        break; 

      case CURLE_COULDNT_CONNECT:
        DPRN("### CURLE_COULDNT_CONNECT");
        sleep(4);
        break; 

      case CURLE_GOT_NOTHING:
        DPRN("### CURLE_GOT_NOTHING");
        sleep(4);
        break; 

      case CURLE_ABORTED_BY_CALLBACK:
        DPRN("### CURLE_ABORTED_BY_CALLBACK");
        sleep(4);
        S3fsCurl::curl_times[hCurl] = time(0);
        break; 

      case CURLE_PARTIAL_FILE:
        DPRN("### CURLE_PARTIAL_FILE");
        sleep(4);
        break; 

      case CURLE_SEND_ERROR:
        DPRN("### CURLE_SEND_ERROR");
        sleep(2);
        break;

      case CURLE_RECV_ERROR:
        DPRN("### CURLE_RECV_ERROR");
        sleep(2);
        break;

      case CURLE_SSL_CONNECT_ERROR:
        DPRN("### CURLE_SSL_CONNECT_ERROR");
        sleep(2);
        break;

      case CURLE_SSL_CACERT:
        DPRN("### CURLE_SSL_CACERT");

        // try to locate cert, if successful, then set the
        // option and continue
        if(0 == S3fsCurl::curl_ca_bundle.size()){
          if(!S3fsCurl::LocateBundle()){
            DPRNCRIT("could not get CURL_CA_BUNDLE.");
            exit(EXIT_FAILURE);
          }
          break; // retry with CAINFO
        }
        DPRNCRIT("curlCode: %d  msg: %s", curlCode, curl_easy_strerror(curlCode));
        exit(EXIT_FAILURE);
        break;

#ifdef CURLE_PEER_FAILED_VERIFICATION
      case CURLE_PEER_FAILED_VERIFICATION:
        DPRN("### CURLE_PEER_FAILED_VERIFICATION");

        first_pos = bucket.find_first_of(".");
        if(first_pos != string::npos){
          FPRNNN("curl returned a CURL_PEER_FAILED_VERIFICATION error");
          FPRNNN("security issue found: buckets with periods in their name are incompatible with http");
          FPRNNN("This check can be over-ridden by using the -o ssl_verify_hostname=0");
          FPRNNN("The certificate will still be checked but the hostname will not be verified.");
          FPRNNN("A more secure method would be to use a bucket name without periods.");
        }else
          DPRNNN("my_curl_easy_perform: curlCode: %d -- %s", curlCode, curl_easy_strerror(curlCode));
        }
        exit(EXIT_FAILURE);
        break;
#endif

      // This should be invalid since curl option HTTP FAILONERROR is now off
      case CURLE_HTTP_RETURNED_ERROR:
        DPRN("### CURLE_HTTP_RETURNED_ERROR");

        if(0 != curl_easy_getinfo(hCurl, CURLINFO_RESPONSE_CODE, &LastResponseCode)){
          return -EIO;
        }
        DPRN("HTTP response code =%ld", LastResponseCode);

        // Let's try to retrieve the 
        if(404 == LastResponseCode){
          return -ENOENT;
        }
        if(500 > LastResponseCode){
          return -EIO;
        }
        break;

      // Unknown CURL return code
      default:
        DPRNCRIT("###curlCode: %d  msg: %s", curlCode, curl_easy_strerror(curlCode));
        exit(EXIT_FAILURE);
        break;
    }
    DPRNNN("### retrying...");

    if(!RemakeHandle()){
      DPRNNN("Failed to reset handle and internal data for retrying.");
      return -EIO;
    }
  }
  DPRN("### giving up");
  return -EIO;
}

//
// Returns the Amazon AWS signature for the given parameters.
//
// @param method e.g., "GET"
// @param content_type e.g., "application/x-directory"
// @param date e.g., get_date_rfc850()
// @param resource e.g., "/pub"
//
string S3fsCurl::CalcSignatureV2(string method, string strMD5, string content_type, string date, string resource)
{
  string Signature;
  string StringToSign;

  if(0 < S3fsCurl::IAM_role.size()){
    if(!S3fsCurl::CheckIAMCredentialUpdate()){
      DPRN("Something error occurred in checking IAM credential.");
      return Signature;  // returns empty string, then it occures error.
    }
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
    free(md);
    return string("");  // ENOMEM
  }
  free(md);

  Signature = base64;
  free(base64);

  return Signature;
}

string S3fsCurl::CalcSignature(string method, string canonical_uri, string query_string, string strdate, string payload_hash, string date8601)
{
  string Signature, StringCQ, StringToSign;
  string uriencode;

  if(0 < S3fsCurl::IAM_role.size()){
    if(!S3fsCurl::CheckIAMCredentialUpdate()){
      DPRN("Something error occurred in checking IAM credential.");
      return Signature;  // returns empty string, then it occures error.
    }
    requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-security-token", S3fsCurl::AWSAccessToken.c_str());
  }

  uriencode = urlEncode(canonical_uri);
  StringCQ  = method + "\n";
  if(0 == strcmp(method.c_str(),"HEAD") || 0 == strcmp(method.c_str(),"PUT") || 0 == strcmp(method.c_str(),"DELETE")){
    StringCQ += uriencode + "\n" + query_string + "\n";
  }else if (0 == strcmp(method.c_str(), "GET") && 0 == strcmp(uriencode.c_str(), "")) {
    StringCQ +="/\n\n";
  }else if (0 == strcmp(method.c_str(), "GET") && 0 == strncmp(uriencode.c_str(), "/", 1)) {
    StringCQ += uriencode +"\n\n";
  }else if (0 == strcmp(method.c_str(), "GET") && 0 != strncmp(uriencode.c_str(), "/", 1)) {
    StringCQ += "/\n" + urlEncode2(canonical_uri) +"\n";
  }else if (0 == strcmp(method.c_str(), "POST")) {
    StringCQ += uriencode +"\n" + query_string +"\n";
  }
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
  free(kDate);
  free(kRegion);
  free(kService);

  const unsigned char* cRequest     = reinterpret_cast<const unsigned char*>(StringCQ.c_str());
  unsigned int         cRequest_len = StringCQ.size();
  s3fs_sha256(cRequest, cRequest_len, &sRequest, &sRequest_len);
  for(cnt = 0; cnt < sRequest_len; cnt++){
    sprintf(&hexsRequest[cnt * 2], "%02x", sRequest[cnt]);
  }
  free(sRequest);

  StringToSign  = "AWS4-HMAC-SHA256\n";
  StringToSign += date8601 + "\n";
  StringToSign += strdate + "/" + endpoint + "/s3/aws4_request\n";
  StringToSign += hexsRequest;

  const unsigned char* cscope     = reinterpret_cast<const unsigned char*>(StringToSign.c_str());
  unsigned int         cscope_len = StringToSign.size();
  unsigned char*       md         = NULL;
  unsigned int         md_len     = 0;
  char                 hexSig[64 + 1];

  s3fs_HMAC256(kSigning, kSigning_len, cscope, cscope_len, &md, &md_len);
  for(cnt = 0; cnt < md_len; cnt++){
    sprintf(&hexSig[cnt * 2], "%02x", md[cnt]);
  }
  free(kSigning);
  free(md);

  Signature = hexSig;

  return Signature;
}

// XML in BodyData has UploadId, Parse XML body for UploadId
bool S3fsCurl::GetUploadId(string& upload_id)
{
  bool result = false;

  if(!bodydata){
    return result;
  }
  upload_id.clear();

  xmlDocPtr doc;
  if(NULL == (doc = xmlReadMemory(bodydata->str(), bodydata->size(), "", NULL, 0))){
    return result;
  }
  if(NULL == doc->children){
    S3FS_XMLFREEDOC(doc);
    return result;
  }
  for(xmlNodePtr cur_node = doc->children->children; NULL != cur_node; cur_node = cur_node->next){
    // For DEBUG
    // string cur_node_name(reinterpret_cast<const char *>(cur_node->name));
    // printf("cur_node_name: %s\n", cur_node_name.c_str());

    if(XML_ELEMENT_NODE == cur_node->type){
      string elementName = reinterpret_cast<const char*>(cur_node->name);
      // For DEBUG
      // printf("elementName: %s\n", elementName.c_str());

      if(cur_node->children){
        if(XML_TEXT_NODE == cur_node->children->type){
          if(elementName == "UploadId") {
            upload_id = reinterpret_cast<const char *>(cur_node->children->content);
            result    = true;
            break;
          }
        }
      }
    }
  }
  S3FS_XMLFREEDOC(doc);

  return result;
}

void S3fsCurl::insertV4Headers(const string &op, const string &path, const string &query_string, const string &payload_hash)
{
  DPRNNN("computing signature [%s] [%s] [%s] [%s]", op.c_str(), path.c_str(), query_string.c_str(), payload_hash.c_str());
  string strdate;
  string date8601;
  get_date_sigv3(strdate, date8601);

  string contentSHA256 = payload_hash.empty() ? empty_payload_hash : payload_hash;

  //string canonical_headers, signed_headers;
  requestHeaders = curl_slist_sort_insert(requestHeaders, "host", get_bucket_host().c_str());
  requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-content-sha256", contentSHA256.c_str());
  requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-date", date8601.c_str());

  if(!S3fsCurl::IsPublicBucket()){
    string Signature = CalcSignature(op, path, query_string, strdate, contentSHA256, date8601);
    string auth = "AWS4-HMAC-SHA256 Credential=" + AWSAccessKeyId + "/" + strdate + "/" + endpoint +
        "/s3/aws4_request, SignedHeaders=" + get_sorted_header_keys(requestHeaders) + ", Signature=" + Signature;
    requestHeaders = curl_slist_sort_insert(requestHeaders, "Authorization", auth.c_str());
  }
}

int S3fsCurl::DeleteRequest(const char* tpath)
{
  FPRNNN("[tpath=%s]", SAFESTRPTR(tpath));

  if(!tpath){
    return -1;
  }
  if(!CreateCurlHandle(true)){
    return -1;
  }
  string resource;
  string turl;
  MakeUrlResource(get_realpath(tpath).c_str(), resource, turl);

  url             = prepare_url(turl.c_str());
  path            = get_realpath(tpath);
  requestHeaders  = NULL;
  responseHeaders.clear();

  if(!S3fsCurl::is_sigv4){
    string date    = get_date_rfc850();
    requestHeaders = curl_slist_sort_insert(requestHeaders, "Date", date.c_str());
    requestHeaders = curl_slist_sort_insert(requestHeaders, "Content-Type", NULL);
    if(!S3fsCurl::IsPublicBucket()){
      string Signature = CalcSignatureV2("DELETE", "", "", date, resource);
      requestHeaders   = curl_slist_sort_insert(requestHeaders, "Authorization", string("AWS " + AWSAccessKeyId + ":" + Signature).c_str());
    }

  }else{
    insertV4Headers("DELETE", path, "", "");
  }

  curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(hCurl, CURLOPT_CUSTOMREQUEST, "DELETE");
  curl_easy_setopt(hCurl, CURLOPT_HTTPHEADER, requestHeaders);

  type = REQTYPE_DELETE;

  return RequestPerform();
}

//
// Get AccessKeyId/SecretAccessKey/AccessToken/Expiration by IAM role,
// and Set these value to class valiable.
//
int S3fsCurl::GetIAMCredentials(void)
{
  FPRNINFO("[IAM role=%s]", S3fsCurl::IAM_role.c_str());

  if(0 == S3fsCurl::IAM_role.size()){
    DPRN("IAM role name is empty.");
    return -EIO;
  }
  // at first set type for handle
  type = REQTYPE_IAMCRED;

  if(!CreateCurlHandle(true)){
    return -EIO;
  }

  // url
  url             = string(IAM_CRED_URL) + S3fsCurl::IAM_role;
  requestHeaders  = NULL;
  responseHeaders.clear();
  bodydata        = new BodyData();

  curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, (void*)bodydata);
  curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);

  int result = RequestPerform();

  // analizing response
  if(0 == result && !S3fsCurl::SetIAMCredentials(bodydata->str())){
    DPRN("Something error occurred, could not get IAM credential.");
  }
  delete bodydata;
  bodydata = NULL;

  return result;
}

//
// If md5 is empty, build by first(current) sse key
//
bool S3fsCurl::AddSseKeyRequestHead(string& md5, bool is_copy)
{
  if(!S3fsCurl::IsSseCustomMode()){
    // Nothing to do
    return true;
  }
  string sseckey;
  if(S3fsCurl::GetSseKey(md5, sseckey)){
    if(is_copy){
      requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-copy-source-server-side-encryption-customer-algorithm", "AES256");
      requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-copy-source-server-side-encryption-customer-key",       sseckey.c_str());
      requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-copy-source-server-side-encryption-customer-key-md5",   md5.c_str());
    }else{
      requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-server-side-encryption-customer-algorithm", "AES256");
      requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-server-side-encryption-customer-key",       sseckey.c_str());
      requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-server-side-encryption-customer-key-md5",   md5.c_str());
    }
  }
  return true;
}

//
// tpath :      target path for head request
// bpath :      saved into base_path
// savedpath :  saved into saved_path
// ssekey_pos : -1 means "not use sse", 0 - X means "use sseckey" and "sseckey position".
//              sseckey position 0 is latest key.
//
bool S3fsCurl::PreHeadRequest(const char* tpath, const char* bpath, const char* savedpath, int ssekey_pos)
{
  FPRNINFO("[tpath=%s][bpath=%s][save=%s]", SAFESTRPTR(tpath), SAFESTRPTR(bpath), SAFESTRPTR(savedpath));

  if(!tpath){
    return false;
  }
  if(!CreateCurlHandle(true)){
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
  if(0 <= ssekey_pos && S3fsCurl::IsSseCustomMode()){
    string md5;
    if(!S3fsCurl::GetSseKeyMd5(ssekey_pos, md5) || !AddSseKeyRequestHead(md5, false)){
      DPRN("Failed to set SSE-C headers for md5(%s).", md5.c_str());
    }
  }
  b_ssekey_pos = ssekey_pos;

  if(!S3fsCurl::is_sigv4){
    string date    = get_date_rfc850();
    requestHeaders = curl_slist_sort_insert(requestHeaders, "Date", date.c_str());
    requestHeaders = curl_slist_sort_insert(requestHeaders, "Content-Type", NULL);

    if(!S3fsCurl::IsPublicBucket()){
      string Signature = CalcSignatureV2("HEAD", "", "", date, resource);
      requestHeaders   = curl_slist_sort_insert(requestHeaders, "Authorization", string("AWS " + AWSAccessKeyId + ":" + Signature).c_str());
    }

  }else{
    insertV4Headers("HEAD", path, "", "");
  }

  curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(hCurl, CURLOPT_NOBODY, true);   // HEAD
  curl_easy_setopt(hCurl, CURLOPT_FILETIME, true); // Last-Modified
  curl_easy_setopt(hCurl, CURLOPT_HTTPHEADER, requestHeaders);

  // responseHeaders
  curl_easy_setopt(hCurl, CURLOPT_HEADERDATA, (void*)&responseHeaders);
  curl_easy_setopt(hCurl, CURLOPT_HEADERFUNCTION, HeaderCallback);

  type = REQTYPE_HEAD;

  return true;
}

int S3fsCurl::HeadRequest(const char* tpath, headers_t& meta)
{
  int result = -1;

  FPRNNN("[tpath=%s]", SAFESTRPTR(tpath));

  if(S3fsCurl::IsSseCustomMode()){
    // SSE-C mode, check all sse-c key at first
    int pos;
    for(pos = 0; static_cast<size_t>(pos) < S3fsCurl::sseckeys.size(); pos++){
      if(0 != pos && !DestroyCurlHandle()){
        return result;
      }
      if(!PreHeadRequest(tpath, NULL, NULL, pos)){
        return result;
      }
      if(0 == (result = RequestPerform())){
        break;
      }
    }
    if(S3fsCurl::sseckeys.size() <= static_cast<size_t>(pos)){
      // If sse-c mode is enable, s3fs fails to get head request for normal and sse object.
      // So try to get head without sse-c header.
      if(!DestroyCurlHandle() || !PreHeadRequest(tpath, NULL, NULL, -1) || 0 != (result = RequestPerform())){
        return result;
      }
    }
  }else{
    // Not sse-c mode
    if(!PreHeadRequest(tpath) || 0 != (result = RequestPerform())){
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
  FPRNNN("[tpath=%s]", SAFESTRPTR(tpath));

  if(!tpath){
    return -1;
  }
  if(!CreateCurlHandle(true)){
    return -1;
  }
  string resource;
  string turl;
  MakeUrlResource(get_realpath(tpath).c_str(), resource, turl);

  url             = prepare_url(turl.c_str());
  path            = get_realpath(tpath);
  requestHeaders  = NULL;
  responseHeaders.clear();
  bodydata        = new BodyData();

  // Make request headers
  string ContentType;
  for(headers_t::iterator iter = meta.begin(); iter != meta.end(); ++iter){
    string key   = lower(iter->first);
    string value = iter->second;
    if(key == "content-type"){
      ContentType    = value;
      requestHeaders = curl_slist_sort_insert(requestHeaders, iter->first.c_str(), value.c_str());
    }else if(key.substr(0, 9) == "x-amz-acl"){
      // not set value, but after set it.
    }else if(key.substr(0, 10) == "x-amz-meta"){
      requestHeaders = curl_slist_sort_insert(requestHeaders, iter->first.c_str(), value.c_str());
    }else if(key == "x-amz-copy-source"){
      requestHeaders = curl_slist_sort_insert(requestHeaders, iter->first.c_str(), value.c_str());
    }else if(key == "x-amz-server-side-encryption"){
      // skip this header, because this header is specified after logic.
    }else if(key == "x-amz-server-side-encryption-customer-algorithm"){
      // skip this header, because this header is specified with "x-amz-...-customer-key-md5".
    }else if(is_copy && key == "x-amz-server-side-encryption-customer-key-md5"){
      // Only copy mode.
      if(!AddSseKeyRequestHead(value, is_copy)){
        DPRNNN("Failed to insert sse(-c) header.");
      }
    }
  }

  // "x-amz-acl", rrs, sse
  requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-acl", S3fsCurl::default_acl.c_str());
  if(S3fsCurl::is_use_rrs){
    requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-storage-class", "REDUCED_REDUNDANCY");
  }
  if(S3fsCurl::is_use_sse){
    requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-server-side-encryption", "AES256");
  }else if(S3fsCurl::IsSseCustomMode()){
    string md5;
    if(!AddSseKeyRequestHead(md5, false)){
      DPRNNN("Failed to insert sse(-c) header.");
    }
  }
  if(is_use_ahbe){
    // set additional header by ahbe conf
    requestHeaders = AdditionalHeader::get()->AddHeader(requestHeaders, tpath);
  }

  if(!S3fsCurl::is_sigv4){
    string date    = get_date_rfc850();
    requestHeaders = curl_slist_sort_insert(requestHeaders, "Date", date.c_str());

    if(!S3fsCurl::IsPublicBucket()){
      string Signature = CalcSignatureV2("PUT", "", ContentType, date, resource);
      requestHeaders   = curl_slist_sort_insert(requestHeaders, "Authorization", string("AWS " + AWSAccessKeyId + ":" + Signature).c_str());
    }

  }else{
    insertV4Headers("PUT", path, "", "");
  }

  // setopt
  curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(hCurl, CURLOPT_UPLOAD, true);                // HTTP PUT
  curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, (void*)bodydata);
  curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(hCurl, CURLOPT_INFILESIZE, 0);               // Content-Length
  curl_easy_setopt(hCurl, CURLOPT_HTTPHEADER, requestHeaders);

  type = REQTYPE_PUTHEAD;

  DPRNNN("copying... [path=%s]", tpath);

  int result = RequestPerform();
  delete bodydata;
  bodydata = NULL;

  return result;
}

int S3fsCurl::PutRequest(const char* tpath, headers_t& meta, int fd)
{
  struct stat st;
  FILE*       file = NULL;
  int         fd2;

  FPRNNN("[tpath=%s]", SAFESTRPTR(tpath));

  if(!tpath){
    return -1;
  }
  if(-1 != fd){
    // duplicate fd
    if(-1 == (fd2 = dup(fd)) || -1 == fstat(fd2, &st) || 0 != lseek(fd2, 0, SEEK_SET) || NULL == (file = fdopen(fd2, "rb"))){
      DPRN("Could not duplicate file discriptor(errno=%d)", errno);
      return -errno;
    }
    b_infile = file;
  }else{
    // This case is creating zero byte obejct.(calling by create_file_object())
    DPRNNN("create zero byte file object.");
  }

  if(!CreateCurlHandle(true)){
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
  bodydata        = new BodyData();

  // Make request headers
  string strMD5;
  if(-1 != fd && S3fsCurl::is_content_md5){
    strMD5         = s3fs_get_content_md5(fd);
    requestHeaders = curl_slist_sort_insert(requestHeaders, "Content-MD5", strMD5.c_str());
  }

  string ContentType;
  for(headers_t::iterator iter = meta.begin(); iter != meta.end(); ++iter){
    string key   = lower(iter->first);
    string value = iter->second;
    if(key == "content-type"){
      ContentType    = value;
      requestHeaders = curl_slist_sort_insert(requestHeaders, iter->first.c_str(), value.c_str());
    }else if(key.substr(0, 9) == "x-amz-acl"){
      // not set value, but after set it.
    }else if(key.substr(0, 10) == "x-amz-meta"){
      requestHeaders = curl_slist_sort_insert(requestHeaders, iter->first.c_str(), value.c_str());
    }else if(key == "x-amz-server-side-encryption"){
      // skip this header, because this header is specified after logic.
    }else if(key == "x-amz-server-side-encryption-customer-algorithm"){
      // skip this header, because this header is specified after logic.
    }else if(key == "x-amz-server-side-encryption-customer-key-md5"){
      // skip this header, because this header is specified after logic.
    }
  }
  // "x-amz-acl", rrs, sse
  requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-acl", S3fsCurl::default_acl.c_str());
  if(S3fsCurl::is_use_rrs){
    requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-storage-class", "REDUCED_REDUNDANCY");
  }
  if(S3fsCurl::is_use_sse){
    requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-server-side-encryption", "AES256");
  }else if(S3fsCurl::IsSseCustomMode()){
    string md5;
    if(!AddSseKeyRequestHead(md5, false)){
      DPRNNN("Failed to insert sse(-c) header.");
    }
  }
  if(is_use_ahbe){
    // set additional header by ahbe conf
    requestHeaders = AdditionalHeader::get()->AddHeader(requestHeaders, tpath);
  }

  if(!S3fsCurl::is_sigv4){
    string date    = get_date_rfc850();
    requestHeaders = curl_slist_sort_insert(requestHeaders, "Date", date.c_str());

    if(!S3fsCurl::IsPublicBucket()){
      string Signature = CalcSignatureV2("PUT", strMD5, ContentType, date, resource);
      requestHeaders   = curl_slist_sort_insert(requestHeaders, "Authorization", string("AWS " + AWSAccessKeyId + ":" + Signature).c_str());
    }

  }else{
    string payload_hash  = s3fs_sha256sum(fd, 0, -1);
    insertV4Headers("PUT", path, "", payload_hash);
  }

  // setopt
  curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(hCurl, CURLOPT_UPLOAD, true);                // HTTP PUT
  curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, (void*)bodydata);
  curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(hCurl, CURLOPT_HTTPHEADER, requestHeaders);
  if(file){
    curl_easy_setopt(hCurl, CURLOPT_INFILESIZE_LARGE, static_cast<curl_off_t>(st.st_size)); // Content-Length
    curl_easy_setopt(hCurl, CURLOPT_INFILE, file);
  }else{
    curl_easy_setopt(hCurl, CURLOPT_INFILESIZE, 0);             // Content-Length: 0
  }

  type = REQTYPE_PUT;

  DPRNNN("uploading... [path=%s][fd=%d][size=%jd]", tpath, fd, (intmax_t)(-1 != fd ? st.st_size : 0));

  int result = RequestPerform();
  delete bodydata;
  bodydata = NULL;
  if(file){
    fclose(file);
  }

  return result;
}

int S3fsCurl::PreGetObjectRequest(const char* tpath, int fd, off_t start, ssize_t size, string& ssekeymd5)
{
  FPRNNN("[tpath=%s][start=%jd][size=%zd]", SAFESTRPTR(tpath), (intmax_t)start, size);

  if(!tpath || -1 == fd || 0 > start || 0 >= size){
    return -1;
  }

  if(!CreateCurlHandle(true)){
    return -1;
  }
  string resource;
  string turl;
  MakeUrlResource(get_realpath(tpath).c_str(), resource, turl);

  url             = prepare_url(turl.c_str());
  path            = get_realpath(tpath);
  requestHeaders  = NULL;
  responseHeaders.clear();

  if(-1 != start && -1 != size){
    string range = "bytes=";
    range       += str(start);
    range       += "-";
    range       += str(start + size - 1);
    requestHeaders = curl_slist_sort_insert(requestHeaders, "Range", range.c_str());
  }
  if(0 < ssekeymd5.length()){
    if(!AddSseKeyRequestHead(ssekeymd5, false)){
      DPRNNN("Failed to insert sse(-c) header.");
    }
  }

  if(!S3fsCurl::is_sigv4){
    string date    = get_date_rfc850();
    requestHeaders = curl_slist_sort_insert(requestHeaders, "Date", date.c_str());
    requestHeaders = curl_slist_sort_insert(requestHeaders, "Content-Type", NULL);

    if(!S3fsCurl::IsPublicBucket()){
      string Signature = CalcSignatureV2("GET", "", "", date, resource);
      requestHeaders   = curl_slist_sort_insert(requestHeaders, "Authorization", string("AWS " + AWSAccessKeyId + ":" + Signature).c_str());
    }

  }else{
    insertV4Headers("GET", path, "", "");
  }

  // setopt
  curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(hCurl, CURLOPT_HTTPHEADER, requestHeaders);
  curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, S3fsCurl::DownloadWriteCallback);
  curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, (void*)this);

  // set info for callback func.
  // (use only fd, startpos and size, other member is not used.)
  partdata.clear();
  partdata.fd         = fd;
  partdata.startpos   = start;
  partdata.size       = size;
  b_partdata_startpos = start;
  b_partdata_size     = size;
  b_ssekey_md5        = ssekeymd5;

  type = REQTYPE_GET;

  return 0;
}

int S3fsCurl::GetObjectRequest(const char* tpath, int fd, off_t start, ssize_t size)
{
  int result;

  FPRNNN("[tpath=%s][start=%jd][size=%zd]", SAFESTRPTR(tpath), (intmax_t)start, size);

  if(!tpath){
    return -1;
  }
  string sseckeymd5("");
  char*  psseckeymd5;
  if(NULL != (psseckeymd5 = get_object_sseckey_md5(tpath))){
    sseckeymd5 = psseckeymd5;
    free(psseckeymd5);
  }
  if(0 != (result = PreGetObjectRequest(tpath, fd, start, size, sseckeymd5))){
    return result;
  }

  DPRNNN("downloading... [path=%s][fd=%d]", tpath, fd);

  result = RequestPerform();
  partdata.clear();

  return result;
}

int S3fsCurl::CheckBucket(void)
{
  FPRNNN("check a bucket.");

  if(!CreateCurlHandle(true)){
    return -1;
  }
  string resource;
  string turl;
  MakeUrlResource(get_realpath("/").c_str(), resource, turl);

  url             = prepare_url(turl.c_str());
  path            = get_realpath("/");
  requestHeaders  = NULL;
  responseHeaders.clear();
  bodydata        = new BodyData();

  if(!S3fsCurl::is_sigv4){
    string date    = get_date_rfc850();
    requestHeaders = curl_slist_sort_insert(requestHeaders, "Date", date.c_str());

    if(!S3fsCurl::IsPublicBucket()){
      string Signature = CalcSignatureV2("GET", "", "", date, resource);
      requestHeaders   = curl_slist_sort_insert(requestHeaders, "Authorization", string("AWS " + AWSAccessKeyId + ":" + Signature).c_str());
    }

  }else{
    insertV4Headers("GET", path, "", "");
  }

  // setopt
  curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, (void*)bodydata);
  curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(hCurl, CURLOPT_HTTPHEADER, requestHeaders);

  type = REQTYPE_CHKBUCKET;

  int result = RequestPerform();
  if (result != 0) {
    DPRN("Check bucket failed, S3 response: %s", (bodydata ? bodydata->str() : ""));
  }
  return result;
}

int S3fsCurl::ListBucketRequest(const char* tpath, const char* query)
{
  FPRNNN("[tpath=%s]", SAFESTRPTR(tpath));

  if(!tpath){
    return -1;
  }
  if(!CreateCurlHandle(true)){
    return -1;
  }
  string resource;
  string turl;
  MakeUrlResource("", resource, turl);    // NOTICE: path is "".
  if(query){
    turl += "?";
    turl += query;
  }

  url             = prepare_url(turl.c_str());
  path            = get_realpath(tpath);
  requestHeaders  = NULL;
  responseHeaders.clear();
  bodydata        = new BodyData();

  if(!S3fsCurl::is_sigv4){
    string date    = get_date_rfc850();
    requestHeaders = curl_slist_sort_insert(requestHeaders, "Date", date.c_str());
    requestHeaders = curl_slist_sort_insert(requestHeaders, "Content-Type", NULL);

    if(!S3fsCurl::IsPublicBucket()){
      string Signature = CalcSignatureV2("GET", "", "", date, (resource + "/"));
      requestHeaders   = curl_slist_sort_insert(requestHeaders, "Authorization", string("AWS " + AWSAccessKeyId + ":" + Signature).c_str());
    }

  }else{
    insertV4Headers("GET", query, "", "");
  }

  // setopt
  curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, (void*)bodydata);
  curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(hCurl, CURLOPT_HTTPHEADER, requestHeaders);

  type = REQTYPE_LISTBUCKET;

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
  FPRNNN("[tpath=%s]", SAFESTRPTR(tpath));

  if(!tpath){
    return -1;
  }
  if(!CreateCurlHandle(true)){
    return -1;
  }
  string resource;
  string turl;
  MakeUrlResource(get_realpath(tpath).c_str(), resource, turl);

  string query_string = "uploads";
  if(S3fsCurl::is_sigv4){
    query_string += "=";
  }
  turl          += "?" + query_string;
  resource      += "?" + query_string;
  url            = prepare_url(turl.c_str());
  path           = get_realpath(tpath);
  requestHeaders = NULL;
  bodydata       = new BodyData();
  responseHeaders.clear();

  string contype = S3fsCurl::LookupMimeType(string(tpath));

  for(headers_t::iterator iter = meta.begin(); iter != meta.end(); ++iter){
    string key   = lower(iter->first);
    string value = iter->second;
    if(key.substr(0, 9) == "x-amz-acl"){
      // not set value, but after set it.
    }else if(key.substr(0, 10) == "x-amz-meta"){
      requestHeaders = curl_slist_sort_insert(requestHeaders, iter->first.c_str(), value.c_str());
    }else if(key == "x-amz-server-side-encryption"){
      // skip this header, because this header is specified after logic.
    }else if(key == "x-amz-server-side-encryption-customer-algorithm"){
      // skip this header, because this header is specified with "x-amz-...-customer-key-md5".
    }else if(is_copy && key == "x-amz-server-side-encryption-customer-key-md5"){
      // Only copy mode.
      if(!AddSseKeyRequestHead(value, is_copy)){
        DPRNNN("Failed to insert sse(-c) header.");
      }
    }
  }
  // "x-amz-acl", rrs, sse
  requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-acl", S3fsCurl::default_acl.c_str());
  if(S3fsCurl::is_use_rrs){
    requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-storage-class", "REDUCED_REDUNDANCY");
  }
  if(S3fsCurl::is_use_sse){
    requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-server-side-encryption", "AES256");
  }else if(S3fsCurl::IsSseCustomMode()){
    string md5;
    if(!AddSseKeyRequestHead(md5, false)){
      DPRNNN("Failed to insert sse(-c) header.");
    }
  }
  if(is_use_ahbe){
    // set additional header by ahbe conf
    requestHeaders = AdditionalHeader::get()->AddHeader(requestHeaders, tpath);
  }

  if(!S3fsCurl::is_sigv4){
    string date    = get_date_rfc850();
    requestHeaders = curl_slist_sort_insert(requestHeaders, "Date", date.c_str());
    requestHeaders = curl_slist_sort_insert(requestHeaders, "Accept", NULL);
    requestHeaders = curl_slist_sort_insert(requestHeaders, "Content-Length", NULL);
    requestHeaders = curl_slist_sort_insert(requestHeaders, "Content-Type", contype.c_str());

    if(!S3fsCurl::IsPublicBucket()){
      string Signature = CalcSignatureV2("POST", "", contype, date, resource);
      requestHeaders   = curl_slist_sort_insert(requestHeaders, "Authorization", string("AWS " + AWSAccessKeyId + ":" + Signature).c_str());
    }

  }else{
    requestHeaders = curl_slist_sort_insert(requestHeaders, "Accept", NULL);
    requestHeaders = curl_slist_sort_insert(requestHeaders, "Content-Length", NULL);
    requestHeaders = curl_slist_sort_insert(requestHeaders, "Content-Type", contype.c_str());
    insertV4Headers("POST", path, query_string, "");
  }

  // setopt
  curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(hCurl, CURLOPT_POST, true);              // POST
  curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, (void*)bodydata);
  curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(hCurl, CURLOPT_POSTFIELDSIZE, 0);
  curl_easy_setopt(hCurl, CURLOPT_HTTPHEADER, requestHeaders);

  type = REQTYPE_PREMULTIPOST;

  // request
  int result;
  if(0 != (result = RequestPerform())){
    delete bodydata;
    bodydata = NULL;
    return result;
  }

  // Parse XML body for UploadId
  if(!S3fsCurl::GetUploadId(upload_id)){
    delete bodydata;
    bodydata = NULL;
    return -1;
  }

  delete bodydata;
  bodydata = NULL;
  return 0;
}

int S3fsCurl::CompleteMultipartPostRequest(const char* tpath, string& upload_id, etaglist_t& parts)
{
  FPRNNN("[tpath=%s][parts=%zu]", SAFESTRPTR(tpath), parts.size());

  if(!tpath){
    return -1;
  }

  // make contents
  string postContent;
  postContent += "<CompleteMultipartUpload>\n";
  for(int cnt = 0; cnt < (int)parts.size(); cnt++){
    if(0 == parts[cnt].length()){
      DPRN("%d file part is not finished uploading.", cnt + 1);
      return -1;
    }
    postContent += "<Part>\n";
    postContent += "  <PartNumber>" + IntToStr(cnt + 1) + "</PartNumber>\n";
    postContent += "  <ETag>\""     + parts[cnt]        + "\"</ETag>\n";
    postContent += "</Part>\n";
  }  
  postContent += "</CompleteMultipartUpload>\n";

  // set postdata
  postdata             = reinterpret_cast<const unsigned char*>(postContent.c_str());
  b_postdata           = postdata;
  postdata_remaining   = postContent.size(); // without null
  b_postdata_remaining = postdata_remaining;

  if(!CreateCurlHandle(true)){
    return -1;
  }
  string resource;
  string turl;
  MakeUrlResource(get_realpath(tpath).c_str(), resource, turl);

  string query_string  = "uploadId=" + upload_id;
  turl                += "?" + query_string;
  resource            += "?" + query_string;
  url                  = prepare_url(turl.c_str());
  path                 = get_realpath(tpath);
  requestHeaders       = NULL;
  bodydata             = new BodyData();
  responseHeaders.clear();
  string contype       = S3fsCurl::LookupMimeType(string(tpath));

  if(!S3fsCurl::is_sigv4){
    string date    = get_date_rfc850();
    requestHeaders = curl_slist_sort_insert(requestHeaders, "Date", date.c_str());
    requestHeaders = curl_slist_sort_insert(requestHeaders, "Accept", NULL);
    requestHeaders = curl_slist_sort_insert(requestHeaders, "Content-Type", contype.c_str());

    if(!S3fsCurl::IsPublicBucket()){
      string Signature = CalcSignatureV2("POST", "", contype, date, resource);
      requestHeaders   = curl_slist_sort_insert(requestHeaders, "Authorization", string("AWS " + AWSAccessKeyId + ":" + Signature).c_str());
    }

  }else{
    string payload_hash;

    const unsigned char* cRequest     = reinterpret_cast<const unsigned char*>(postContent.c_str());
    unsigned int         cRequest_len = postContent.size();
    unsigned char*       sRequest     = NULL;
    unsigned int         sRequest_len = 0;
    char                 hexsRequest[64 + 1];
    unsigned int         cnt;
    s3fs_sha256(cRequest, cRequest_len, &sRequest, &sRequest_len);
    for(cnt = 0; cnt < sRequest_len; cnt++){
      sprintf(&hexsRequest[cnt * 2], "%02x", sRequest[cnt]);
    }
    payload_hash.assign(hexsRequest, &hexsRequest[sRequest_len * 2]);

    requestHeaders = curl_slist_sort_insert(requestHeaders, "Date", get_date_rfc850().c_str());
    requestHeaders = curl_slist_sort_insert(requestHeaders, "Accept", NULL);
    requestHeaders = curl_slist_sort_insert(requestHeaders, "Content-Type", contype.c_str());

    insertV4Headers("POST", path, query_string, payload_hash);
  }

  // setopt
  curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(hCurl, CURLOPT_HTTPHEADER, requestHeaders);
  curl_easy_setopt(hCurl, CURLOPT_POST, true);              // POST
  curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, (void*)bodydata);
  curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(hCurl, CURLOPT_POSTFIELDSIZE, static_cast<curl_off_t>(postdata_remaining));
  curl_easy_setopt(hCurl, CURLOPT_READDATA, (void*)this);
  curl_easy_setopt(hCurl, CURLOPT_READFUNCTION, S3fsCurl::ReadCallback);

  type = REQTYPE_COMPLETEMULTIPOST;

  // request
  int result = RequestPerform();
  delete bodydata;
  bodydata = NULL;
  postdata = NULL;

  return result;
}

int S3fsCurl::MultipartListRequest(string& body)
{
  FPRNNN("list request(multipart)");

  if(!CreateCurlHandle(true)){
    return -1;
  }
  string resource;
  string turl;
  path            = get_realpath("/");
  MakeUrlResource(path.c_str(), resource, turl);

  turl           += "?uploads";
  resource       += "?uploads";
  url             = prepare_url(turl.c_str());
  requestHeaders  = NULL;
  responseHeaders.clear();
  bodydata        = new BodyData();

  if(!S3fsCurl::is_sigv4){
    string date    = get_date_rfc850();
    requestHeaders = curl_slist_sort_insert(requestHeaders, "Date", date.c_str());
    requestHeaders = curl_slist_sort_insert(requestHeaders, "Accept", NULL);

    if(!S3fsCurl::IsPublicBucket()){
      string Signature = CalcSignatureV2("GET", "", "", date, resource);
      requestHeaders   = curl_slist_sort_insert(requestHeaders, "Authorization", string("AWS " + AWSAccessKeyId + ":" + Signature).c_str());
    }

  }else{
    insertV4Headers("GET", path, "", "");
  }

  // setopt
  curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, (void*)bodydata);
  curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(hCurl, CURLOPT_HTTPHEADER, requestHeaders);

  type = REQTYPE_MULTILIST;

  int result;
  if(0 == (result = RequestPerform()) && 0 < bodydata->size()){
    body = bodydata->str();
  }else{
    body = "";
  }
  delete bodydata;
  bodydata = NULL;

  return result;
}

int S3fsCurl::AbortMultipartUpload(const char* tpath, string& upload_id)
{
  FPRNNN("[tpath=%s]", SAFESTRPTR(tpath));

  if(!tpath){
    return -1;
  }
  if(!CreateCurlHandle(true)){
    return -1;
  }
  string resource;
  string turl;
  MakeUrlResource(get_realpath(tpath).c_str(), resource, turl);

  turl           += "?uploadId=" + upload_id;
  resource       += "?uploadId=" + upload_id;
  url             = prepare_url(turl.c_str());
  path            = get_realpath(tpath);
  requestHeaders  = NULL;
  responseHeaders.clear();

  if(!S3fsCurl::is_sigv4){
    string date    = get_date_rfc850();
    requestHeaders = curl_slist_sort_insert(requestHeaders, "Date", date.c_str());

    if(!S3fsCurl::IsPublicBucket()){
      string Signature = CalcSignatureV2("DELETE", "", "", date, resource);
      requestHeaders   = curl_slist_sort_insert(requestHeaders, "Authorization", string("AWS " + AWSAccessKeyId + ":" + Signature).c_str());
    }

  }else{
    insertV4Headers("DELETE", path, "", "");
  }

  curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(hCurl, CURLOPT_CUSTOMREQUEST, "DELETE");
  curl_easy_setopt(hCurl, CURLOPT_HTTPHEADER, requestHeaders);

  type = REQTYPE_ABORTMULTIUPLOAD;

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

int S3fsCurl::UploadMultipartPostSetup(const char* tpath, int part_num, string& upload_id)
{
  FPRNNN("[tpath=%s][start=%jd][size=%zd][part=%d]", SAFESTRPTR(tpath), (intmax_t)(partdata.startpos), partdata.size, part_num);

  if(-1 == partdata.fd || -1 == partdata.startpos || -1 == partdata.size){
    return -1;
  }

  // make md5 and file pointer
  partdata.etag = s3fs_md5sum(partdata.fd, partdata.startpos, partdata.size);
  if(partdata.etag.empty()){
    DPRN("Could not make md5 for file(part %d)", part_num);
    return -1;
  }

  // create handle
  if(!CreateCurlHandle(true)){
    return -1;
  }

  // make request
  string request_uri = "partNumber=" + IntToStr(part_num) + "&uploadId=" + upload_id;
  string urlargs     = "?" + request_uri;
  string resource;
  string turl;
  MakeUrlResource(get_realpath(tpath).c_str(), resource, turl);

  resource          += urlargs;
  turl              += urlargs;
  url                = prepare_url(turl.c_str());
  path               = get_realpath(tpath);
  requestHeaders     = NULL;
  bodydata           = new BodyData();
  headdata           = new BodyData();
  responseHeaders.clear();

  if(!S3fsCurl::is_sigv4){
    string date    = get_date_rfc850();
    requestHeaders = curl_slist_sort_insert(requestHeaders, "Date", date.c_str());
    requestHeaders = curl_slist_sort_insert(requestHeaders, "Accept", NULL);

    if(!S3fsCurl::IsPublicBucket()){
      string Signature = CalcSignatureV2("PUT", "", "", date, resource);
      requestHeaders   = curl_slist_sort_insert(requestHeaders, "Authorization", string("AWS " + AWSAccessKeyId + ":" + Signature).c_str());
    }

  }else{
    string payload_hash = s3fs_sha256sum(partdata.fd, partdata.startpos, partdata.size);
    insertV4Headers("PUT", path, request_uri, payload_hash);
  }

  // setopt
  curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(hCurl, CURLOPT_UPLOAD, true);              // HTTP PUT
  curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, (void*)bodydata);
  curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(hCurl, CURLOPT_HEADERDATA, (void*)headdata);
  curl_easy_setopt(hCurl, CURLOPT_HEADERFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(hCurl, CURLOPT_INFILESIZE_LARGE, static_cast<curl_off_t>(partdata.size)); // Content-Length
  curl_easy_setopt(hCurl, CURLOPT_READFUNCTION, S3fsCurl::UploadReadCallback);
  curl_easy_setopt(hCurl, CURLOPT_READDATA, (void*)this);
  curl_easy_setopt(hCurl, CURLOPT_HTTPHEADER, requestHeaders);

  type = REQTYPE_UPLOADMULTIPOST;

  return 0;
}

int S3fsCurl::UploadMultipartPostRequest(const char* tpath, int part_num, string& upload_id)
{
  int result;

  FPRNNN("[tpath=%s][start=%jd][size=%zd][part=%d]", SAFESTRPTR(tpath), (intmax_t)(partdata.startpos), partdata.size, part_num);

  // setup
  if(0 != (result = S3fsCurl::UploadMultipartPostSetup(tpath, part_num, upload_id))){
    return result;
  }

  // request
  if(0 == (result = RequestPerform())){
    // check etag
    if(NULL != strstr(headdata->str(), partdata.etag.c_str())){
      partdata.uploaded = true;
    }else{
      result = -1;
    }
  }

  // closing
  delete bodydata;
  bodydata = NULL;
  delete headdata;
  headdata = NULL;

  return result;
}

int S3fsCurl::CopyMultipartPostRequest(const char* from, const char* to, int part_num, string& upload_id, headers_t& meta)
{
  FPRNNN("[from=%s][to=%s][part=%d]", SAFESTRPTR(from), SAFESTRPTR(to), part_num);

  if(!from || !to){
    return -1;
  }
  if(!CreateCurlHandle(true)){
    return -1;
  }
  string urlargs  = "?partNumber=" + IntToStr(part_num) + "&uploadId=" + upload_id;
  string resource;
  string turl;
  MakeUrlResource(get_realpath(to).c_str(), resource, turl);

  resource       += urlargs;
  turl           += urlargs;
  url             = prepare_url(turl.c_str());
  path            = get_realpath(to);
  requestHeaders  = NULL;
  responseHeaders.clear();
  bodydata        = new BodyData();
  headdata        = new BodyData();

  // Make request headers
  string ContentType;
  for(headers_t::iterator iter = meta.begin(); iter != meta.end(); ++iter){
    string key   = lower(iter->first);
    string value = iter->second;
    if(key == "content-type"){
      ContentType    = value;
      requestHeaders = curl_slist_sort_insert(requestHeaders, iter->first.c_str(), value.c_str());
    }else if(key == "x-amz-copy-source"){
      requestHeaders = curl_slist_sort_insert(requestHeaders, iter->first.c_str(), value.c_str());
    }else if(key == "x-amz-copy-source-range"){
      requestHeaders = curl_slist_sort_insert(requestHeaders, iter->first.c_str(), value.c_str());
    }
    // NOTICE: x-amz-acl, x-amz-server-side-encryption is not set!
  }

  if(!S3fsCurl::is_sigv4){
    string date    = get_date_rfc850();
    requestHeaders = curl_slist_sort_insert(requestHeaders, "Date", date.c_str());

    if(!S3fsCurl::IsPublicBucket()){
      string Signature = CalcSignatureV2("PUT", "", ContentType, date, resource);
      requestHeaders   = curl_slist_sort_insert(requestHeaders, "Authorization", string("AWS " + AWSAccessKeyId + ":" + Signature).c_str());
    }

  }else{
    insertV4Headers("PUT", path, "", "");
  }

  // setopt
  curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(hCurl, CURLOPT_UPLOAD, true);                // HTTP PUT
  curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, (void*)bodydata);
  curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(hCurl, CURLOPT_HEADERDATA, (void*)headdata);
  curl_easy_setopt(hCurl, CURLOPT_HEADERFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(hCurl, CURLOPT_INFILESIZE, 0);               // Content-Length
  curl_easy_setopt(hCurl, CURLOPT_HTTPHEADER, requestHeaders);

  type = REQTYPE_COPYMULTIPOST;

  // request
  DPRNNN("copying... [from=%s][to=%s][part=%d]", from, to, part_num);

  int result = RequestPerform();
  if(0 == result){
    const char* start_etag= strstr(bodydata->str(), "ETag");
    const char* end_etag  = strstr(bodydata->str(), "/ETag>");

    partdata.etag.assign((start_etag + 11), (size_t)(end_etag - (start_etag + 11) - 7));
    partdata.uploaded = true;
  }
  delete bodydata;
  bodydata = NULL;
  delete headdata;
  headdata = NULL;

  return result;
}

int S3fsCurl::MultipartHeadRequest(const char* tpath, off_t size, headers_t& meta, bool is_copy)
{
  int            result;
  string         upload_id;
  off_t          chunk;
  off_t          bytes_remaining;
  etaglist_t     list;
  stringstream   strrange;

  FPRNNN("[tpath=%s]", SAFESTRPTR(tpath));

  if(0 != (result = PreMultipartPostRequest(tpath, meta, upload_id, is_copy))){
    return result;
  }
  DestroyCurlHandle();

  for(bytes_remaining = size, chunk = 0; 0 < bytes_remaining; bytes_remaining -= chunk){
    chunk = bytes_remaining > MAX_MULTI_COPY_SOURCE_SIZE ? MAX_MULTI_COPY_SOURCE_SIZE : bytes_remaining;

    strrange << "bytes=" << (size - bytes_remaining) << "-" << (size - bytes_remaining + chunk - 1);
    meta["x-amz-copy-source-range"] = strrange.str();
    strrange.str("");
    strrange.clear(stringstream::goodbit);

    if(0 != (result = CopyMultipartPostRequest(tpath, tpath, (list.size() + 1), upload_id, meta))){
      return result;
    }
    list.push_back(partdata.etag);
    DestroyCurlHandle();
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

  FPRNNN("[tpath=%s][fd=%d]", SAFESTRPTR(tpath), fd);

  // duplicate fd
  if(-1 == (fd2 = dup(fd)) || 0 != lseek(fd2, 0, SEEK_SET)){
    DPRN("Could not duplicate file descriptor(errno=%d)", errno);
    if(-1 != fd2){
      close(fd2);
    }
    return -errno;
  }
  if(-1 == fstat(fd2, &st)){
    DPRN("Invalid file descriptor(errno=%d)", errno);
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

    // upload part
    if(0 != (result = UploadMultipartPostRequest(tpath, (list.size() + 1), upload_id))){
      DPRN("failed uploading part(%d)", result);
      close(fd2);
      return result;
    }
    list.push_back(partdata.etag);
    DestroyCurlHandle();
  }
  close(fd2);

  if(0 != (result = CompleteMultipartPostRequest(tpath, upload_id, list))){
    return result;
  }
  return 0;
}

int S3fsCurl::MultipartRenameRequest(const char* from, const char* to, headers_t& meta, off_t size)
{
  int            result;
  string         upload_id;
  off_t          chunk;
  off_t          bytes_remaining;
  etaglist_t     list;
  stringstream   strrange;

  FPRNNN("[from=%s][to=%s]", SAFESTRPTR(from), SAFESTRPTR(to));

  string srcresource;
  string srcurl;
  MakeUrlResource(get_realpath(from).c_str(), srcresource, srcurl);

  meta["Content-Type"]      = S3fsCurl::LookupMimeType(string(to));
  meta["x-amz-copy-source"] = srcresource;

  if(0 != (result = PreMultipartPostRequest(to, meta, upload_id, true))){
    return result;
  }
  DestroyCurlHandle();

  for(bytes_remaining = size, chunk = 0; 0 < bytes_remaining; bytes_remaining -= chunk){
    chunk = bytes_remaining > MAX_MULTI_COPY_SOURCE_SIZE ? MAX_MULTI_COPY_SOURCE_SIZE : bytes_remaining;

    strrange << "bytes=" << (size - bytes_remaining) << "-" << (size - bytes_remaining + chunk - 1);
    meta["x-amz-copy-source-range"] = strrange.str();
    strrange.str("");
    strrange.clear(stringstream::goodbit);

    if(0 != (result = CopyMultipartPostRequest(from, to, (list.size() + 1), upload_id, meta))){
      return result;
    }
    list.push_back(partdata.etag);
    DestroyCurlHandle();
  }

  if(0 != (result = CompleteMultipartPostRequest(to, upload_id, list))){
    return result;
  }
  return 0;
}

//-------------------------------------------------------------------
// Class S3fsMultiCurl 
//-------------------------------------------------------------------
#define MAX_MULTI_HEADREQ   20   // default: max request count in readdir curl_multi.

//-------------------------------------------------------------------
// Class method for S3fsMultiCurl 
//-------------------------------------------------------------------
int S3fsMultiCurl::max_multireq = MAX_MULTI_HEADREQ;

int S3fsMultiCurl::SetMaxMultiRequest(int max)
{
  int old = S3fsMultiCurl::max_multireq;
  S3fsMultiCurl::max_multireq= max;
  return old;
}

//-------------------------------------------------------------------
// method for S3fsMultiCurl 
//-------------------------------------------------------------------
S3fsMultiCurl::S3fsMultiCurl() : hMulti(NULL), SuccessCallback(NULL), RetryCallback(NULL)
{
}

S3fsMultiCurl::~S3fsMultiCurl()
{
  Clear();
}

bool S3fsMultiCurl::ClearEx(bool is_all)
{
  s3fscurlmap_t::iterator iter;
  for(iter = cMap_req.begin(); iter != cMap_req.end(); cMap_req.erase(iter++)){
    CURL*     hCurl    = (*iter).first;
    S3fsCurl* s3fscurl = (*iter).second;
    if(hMulti && hCurl){
      curl_multi_remove_handle(hMulti, hCurl);
    }
    if(s3fscurl){
      s3fscurl->DestroyCurlHandle();
      delete s3fscurl;  // with destroy curl handle.
    }
  }

  if(hMulti){
    curl_multi_cleanup(hMulti);
    hMulti = NULL;
  }

  if(is_all){
    for(iter = cMap_all.begin(); iter != cMap_all.end(); cMap_all.erase(iter++)){
      S3fsCurl* s3fscurl = (*iter).second;
      s3fscurl->DestroyCurlHandle();
      delete s3fscurl;
    }
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
  if(hMulti){
    DPRN("Internal error: hMulti is not null");
    return false;
  }
  if(!s3fscurl){
    return false;
  }
  if(cMap_all.end() != cMap_all.find(s3fscurl->hCurl)){
    return false;
  }
  cMap_all[s3fscurl->hCurl] = s3fscurl;
  return true;
}

int S3fsMultiCurl::MultiPerform(void)
{
  CURLMcode curlm_code;
  int       still_running;

  if(!hMulti){
    return -1;
  }

  // Send multi request.
  do{
    // Start making requests and check running.
    still_running = 0;
    do {
      curlm_code = curl_multi_perform(hMulti, &still_running);
    } while(curlm_code == CURLM_CALL_MULTI_PERFORM);

    if(curlm_code != CURLM_OK) {
      DPRNNN("curl_multi_perform code: %d msg: %s", curlm_code, curl_multi_strerror(curlm_code));
    }

    // Set timer when still running
    if(still_running) {
      long milliseconds;
      fd_set r_fd;
      fd_set w_fd;
      fd_set e_fd;
      FD_ZERO(&r_fd);
      FD_ZERO(&w_fd);
      FD_ZERO(&e_fd);

      if(CURLM_OK != (curlm_code = curl_multi_timeout(hMulti, &milliseconds))){
        DPRNNN("curl_multi_timeout code: %d msg: %s", curlm_code, curl_multi_strerror(curlm_code));
      }
      if(milliseconds < 0){
        milliseconds = 50;
      }
      if(milliseconds > 0) {
        int max_fd;
        struct timeval timeout;
        timeout.tv_sec  = 1000 * milliseconds / 1000000;
        timeout.tv_usec = 1000 * milliseconds % 1000000;

        if(CURLM_OK != (curlm_code = curl_multi_fdset(hMulti, &r_fd, &w_fd, &e_fd, &max_fd))){
          DPRN("curl_multi_fdset code: %d msg: %s", curlm_code, curl_multi_strerror(curlm_code));
          return -EIO;
        }
        if(-1 == select(max_fd + 1, &r_fd, &w_fd, &e_fd, &timeout)){
          DPRN("failed select - errno(%d)", errno);
          return -errno;
        }
      }
    }
  }while(still_running);

  return 0;
}

int S3fsMultiCurl::MultiRead(void)
{
  CURLMsg*  msg;
  int       remaining_messages;
  CURL*     hCurl    = NULL;
  S3fsCurl* s3fscurl = NULL;
  S3fsCurl* retrycurl= NULL;

  while(NULL != (msg = curl_multi_info_read(hMulti, &remaining_messages))){
    if(CURLMSG_DONE != msg->msg){
      DPRN("curl_multi_info_read code: %d", msg->msg);
      return -EIO;
    }
    hCurl    = msg->easy_handle;
    if(cMap_req.end() != cMap_req.find(hCurl)){
      s3fscurl = cMap_req[hCurl];
    }else{
      s3fscurl = NULL;
    }
    retrycurl= NULL;

    if(s3fscurl){
      bool isRetry = false;
      if(CURLE_OK == msg->data.result){
        long responseCode = -1;
        if(s3fscurl->GetResponseCode(responseCode)){
          if(400 > responseCode){
            // add into stat cache
            if(SuccessCallback && !SuccessCallback(s3fscurl)){
              DPRN("error from callback function(%s).", s3fscurl->url.c_str());
            }
          }else if(400 == responseCode){
            // as possibly in multipart
            DPRN("failed a request(%ld: %s)", responseCode, s3fscurl->url.c_str());
            isRetry = true;
          }else if(404 == responseCode){
            // not found
            DPRN("failed a request(%ld: %s)", responseCode, s3fscurl->url.c_str());
          }else if(500 == responseCode){
            // case of all other result, do retry.(11/13/2013)
            // because it was found that s3fs got 500 error from S3, but could success
            // to retry it.
            DPRN("failed a request(%ld: %s)", responseCode, s3fscurl->url.c_str());
            isRetry = true;
          }else{
            // Retry in other case.
            DPRN("failed a request(%ld: %s)", responseCode, s3fscurl->url.c_str());
            isRetry = true;
          }
        }else{
          DPRN("failed a request(Unknown respons code: %s)", s3fscurl->url.c_str());
        }
      }else{
        DPRN("failed to read(remaining: %d code: %d  msg: %s), so retry this.",
              remaining_messages, msg->data.result, curl_easy_strerror(msg->data.result));
        isRetry = true;
      }

      if(!isRetry){
        cMap_req.erase(hCurl);
        curl_multi_remove_handle(hMulti, hCurl);

        s3fscurl->DestroyCurlHandle();
        delete s3fscurl;

      }else{
        cMap_req.erase(hCurl);
        curl_multi_remove_handle(hMulti, hCurl);

        // For retry
        if(RetryCallback){
          if(NULL != (retrycurl = RetryCallback(s3fscurl))){
            cMap_all[retrycurl->hCurl] = retrycurl;
          }else{
            // Could not set up callback.
            return -EIO;
          }
        }
        if(s3fscurl != retrycurl){
          s3fscurl->DestroyCurlHandle();
          delete s3fscurl;
        }
      }
    }else{
      assert(false);
    }
  }
  return 0;
}

int S3fsMultiCurl::Request(void)
{
  int       result;
  CURLMcode curlm_code;

  FPRNNN("[count=%zu]", cMap_all.size());

  if(hMulti){
    DPRNNN("Warning: hMulti is not null, thus clear itself.");
    ClearEx(false);
  }

  // Make request list.
  //
  // Send multi request loop( with retry )
  // (When many request is sends, sometimes gets "Couldn't connect to server")
  //
  while(0 < cMap_all.size()){
    // populate the multi interface with an initial set of requests
    if(NULL == (hMulti = curl_multi_init())){
      Clear();
      return -1;
    }

    // set curl handle to multi handle
    int                     cnt;
    s3fscurlmap_t::iterator iter;
    for(cnt = 0, iter = cMap_all.begin(); cnt < S3fsMultiCurl::max_multireq && iter != cMap_all.end(); cMap_all.erase(iter++), cnt++){
      CURL*     hCurl    = (*iter).first;
      S3fsCurl* s3fscurl = (*iter).second;

      if(CURLM_OK != (curlm_code = curl_multi_add_handle(hMulti, hCurl))){
        DPRN("curl_multi_add_handle code: %d msg: %s", curlm_code, curl_multi_strerror(curlm_code));
        Clear();
        return -EIO;
      }
      cMap_req[hCurl] = s3fscurl;
    }

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

//-------------------------------------------------------------------
// Class AdditionalHeader
//-------------------------------------------------------------------
AdditionalHeader AdditionalHeader::singleton;

//-------------------------------------------------------------------
// Class AdditionalHeader method
//-------------------------------------------------------------------
AdditionalHeader::AdditionalHeader()
{
  if(this == AdditionalHeader::get()){
    is_enable = false;
  }else{
    assert(false);
  }
}

AdditionalHeader::~AdditionalHeader()
{
  if(this == AdditionalHeader::get()){
    Unload();
  }else{
    assert(false);
  }
}

bool AdditionalHeader::Load(const char* file)
{
  if(!file){
    DPRNNN("file is NULL.");
    return false;
  }
  Unload();

  ifstream AH(file);
  if(!AH.good()){
    DPRNNN("Could not open file(%s).", file);
    return false;
  }

  // read file
  string line;
  while(getline(AH, line)){
    if('#' == line[0]){
      continue;
    }
    if(0 == line.size()){
      continue;
    }
    // load a line
    stringstream ss(line);
    string       key("");       // suffix(key)
    string       head;          // additional HTTP header
    string       value;         // header value
    if(0 == isblank(line[0])){
      ss >> key;
    }
    if(ss){
      ss >> head;
      if(ss && static_cast<size_t>(ss.tellg()) < line.size()){
        value = line.substr(static_cast<int>(ss.tellg()) + 1);
      }
    }

    // check it
    if(0 == head.size()){
      if(0 == key.size()){
        continue;
      }
      DPRNNN("file format error: %s key(suffix) is no HTTP header value.", key.c_str());
      Unload();
      return false;
    }

    // set charcntlist
    int keylen = key.size();
    charcnt_list_t::iterator iter;
    for(iter = charcntlist.begin(); iter != charcntlist.end(); ++iter){
      if(keylen == (*iter)){
        break;
      }
    }
    if(iter == charcntlist.end()){
      charcntlist.push_back(keylen);
    }
    // set addheader
    if(addheader.end() == addheader.find(key)){
      headerpair_t hpair;
      hpair[head]    = value;
      addheader[key] = hpair;
    }else{
      (addheader[key])[head] = value;
    }
    // set flag
    if(!is_enable){
      is_enable = true;
    }
  }
  return true;
}

void AdditionalHeader::Unload(void)
{
  is_enable = false;
  charcntlist.clear();
  addheader.clear();
}

bool AdditionalHeader::AddHeader(headers_t& meta, const char* path) const
{
  if(!is_enable){
    return true;
  }
  if(!path){
    DPRNNN("path is NULL.");
    return false;
  }
  int nPathLen = strlen(path);
  for(charcnt_list_t::const_iterator iter = charcntlist.begin(); iter != charcntlist.end(); ++iter){
    // get target character count
    if(nPathLen < (*iter)){
      continue;
    }
    // make target suffix(same character count) & find
    string suffix(&path[nPathLen - (*iter)]);
    if(addheader.end() == addheader.find(suffix)){
      continue;
    }
    for(headerpair_t::const_iterator piter = addheader.at(suffix).begin(); piter != addheader.at(suffix).end(); ++piter){
      // Adding header
      meta[(*piter).first] = (*piter).second;
    }
  }
  return true;
}

struct curl_slist* AdditionalHeader::AddHeader(struct curl_slist* list, const char* path) const
{
  headers_t meta;

  if(!AddHeader(meta, path)){
    return list;
  }
  for(headers_t::iterator iter = meta.begin(); iter != meta.end(); ++iter){
    // Adding header
    list = curl_slist_sort_insert(list, iter->first.c_str(), iter->second.c_str());
  }
  meta.clear();
  S3FS_MALLOCTRIM(0);
  return list;
}

bool AdditionalHeader::Dump(void) const
{
  if(!foreground2){
    return true;
  }
  // character count list
  stringstream ssdbg;
  ssdbg << "Character count list[" << charcntlist.size() << "] = {";
  for(charcnt_list_t::const_iterator citer = charcntlist.begin(); citer != charcntlist.end(); ++citer){
    ssdbg << " " << (*citer);
  }
  ssdbg << " }\n";

  // additional header
  ssdbg << "Additional Header list[" << addheader.size() << "] = {\n";
  for(addheader_t::const_iterator aiter = addheader.begin(); aiter != addheader.end(); ++aiter){
    string key = (*aiter).first;
    if(0 == key.size()){
      key = "*";
    }
    for(headerpair_t::const_iterator piter = (*aiter).second.begin(); piter != (*aiter).second.end(); ++piter){
      ssdbg << "    " << key << "\t--->\t" << (*piter).first << ": " << (*piter).second << "\n";
    }
  }
  ssdbg << "}";

  // print all
  FPRNINFO("%s", ssdbg.str().c_str());

  return true;
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
  string strval = "";

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
  if(NULL == (new_item = (struct curl_slist*)malloc(sizeof(struct curl_slist)))){
    return list;
  }

  // key & value are trimed and lower(only key)
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
      strkey = strkey.substr(0, pos);
    }
    if(0 < sorted_headers.length()){
      sorted_headers += ";";
    }
    sorted_headers += lower(strkey);
  }

  return sorted_headers;
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
      strhead       = strkey + string(":") + strval;
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
      strhead       = strkey + string(":") + strval;
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
  FPRNINFO("URL is %s", url);

  string uri;
  string host;
  string path;
  string url_str = str(url);
  string token =  str("/" + bucket);
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
    host = bucket + "." + url_str.substr(uri_length, bucket_pos - uri_length).c_str();
    path = url_str.substr((bucket_pos + bucket_length));
  }else{
    host = url_str.substr(uri_length, bucket_pos - uri_length).c_str();
    string part = url_str.substr((bucket_pos + bucket_length));
    if('/' != part[0]){
      part = "/" + part;
    }
    path = "/" + bucket + part;
  }

  url_str = uri + host + path;

  FPRNINFO("URL changed is %s", url_str.c_str());

  return str(url_str);
}

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: noet sw=4 ts=4 fdm=marker
* vim<600: noet sw=4 ts=4
*/
