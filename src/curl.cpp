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
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/md5.h>
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

using namespace std;

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

pthread_mutex_t  S3fsCurl::curl_handles_lock;
pthread_mutex_t  S3fsCurl::curl_share_lock[SHARE_MUTEX_MAX];
pthread_mutex_t* S3fsCurl::crypt_mutex         = NULL;
bool             S3fsCurl::is_initglobal_done  = false;
CURLSH*          S3fsCurl::hCurlShare          = NULL;
bool             S3fsCurl::is_dns_cache        = true; // default
bool             S3fsCurl::is_ssl_session_cache= true; // default
long             S3fsCurl::connect_timeout     = 10;   // default
time_t           S3fsCurl::readwrite_timeout   = 30;   // default
int              S3fsCurl::retries             = 3;    // default
bool             S3fsCurl::is_public_bucket    = false;
string           S3fsCurl::default_acl         = "private";
bool             S3fsCurl::is_use_rrs          = false;
bool             S3fsCurl::is_use_sse          = false;
bool             S3fsCurl::is_content_md5      = false;
bool             S3fsCurl::is_verbose          = false;
string           S3fsCurl::AWSAccessKeyId;
string           S3fsCurl::AWSSecretAccessKey;
string           S3fsCurl::AWSAccessToken;
time_t           S3fsCurl::AWSAccessTokenExpire= 0;
string           S3fsCurl::IAM_role;
long             S3fsCurl::ssl_verify_hostname = 1;    // default(original code...)
const EVP_MD*    S3fsCurl::evp_md              = EVP_sha1();
curltime_t       S3fsCurl::curl_times;
curlprogress_t   S3fsCurl::curl_progress;
string           S3fsCurl::curl_ca_bundle;
mimes_t          S3fsCurl::mimeTypes;
int              S3fsCurl::max_parallel_cnt    = 5;    // default

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
  if(!S3fsCurl::is_dns_cache){
    if(CURLSHE_OK != (nSHCode = curl_share_setopt(S3fsCurl::hCurlShare, CURLSHOPT_SHARE, CURL_LOCK_DATA_DNS))){
      DPRN("curl_share_setopt(DNS) returns %d(%s)", nSHCode, curl_share_strerror(nSHCode));
      return false;
    }
  }
  if(!S3fsCurl::is_ssl_session_cache){
    if(CURLSHE_OK != (nSHCode = curl_share_setopt(S3fsCurl::hCurlShare, CURLSHOPT_SHARE, CURL_LOCK_DATA_SSL_SESSION))){
      DPRN("curl_share_setopt(SSL SESSION) returns %d(%s)", nSHCode, curl_share_strerror(nSHCode));
      return false;
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
  if(S3fsCurl::crypt_mutex){
    FPRNNN("crypt_mutex is not NULL, destory it.");
    if(!S3fsCurl::DestroyCryptMutex()){
      DPRN("Failed to destroy crypt mutex");
      return false;
    }
  }
  if(NULL == (S3fsCurl::crypt_mutex = static_cast<pthread_mutex_t*>(malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t))))){
    DPRNCRIT("Could not allocate memory for crypt mutex");
    return false;
  }
  for(int cnt = 0; cnt < CRYPTO_num_locks(); cnt++){
    pthread_mutex_init(&S3fsCurl::crypt_mutex[cnt], NULL);
  }
  // static lock
  CRYPTO_set_locking_callback(S3fsCurl::CryptMutexLock);
  CRYPTO_set_id_callback(S3fsCurl::CryptGetThreadid);
  // dynamic lock
  CRYPTO_set_dynlock_create_callback(S3fsCurl::CreateDynCryptMutex);
  CRYPTO_set_dynlock_lock_callback(S3fsCurl::DynCryptMutexLock);
  CRYPTO_set_dynlock_destroy_callback(S3fsCurl::DestoryDynCryptMutex);

  return true;
}

bool S3fsCurl::DestroyCryptMutex(void)
{
  if(!S3fsCurl::crypt_mutex){
    return true;
  }

  CRYPTO_set_dynlock_destroy_callback(NULL);
  CRYPTO_set_dynlock_lock_callback(NULL);
  CRYPTO_set_dynlock_create_callback(NULL);
  CRYPTO_set_id_callback(NULL);
  CRYPTO_set_locking_callback(NULL);

  for(int cnt = 0; cnt < CRYPTO_num_locks(); cnt++){
    pthread_mutex_destroy(&S3fsCurl::crypt_mutex[cnt]);
  }
  CRYPTO_cleanup_all_ex_data();
  free(S3fsCurl::crypt_mutex);
  S3fsCurl::crypt_mutex = NULL;

  return true;
}

void S3fsCurl::CryptMutexLock(int mode, int pos, const char* file, int line)
{
  if(S3fsCurl::crypt_mutex){
    if(mode & CRYPTO_LOCK){
      pthread_mutex_lock(&S3fsCurl::crypt_mutex[pos]);
    }else{
      pthread_mutex_unlock(&S3fsCurl::crypt_mutex[pos]);
    }
  }
}

unsigned long S3fsCurl::CryptGetThreadid(void)
{
  return (unsigned long)pthread_self();
}

struct CRYPTO_dynlock_value* S3fsCurl::CreateDynCryptMutex(const char* file, int line)
{
  struct CRYPTO_dynlock_value* dyndata;

  if(NULL == (dyndata = (struct CRYPTO_dynlock_value*)malloc(sizeof(struct CRYPTO_dynlock_value)))){
    return NULL;
  }
  pthread_mutex_init(&(dyndata->dyn_mutex), NULL);
  return dyndata;
}

void S3fsCurl::DynCryptMutexLock(int mode, struct CRYPTO_dynlock_value* dyndata, const char* file, int line)
{
  if(dyndata){
    if(mode & CRYPTO_LOCK){
      pthread_mutex_lock(&(dyndata->dyn_mutex));
    }else{
      pthread_mutex_unlock(&(dyndata->dyn_mutex));
    }
  }
}

void S3fsCurl::DestoryDynCryptMutex(struct CRYPTO_dynlock_value* dyndata, const char* file, int line)
{
  if(dyndata){
    pthread_mutex_destroy(&(dyndata->dyn_mutex));
    free(dyndata);
  }
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
      // check for existance and readability of the file
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

int S3fsCurl::ParallelMultipartUploadRequest(const char* tpath, headers_t& meta, int fd, bool ow_sse_flg)
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
    DPRN("Cloud not duplicate file discriptor(errno=%d)", errno);
    if(-1 != fd2){
      close(fd2);
    }
    return -errno;
  }
  if(-1 == fstat(fd2, &st)){
    DPRN("Invalid file discriptor(errno=%d)", errno);
    close(fd2);
    return -errno;
  }

  if(0 != (result = s3fscurl.PreMultipartPostRequest(tpath, meta, upload_id, ow_sse_flg))){
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
      chunk = remaining_bytes > MULTIPART_SIZE ?  MULTIPART_SIZE : remaining_bytes;

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
           s3fscurl->path.c_str(), s3fscurl->partdata.fd, s3fscurl->partdata.startpos, s3fscurl->partdata.size))){
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
      chunk = remaining_bytes > MULTIPART_SIZE ?  MULTIPART_SIZE : remaining_bytes;

      // s3fscurl sub object
      S3fsCurl* s3fscurl_para = new S3fsCurl();
      if(0 != (result = s3fscurl_para->PreGetObjectRequest(tpath, fd, (start + size - remaining_bytes), chunk))){
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
    retry_count(0), b_infile(NULL), b_postdata(NULL), b_postdata_remaining(0), b_partdata_startpos(0), b_partdata_size(0)
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
      curl_easy_setopt(hCurl, CURLOPT_FAILONERROR, true);
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
        DPRNNN("HTTP response code %ld", LastResponseCode);

        if(400 > LastResponseCode){
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

      case CURLE_SSL_CACERT:
        // try to locate cert, if successful, then set the
        // option and continue
        if(0 == S3fsCurl::curl_ca_bundle.size()){
          if(!S3fsCurl::LocateBundle()){
            exit(EXIT_FAILURE);
          }
          break; // retry with CAINFO
        }
        DPRNCRIT("curlCode: %d  msg: %s", curlCode, curl_easy_strerror(curlCode));
        exit(EXIT_FAILURE);
        break;

#ifdef CURLE_PEER_FAILED_VERIFICATION
      case CURLE_PEER_FAILED_VERIFICATION:
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
// @param date e.g., get_date()
// @param resource e.g., "/pub"
//
string S3fsCurl::CalcSignature(string method, string strMD5, string content_type, string date, string resource)
{
  int ret;
  int bytes_written;
  int offset;
  int write_attempts = 0;
  string Signature;
  string StringToSign;

  if(0 < S3fsCurl::IAM_role.size()){
    if(!S3fsCurl::CheckIAMCredentialUpdate()){
      DPRN("Something error occurred in checking IAM credential.");  
      return Signature;  // returns empty string, then it occures error.
    }
    requestHeaders = curl_slist_sort_insert(requestHeaders, string("x-amz-security-token:" + S3fsCurl::AWSAccessToken).c_str());
  }

  StringToSign += method + "\n";
  StringToSign += strMD5 + "\n";        // md5
  StringToSign += content_type + "\n";
  StringToSign += date + "\n";
  for(curl_slist* headers = requestHeaders; headers; headers = headers->next){
    if(0 == strncmp(headers->data, "x-amz", 5)){
      StringToSign += headers->data;
      StringToSign += "\n";
    }
  }
  StringToSign += resource;

  const void* key            = S3fsCurl::AWSSecretAccessKey.data();
  int key_len                = S3fsCurl::AWSSecretAccessKey.size();
  const unsigned char* sdata = reinterpret_cast<const unsigned char*>(StringToSign.data());
  int sdata_len              = StringToSign.size();
  unsigned char md[EVP_MAX_MD_SIZE];
  unsigned int md_len;

  HMAC(S3fsCurl::evp_md, key, key_len, sdata, sdata_len, md, &md_len);

  BIO* b64  = BIO_new(BIO_f_base64());
  BIO* bmem = BIO_new(BIO_s_mem());
  b64       = BIO_push(b64, bmem);

  offset = 0;
  for(;;){
    bytes_written = BIO_write(b64, &(md[offset]), md_len);
    write_attempts++;
    // -1 indicates that an error occurred, or a temporary error, such as
    // the server is busy, occurred and we need to retry later.
    // BIO_write can do a short write, this code addresses this condition
    if(bytes_written <= 0){
      // Indicates whether a temporary error occurred or a failure to
      // complete the operation occurred
      if((ret = BIO_should_retry(b64))){
        // Wait until the write can be accomplished
        if(write_attempts <= 10){
          continue;
        }
        // Too many write attempts
        DPRNNN("Failure during BIO_write, returning null String");  
        CRYPTO_free_ex_data(CRYPTO_EX_INDEX_BIO, b64, &b64->ex_data);
        BIO_free_all(b64);
        Signature.clear();
        return Signature;

      }else{
        // If not a retry then it is an error
        DPRNNN("Failure during BIO_write, returning null String");  
        CRYPTO_free_ex_data(CRYPTO_EX_INDEX_BIO, b64, &b64->ex_data);
        BIO_free_all(b64);
        Signature.clear();
        return Signature;
      }
    }
  
    // The write request succeeded in writing some Bytes
    offset += bytes_written;
    md_len -= bytes_written;
  
    // If there is no more data to write, the request sending has been
    // completed
    if(md_len <= 0){
      break;
    }
  }

  // Flush the data
  ret = BIO_flush(b64);
  if(ret <= 0){ 
    DPRNNN("Failure during BIO_flush, returning null String");  
    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_BIO, b64, &b64->ex_data);
    BIO_free_all(b64);
    Signature.clear();
    return Signature;
  } 

  BUF_MEM *bptr;
  BIO_get_mem_ptr(b64, &bptr);
  Signature.assign(bptr->data, bptr->length - 1);

  CRYPTO_free_ex_data(CRYPTO_EX_INDEX_BIO, b64, &b64->ex_data);
  BIO_free_all(b64);

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
  path            = tpath;
  requestHeaders  = NULL;
  responseHeaders.clear();

  string date    = get_date();
  requestHeaders = curl_slist_sort_insert(requestHeaders, string("Date: " + date).c_str());
  requestHeaders = curl_slist_sort_insert(requestHeaders, "Content-Type: ");
  if(!S3fsCurl::IsPublicBucket()){
    requestHeaders = curl_slist_sort_insert(
          requestHeaders,
          string("Authorization: AWS " + AWSAccessKeyId + ":" +
          CalcSignature("DELETE", "", "", date, resource)).c_str());
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
    DPRN("Something error occured, could not get IAM credential.");
  }
  delete bodydata;
  bodydata = NULL;

  return result;
}

//
// tpath :      target path for head request
// bpath :      saved into base_path
// savedpath :  saved into saved_path
//
bool S3fsCurl::PreHeadRequest(const char* tpath, const char* bpath, const char* savedpath)
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
  path            = tpath;
  base_path       = SAFESTRPTR(bpath);
  saved_path      = SAFESTRPTR(savedpath);
  requestHeaders  = NULL;
  responseHeaders.clear();

  // requestHeaders
  string date    = get_date();
  requestHeaders = curl_slist_sort_insert(requestHeaders, string("Date: " + date).c_str());
  requestHeaders = curl_slist_sort_insert(requestHeaders, "Content-Type: ");
  if(!S3fsCurl::IsPublicBucket()){
    requestHeaders = curl_slist_sort_insert(
          requestHeaders,
          string("Authorization: AWS " + AWSAccessKeyId + ":" +
          CalcSignature("HEAD", "", "", date, resource)).c_str());
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
  int result;

  FPRNNN("[tpath=%s]", SAFESTRPTR(tpath));

  if(!PreHeadRequest(tpath)){
    return -1;
  }
  // Requests
  if(0 != (result = RequestPerform())){
    return result;
  }
  // file exists in s3
  // fixme: clean this up.
  meta.clear();
  for(headers_t::iterator iter = responseHeaders.begin(); iter != responseHeaders.end(); ++iter){
    string key = (*iter).first;
    string value = (*iter).second;
    if(key == "Content-Type"){
      meta[key] = value;
    }else if(key == "Content-Length"){
      meta[key] = value;
    }else if(key == "ETag"){
      meta[key] = value;
    }else if(key == "Last-Modified"){
      meta[key] = value;
    }else if(key.substr(0, 5) == "x-amz"){
      meta[key] = value;
    }else{
      // Check for upper case
      transform(key.begin(), key.end(), key.begin(), static_cast<int (*)(int)>(std::tolower));
      if(key.substr(0, 5) == "x-amz"){
        meta[key] = value;
      }
    }
  }
  return 0;
}

int S3fsCurl::PutHeadRequest(const char* tpath, headers_t& meta, bool ow_sse_flg)
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
  path            = tpath;
  requestHeaders  = NULL;
  responseHeaders.clear();
  bodydata        = new BodyData();

  // Make request headers
  string date    = get_date();
  requestHeaders = curl_slist_sort_insert(requestHeaders, string("Date: " + date).c_str());

  string ContentType;
  for(headers_t::iterator iter = meta.begin(); iter != meta.end(); ++iter){
    string key = (*iter).first;
    string value = (*iter).second;
    if(key == "Content-Type"){
      ContentType    = value;
      requestHeaders = curl_slist_sort_insert(requestHeaders, string(key + ":" + value).c_str());
    }else if(key.substr(0,9) == "x-amz-acl"){
      // not set value, but after set it.
    }else if(key.substr(0,10) == "x-amz-meta"){
      requestHeaders = curl_slist_sort_insert(requestHeaders, string(key + ":" + value).c_str());
    }else if(key == "x-amz-copy-source"){
      requestHeaders = curl_slist_sort_insert(requestHeaders, string(key + ":" + value).c_str());
    }else if(!ow_sse_flg && key == "x-amz-server-side-encryption"){
      // If ow_sse_flg is false, SSE inherit from meta.
      requestHeaders = curl_slist_sort_insert(requestHeaders, string(key + ":" + value).c_str());
    }
  }
  // "x-amz-acl", rrs, sse
  requestHeaders = curl_slist_sort_insert(requestHeaders, string("x-amz-acl:" + S3fsCurl::default_acl).c_str());
  if(S3fsCurl::is_use_rrs){
    requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-storage-class:REDUCED_REDUNDANCY");
  }
  if(ow_sse_flg && S3fsCurl::is_use_sse){
    requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-server-side-encryption:AES256");
  }
  if(is_use_ahbe){
    // set additional header by ahbe conf
    requestHeaders = AdditionalHeader::get()->AddHeader(requestHeaders, tpath);
  }
  if(!S3fsCurl::IsPublicBucket()){
    requestHeaders = curl_slist_sort_insert(
          requestHeaders,
          string("Authorization: AWS " + AWSAccessKeyId + ":" +
          CalcSignature("PUT", "", ContentType, date, resource)).c_str());
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

int S3fsCurl::PutRequest(const char* tpath, headers_t& meta, int fd, bool ow_sse_flg)
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
  path            = tpath;
  requestHeaders  = NULL;
  responseHeaders.clear();
  bodydata        = new BodyData();

  // Make request headers
  string date    = get_date();
  requestHeaders = curl_slist_sort_insert(requestHeaders, string("Date: " + date).c_str());

  string strMD5;
  if(-1 != fd && S3fsCurl::is_content_md5){
    strMD5         = GetContentMD5(fd);
    requestHeaders = curl_slist_sort_insert(requestHeaders, string("Content-MD5: " + strMD5).c_str());
  }

  string ContentType;
  for(headers_t::iterator iter = meta.begin(); iter != meta.end(); ++iter){
    string key = (*iter).first;
    string value = (*iter).second;
    if(key == "Content-Type"){
      ContentType    = value;
      requestHeaders = curl_slist_sort_insert(requestHeaders, string(key + ":" + value).c_str());
    }else if(key.substr(0,9) == "x-amz-acl"){
      // not set value, but after set it.
    }else if(key.substr(0,10) == "x-amz-meta"){
      requestHeaders = curl_slist_sort_insert(requestHeaders, string(key + ":" + value).c_str());
    }else if(!ow_sse_flg && key == "x-amz-server-side-encryption"){
      // If ow_sse_flg is false, SSE inherit from meta.
      requestHeaders = curl_slist_sort_insert(requestHeaders, string(key + ":" + value).c_str());
    }
  }
  // "x-amz-acl", rrs, sse
  requestHeaders = curl_slist_sort_insert(requestHeaders, string("x-amz-acl:" + S3fsCurl::default_acl).c_str());
  if(S3fsCurl::is_use_rrs){
    requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-storage-class:REDUCED_REDUNDANCY");
  }
  if(ow_sse_flg && S3fsCurl::is_use_sse){
    requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-server-side-encryption:AES256");
  }
  if(is_use_ahbe){
    // set additional header by ahbe conf
    requestHeaders = AdditionalHeader::get()->AddHeader(requestHeaders, tpath);
  }
  if(!S3fsCurl::IsPublicBucket()){
    requestHeaders = curl_slist_sort_insert(
          requestHeaders,
          string("Authorization: AWS " + AWSAccessKeyId + ":" +
          CalcSignature("PUT", strMD5, ContentType, date, resource)).c_str());
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

int S3fsCurl::PreGetObjectRequest(const char* tpath, int fd, off_t start, ssize_t size)
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
  path            = tpath;
  requestHeaders  = NULL;
  responseHeaders.clear();

  string date    = get_date();
  requestHeaders = curl_slist_sort_insert(requestHeaders, string("Date: " + date).c_str());
  requestHeaders = curl_slist_sort_insert(requestHeaders, "Content-Type: ");
  if(-1 != start && -1 != size){
    string range = "Range: bytes=";
    range       += str(start);
    range       += "-";
    range       += str(start + size - 1);
    requestHeaders = curl_slist_sort_insert(requestHeaders, range.c_str());
  }

  if(!S3fsCurl::IsPublicBucket()){
    requestHeaders = curl_slist_sort_insert(
          requestHeaders,
          string("Authorization: AWS " + AWSAccessKeyId + ":" +
          CalcSignature("GET", "", "", date, resource)).c_str());
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
  if(0 != (result = PreGetObjectRequest(tpath, fd, start, size))){
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
  path            = "/";
  requestHeaders  = NULL;
  responseHeaders.clear();
  bodydata        = new BodyData();

  string date    = get_date();
  requestHeaders = curl_slist_sort_insert(requestHeaders, string("Date: " + date).c_str());

  if(!S3fsCurl::IsPublicBucket()){
    requestHeaders = curl_slist_sort_insert(
          requestHeaders,
          string("Authorization: AWS " + AWSAccessKeyId + ":" +
          CalcSignature("GET", "", "", date, resource)).c_str());
  }
  // setopt
  curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(hCurl, CURLOPT_FAILONERROR, true);
  curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, (void*)bodydata);
  curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(hCurl, CURLOPT_HTTPHEADER, requestHeaders);

  type = REQTYPE_CHKBUCKET;

  int result = RequestPerform();
  delete bodydata;
  bodydata = NULL;

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
  path            = tpath;
  requestHeaders  = NULL;
  responseHeaders.clear();
  bodydata        = new BodyData();

  string date    = get_date();
  requestHeaders = curl_slist_sort_insert(requestHeaders, string("Date: " + date).c_str());
  requestHeaders = curl_slist_sort_insert(requestHeaders, "Content-Type: ");

  if(!S3fsCurl::IsPublicBucket()){
    requestHeaders = curl_slist_sort_insert(
          requestHeaders,
          string("Authorization: AWS " + AWSAccessKeyId + ":" +
          CalcSignature("GET", "", "", date, (resource + "/"))).c_str());
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
int S3fsCurl::PreMultipartPostRequest(const char* tpath, headers_t& meta, string& upload_id, bool ow_sse_flg)
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

  turl           += "?uploads";
  resource       += "?uploads";
  url             = prepare_url(turl.c_str());
  path            = tpath;
  requestHeaders  = NULL;
  responseHeaders.clear();
  bodydata        = new BodyData();

  string date    = get_date();
  string contype = S3fsCurl::LookupMimeType(string(tpath));
  requestHeaders = curl_slist_sort_insert(requestHeaders, string("Date: " + date).c_str());
  requestHeaders = curl_slist_sort_insert(requestHeaders, "Accept: ");
  requestHeaders = curl_slist_sort_insert(requestHeaders, "Content-Length: ");
  requestHeaders = curl_slist_sort_insert(requestHeaders, string("Content-Type: " + contype).c_str());

  for(headers_t::iterator iter = meta.begin(); iter != meta.end(); ++iter){
    string key   = (*iter).first;
    string value = (*iter).second;

    if(key.substr(0,9) == "x-amz-acl"){
      // not set value, but after set it.
    }else if(key.substr(0,10) == "x-amz-meta"){
      requestHeaders = curl_slist_sort_insert(requestHeaders, string(key + ":" + value).c_str());
    }else if(!ow_sse_flg && key == "x-amz-server-side-encryption"){
      // If ow_sse_flg is false, SSE inherit from meta.
      requestHeaders = curl_slist_sort_insert(requestHeaders, string(key + ":" + value).c_str());
    }
  }
  // "x-amz-acl", rrs, sse
  requestHeaders = curl_slist_sort_insert(requestHeaders, string("x-amz-acl:" + S3fsCurl::default_acl).c_str());
  if(S3fsCurl::is_use_rrs){
    requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-storage-class:REDUCED_REDUNDANCY");
  }
  if(ow_sse_flg && S3fsCurl::is_use_sse){
    requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-server-side-encryption:AES256");
  }
  if(is_use_ahbe){
    // set additional header by ahbe conf
    requestHeaders = AdditionalHeader::get()->AddHeader(requestHeaders, tpath);
  }
  if(!S3fsCurl::IsPublicBucket()){
    requestHeaders = curl_slist_sort_insert(
          requestHeaders,
          string("Authorization: AWS " + AWSAccessKeyId + ":" +
          CalcSignature("POST", "", contype, date, resource)).c_str());
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

  turl           += "?uploadId=" + upload_id;
  resource       += "?uploadId=" + upload_id;
  url             = prepare_url(turl.c_str());
  path            = tpath;
  requestHeaders  = NULL;
  responseHeaders.clear();
  bodydata        = new BodyData();

  string date    = get_date();
  requestHeaders = curl_slist_sort_insert(requestHeaders, string("Date: " + date).c_str());
  requestHeaders = curl_slist_sort_insert(requestHeaders, "Accept:");
  requestHeaders = curl_slist_sort_insert(requestHeaders, "Content-Type:");

  if(!S3fsCurl::IsPublicBucket()){
    requestHeaders = curl_slist_sort_insert(
          requestHeaders,
          string("Authorization: AWS " + AWSAccessKeyId + ":" +
          CalcSignature("POST", "", "", date, resource)).c_str());
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
  path            = "/";
  MakeUrlResource(get_realpath(path.c_str()).c_str(), resource, turl);

  turl           += "?uploads";
  resource       += "?uploads";
  url             = prepare_url(turl.c_str());
  requestHeaders  = NULL;
  responseHeaders.clear();
  bodydata        = new BodyData();

  string date    = get_date();
  requestHeaders = curl_slist_sort_insert(requestHeaders, string("Date: " + date).c_str());
  requestHeaders = curl_slist_sort_insert(requestHeaders, "Accept: ");

  if(!S3fsCurl::IsPublicBucket()){
    requestHeaders = curl_slist_sort_insert(
          requestHeaders,
          string("Authorization: AWS " + AWSAccessKeyId + ":" +
          CalcSignature("GET", "", "", date, resource)).c_str());
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
  path            = tpath;
  requestHeaders  = NULL;
  responseHeaders.clear();

  string date    = get_date();
  requestHeaders = curl_slist_sort_insert(requestHeaders, string("Date: " + date).c_str());
  if(!S3fsCurl::IsPublicBucket()){
    requestHeaders = curl_slist_sort_insert(
          requestHeaders,
          string("Authorization: AWS " + AWSAccessKeyId + ":" +
          CalcSignature("DELETE", "", "", date, resource)).c_str());
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
  partdata.etag = md5sum(partdata.fd, partdata.startpos, partdata.size);
  if(partdata.etag.empty()){
    DPRN("Could not make md5 for file(part %d)", part_num);
    return -1;
  }

  // create handle
  if(!CreateCurlHandle(true)){
    return -1;
  }

  // make request
  string urlargs  = "?partNumber=" + IntToStr(part_num) + "&uploadId=" + upload_id;
  string resource;
  string turl;
  MakeUrlResource(get_realpath(tpath).c_str(), resource, turl);

  resource       += urlargs;
  turl           += urlargs;
  url             = prepare_url(turl.c_str());
  path            = tpath;
  requestHeaders  = NULL;
  responseHeaders.clear();
  bodydata        = new BodyData();
  headdata        = new BodyData();

  string date    = get_date();
  requestHeaders = curl_slist_sort_insert(requestHeaders, string("Date: " + date).c_str());
  requestHeaders = curl_slist_sort_insert(requestHeaders, "Accept: ");

  if(!S3fsCurl::IsPublicBucket()){
    requestHeaders = curl_slist_sort_insert(
          requestHeaders,
          string("Authorization: AWS " + AWSAccessKeyId + ":" +
          CalcSignature("PUT", "", "", date, resource)).c_str());
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
  path            = to;
  requestHeaders  = NULL;
  responseHeaders.clear();
  bodydata        = new BodyData();
  headdata        = new BodyData();

  // Make request headers
  string date    = get_date();
  requestHeaders = curl_slist_sort_insert(requestHeaders, string("Date: " + date).c_str());

  string ContentType;
  for(headers_t::iterator iter = meta.begin(); iter != meta.end(); ++iter){
    string key = (*iter).first;
    string value = (*iter).second;
    if(key == "Content-Type"){
      ContentType    = value;
      requestHeaders = curl_slist_sort_insert(requestHeaders, string(key + ":" + value).c_str());
    }else if(key == "x-amz-copy-source"){
      requestHeaders = curl_slist_sort_insert(requestHeaders, string(key + ":" + value).c_str());
    }else if(key == "x-amz-copy-source-range"){
      requestHeaders = curl_slist_sort_insert(requestHeaders, string(key + ":" + value).c_str());
    }
    // NOTICE: x-amz-acl, x-amz-server-side-encryption is not set!
  }
  if(!S3fsCurl::IsPublicBucket()){
    requestHeaders = curl_slist_sort_insert(
          requestHeaders,
          string("Authorization: AWS " + AWSAccessKeyId + ":" +
          CalcSignature("PUT", "", ContentType, date, resource)).c_str());
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

int S3fsCurl::MultipartHeadRequest(const char* tpath, off_t size, headers_t& meta)
{
  int            result;
  string         upload_id;
  off_t          chunk;
  off_t          bytes_remaining;
  etaglist_t     list;
  stringstream   strrange;

  FPRNNN("[tpath=%s]", SAFESTRPTR(tpath));

  if(0 != (result = PreMultipartPostRequest(tpath, meta, upload_id, false))){
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

int S3fsCurl::MultipartUploadRequest(const char* tpath, headers_t& meta, int fd, bool ow_sse_flg)
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
    DPRN("Cloud not duplicate file discriptor(errno=%d)", errno);
    if(-1 != fd2){
      close(fd2);
    }
    return -errno;
  }
  if(-1 == fstat(fd2, &st)){
    DPRN("Invalid file discriptor(errno=%d)", errno);
    close(fd2);
    return -errno;
  }

  if(0 != (result = PreMultipartPostRequest(tpath, meta, upload_id, ow_sse_flg))){
    close(fd2);
    return result;
  }
  DestroyCurlHandle();

  // cycle through open fd, pulling off 10MB chunks at a time
  for(remaining_bytes = st.st_size; 0 < remaining_bytes; remaining_bytes -= chunk){
    // chunk size
    chunk = remaining_bytes > MULTIPART_SIZE ?  MULTIPART_SIZE : remaining_bytes;

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

  if(0 != (result = PreMultipartPostRequest(to, meta, upload_id, false))){
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
          retrycurl = RetryCallback(s3fscurl);
          cMap_all[retrycurl->hCurl] = retrycurl;
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
    // get target charactor count
    if(nPathLen < (*iter)){
      continue;
    }
    // make target suffix(same charactor count) & find
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
    string slistval = (*iter).first + ": " + (*iter).second;
    // Adding header
    list = curl_slist_sort_insert(list, slistval.c_str());
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
  // charactor count list
  stringstream ssdbg;
  ssdbg << "Charactor count list[" << charcntlist.size() << "] = {";
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
string GetContentMD5(int fd)
{
  BIO*     b64;
  BIO*     bmem;
  BUF_MEM* bptr;
  string   Signature;
  unsigned char* md5hex;

  if(NULL == (md5hex = md5hexsum(fd, 0, -1))){
    return string("");
  }

  b64  = BIO_new(BIO_f_base64());
  bmem = BIO_new(BIO_s_mem());
  b64  = BIO_push(b64, bmem);

  BIO_write(b64, md5hex, MD5_DIGEST_LENGTH);
  free(md5hex);
  if(1 != BIO_flush(b64)){
    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_BIO, b64, &b64->ex_data);
    BIO_free_all(b64);
    return string("");
  }
  BIO_get_mem_ptr(b64, &bptr);
  Signature.assign(bptr->data, bptr->length - 1);

  CRYPTO_free_ex_data(CRYPTO_EX_INDEX_BIO, b64, &b64->ex_data);
  BIO_free_all(b64);

  return Signature;
}

unsigned char* md5hexsum(int fd, off_t start, ssize_t size)
{
  MD5_CTX c;
  char    buf[512];
  ssize_t bytes;
  unsigned char* result;

  // seek to top of file.
  if(-1 == lseek(fd, start, SEEK_SET)){
    return NULL;
  }
  if(NULL == (result = (unsigned char*)malloc(MD5_DIGEST_LENGTH))){
    return NULL;
  }

  memset(buf, 0, 512);
  MD5_Init(&c);
  for(ssize_t total = 0; total < size; total += bytes){
    bytes = 512 < (size - total) ? 512 : (size - total);
    bytes = read(fd, buf, bytes);
    if(0 == bytes){
      // end of file
      break;
    }else if(-1 == bytes){
      // error
      DPRNNN("file read error(%d)", errno);
      free(result);
      return NULL;
    }
    MD5_Update(&c, buf, bytes);
    memset(buf, 0, 512);
  }
  MD5_Final(result, &c);

  if(-1 == lseek(fd, start, SEEK_SET)){
    free(result);
    return NULL;
  }

  return result;
}

string md5sum(int fd, off_t start, ssize_t size)
{
  char md5[2 * MD5_DIGEST_LENGTH + 1];
  char hexbuf[3];
  unsigned char* md5hex;

  if(NULL == (md5hex = md5hexsum(fd, start, size))){
    return string("");
  }

  memset(md5, 0, 2 * MD5_DIGEST_LENGTH + 1);
  for(int i = 0; i < MD5_DIGEST_LENGTH; i++) {
    snprintf(hexbuf, 3, "%02x", md5hex[i]);
    strncat(md5, hexbuf, 2);
  }
  free(md5hex);

  return string(md5);
}

//
// curl_slist_sort_insert
// This function is like curl_slist_append function, but this adds data by a-sorting.
// Because AWS signature needs sorted header.
//
struct curl_slist* curl_slist_sort_insert(struct curl_slist* list, const char* data)
{
  struct curl_slist* curpos;
  struct curl_slist* lastpos;
  struct curl_slist* new_item;

  if(!data){
    return list;
  }
  if(NULL == (new_item = (struct curl_slist*)malloc(sizeof(struct curl_slist)))){
    return list;
  }
  if(NULL == (new_item->data = strdup(data))){
    free(new_item);
    return list;
  }
  new_item->next = NULL;

  string strnew = data;
  string::size_type pos = strnew.find(':', 0);
  if(string::npos != pos){
    strnew = strnew.substr(0, pos);
  }
  
  for(lastpos = NULL, curpos = list; curpos; curpos = curpos->next){
    string strcur = curpos->data;
    if(string::npos != (pos = strcur.find(':', 0))){
      strcur = strcur.substr(0, pos);
    }

    int result = strcmp(strnew.c_str(), strcur.c_str());
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
    lastpos = curpos;
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

/// END
