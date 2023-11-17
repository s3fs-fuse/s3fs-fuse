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

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <memory>
#include <unistd.h>
#include <fstream>
#include <sstream>
#include <algorithm>

#include "common.h"
#include "s3fs.h"
#include "s3fs_logger.h"
#include "curl.h"
#include "curl_multi.h"
#include "curl_util.h"
#include "s3fs_auth.h"
#include "autolock.h"
#include "curl_handlerpool.h"
#include "s3fs_cred.h"
#include "s3fs_util.h"
#include "string_util.h"
#include "addhead.h"

//-------------------------------------------------------------------
// Symbols
//-------------------------------------------------------------------
static constexpr char EMPTY_PAYLOAD_HASH[]              = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
static constexpr char EMPTY_MD5_BASE64_HASH[]           = "1B2M2Y8AsgTpgAmY7PhCfg==";

//-------------------------------------------------------------------
// Class S3fsCurl
//-------------------------------------------------------------------
static constexpr int MULTIPART_SIZE                     = 10 * 1024 * 1024;
static constexpr int GET_OBJECT_RESPONSE_LIMIT          = 1024;

// [NOTE] about default mime.types file
// If no mime.types file is specified in the mime option, s3fs
// will look for /etc/mime.types on all operating systems and
// load mime information.
// However, in the case of macOS, when this file does not exist,
// it tries to detect the /etc/apache2/mime.types file.
// The reason for this is that apache2 is preinstalled on macOS,
// and the mime.types file is expected to exist in this path.
// If the mime.types file is not found, s3fs will exit with an
// error.
//
static constexpr char DEFAULT_MIME_FILE[]               = "/etc/mime.types";
static constexpr char SPECIAL_DARWIN_MIME_FILE[]        = "/etc/apache2/mime.types";

// [NOTICE]
// This symbol is for libcurl under 7.23.0
#ifndef CURLSHE_NOT_BUILT_IN
#define CURLSHE_NOT_BUILT_IN                        5
#endif

#if LIBCURL_VERSION_NUM >= 0x073100
#define S3FS_CURLOPT_XFERINFOFUNCTION   CURLOPT_XFERINFOFUNCTION
#else
#define S3FS_CURLOPT_XFERINFOFUNCTION   CURLOPT_PROGRESSFUNCTION
#endif

//-------------------------------------------------------------------
// Class S3fsCurl
//-------------------------------------------------------------------
pthread_mutex_t  S3fsCurl::curl_warnings_lock;
pthread_mutex_t  S3fsCurl::curl_handles_lock;
S3fsCurl::callback_locks_t S3fsCurl::callback_locks;
bool             S3fsCurl::is_initglobal_done  = false;
CurlHandlerPool* S3fsCurl::sCurlPool           = nullptr;
int              S3fsCurl::sCurlPoolSize       = 32;
CURLSH*          S3fsCurl::hCurlShare          = nullptr;
bool             S3fsCurl::is_cert_check       = true; // default
bool             S3fsCurl::is_dns_cache        = true; // default
bool             S3fsCurl::is_ssl_session_cache= true; // default
long             S3fsCurl::connect_timeout     = 300;  // default
time_t           S3fsCurl::readwrite_timeout   = 120;  // default
int              S3fsCurl::retries             = 5;    // default
bool             S3fsCurl::is_public_bucket    = false;
acl_t            S3fsCurl::default_acl         = acl_t::PRIVATE;
std::string      S3fsCurl::storage_class       = "STANDARD";
sseckeylist_t    S3fsCurl::sseckeys;
std::string      S3fsCurl::ssekmsid;
sse_type_t       S3fsCurl::ssetype             = sse_type_t::SSE_DISABLE;
bool             S3fsCurl::is_content_md5      = false;
bool             S3fsCurl::is_verbose          = false;
bool             S3fsCurl::is_dump_body        = false;
S3fsCred*        S3fsCurl::ps3fscred           = nullptr;
long             S3fsCurl::ssl_verify_hostname = 1;    // default(original code...)

// protected by curl_warnings_lock
bool             S3fsCurl::curl_warnings_once = false;

// protected by curl_handles_lock
curltime_t       S3fsCurl::curl_times;
curlprogress_t   S3fsCurl::curl_progress;

std::string      S3fsCurl::curl_ca_bundle;
mimes_t          S3fsCurl::mimeTypes;
std::string      S3fsCurl::userAgent;
int              S3fsCurl::max_parallel_cnt    = 5;              // default
int              S3fsCurl::max_multireq        = 20;             // default
off_t            S3fsCurl::multipart_size      = MULTIPART_SIZE; // default
off_t            S3fsCurl::multipart_copy_size = 512 * 1024 * 1024;  // default
signature_type_t S3fsCurl::signature_type      = signature_type_t::V2_OR_V4;       // default
bool             S3fsCurl::is_unsigned_payload = false;          // default
bool             S3fsCurl::is_ua               = true;           // default
bool             S3fsCurl::listobjectsv2       = false;          // default
bool             S3fsCurl::requester_pays      = false;          // default
std::string      S3fsCurl::proxy_url;
bool             S3fsCurl::proxy_http          = false;
std::string      S3fsCurl::proxy_userpwd;

//-------------------------------------------------------------------
// Class methods for S3fsCurl
//-------------------------------------------------------------------
bool S3fsCurl::InitS3fsCurl()
{
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
#if S3FS_PTHREAD_ERRORCHECK
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK);
#endif
    if(0 != pthread_mutex_init(&S3fsCurl::curl_warnings_lock, &attr)){
        return false;
    }
    if(0 != pthread_mutex_init(&S3fsCurl::curl_handles_lock, &attr)){
        return false;
    }
    if(0 != pthread_mutex_init(&S3fsCurl::callback_locks.dns, &attr)){
        return false;
    }
    if(0 != pthread_mutex_init(&S3fsCurl::callback_locks.ssl_session, &attr)){
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
    sCurlPool = nullptr;
    if(!S3fsCurl::DestroyShareCurl()){
        result = false;
    }
    if(!S3fsCurl::DestroyGlobalCurl()){
        result = false;
    }
    if(0 != pthread_mutex_destroy(&S3fsCurl::callback_locks.dns)){
        result = false;
    }
    if(0 != pthread_mutex_destroy(&S3fsCurl::callback_locks.ssl_session)){
        result = false;
    }
    if(0 != pthread_mutex_destroy(&S3fsCurl::curl_handles_lock)){
        result = false;
    }
    if(0 != pthread_mutex_destroy(&S3fsCurl::curl_warnings_lock)){
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
    if(nullptr == (S3fsCurl::hCurlShare = curl_share_init())){
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
    if(CURLSHE_OK != (nSHCode = curl_share_setopt(S3fsCurl::hCurlShare, CURLSHOPT_USERDATA, &S3fsCurl::callback_locks))){
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
    S3fsCurl::hCurlShare = nullptr;
    return true;
}

void S3fsCurl::LockCurlShare(CURL* handle, curl_lock_data nLockData, curl_lock_access laccess, void* useptr)
{
    if(!hCurlShare){
        return;
    }
    S3fsCurl::callback_locks_t* locks = static_cast<S3fsCurl::callback_locks_t*>(useptr);
    int result;
    if(CURL_LOCK_DATA_DNS == nLockData){
        if(0 != (result = pthread_mutex_lock(&locks->dns))){
            S3FS_PRN_CRIT("pthread_mutex_lock returned: %d", result);
            abort();
        }
    }else if(CURL_LOCK_DATA_SSL_SESSION == nLockData){
        if(0 != (result = pthread_mutex_lock(&locks->ssl_session))){
            S3FS_PRN_CRIT("pthread_mutex_lock returned: %d", result);
            abort();
        }
    }
}

void S3fsCurl::UnlockCurlShare(CURL* handle, curl_lock_data nLockData, void* useptr)
{
    if(!hCurlShare){
        return;
    }
    S3fsCurl::callback_locks_t* locks = static_cast<S3fsCurl::callback_locks_t*>(useptr);
    int result;
    if(CURL_LOCK_DATA_DNS == nLockData){
        if(0 != (result = pthread_mutex_unlock(&locks->dns))){
            S3FS_PRN_CRIT("pthread_mutex_unlock returned: %d", result);
            abort();
        }
    }else if(CURL_LOCK_DATA_SSL_SESSION == nLockData){
        if(0 != (result = pthread_mutex_unlock(&locks->ssl_session))){
            S3FS_PRN_CRIT("pthread_mutex_unlock returned: %d", result);
            abort();
        }
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
    CURL*      curl = static_cast<CURL*>(clientp);
    time_t     now = time(nullptr);
    progress_t p(dlnow, ulnow);

    AutoLock   lock(&S3fsCurl::curl_handles_lock);

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

bool S3fsCurl::InitCredentialObject(S3fsCred* pcredobj)
{
    // Set the only Credential object
    if(!pcredobj || S3fsCurl::ps3fscred){
        S3FS_PRN_ERR("Unable to set the only Credential object.");
        return false;
    }
    S3fsCurl::ps3fscred = pcredobj;

    return true;
}

bool S3fsCurl::InitMimeType(const std::string& strFile)
{
    std::string MimeFile;
    if(!strFile.empty()){
        MimeFile = strFile;
    }else{
        // search default mime.types
        std::string errPaths = DEFAULT_MIME_FILE;
        struct stat st;
        if(0 == stat(DEFAULT_MIME_FILE, &st)){
            MimeFile = DEFAULT_MIME_FILE;
        }else if(compare_sysname("Darwin")){
            // for macOS, search another default file.
            if(0 == stat(SPECIAL_DARWIN_MIME_FILE, &st)){
                MimeFile = SPECIAL_DARWIN_MIME_FILE;
            }else{
                errPaths += " and ";
                errPaths += SPECIAL_DARWIN_MIME_FILE;
            }
        }
        if(MimeFile.empty()){
            S3FS_PRN_WARN("Could not find mime.types files, you have to create file(%s) or specify mime option for existing mime.types file.", errPaths.c_str());
            return false;
        }
    }
    S3FS_PRN_DBG("Try to load mime types from %s file.", MimeFile.c_str());

    std::ifstream MT(MimeFile.c_str());
    if(MT.good()){
        S3FS_PRN_DBG("The old mime types are cleared to load new mime types.");
        S3fsCurl::mimeTypes.clear();
        std::string line;

        while(getline(MT, line)){
            if(line.empty()){
                continue;
            }
            if(line[0]=='#'){
                continue;
            }

            std::istringstream tmp(line);
            std::string mimeType;
            tmp >> mimeType;
            std::string ext;
            while(tmp >> ext){
                S3fsCurl::mimeTypes[ext] = mimeType;
            }
        }
        S3FS_PRN_INIT_INFO("Loaded mime information from %s", MimeFile.c_str());
    }else{
        S3FS_PRN_WARN("Could not load mime types from %s, please check the existence and permissions of this file.", MimeFile.c_str());
        return false;
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
std::string S3fsCurl::LookupMimeType(const std::string& name)
{
    if(!name.empty() && name[name.size() - 1] == '/'){
        return "application/x-directory";
    }

    std::string            result("application/octet-stream");
    std::string::size_type last_pos  = name.find_last_of('.');
    std::string::size_type first_pos = name.find_first_of('.');
    std::string            prefix, ext, ext2;

    // No dots in name, just return
    if(last_pos == std::string::npos){
        return result;
    }
    // extract the last extension
    ext = name.substr(1+last_pos, std::string::npos);

    if (last_pos != std::string::npos) {
        // one dot was found, now look for another
        if (first_pos != std::string::npos && first_pos < last_pos) {
            prefix = name.substr(0, last_pos);
            // Now get the second to last file extension
            std::string::size_type next_pos = prefix.find_last_of('.');
            if (next_pos != std::string::npos) {
                ext2 = prefix.substr(1+next_pos, std::string::npos);
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
        if(CURL_CA_BUNDLE != nullptr)  {
            // check for existence and readability of the file
            std::ifstream BF(CURL_CA_BUNDLE);
            if(!BF.good()){
                S3FS_PRN_ERR("%s: file specified by CURL_CA_BUNDLE environment variable is not readable", program_name.c_str());
                return false;
            }
            BF.close();
            S3fsCurl::curl_ca_bundle = CURL_CA_BUNDLE;
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
    std::ifstream BF("/etc/pki/tls/certs/ca-bundle.crt");
    if(BF.good()){
        BF.close();
        S3fsCurl::curl_ca_bundle = "/etc/pki/tls/certs/ca-bundle.crt";
    }else{
        BF.open("/etc/ssl/certs/ca-certificates.crt");
        if(BF.good()){
            BF.close();
            S3fsCurl::curl_ca_bundle = "/etc/ssl/certs/ca-certificates.crt";
        }else{
            BF.open("/usr/share/ssl/certs/ca-bundle.crt");
            if(BF.good()){
                BF.close();
                S3fsCurl::curl_ca_bundle = "/usr/share/ssl/certs/ca-bundle.crt";
            }else{
                BF.open("/usr/local/share/certs/ca-root.crt");
                if(BF.good()){
                    BF.close();
                    S3fsCurl::curl_ca_bundle = "/usr/share/ssl/certs/ca-bundle.crt";
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
    std::string* body  = static_cast<std::string*>(data);
    body->append(static_cast<const char*>(ptr), blockSize * numBlocks);
    return (blockSize * numBlocks);
}

size_t S3fsCurl::ReadCallback(void* ptr, size_t size, size_t nmemb, void* userp)
{
    S3fsCurl* pCurl = static_cast<S3fsCurl*>(userp);

    if(1 > (size * nmemb)){
        return 0;
    }
    if(0 >= pCurl->postdata_remaining){
        return 0;
    }
    size_t copysize = std::min(static_cast<off_t>(size * nmemb), pCurl->postdata_remaining);
    memcpy(ptr, pCurl->postdata, copysize);

    pCurl->postdata_remaining = (pCurl->postdata_remaining > static_cast<off_t>(copysize) ? (pCurl->postdata_remaining - copysize) : 0);
    pCurl->postdata          += static_cast<size_t>(copysize);

    return copysize;
}

size_t S3fsCurl::HeaderCallback(void* data, size_t blockSize, size_t numBlocks, void* userPtr)
{
    headers_t* headers = static_cast<headers_t*>(userPtr);
    std::string header(static_cast<char*>(data), blockSize * numBlocks);
    std::string key;
    std::istringstream ss(header);

    if(getline(ss, key, ':')){
        // Force to lower, only "x-amz"
        std::string lkey = key;
        transform(lkey.begin(), lkey.end(), lkey.begin(), static_cast<int (*)(int)>(std::tolower));
        if(is_prefix(lkey.c_str(), "x-amz")){
            key = lkey;
        }
        std::string value;
        getline(ss, value);
        (*headers)[key] = trim(value);
    }
    return blockSize * numBlocks;
}

size_t S3fsCurl::UploadReadCallback(void* ptr, size_t size, size_t nmemb, void* userp)
{
    S3fsCurl* pCurl = static_cast<S3fsCurl*>(userp);

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
        readbytes = pread(pCurl->partdata.fd, &(static_cast<char*>(ptr))[totalread], (copysize - totalread), pCurl->partdata.startpos + totalread);
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
    S3fsCurl* pCurl = static_cast<S3fsCurl*>(userp);

    if(1 > (size * nmemb)){
        return 0;
    }
    if(-1 == pCurl->partdata.fd || 0 >= pCurl->partdata.size){
        return 0;
    }

    // Buffer initial bytes in case it is an XML error response.
    if(pCurl->bodydata.size() < GET_OBJECT_RESPONSE_LIMIT){
        pCurl->bodydata.append(static_cast<const char*>(ptr), std::min(size * nmemb, GET_OBJECT_RESPONSE_LIMIT - pCurl->bodydata.size()));
    }

    // write size
    ssize_t copysize = (size * nmemb) < (size_t)pCurl->partdata.size ? (size * nmemb) : (size_t)pCurl->partdata.size;
    ssize_t writebytes;
    ssize_t totalwrite;

    // write
    for(totalwrite = 0, writebytes = 0; totalwrite < copysize; totalwrite += writebytes){
        writebytes = pwrite(pCurl->partdata.fd, &(static_cast<char*>(ptr))[totalwrite], (copysize - totalwrite), pCurl->partdata.startpos + totalwrite);
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

bool S3fsCurl::SetCheckCertificate(bool isCertCheck)
{
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

void S3fsCurl::ResetOffset(S3fsCurl* pCurl)
{
    pCurl->partdata.startpos = pCurl->b_partdata_startpos;
    pCurl->partdata.size     = pCurl->b_partdata_size;
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

std::string S3fsCurl::SetStorageClass(const std::string& storage_class)
{
    std::string old = S3fsCurl::storage_class;
    S3fsCurl::storage_class = storage_class;
    // AWS requires uppercase storage class values
    transform(S3fsCurl::storage_class.begin(), S3fsCurl::storage_class.end(), S3fsCurl::storage_class.begin(), ::toupper);
    return old;
}

bool S3fsCurl::PushbackSseKeys(const std::string& input)
{
    std::string onekey = trim(input);
    if(onekey.empty()){
        return false;
    }
    if('#' == onekey[0]){
        return false;
    }
    // make base64 if the key is short enough, otherwise assume it is already so
    std::string base64_key;
    std::string raw_key;
    if(onekey.length() > 256 / 8){
        std::string p_key(s3fs_decode64(onekey.c_str(), onekey.size()));
        raw_key = p_key;
        base64_key = onekey;
    } else {
        base64_key = s3fs_base64(reinterpret_cast<const unsigned char*>(onekey.c_str()), onekey.length());
        raw_key = onekey;
    }

    // make MD5
    std::string strMd5;
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

    std::ifstream ssefs(filepath);
    if(!ssefs.good()){
        S3FS_PRN_ERR("Could not open SSE-C keys file(%s).", filepath);
        return false;
    }

    std::string line;
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
    switch(S3fsCurl::ssetype){
        case sse_type_t::SSE_DISABLE:
            S3fsCurl::ssekmsid.erase();
            return true;
        case sse_type_t::SSE_S3:
            S3fsCurl::ssekmsid.erase();
            return true;
        case sse_type_t::SSE_C:
            if(S3fsCurl::sseckeys.empty()){
                S3FS_PRN_ERR("sse type is SSE-C, but there is no custom key.");
                return false;
            }
            S3fsCurl::ssekmsid.erase();
            return true;
        case sse_type_t::SSE_KMS:
            if(S3fsCurl::ssekmsid.empty()){
                S3FS_PRN_ERR("sse type is SSE-KMS, but there is no specified kms id.");
                return false;
            }
            if(S3fsCurl::GetSignatureType() == signature_type_t::V2_ONLY){
                S3FS_PRN_ERR("sse type is SSE-KMS, but signature type is not v4. SSE-KMS require signature v4.");
                return false;
            }
            return true;
    }
    S3FS_PRN_ERR("sse type is unknown(%d).", static_cast<int>(S3fsCurl::ssetype));

    return false;
}
                                                                                                                                                   
bool S3fsCurl::LoadEnvSseCKeys()
{
    char* envkeys = getenv("AWSSSECKEYS");
    if(nullptr == envkeys){
        // nothing to do
        return true;
    }
    S3fsCurl::sseckeys.clear();

    std::istringstream fullkeys(envkeys);
    std::string        onekey;
    while(getline(fullkeys, onekey, ':')){
        S3fsCurl::PushbackSseKeys(onekey);
    }

    // cppcheck-suppress unmatchedSuppression
    // cppcheck-suppress knownConditionTrueFalse
    if(S3fsCurl::sseckeys.empty()){
        S3FS_PRN_ERR("There is no SSE Key in environment(AWSSSECKEYS=%s).", envkeys);
        return false;
    }
    return true;
}

bool S3fsCurl::LoadEnvSseKmsid()
{
    const char* envkmsid = getenv("AWSSSEKMSID");
    if(nullptr == envkmsid){
        // nothing to do
        return true;
    }
    return S3fsCurl::SetSseKmsid(envkmsid);
}

//
// If md5 is empty, returns first(current) sse key.
//
bool S3fsCurl::GetSseKey(std::string& md5, std::string& ssekey)
{
    for(sseckeylist_t::const_iterator iter = S3fsCurl::sseckeys.begin(); iter != S3fsCurl::sseckeys.end(); ++iter){
        if(md5.empty() || md5 == (*iter).begin()->first){
            md5    = iter->begin()->first;
            ssekey = iter->begin()->second;
            return true;
        }
    }
    return false;
}

bool S3fsCurl::GetSseKeyMd5(size_t pos, std::string& md5)
{
    if(S3fsCurl::sseckeys.size() <= static_cast<size_t>(pos)){
        return false;
    }
    size_t cnt = 0;
    for(sseckeylist_t::const_iterator iter = S3fsCurl::sseckeys.begin(); iter != S3fsCurl::sseckeys.end(); ++iter, ++cnt){
        if(pos == cnt){
            md5 = iter->begin()->first;
            return true;
        }
    }
    return false;
}

size_t S3fsCurl::GetSseKeyCount()
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

bool S3fsCurl::SetDumpBody(bool flag)
{
    bool old = S3fsCurl::is_dump_body;
    S3fsCurl::is_dump_body = flag;
    return old;
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

bool S3fsCurl::SetMultipartSize(off_t size)
{
    size = size * 1024 * 1024;
    if(size < MIN_MULTIPART_SIZE){
        return false;
    }
    S3fsCurl::multipart_size = size;
    return true;
}

bool S3fsCurl::SetMultipartCopySize(off_t size)
{
    size = size * 1024 * 1024;
    if(size < MIN_MULTIPART_SIZE){
        return false;
    }
    S3fsCurl::multipart_copy_size = size;
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

// [NOTE]
// This proxy setting is as same as the "--proxy" option of the curl command,
// and equivalent to the "CURLOPT_PROXY" option of the curl_easy_setopt()
// function.
// However, currently s3fs does not provide another option to set the schema
// and port, so you need to specify these it in this function. (Other than
// this function, there is no means of specifying the schema and port.)
// Therefore, it should be specified "url" as "[<schema>://]<fqdn>[:<port>]".
// s3fs passes this string to curl_easy_setopt() function with "CURLOPT_PROXY".
// If no "schema" is specified, "http" will be used as default, and if no port
// is specified, "443" will be used for "HTTPS" and "1080" otherwise.
// (See the description of "CURLOPT_PROXY" in libcurl document.)
//
bool S3fsCurl::SetProxy(const char* url)
{
    if(!url || '\0' == url[0]){
        return false;
    }
    std::string tmpurl = url;

    // check schema
    bool   is_http = true;
    size_t pos = 0;
    if(std::string::npos != (pos = tmpurl.find("://", pos))){
        if(0 == pos){
            // no schema string before "://"
            return false;
        }
        pos += strlen("://");

        // Check if it is other than "http://"
        if(0 != tmpurl.find("http://", 0)){
            is_http = false;
        }
    }else{
        // not have schema string
        pos = 0;
    }
    // check fqdn and port number string
    if(std::string::npos != (pos = tmpurl.find(':', pos))){
        // specify port
        if(0 == pos){
            // no fqdn(hostname) string before ":"
            return false;
        }
        pos += strlen(":");
        if(std::string::npos != tmpurl.find(':', pos)){
            // found wrong separator
            return false;
        }
    }

    S3fsCurl::proxy_url  = tmpurl;
    S3fsCurl::proxy_http = is_http;
    return true;
}

// [NOTE]
// This function loads proxy credentials(username and  passphrase)
// from a file.
// The loaded values is set to "CURLOPT_PROXYUSERPWD" in the
// curl_easy_setopt() function. (But only used if the proxy is HTTP
// schema.)
//
// The file is expected to contain only one valid line:
//     ------------------------
//     # comment line
//     <username>:<passphrase>
//     ------------------------
// Lines starting with a '#' character are treated as comments.
// Lines with only space characters and blank lines are ignored.
// If the user name contains spaces, it must be url encoded(ex. %20).
//
bool S3fsCurl::SetProxyUserPwd(const char* file)
{
    if(!file || '\0' == file[0]){
        return false;
    }
    if(!S3fsCurl::proxy_userpwd.empty()){
        S3FS_PRN_WARN("Already set username and passphrase for proxy.");
        return false;
    }

    std::ifstream credFileStream(file);
    if(!credFileStream.good()){
        S3FS_PRN_WARN("Could not load username and passphrase for proxy from %s.", file);
        return false;
    }

    std::string userpwd;
    std::string line;
    while(getline(credFileStream, line)){
        line = trim(line);
        if(line.empty()){
            continue;
        }
        if(line[0]=='#'){
            continue;
        }
        if(!userpwd.empty()){
            S3FS_PRN_WARN("Multiple valid username and passphrase found in %s file. Should specify only one pair.", file);
            return false;
        }
        // check separator for username and passphrase
        size_t pos = 0;
        if(std::string::npos == (pos = line.find(':', pos))){
            S3FS_PRN_WARN("Found string for username and passphrase in %s file does not have separator ':'.", file);
            return false;
        }
        if(0 == pos || (pos + 1) == line.length()){
            S3FS_PRN_WARN("Found string for username or passphrase in %s file is empty.", file);
            return false;
        }
        if(std::string::npos != line.find(':', ++pos)){
            S3FS_PRN_WARN("Found string for username and passphrase in %s file has multiple separator ':'.", file);
            return false;
        }
        userpwd = line;
    }
    if(userpwd.empty()){
        S3FS_PRN_WARN("No valid username and passphrase found in %s.", file);
        return false;
    }

    S3fsCurl::proxy_userpwd = userpwd;
    return true;
}

// cppcheck-suppress unmatchedSuppression
// cppcheck-suppress constParameter
// cppcheck-suppress constParameterCallback
bool S3fsCurl::UploadMultipartPostCallback(S3fsCurl* s3fscurl, void* param)
{
    if(!s3fscurl || param){     // this callback does not need a parameter
        return false;
    }

    return s3fscurl->UploadMultipartPostComplete();
}

// cppcheck-suppress unmatchedSuppression
// cppcheck-suppress constParameter
// cppcheck-suppress constParameterCallback
bool S3fsCurl::MixMultipartPostCallback(S3fsCurl* s3fscurl, void* param)
{
    if(!s3fscurl || param){     // this callback does not need a parameter
        return false;
    }

    return s3fscurl->MixMultipartPostComplete();
}

std::unique_ptr<S3fsCurl> S3fsCurl::UploadMultipartPostRetryCallback(S3fsCurl* s3fscurl)
{
    if(!s3fscurl){
        return nullptr;
    }
    // parse and get part_num, upload_id.
    std::string upload_id;
    std::string part_num_str;
    int part_num;
    off_t  tmp_part_num = 0;
    if(!get_keyword_value(s3fscurl->url, "uploadId", upload_id)){
        return nullptr;
    }
    upload_id = urlDecode(upload_id);       // decode
    if(!get_keyword_value(s3fscurl->url, "partNumber", part_num_str)){
        return nullptr;
    }
    if(!s3fs_strtoofft(&tmp_part_num, part_num_str.c_str(), /*base=*/ 10)){
        return nullptr;
    }
    part_num = static_cast<int>(tmp_part_num);

    if(s3fscurl->retry_count >= S3fsCurl::retries){
        S3FS_PRN_ERR("Over retry count(%d) limit(%s:%d).", s3fscurl->retry_count, s3fscurl->path.c_str(), part_num);
        return nullptr;
    }

    // duplicate request
    std::unique_ptr<S3fsCurl> newcurl(new S3fsCurl(s3fscurl->IsUseAhbe()));
    newcurl->partdata.petag      = s3fscurl->partdata.petag;
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
        return nullptr;
    }
    return newcurl;
}

std::unique_ptr<S3fsCurl> S3fsCurl::CopyMultipartPostRetryCallback(S3fsCurl* s3fscurl)
{
    if(!s3fscurl){
        return nullptr;
    }
    // parse and get part_num, upload_id.
    std::string upload_id;
    std::string part_num_str;
    int part_num;
    off_t  tmp_part_num = 0;
    if(!get_keyword_value(s3fscurl->url, "uploadId", upload_id)){
        return nullptr;
    }
    upload_id = urlDecode(upload_id);       // decode
    if(!get_keyword_value(s3fscurl->url, "partNumber", part_num_str)){
        return nullptr;
    }
    if(!s3fs_strtoofft(&tmp_part_num, part_num_str.c_str(), /*base=*/ 10)){
        return nullptr;
    }
    part_num = static_cast<int>(tmp_part_num);

    if(s3fscurl->retry_count >= S3fsCurl::retries){
        S3FS_PRN_ERR("Over retry count(%d) limit(%s:%d).", s3fscurl->retry_count, s3fscurl->path.c_str(), part_num);
        return nullptr;
    }

    // duplicate request
    std::unique_ptr<S3fsCurl> newcurl(new S3fsCurl(s3fscurl->IsUseAhbe()));
    newcurl->partdata.petag      = s3fscurl->partdata.petag;
    newcurl->b_from              = s3fscurl->b_from;
    newcurl->b_meta              = s3fscurl->b_meta;
    newcurl->retry_count         = s3fscurl->retry_count + 1;
    newcurl->op                  = s3fscurl->op;
    newcurl->type                = s3fscurl->type;

    // setup new curl object
    if(0 != newcurl->CopyMultipartPostSetup(s3fscurl->b_from.c_str(), s3fscurl->path.c_str(), part_num, upload_id, s3fscurl->b_meta)){
        S3FS_PRN_ERR("Could not duplicate curl object(%s:%d).", s3fscurl->path.c_str(), part_num);
        return nullptr;
    }
    return newcurl;
}

std::unique_ptr<S3fsCurl> S3fsCurl::MixMultipartPostRetryCallback(S3fsCurl* s3fscurl)
{
    if(!s3fscurl){
        return nullptr;
    }

    if(-1 == s3fscurl->partdata.fd){
        return S3fsCurl::CopyMultipartPostRetryCallback(s3fscurl);
    }else{
        return S3fsCurl::UploadMultipartPostRetryCallback(s3fscurl);
    }
}

int S3fsCurl::MapPutErrorResponse(int result)
{
    if(result != 0){
        return result;
    }
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
    const char* pstrbody = bodydata.c_str();
    std::string code;
    if(simple_parse_xml(pstrbody, bodydata.size(), "Code", code)){
        S3FS_PRN_ERR("Put request get 200 status response, but it included error body(or nullptr). The request failed during copying the object in S3.  Code: %s", code.c_str());
        // TODO: parse more specific error from <Code>
        result = -EIO;
    }
    return result;
}

// [NOTE]
// It is a factory method as utility because it requires an S3fsCurl object
// initialized for multipart upload from outside this class.
//
std::unique_ptr<S3fsCurl> S3fsCurl::CreateParallelS3fsCurl(const char* tpath, int fd, off_t start, off_t size, int part_num, bool is_copy, etagpair* petag, const std::string& upload_id, int& result)
{
    // duplicate fd
    if(!tpath || -1 == fd || start < 0 || size <= 0 || !petag){
        S3FS_PRN_ERR("Parameters are wrong: tpath(%s), fd(%d), start(%lld), size(%lld), petag(%s)", SAFESTRPTR(tpath), fd, static_cast<long long int>(start), static_cast<long long int>(size), (petag ? "not null" : "null"));
        result = -EIO;
        return nullptr;
    }
    result = 0;

    std::unique_ptr<S3fsCurl> s3fscurl(new S3fsCurl(true));

    if(!is_copy){
        s3fscurl->partdata.fd         = fd;
        s3fscurl->partdata.startpos   = start;
        s3fscurl->partdata.size       = size;
        s3fscurl->partdata.is_copy    = is_copy;
        s3fscurl->partdata.petag      = petag;                          // [NOTE] be careful, the value is set directly
        s3fscurl->b_partdata_startpos = s3fscurl->partdata.startpos;
        s3fscurl->b_partdata_size     = s3fscurl->partdata.size;

        S3FS_PRN_INFO3("Upload Part [tpath=%s][start=%lld][size=%lld][part=%d]", SAFESTRPTR(tpath), static_cast<long long>(start), static_cast<long long>(size), part_num);

        if(0 != (result = s3fscurl->UploadMultipartPostSetup(tpath, part_num, upload_id))){
            S3FS_PRN_ERR("failed uploading part setup(%d)", result);
            return nullptr;
        }
    }else{
        headers_t   meta;
        std::string srcresource;
        std::string srcurl;
        MakeUrlResource(get_realpath(tpath).c_str(), srcresource, srcurl);
        meta["x-amz-copy-source"] = srcresource;

        std::ostringstream strrange;
        strrange << "bytes=" << start << "-" << (start + size - 1);
        meta["x-amz-copy-source-range"]   = strrange.str();

        s3fscurl->b_from         = SAFESTRPTR(tpath);
        s3fscurl->b_meta         = meta;
        s3fscurl->partdata.petag = petag;                               // [NOTE] be careful, the value is set directly

        S3FS_PRN_INFO3("Copy Part [tpath=%s][start=%lld][size=%lld][part=%d]", SAFESTRPTR(tpath), static_cast<long long>(start), static_cast<long long>(size), part_num);

        if(0 != (result = s3fscurl->CopyMultipartPostSetup(tpath, tpath, part_num, upload_id, meta))){
            S3FS_PRN_ERR("failed uploading part setup(%d)", result);
            return nullptr;
        }
    }

    // Call lazy function
    if(!s3fscurl->fpLazySetup || !s3fscurl->fpLazySetup(s3fscurl.get())){
        S3FS_PRN_ERR("failed lazy function setup for uploading part");
        result = -EIO;
        return nullptr;
    }
    return s3fscurl;
}

int S3fsCurl::ParallelMultipartUploadRequest(const char* tpath, headers_t& meta, int fd)
{
    int            result;
    std::string    upload_id;
    struct stat    st;
    etaglist_t     list;
    off_t          remaining_bytes;
    S3fsCurl       s3fscurl(true);

    S3FS_PRN_INFO3("[tpath=%s][fd=%d]", SAFESTRPTR(tpath), fd);

    if(-1 == fstat(fd, &st)){
        S3FS_PRN_ERR("Invalid file descriptor(errno=%d)", errno);
        return -errno;
    }

    if(0 != (result = s3fscurl.PreMultipartPostRequest(tpath, meta, upload_id, false))){
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
        std::unique_ptr<S3fsCurl> s3fscurl_para(new S3fsCurl(true));
        s3fscurl_para->partdata.fd         = fd;
        s3fscurl_para->partdata.startpos   = st.st_size - remaining_bytes;
        s3fscurl_para->partdata.size       = chunk;
        s3fscurl_para->b_partdata_startpos = s3fscurl_para->partdata.startpos;
        s3fscurl_para->b_partdata_size     = s3fscurl_para->partdata.size;
        s3fscurl_para->partdata.add_etag_list(list);

        // initiate upload part for parallel
        if(0 != (result = s3fscurl_para->UploadMultipartPostSetup(tpath, s3fscurl_para->partdata.get_part_number(), upload_id))){
            S3FS_PRN_ERR("failed uploading part setup(%d)", result);
            return result;
        }

        // set into parallel object
        if(!curlmulti.SetS3fsCurlObject(std::move(s3fscurl_para))){
            S3FS_PRN_ERR("Could not make curl object into multi curl(%s).", tpath);
            return -EIO;
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

    if(0 != (result = s3fscurl.CompleteMultipartPostRequest(tpath, upload_id, list))){
        return result;
    }
    return 0;
}

int S3fsCurl::ParallelMixMultipartUploadRequest(const char* tpath, headers_t& meta, int fd, const fdpage_list_t& mixuppages)
{
    int            result;
    std::string    upload_id;
    struct stat    st;
    etaglist_t     list;
    S3fsCurl       s3fscurl(true);

    S3FS_PRN_INFO3("[tpath=%s][fd=%d]", SAFESTRPTR(tpath), fd);

    if(-1 == fstat(fd, &st)){
        S3FS_PRN_ERR("Invalid file descriptor(errno=%d)", errno);
        return -errno;
    }

    if(0 != (result = s3fscurl.PreMultipartPostRequest(tpath, meta, upload_id, true))){
        return result;
    }
    s3fscurl.DestroyCurlHandle();

    // for copy multipart
    std::string srcresource;
    std::string srcurl;
    MakeUrlResource(get_realpath(tpath).c_str(), srcresource, srcurl);
    meta["Content-Type"]      = S3fsCurl::LookupMimeType(tpath);
    meta["x-amz-copy-source"] = srcresource;

    // Initialize S3fsMultiCurl
    S3fsMultiCurl curlmulti(GetMaxParallelCount());
    curlmulti.SetSuccessCallback(S3fsCurl::MixMultipartPostCallback);
    curlmulti.SetRetryCallback(S3fsCurl::MixMultipartPostRetryCallback);

    for(fdpage_list_t::const_iterator iter = mixuppages.begin(); iter != mixuppages.end(); ++iter){
        if(iter->modified){
            // Multipart upload
            std::unique_ptr<S3fsCurl> s3fscurl_para(new S3fsCurl(true));
            s3fscurl_para->partdata.fd         = fd;
            s3fscurl_para->partdata.startpos   = iter->offset;
            s3fscurl_para->partdata.size       = iter->bytes;
            s3fscurl_para->b_partdata_startpos = s3fscurl_para->partdata.startpos;
            s3fscurl_para->b_partdata_size     = s3fscurl_para->partdata.size;
            s3fscurl_para->partdata.add_etag_list(list);

            S3FS_PRN_INFO3("Upload Part [tpath=%s][start=%lld][size=%lld][part=%d]", SAFESTRPTR(tpath), static_cast<long long>(iter->offset), static_cast<long long>(iter->bytes), s3fscurl_para->partdata.get_part_number());

            // initiate upload part for parallel
            if(0 != (result = s3fscurl_para->UploadMultipartPostSetup(tpath, s3fscurl_para->partdata.get_part_number(), upload_id))){
                S3FS_PRN_ERR("failed uploading part setup(%d)", result);
                return result;
            }

            // set into parallel object
            if(!curlmulti.SetS3fsCurlObject(std::move(s3fscurl_para))){
                S3FS_PRN_ERR("Could not make curl object into multi curl(%s).", tpath);
                return -EIO;
            }
        }else{
            // Multipart copy
            for(off_t i = 0, bytes = 0; i < iter->bytes; i += bytes){
                std::unique_ptr<S3fsCurl> s3fscurl_para(new S3fsCurl(true));

                bytes = std::min(static_cast<off_t>(GetMultipartCopySize()), iter->bytes - i);
                /* every part should be larger than MIN_MULTIPART_SIZE and smaller than FIVE_GB */
                off_t remain_bytes = iter->bytes - i - bytes;

                if ((MIN_MULTIPART_SIZE > remain_bytes) && (0 < remain_bytes)){
                    if(FIVE_GB < (bytes + remain_bytes)){
                        bytes = (bytes + remain_bytes)/2;
                    } else{
                        bytes += remain_bytes;
                    }
                }

                std::ostringstream strrange;
                strrange << "bytes=" << (iter->offset + i) << "-" << (iter->offset + i + bytes - 1);
                meta["x-amz-copy-source-range"] = strrange.str();

                s3fscurl_para->b_from   = SAFESTRPTR(tpath);
                s3fscurl_para->b_meta   = meta;
                s3fscurl_para->partdata.add_etag_list(list);

                S3FS_PRN_INFO3("Copy Part [tpath=%s][start=%lld][size=%lld][part=%d]", SAFESTRPTR(tpath), static_cast<long long>(iter->offset + i), static_cast<long long>(bytes), s3fscurl_para->partdata.get_part_number());

                // initiate upload part for parallel
                if(0 != (result = s3fscurl_para->CopyMultipartPostSetup(tpath, tpath, s3fscurl_para->partdata.get_part_number(), upload_id, meta))){
                    S3FS_PRN_ERR("failed uploading part setup(%d)", result);
                    return result;
                }

                // set into parallel object
                if(!curlmulti.SetS3fsCurlObject(std::move(s3fscurl_para))){
                    S3FS_PRN_ERR("Could not make curl object into multi curl(%s).", tpath);
                    return -EIO;
                }
            }
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

    if(0 != (result = s3fscurl.CompleteMultipartPostRequest(tpath, upload_id, list))){
        return result;
    }
    return 0;
}

std::unique_ptr<S3fsCurl> S3fsCurl::ParallelGetObjectRetryCallback(S3fsCurl* s3fscurl)
{
    int result;

    if(!s3fscurl){
        return nullptr;
    }
    if(s3fscurl->retry_count >= S3fsCurl::retries){
        S3FS_PRN_ERR("Over retry count(%d) limit(%s).", s3fscurl->retry_count, s3fscurl->path.c_str());
        return nullptr;
    }

    // duplicate request(setup new curl object)
    std::unique_ptr<S3fsCurl> newcurl(new S3fsCurl(s3fscurl->IsUseAhbe()));
    
    if(0 != (result = newcurl->PreGetObjectRequest(s3fscurl->path.c_str(), s3fscurl->partdata.fd, s3fscurl->partdata.startpos, s3fscurl->partdata.size, s3fscurl->b_ssetype, s3fscurl->b_ssevalue))){
        S3FS_PRN_ERR("failed downloading part setup(%d)", result);
        return nullptr;
    }
    newcurl->retry_count = s3fscurl->retry_count + 1;

    return newcurl;
}

int S3fsCurl::ParallelGetObjectRequest(const char* tpath, int fd, off_t start, off_t size)
{
    S3FS_PRN_INFO3("[tpath=%s][fd=%d]", SAFESTRPTR(tpath), fd);

    sse_type_t ssetype = sse_type_t::SSE_DISABLE;
    std::string ssevalue;
    if(!get_object_sse_type(tpath, ssetype, ssevalue)){
        S3FS_PRN_WARN("Failed to get SSE type for file(%s).", SAFESTRPTR(tpath));
    }
    int        result = 0;
    off_t      remaining_bytes;

    // cycle through open fd, pulling off 10MB chunks at a time
    for(remaining_bytes = size; 0 < remaining_bytes; ){
        S3fsMultiCurl curlmulti(GetMaxParallelCount());
        int           para_cnt;
        off_t         chunk;

        // Initialize S3fsMultiCurl
        //curlmulti.SetSuccessCallback(nullptr);   // not need to set success callback
        curlmulti.SetRetryCallback(S3fsCurl::ParallelGetObjectRetryCallback);

        // Loop for setup parallel upload(multipart) request.
        for(para_cnt = 0; para_cnt < S3fsCurl::max_parallel_cnt && 0 < remaining_bytes; para_cnt++, remaining_bytes -= chunk){
            // chunk size
            chunk = remaining_bytes > S3fsCurl::multipart_size ? S3fsCurl::multipart_size : remaining_bytes;

            // s3fscurl sub object
            std::unique_ptr<S3fsCurl> s3fscurl_para(new S3fsCurl(true));
            if(0 != (result = s3fscurl_para->PreGetObjectRequest(tpath, fd, (start + size - remaining_bytes), chunk, ssetype, ssevalue))){
                S3FS_PRN_ERR("failed downloading part setup(%d)", result);
                return result;
            }

            // set into parallel object
            if(!curlmulti.SetS3fsCurlObject(std::move(s3fscurl_para))){
                S3FS_PRN_ERR("Could not make curl object into multi curl(%s).", tpath);
                return -EIO;
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
    if(CURLE_OK != curl_easy_setopt(s3fscurl->hCurl, CURLOPT_URL, s3fscurl->url.c_str())){
        return false;
    }
    if(CURLE_OK != curl_easy_setopt(s3fscurl->hCurl, CURLOPT_UPLOAD, true)){              // HTTP PUT
        return false;
    }
    if(CURLE_OK != curl_easy_setopt(s3fscurl->hCurl, CURLOPT_WRITEDATA, reinterpret_cast<void*>(&s3fscurl->bodydata))){
        return false;
    }
    if(CURLE_OK != curl_easy_setopt(s3fscurl->hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback)){
        return false;
    }
    if(CURLE_OK != curl_easy_setopt(s3fscurl->hCurl, CURLOPT_HEADERDATA, reinterpret_cast<void*>(&s3fscurl->responseHeaders))){
        return false;
    }
    if(CURLE_OK != curl_easy_setopt(s3fscurl->hCurl, CURLOPT_HEADERFUNCTION, HeaderCallback)){
        return false;
    }
    if(CURLE_OK != curl_easy_setopt(s3fscurl->hCurl, CURLOPT_INFILESIZE_LARGE, static_cast<curl_off_t>(s3fscurl->partdata.size))){ // Content-Length
        return false;
    }
    if(CURLE_OK != curl_easy_setopt(s3fscurl->hCurl, CURLOPT_READFUNCTION, UploadReadCallback)){
        return false;
    }
    if(CURLE_OK != curl_easy_setopt(s3fscurl->hCurl, CURLOPT_READDATA, reinterpret_cast<void*>(s3fscurl))){
        return false;
    }
    if(!S3fsCurl::AddUserAgent(s3fscurl->hCurl)){                            // put User-Agent
        return false;
    }

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

    if(CURLE_OK != curl_easy_setopt(s3fscurl->hCurl, CURLOPT_URL, s3fscurl->url.c_str())){
        return false;
    }
    if(CURLE_OK != curl_easy_setopt(s3fscurl->hCurl, CURLOPT_UPLOAD, true)){                // HTTP PUT
        return false;
    }
    if(CURLE_OK != curl_easy_setopt(s3fscurl->hCurl, CURLOPT_WRITEDATA, reinterpret_cast<void*>(&s3fscurl->bodydata))){
        return false;
    }
    if(CURLE_OK != curl_easy_setopt(s3fscurl->hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback)){
        return false;
    }
    if(CURLE_OK != curl_easy_setopt(s3fscurl->hCurl, CURLOPT_HEADERDATA, reinterpret_cast<void*>(&s3fscurl->headdata))){
        return false;
    }
    if(CURLE_OK != curl_easy_setopt(s3fscurl->hCurl, CURLOPT_HEADERFUNCTION, WriteMemoryCallback)){
        return false;
    }
    if(CURLE_OK != curl_easy_setopt(s3fscurl->hCurl, CURLOPT_INFILESIZE, 0)){               // Content-Length
        return false;
    }
    if(!S3fsCurl::AddUserAgent(s3fscurl->hCurl)){                            // put User-Agent
        return false;
    }

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

    if(CURLE_OK != curl_easy_setopt(s3fscurl->hCurl, CURLOPT_URL, s3fscurl->url.c_str())){
        return false;
    }
    if(CURLE_OK != curl_easy_setopt(s3fscurl->hCurl, CURLOPT_WRITEFUNCTION, DownloadWriteCallback)){
        return false;
    }
    if(CURLE_OK != curl_easy_setopt(s3fscurl->hCurl, CURLOPT_WRITEDATA, reinterpret_cast<void*>(s3fscurl))){
        return false;
    }
    if(!S3fsCurl::AddUserAgent(s3fscurl->hCurl)){                            // put User-Agent
        return false;
    }

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

    if(CURLE_OK != curl_easy_setopt(s3fscurl->hCurl, CURLOPT_URL, s3fscurl->url.c_str())){
        return false;
    }
    if(CURLE_OK != curl_easy_setopt(s3fscurl->hCurl, CURLOPT_NOBODY, true)){   // HEAD
        return false;
    }
    if(CURLE_OK != curl_easy_setopt(s3fscurl->hCurl, CURLOPT_FILETIME, true)){ // Last-Modified
        return false;
    }

    // responseHeaders
    if(CURLE_OK != curl_easy_setopt(s3fscurl->hCurl, CURLOPT_HEADERDATA, reinterpret_cast<void*>(&s3fscurl->responseHeaders))){
        return false;
    }
    if(CURLE_OK != curl_easy_setopt(s3fscurl->hCurl, CURLOPT_HEADERFUNCTION, HeaderCallback)){
        return false;
    }
    if(!S3fsCurl::AddUserAgent(s3fscurl->hCurl)){                            // put User-Agent
        return false;
    }

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

int S3fsCurl::CurlDebugFunc(const CURL* hcurl, curl_infotype type, char* data, size_t size, void* userptr)
{
    return S3fsCurl::RawCurlDebugFunc(hcurl, type, data, size, userptr, CURLINFO_END);
}

int S3fsCurl::CurlDebugBodyInFunc(const CURL* hcurl, curl_infotype type, char* data, size_t size, void* userptr)
{
    return S3fsCurl::RawCurlDebugFunc(hcurl, type, data, size, userptr, CURLINFO_DATA_IN);
}

int S3fsCurl::CurlDebugBodyOutFunc(const CURL* hcurl, curl_infotype type, char* data, size_t size, void* userptr)
{
    return S3fsCurl::RawCurlDebugFunc(hcurl, type, data, size, userptr, CURLINFO_DATA_OUT);
}

int S3fsCurl::RawCurlDebugFunc(const CURL* hcurl, curl_infotype type, char* data, size_t size, void* userptr, curl_infotype datatype)
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
            if(foreground && 0 < size && '\n' == data[size - 1]){
                size--;
            }
            S3FS_PRN_CURL("* %*s%.*s", indent, "", (int)size, data);
            break;

        case CURLINFO_DATA_IN:
        case CURLINFO_DATA_OUT:
            if(type != datatype || !S3fsCurl::is_dump_body){
                // not put
                break;
            }
        case CURLINFO_HEADER_IN:
        case CURLINFO_HEADER_OUT:
            size_t remaining;
            char* p;

            // Print each line individually for tidy output
            remaining = size;
            p = data;
            do {
                char* eol = reinterpret_cast<char*>(memchr(p, '\n', remaining));
                int newline = 0;
                if (eol == nullptr) {
                    eol = reinterpret_cast<char*>(memchr(p, '\r', remaining));
                } else {
                    if (eol > p && *(eol - 1) == '\r') {
                        newline++;
                    }
                    newline++;
                    eol++;
                }
                size_t length = eol - p;
                S3FS_PRN_CURL("%s %.*s", getCurlDebugHead(type), (int)length - newline, p);
                remaining -= length;
                p = eol;
            } while (p != nullptr && remaining > 0);
            break;

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
    hCurl(nullptr), type(REQTYPE::UNSET), requestHeaders(nullptr),
    LastResponseCode(S3FSCURL_RESPONSECODE_NOTSET), postdata(nullptr), postdata_remaining(0), is_use_ahbe(ahbe),
    retry_count(0), b_infile(nullptr), b_postdata(nullptr), b_postdata_remaining(0), b_partdata_startpos(0), b_partdata_size(0),
    b_ssekey_pos(-1), b_ssetype(sse_type_t::SSE_DISABLE),
    sem(nullptr), completed_tids_lock(nullptr), completed_tids(nullptr), fpLazySetup(nullptr), curlCode(CURLE_OK)
{
    if(!S3fsCurl::ps3fscred){
        S3FS_PRN_CRIT("The object of S3fs Credential class is not initialized.");
        abort();
    }
}

S3fsCurl::~S3fsCurl()
{
    DestroyCurlHandle();
}

bool S3fsCurl::ResetHandle(AutoLock::Type locktype)
{
    bool run_once;
    {
        AutoLock lock(&S3fsCurl::curl_warnings_lock);
        run_once = curl_warnings_once;
        curl_warnings_once = true;
    }

    sCurlPool->ResetHandler(hCurl);

    if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_NOSIGNAL, 1)){
        return false;
    }
    if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_FOLLOWLOCATION, true)){
        return false;
    }
    if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_CONNECTTIMEOUT, S3fsCurl::connect_timeout)){
        return false;
    }
    if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_NOPROGRESS, 0)){
        return false;
    }
    if(CURLE_OK != curl_easy_setopt(hCurl, S3FS_CURLOPT_XFERINFOFUNCTION, S3fsCurl::CurlProgress)){
        return false;
    }
    if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_PROGRESSDATA, hCurl)){
        return false;
    }
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

    if(type != REQTYPE::IAMCRED && type != REQTYPE::IAMROLE){
        // REQTYPE::IAMCRED and REQTYPE::IAMROLE are always HTTP
        if(0 == S3fsCurl::ssl_verify_hostname){
            if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_SSL_VERIFYHOST, 0)){
                return false;
            }
        }
        if(!S3fsCurl::curl_ca_bundle.empty()){
            if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_CAINFO, S3fsCurl::curl_ca_bundle.c_str())){
                return false;
            }
        }
    }
    if((S3fsCurl::is_dns_cache || S3fsCurl::is_ssl_session_cache) && S3fsCurl::hCurlShare){
        if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_SHARE, S3fsCurl::hCurlShare)){
            return false;
        }
    }
    if(!S3fsCurl::is_cert_check) {
        S3FS_PRN_DBG("'no_check_certificate' option in effect.");
        S3FS_PRN_DBG("The server certificate won't be checked against the available certificate authorities.");
        if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_SSL_VERIFYPEER, false)){
            return false;
        }
    }
    if(S3fsCurl::is_verbose){
        if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_VERBOSE, true)){
            return false;
        }
        if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_DEBUGFUNCTION, S3fsCurl::CurlDebugFunc)){
            return false;
        }
    }
    if(!cipher_suites.empty()) {
        if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_SSL_CIPHER_LIST, cipher_suites.c_str())){
            return false;
        }
    }
    if(!S3fsCurl::proxy_url.empty()){
        if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_PROXY, S3fsCurl::proxy_url.c_str())){
            return false;
        }
        if(S3fsCurl::proxy_http){
            if(!S3fsCurl::proxy_userpwd.empty()){
                if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_PROXYUSERPWD, S3fsCurl::proxy_userpwd.c_str())){
                    return false;
                }
            }
        }else if(!S3fsCurl::proxy_userpwd.empty()){
            S3FS_PRN_DBG("Username and passphrase are specified even though proxy is not 'http' scheme, so skip to set those.");
        }
    }

    AutoLock lock(&S3fsCurl::curl_handles_lock, locktype);
    S3fsCurl::curl_times[hCurl]    = time(nullptr);
    S3fsCurl::curl_progress[hCurl] = progress_t(-1, -1);

    return true;
}

bool S3fsCurl::CreateCurlHandle(bool only_pool, bool remake)
{
    AutoLock lock(&S3fsCurl::curl_handles_lock);

    if(hCurl && remake){
        if(!DestroyCurlHandle(false, true, AutoLock::ALREADY_LOCKED)){
            S3FS_PRN_ERR("could not destroy handle.");
            return false;
        }
        S3FS_PRN_INFO3("already has handle, so destroyed it or restored it to pool.");
    }

    if(!hCurl){
        if(nullptr == (hCurl = sCurlPool->GetHandler(only_pool))){
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
    ResetHandle(AutoLock::ALREADY_LOCKED);

    return true;
}

bool S3fsCurl::DestroyCurlHandle(bool restore_pool, bool clear_internal_data, AutoLock::Type locktype)
{
    // [NOTE]
    // If type is REQTYPE::IAMCRED or REQTYPE::IAMROLE, do not clear type.
    // Because that type only uses HTTP protocol, then the special
    // logic in ResetHandle function.
    //
    if(type != REQTYPE::IAMCRED && type != REQTYPE::IAMROLE){
        type = REQTYPE::UNSET;
    }

    AutoLock lock(&S3fsCurl::curl_handles_lock, locktype);

    if(clear_internal_data){
        ClearInternalData();
    }

    if(hCurl){
        S3fsCurl::curl_times.erase(hCurl);
        S3fsCurl::curl_progress.erase(hCurl);
        sCurlPool->ReturnHandler(hCurl, restore_pool);
        hCurl = nullptr;
    }else{
        return false;
    }
    return true;
}

bool S3fsCurl::ClearInternalData()
{
    // Always clear internal data
    //
    type        = REQTYPE::UNSET;
    path        = "";
    base_path   = "";
    saved_path  = "";
    url         = "";
    op          = "";
    query_string= "";
    if(requestHeaders){
        curl_slist_free_all(requestHeaders);
        requestHeaders = nullptr;
    }
    responseHeaders.clear();
    bodydata.clear();
    headdata.clear();
    LastResponseCode     = S3FSCURL_RESPONSECODE_NOTSET;
    postdata             = nullptr;
    postdata_remaining   = 0;
    retry_count          = 0;
    b_infile             = nullptr;
    b_postdata           = nullptr;
    b_postdata_remaining = 0;
    b_partdata_startpos  = 0;
    b_partdata_size      = 0;
    partdata.clear();

    fpLazySetup          = nullptr;

    S3FS_MALLOCTRIM(0);

    return true;
}

bool S3fsCurl::SetUseAhbe(bool ahbe)
{
    bool old = is_use_ahbe;
    is_use_ahbe = ahbe;
    return old;
}

bool S3fsCurl::GetResponseCode(long& responseCode, bool from_curl_handle) const
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
    S3FS_PRN_INFO3("Retry request. [type=%d][url=%s][path=%s]", static_cast<int>(type), url.c_str(), path.c_str());

    if(REQTYPE::UNSET == type){
        return false;
    }

    // rewind file
    struct stat st;
    if(b_infile){
        if(-1 == fseek(b_infile, 0, SEEK_SET)){
            S3FS_PRN_WARN("Could not reset position(fd=%d)", fileno(b_infile));
            return false;
        }
        if(-1 == fstat(fileno(b_infile), &st)){
            S3FS_PRN_WARN("Could not get file stat(fd=%d)", fileno(b_infile));
            return false;
        }
    }

    // reinitialize internal data
    requestHeaders = curl_slist_remove(requestHeaders, "Authorization");
    responseHeaders.clear();
    bodydata.clear();
    headdata.clear();
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
        case REQTYPE::DELETE:
            if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str())){
                return false;
            }
            if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_CUSTOMREQUEST, "DELETE")){
                return false;
            }
            break;

        case REQTYPE::HEAD:
            if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str())){
                return false;
            }
            if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_NOBODY, true)){
                return false;
            }
            if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_FILETIME, true)){
                return false;
            }
            // responseHeaders
            if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_HEADERDATA, reinterpret_cast<void*>(&responseHeaders))){
                return false;
            }
            if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_HEADERFUNCTION, HeaderCallback)){
                return false;
            }
            break;

        case REQTYPE::PUTHEAD:
            if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str())){
                return false;
            }
            if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_UPLOAD, true)){
                return false;
            }
            if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, reinterpret_cast<void*>(&bodydata))){
                return false;
            }
            if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback)){
                return false;
            }
            if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_INFILESIZE, 0)){
                return false;
            }
            break;

        case REQTYPE::PUT:
            if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str())){
                return false;
            }
            if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_UPLOAD, true)){
                return false;
            }
            if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, reinterpret_cast<void*>(&bodydata))){
                return false;
            }
            if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback)){
                return false;
            }
            if(b_infile){
                if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_INFILESIZE_LARGE, static_cast<curl_off_t>(st.st_size))){
                    return false;
                }
                if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_INFILE, b_infile)){
                    return false;
                }
            }else{
                if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_INFILESIZE, 0)){
                    return false;
                }
            }
            break;

        case REQTYPE::GET:
            if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str())){
                return false;
            }
            if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, S3fsCurl::DownloadWriteCallback)){
                return false;
            }
            if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, reinterpret_cast<void*>(this))){
                return false;
            }
            break;

        case REQTYPE::CHKBUCKET:
            if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str())){
                return false;
            }
            if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, reinterpret_cast<void*>(&bodydata))){
                return false;
            }
            if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback)){
                return false;
            }
            break;

        case REQTYPE::LISTBUCKET:
            if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str())){
                return false;
            }
            if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, reinterpret_cast<void*>(&bodydata))){
                return false;
            }
            if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback)){
                return false;
            }
            break;

        case REQTYPE::PREMULTIPOST:
            if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str())){
                return false;
            }
            if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_POST, true)){
                return false;
            }
            if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, reinterpret_cast<void*>(&bodydata))){
                return false;
            }
            if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback)){
                return false;
            }
            if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_POSTFIELDSIZE, 0)){
                return false;
            }
            break;

        case REQTYPE::COMPLETEMULTIPOST:
            if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str())){
                return false;
            }
            if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_POST, true)){
                return false;
            }
            if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, reinterpret_cast<void*>(&bodydata))){
                return false;
            }
            if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback)){
                return false;
            }
            if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_POSTFIELDSIZE, static_cast<curl_off_t>(postdata_remaining))){
                return false;
            }
            if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_READDATA, reinterpret_cast<void*>(this))){
                return false;
            }
            if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_READFUNCTION, S3fsCurl::ReadCallback)){
                return false;
            }
            break;

        case REQTYPE::UPLOADMULTIPOST:
            if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str())){
                return false;
            }
            if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_UPLOAD, true)){
                return false;
            }
            if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, reinterpret_cast<void*>(&bodydata))){
                return false;
            }
            if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback)){
                return false;
            }
            if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_HEADERDATA, reinterpret_cast<void*>(&responseHeaders))){
                return false;
            }
            if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_HEADERFUNCTION, HeaderCallback)){
                return false;
            }
            if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_INFILESIZE_LARGE, static_cast<curl_off_t>(partdata.size))){
                return false;
            }
            if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_READFUNCTION, S3fsCurl::UploadReadCallback)){
                return false;
            }
            if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_READDATA, reinterpret_cast<void*>(this))){
                return false;
            }
            break;

        case REQTYPE::COPYMULTIPOST:
            if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str())){
                return false;
            }
            if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_UPLOAD, true)){
                return false;
            }
            if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, reinterpret_cast<void*>(&bodydata))){
                return false;
            }
            if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback)){
                return false;
            }
            if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_HEADERDATA, reinterpret_cast<void*>(&headdata))){
                return false;
            }
            if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_HEADERFUNCTION, WriteMemoryCallback)){
                return false;
            }
            if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_INFILESIZE, 0)){
                return false;
            }
            break;

        case REQTYPE::MULTILIST:
            if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str())){
                return false;
            }
            if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, reinterpret_cast<void*>(&bodydata))){
                return false;
            }
            if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback)){
                return false;
            }
            break;

        case REQTYPE::IAMCRED:
            if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str())){
                return false;
            }
            if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, reinterpret_cast<void*>(&bodydata))){
                return false;
            }
            if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback)){
                return false;
            }
            if(S3fsCurl::ps3fscred->IsIBMIAMAuth()){
                if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_POST, true)){
                    return false;
                }
                if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_POSTFIELDSIZE, static_cast<curl_off_t>(postdata_remaining))){
                    return false;
                }
                if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_READDATA, reinterpret_cast<void*>(this))){
                    return false;
                }
                if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_READFUNCTION, S3fsCurl::ReadCallback)){
                    return false;
                }
            }
            break;

        case REQTYPE::ABORTMULTIUPLOAD:
            if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str())){
                return false;
            }
            if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_CUSTOMREQUEST, "DELETE")){
                return false;
            }
            break;

        case REQTYPE::IAMROLE:
            if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str())){
                return false;
            }
            if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, reinterpret_cast<void*>(&bodydata))){
                return false;
            }
            if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback)){
                return false;
            }
            break;

        default:
            S3FS_PRN_ERR("request type is unknown(%d)", static_cast<int>(type));
            return false;
    }
    if(!S3fsCurl::AddUserAgent(hCurl)){                            // put User-Agent
        return false;
    }

    return true;
}

//
// returns curl return code
//
int S3fsCurl::RequestPerform(bool dontAddAuthHeaders /*=false*/)
{
    if(S3fsLog::IsS3fsLogDbg()){
        char* ptr_url = nullptr;
        curl_easy_getinfo(hCurl, CURLINFO_EFFECTIVE_URL , &ptr_url);
        S3FS_PRN_DBG("connecting to URL %s", SAFESTRPTR(ptr_url));
    }

    LastResponseCode  = S3FSCURL_RESPONSECODE_NOTSET;
    long responseCode = S3FSCURL_RESPONSECODE_NOTSET;
    int result        = S3FSCURL_PERFORM_RESULT_NOTSET;

    // 1 attempt + retries...
    for(int retrycnt = 0; S3FSCURL_PERFORM_RESULT_NOTSET == result && retrycnt < S3fsCurl::retries; ++retrycnt){
        // Reset response code
        responseCode = S3FSCURL_RESPONSECODE_NOTSET;
        
        // Insert headers
        if(!dontAddAuthHeaders) {
             insertAuthHeaders();
        }

        if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_HTTPHEADER, requestHeaders)){
            return false;
        }

        // Requests
        curlCode = curl_easy_perform(hCurl);

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

                {
                    // Try to parse more specific AWS error code otherwise fall back to HTTP error code.
                    std::string value;
                    if(simple_parse_xml(bodydata.c_str(), bodydata.size(), "Code", value)){
                        // TODO: other error codes
                        if(value == "EntityTooLarge"){
                            result = -EFBIG;
                            break;
                        }else if(value == "InvalidObjectState"){
                            result = -EREMOTE;
                            break;
                        }else if(value == "KeyTooLongError"){
                            result = -ENAMETOOLONG;
                            break;
                        }
                    }
                }

                // Service response codes which are >= 300 && < 500
                switch(responseCode){
                    case 301:
                    case 307:
                        S3FS_PRN_ERR("HTTP response code 301(Moved Permanently: also happens when bucket's region is incorrect), returning EIO. Body Text: %s", bodydata.c_str());
                        S3FS_PRN_ERR("The options of url and endpoint may be useful for solving, please try to use both options.");
                        result = -EIO;
                        break;

                    case 400:
                        if(op == "HEAD"){
                            if(path.size() > 1024){
                                S3FS_PRN_ERR("HEAD HTTP response code %ld with path longer than 1024, returning ENAMETOOLONG.", responseCode);
                                return -ENAMETOOLONG;
                            }
                            S3FS_PRN_ERR("HEAD HTTP response code %ld, returning EPERM.", responseCode);
                            result = -EPERM;
                        }else{
                            S3FS_PRN_ERR("HTTP response code %ld, returning EIO. Body Text: %s", responseCode, bodydata.c_str());
                            result = -EIO;
                        }
                        break;

                    case 403:
                        S3FS_PRN_ERR("HTTP response code %ld, returning EPERM. Body Text: %s", responseCode, bodydata.c_str());
                        result = -EPERM;
                        break;

                    case 404:
                        S3FS_PRN_INFO3("HTTP response code 404 was returned, returning ENOENT");
                        S3FS_PRN_DBG("Body Text: %s", bodydata.c_str());
                        result = -ENOENT;
                        break;

                    case 416:
                        S3FS_PRN_INFO3("HTTP response code 416 was returned, returning EIO");
                        result = -EIO;
                        break;

                    case 501:
                        S3FS_PRN_INFO3("HTTP response code 501 was returned, returning ENOTSUP");
                        S3FS_PRN_DBG("Body Text: %s", bodydata.c_str());
                        result = -ENOTSUP;
                        break;

                    case 500:
                    case 503: {
                        S3FS_PRN_INFO3("HTTP response code %ld was returned, slowing down", responseCode);
                        S3FS_PRN_DBG("Body Text: %s", bodydata.c_str());
                        // Add jitter to avoid thundering herd.
                        unsigned int sleep_time = 2 << retry_count;
                        sleep(sleep_time + static_cast<unsigned int>(random()) % sleep_time);
                        break;
                    }
                    default:
                        S3FS_PRN_ERR("HTTP response code %ld, returning EIO. Body Text: %s", responseCode, bodydata.c_str());
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
                {
                    AutoLock lock(&S3fsCurl::curl_handles_lock);
                    S3fsCurl::curl_times[hCurl] = time(nullptr);
                }
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

                first_pos = S3fsCred::GetBucket().find_first_of('.');
                if(first_pos != std::string::npos){
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
        } // switch

        if(S3FSCURL_PERFORM_RESULT_NOTSET == result){
            S3FS_PRN_INFO("### retrying...");

            if(!RemakeHandle()){
                S3FS_PRN_INFO("Failed to reset handle and internal data for retrying.");
                result = -EIO;
                break;
            }
        }
    } // for

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
std::string S3fsCurl::CalcSignatureV2(const std::string& method, const std::string& strMD5, const std::string& content_type, const std::string& date, const std::string& resource, const std::string& secret_access_key, const std::string& access_token)
{
    std::string Signature;
    std::string StringToSign;

    if(!access_token.empty()){
        requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-security-token", access_token.c_str());
    }

    StringToSign += method + "\n";
    StringToSign += strMD5 + "\n";        // md5
    StringToSign += content_type + "\n";
    StringToSign += date + "\n";
    StringToSign += get_canonical_headers(requestHeaders, true);
    StringToSign += resource;

    const void* key            = secret_access_key.data();
    size_t key_len             = secret_access_key.size();
    const unsigned char* sdata = reinterpret_cast<const unsigned char*>(StringToSign.data());
    size_t sdata_len           = StringToSign.size();
    unsigned int md_len        = 0;

    std::unique_ptr<unsigned char[]> md = s3fs_HMAC(key, key_len, sdata, sdata_len, &md_len);

    Signature = s3fs_base64(md.get(), md_len);

    return Signature;
}

std::string S3fsCurl::CalcSignature(const std::string& method, const std::string& canonical_uri, const std::string& query_string, const std::string& strdate, const std::string& payload_hash, const std::string& date8601, const std::string& secret_access_key, const std::string& access_token)
{
    std::string StringCQ, StringToSign;
    std::string uriencode;

    if(!access_token.empty()){
        requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-security-token", access_token.c_str());
    }

    uriencode = urlEncodePath(canonical_uri);
    StringCQ  = method + "\n";
    if(method == "HEAD" || method == "PUT" || method == "DELETE"){
        StringCQ += uriencode + "\n";
    }else if(method == "GET" && uriencode.empty()){
        StringCQ +="/\n";
    }else if(method == "GET" && is_prefix(uriencode.c_str(), "/")){
        StringCQ += uriencode +"\n";
    }else if(method == "GET" && !is_prefix(uriencode.c_str(), "/")){
        StringCQ += "/\n" + urlEncodeQuery(canonical_uri) +"\n";
    }else if(method == "POST"){
        StringCQ += uriencode + "\n";
    }
    StringCQ += urlEncodeQuery(query_string) + "\n";
    StringCQ += get_canonical_headers(requestHeaders) + "\n";
    StringCQ += get_sorted_header_keys(requestHeaders) + "\n";
    StringCQ += payload_hash;

    std::string   kSecret = "AWS4" + secret_access_key;
    unsigned int  kDate_len,kRegion_len, kService_len, kSigning_len = 0;

    std::unique_ptr<unsigned char[]> kDate = s3fs_HMAC256(kSecret.c_str(), kSecret.size(), reinterpret_cast<const unsigned char*>(strdate.data()), strdate.size(), &kDate_len);
    std::unique_ptr<unsigned char[]> kRegion = s3fs_HMAC256(kDate.get(), kDate_len, reinterpret_cast<const unsigned char*>(endpoint.c_str()), endpoint.size(), &kRegion_len);
    std::unique_ptr<unsigned char[]> kService = s3fs_HMAC256(kRegion.get(), kRegion_len, reinterpret_cast<const unsigned char*>("s3"), sizeof("s3") - 1, &kService_len);
    std::unique_ptr<unsigned char[]> kSigning = s3fs_HMAC256(kService.get(), kService_len, reinterpret_cast<const unsigned char*>("aws4_request"), sizeof("aws4_request") - 1, &kSigning_len);

    const unsigned char* cRequest     = reinterpret_cast<const unsigned char*>(StringCQ.c_str());
    size_t               cRequest_len = StringCQ.size();
    sha256_t sRequest;
    s3fs_sha256(cRequest, cRequest_len, &sRequest);

    StringToSign  = "AWS4-HMAC-SHA256\n";
    StringToSign += date8601 + "\n";
    StringToSign += strdate + "/" + endpoint + "/s3/aws4_request\n";
    StringToSign += s3fs_hex_lower(sRequest.data(), sRequest.size());

    const unsigned char* cscope     = reinterpret_cast<const unsigned char*>(StringToSign.c_str());
    size_t               cscope_len = StringToSign.size();
    unsigned int         md_len     = 0;

    std::unique_ptr<unsigned char[]> md = s3fs_HMAC256(kSigning.get(), kSigning_len, cscope, cscope_len, &md_len);

    return s3fs_hex_lower(md.get(), md_len);
}

void S3fsCurl::insertV4Headers(const std::string& access_key_id, const std::string& secret_access_key, const std::string& access_token)
{
    std::string server_path = type == REQTYPE::LISTBUCKET ? "/" : path;
    std::string payload_hash;
    switch (type) {
        case REQTYPE::PUT:
            if(GetUnsignedPayload()){
                payload_hash = "UNSIGNED-PAYLOAD";
            }else{
                payload_hash = s3fs_sha256_hex_fd(b_infile == nullptr ? -1 : fileno(b_infile), 0, -1);
            }
            break;

        case REQTYPE::COMPLETEMULTIPOST:
            {
                size_t          cRequest_len = strlen(reinterpret_cast<const char *>(b_postdata));
                sha256_t sRequest;
                s3fs_sha256(b_postdata, cRequest_len, &sRequest);
                payload_hash = s3fs_hex_lower(sRequest.data(), sRequest.size());
                break;
            }

        case REQTYPE::UPLOADMULTIPOST:
            if(GetUnsignedPayload()){
                payload_hash = "UNSIGNED-PAYLOAD";
            }else{
                payload_hash = s3fs_sha256_hex_fd(partdata.fd, partdata.startpos, partdata.size);
            }
            break;
        default:
            break;
    }

    if(b_infile != nullptr && payload_hash.empty()){
        S3FS_PRN_ERR("Failed to make SHA256.");
        // TODO: propagate error
    }

    S3FS_PRN_INFO3("computing signature [%s] [%s] [%s] [%s]", op.c_str(), server_path.c_str(), query_string.c_str(), payload_hash.c_str());
    std::string strdate;
    std::string date8601;
    get_date_sigv3(strdate, date8601);

    std::string contentSHA256 = payload_hash.empty() ? EMPTY_PAYLOAD_HASH : payload_hash;
    const std::string realpath = pathrequeststyle ? "/" + S3fsCred::GetBucket() + server_path : server_path;

    //string canonical_headers, signed_headers;
    requestHeaders = curl_slist_sort_insert(requestHeaders, "host", get_bucket_host().c_str());
    requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-content-sha256", contentSHA256.c_str());
    requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-date", date8601.c_str());

    if (S3fsCurl::IsRequesterPays()) {
        requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-request-payer", "requester");
    }

    if(!S3fsCurl::IsPublicBucket()){
        std::string Signature = CalcSignature(op, realpath, query_string + (type == REQTYPE::PREMULTIPOST || type == REQTYPE::MULTILIST ? "=" : ""), strdate, contentSHA256, date8601, secret_access_key, access_token);
        std::string auth = "AWS4-HMAC-SHA256 Credential=" + access_key_id + "/" + strdate + "/" + endpoint + "/s3/aws4_request, SignedHeaders=" + get_sorted_header_keys(requestHeaders) + ", Signature=" + Signature;
        requestHeaders = curl_slist_sort_insert(requestHeaders, "Authorization", auth.c_str());
    }
}

void S3fsCurl::insertV2Headers(const std::string& access_key_id, const std::string& secret_access_key, const std::string& access_token)
{
    std::string resource;
    std::string turl;
    std::string server_path = type == REQTYPE::LISTBUCKET ? "/" : path;
    MakeUrlResource(server_path.c_str(), resource, turl);
    if(!query_string.empty() && type != REQTYPE::CHKBUCKET && type != REQTYPE::LISTBUCKET){
        resource += "?" + query_string;
    }

    std::string date = get_date_rfc850();
    requestHeaders = curl_slist_sort_insert(requestHeaders, "Date", date.c_str());
    if(op != "PUT" && op != "POST"){
        requestHeaders = curl_slist_sort_insert(requestHeaders, "Content-Type", nullptr);
    }

    if(!S3fsCurl::IsPublicBucket()){
        std::string Signature = CalcSignatureV2(op, get_header_value(requestHeaders, "Content-MD5"), get_header_value(requestHeaders, "Content-Type"), date, resource, secret_access_key, access_token);
        requestHeaders   = curl_slist_sort_insert(requestHeaders, "Authorization", ("AWS " + access_key_id + ":" + Signature).c_str());
    }
}

void S3fsCurl::insertIBMIAMHeaders(const std::string& access_key_id, const std::string& access_token)
{
    requestHeaders = curl_slist_sort_insert(requestHeaders, "Authorization", ("Bearer " + access_token).c_str());

    if(op == "PUT" && path == mount_prefix + "/"){
        // ibm-service-instance-id header is required for bucket creation requests
        requestHeaders = curl_slist_sort_insert(requestHeaders, "ibm-service-instance-id", access_key_id.c_str());
    }
}

void S3fsCurl::insertAuthHeaders()
{
    std::string access_key_id;
    std::string secret_access_key;
    std::string access_token;

    // check and get credential variables
    if(!S3fsCurl::ps3fscred->CheckIAMCredentialUpdate(&access_key_id, &secret_access_key, &access_token)){
        S3FS_PRN_ERR("An error occurred in checking IAM credential.");
        return; // do not insert auth headers on error
    }

    if(S3fsCurl::ps3fscred->IsIBMIAMAuth()){
        insertIBMIAMHeaders(access_key_id, access_token);
    }else if(S3fsCurl::signature_type == signature_type_t::V2_ONLY){
        insertV2Headers(access_key_id, secret_access_key, access_token);
    }else{
        insertV4Headers(access_key_id, secret_access_key, access_token);
    }
}

int S3fsCurl::DeleteRequest(const char* tpath)
{
    S3FS_PRN_INFO3("[tpath=%s]", SAFESTRPTR(tpath));

    if(!tpath){
        return -EINVAL;
    }
    if(!CreateCurlHandle()){
        return -EIO;
    }
    std::string resource;
    std::string turl;
    MakeUrlResource(get_realpath(tpath).c_str(), resource, turl);

    url             = prepare_url(turl.c_str());
    path            = get_realpath(tpath);
    requestHeaders  = nullptr;
    responseHeaders.clear();

    op = "DELETE";
    type = REQTYPE::DELETE;

    if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str())){
        return -EIO;
    }
    if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_CUSTOMREQUEST, "DELETE")){
        return -EIO;
    }
    if(!S3fsCurl::AddUserAgent(hCurl)){                            // put User-Agent
        return -EIO;
    }

    return RequestPerform();
}

int S3fsCurl::GetIAMv2ApiToken(const char* token_url, int token_ttl, const char* token_ttl_hdr, std::string& response)
{
    if(!token_url || !token_ttl_hdr){
        S3FS_PRN_ERR("IAMv2 token url(%s) or ttl_hdr(%s) parameter are wrong.", token_url ? token_url : "null", token_ttl_hdr ? token_ttl_hdr : "null");
        return -EIO;
    }
    response.erase();
    url = token_url;
    if(!CreateCurlHandle()){
        return -EIO;
    }
    requestHeaders  = nullptr;
    responseHeaders.clear();
    bodydata.clear();

    std::string ttlstr = std::to_string(token_ttl);
    requestHeaders = curl_slist_sort_insert(requestHeaders, token_ttl_hdr, ttlstr.c_str());

    // Curl appends an "Expect: 100-continue" header to the token request, 
    // and aws responds with a 417 Expectation Failed. This ensures the 
    // Expect header is empty before the request is sent.
    requestHeaders = curl_slist_sort_insert(requestHeaders, "Expect", "");

    if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_UPLOAD, true)){
        return -EIO;
    }
    if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str())){
        return -EIO;
    }
    if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, reinterpret_cast<void*>(&bodydata))){
        return -EIO;
    }
    if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback)){
        return -EIO;
    }
    if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_INFILESIZE, 0)){
        return false;
    }
    if(!S3fsCurl::AddUserAgent(hCurl)){                            // put User-Agent
        return -EIO;
    }

    // [NOTE]
    // Be sure to give "dontAddAuthHeaders=true".
    // If set to false(default), it will deadlock in S3fsCred.
    //
    int result = RequestPerform(true);

    if(0 == result){
        response.swap(bodydata);
    }else{
        S3FS_PRN_ERR("Error(%d) occurred, could not get IAMv2 api token.", result);
    }
    bodydata.clear();

    return result;
}

//
// Get AccessKeyId/SecretAccessKey/AccessToken/Expiration by IAM role,
// and Set these value to class variable.
//
bool S3fsCurl::GetIAMCredentials(const char* cred_url, const char* iam_v2_token, const char* ibm_secret_access_key, std::string& response)
{
    if(!cred_url){
        S3FS_PRN_ERR("url is null.");
        return false;
    }
    url = cred_url;
    response.erase();

    // at first set type for handle
    type = REQTYPE::IAMCRED;

    if(!CreateCurlHandle()){
        return false;
    }
    requestHeaders  = nullptr;
    responseHeaders.clear();
    bodydata.clear();
    std::string postContent;

    if(ibm_secret_access_key){
        // make contents
        postContent += "grant_type=urn:ibm:params:oauth:grant-type:apikey";
        postContent += "&response_type=cloud_iam";
        postContent += "&apikey=";
        postContent += ibm_secret_access_key;

        // set postdata
        postdata             = reinterpret_cast<const unsigned char*>(postContent.c_str());
        b_postdata           = postdata;
        postdata_remaining   = postContent.size(); // without null
        b_postdata_remaining = postdata_remaining;

        requestHeaders = curl_slist_sort_insert(requestHeaders, "Authorization", "Basic Yng6Yng=");

        if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_POST, true)){              // POST
            return false;
        }
        if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_POSTFIELDSIZE, static_cast<curl_off_t>(postdata_remaining))){
            return false;
        }
        if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_READDATA, reinterpret_cast<void*>(this))){
            return false;
        }
        if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_READFUNCTION, S3fsCurl::ReadCallback)){
            return false;
        }
    }

    if(iam_v2_token){
        requestHeaders = curl_slist_sort_insert(requestHeaders, S3fsCred::IAMv2_token_hdr, iam_v2_token);
    }

    if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str())){
        return false;
    }
    if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, reinterpret_cast<void*>(&bodydata))){
        return false;
    }
    if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback)){
        return false;
    }
    if(!S3fsCurl::AddUserAgent(hCurl)){                            // put User-Agent
        return false;
    }

    // [NOTE]
    // Be sure to give "dontAddAuthHeaders=true".
    // If set to false(default), it will deadlock in S3fsCred.
    //
    int result = RequestPerform(true);

    // analyzing response
    if(0 == result){
        response.swap(bodydata);
    }else{
        S3FS_PRN_ERR("Error(%d) occurred, could not get IAM role name.", result);
    }
    bodydata.clear();

    return (0 == result);
}

//
// Get IAM role name automatically.
//
bool S3fsCurl::GetIAMRoleFromMetaData(const char* cred_url, const char* iam_v2_token, std::string& token)
{
    if(!cred_url){
        S3FS_PRN_ERR("url is null.");
        return false;
    }
    url = cred_url;
    token.erase();

    S3FS_PRN_INFO3("Get IAM Role name");

    // at first set type for handle
    type = REQTYPE::IAMROLE;

    if(!CreateCurlHandle()){
        return false;
    }
    requestHeaders  = nullptr;
    responseHeaders.clear();
    bodydata.clear();

    if(iam_v2_token){
        requestHeaders = curl_slist_sort_insert(requestHeaders, S3fsCred::IAMv2_token_hdr, iam_v2_token);
    }

    if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str())){
        return false;
    }
    if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, reinterpret_cast<void*>(&bodydata))){
        return false;
    }
    if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback)){
        return false;
    }
    if(!S3fsCurl::AddUserAgent(hCurl)){                            // put User-Agent
        return false;
    }

    // [NOTE]
    // Be sure to give "dontAddAuthHeaders=true".
    // If set to false(default), it will deadlock in S3fsCred.
    //
    int result = RequestPerform(true);

    // analyzing response
    if(0 == result){
        token.swap(bodydata);
    }else{
        S3FS_PRN_ERR("Error(%d) occurred, could not get IAM role name from meta data.", result);
    }
    bodydata.clear();

    return (0 == result);
}

bool S3fsCurl::AddSseRequestHead(sse_type_t ssetype, const std::string& input, bool is_copy)
{
    std::string ssevalue = input;
    switch(ssetype){
        case sse_type_t::SSE_DISABLE:
            return true;
        case sse_type_t::SSE_S3:
            if(!is_copy){
                requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-server-side-encryption", "AES256");
            }
            return true;
        case sse_type_t::SSE_C:
            {
                std::string sseckey;
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
                return true;
            }
        case sse_type_t::SSE_KMS:
            if(!is_copy){
                if(ssevalue.empty()){
                    ssevalue = S3fsCurl::GetSseKmsId();
                }
                requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-server-side-encryption", "aws:kms");
                requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-server-side-encryption-aws-kms-key-id", ssevalue.c_str());
            }
            return true;
    }
    S3FS_PRN_ERR("sse type is unknown(%d).", static_cast<int>(S3fsCurl::ssetype));

    return false;
}

//
// tpath :      target path for head request
// bpath :      saved into base_path
// savedpath :  saved into saved_path
// ssekey_pos : -1    means "not" SSE-C type
//              0 - X means SSE-C type and position for SSE-C key(0 is latest key)
//
bool S3fsCurl::PreHeadRequest(const char* tpath, const char* bpath, const char* savedpath, size_t ssekey_pos)
{
    S3FS_PRN_INFO3("[tpath=%s][bpath=%s][save=%s][sseckeypos=%zu]", SAFESTRPTR(tpath), SAFESTRPTR(bpath), SAFESTRPTR(savedpath), ssekey_pos);

    if(!tpath){
        return false;
    }
    std::string resource;
    std::string turl;
    MakeUrlResource(get_realpath(tpath).c_str(), resource, turl);

    // libcurl 7.17 does deep copy of url, deep copy "stable" url
    url             = prepare_url(turl.c_str());
    path            = get_realpath(tpath);
    base_path       = SAFESTRPTR(bpath);
    saved_path      = SAFESTRPTR(savedpath);
    requestHeaders  = nullptr;
    responseHeaders.clear();

    // requestHeaders(SSE-C)
    if(0 <= static_cast<ssize_t>(ssekey_pos) && ssekey_pos < S3fsCurl::sseckeys.size()){
        std::string md5;
        if(!S3fsCurl::GetSseKeyMd5(ssekey_pos, md5) || !AddSseRequestHead(sse_type_t::SSE_C, md5, false)){
            S3FS_PRN_ERR("Failed to set SSE-C headers for sse-c key pos(%zu)(=md5(%s)).", ssekey_pos, md5.c_str());
            return false;
        }
    }
    b_ssekey_pos = ssekey_pos;

    op = "HEAD";
    type = REQTYPE::HEAD;

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
        for(size_t pos = 0; pos < S3fsCurl::sseckeys.size(); pos++){
            if(!DestroyCurlHandle()){
                break;
            }
            if(!PreHeadRequest(tpath, nullptr, nullptr, pos)){
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
        std::string key   = lower(iter->first);
        std::string value = iter->second;
        if(key == "content-type"){
            meta[iter->first] = value;
        }else if(key == "content-length"){
            meta[iter->first] = value;
        }else if(key == "etag"){
            meta[iter->first] = value;
        }else if(key == "last-modified"){
            meta[iter->first] = value;
        }else if(is_prefix(key.c_str(), "x-amz")){
            meta[key] = value;        // key is lower case for "x-amz"
        }
    }
    return 0;
}

int S3fsCurl::PutHeadRequest(const char* tpath, headers_t& meta, bool is_copy)
{
    S3FS_PRN_INFO3("[tpath=%s]", SAFESTRPTR(tpath));

    if(!tpath){
        return -EINVAL;
    }
    if(!CreateCurlHandle()){
        return -EIO;
    }
    std::string resource;
    std::string turl;
    MakeUrlResource(get_realpath(tpath).c_str(), resource, turl);

    url             = prepare_url(turl.c_str());
    path            = get_realpath(tpath);
    requestHeaders  = nullptr;
    responseHeaders.clear();
    bodydata.clear();

    std::string contype = S3fsCurl::LookupMimeType(tpath);
    requestHeaders      = curl_slist_sort_insert(requestHeaders, "Content-Type", contype.c_str());

    // Make request headers
    for(headers_t::iterator iter = meta.begin(); iter != meta.end(); ++iter){
        std::string key   = lower(iter->first);
        std::string value = iter->second;
        if(is_prefix(key.c_str(), "x-amz-acl")){
            // not set value, but after set it.
        }else if(is_prefix(key.c_str(), "x-amz-meta")){
            requestHeaders = curl_slist_sort_insert(requestHeaders, iter->first.c_str(), value.c_str());
        }else if(key == "x-amz-copy-source"){
            requestHeaders = curl_slist_sort_insert(requestHeaders, iter->first.c_str(), value.c_str());
        }else if(key == "x-amz-server-side-encryption" && value != "aws:kms"){
            // skip this header, because this header is specified after logic.
        }else if(key == "x-amz-server-side-encryption-aws-kms-key-id"){
            // skip this header, because this header is specified after logic.
        }else if(key == "x-amz-server-side-encryption-customer-key-md5"){
            // Only copy mode.
            if(is_copy){
                if(!AddSseRequestHead(sse_type_t::SSE_C, value, true)){
                    S3FS_PRN_WARN("Failed to insert SSE-C header.");
                }
            }
        }
    }

    // "x-amz-acl", storage class, sse
    if(S3fsCurl::default_acl != acl_t::PRIVATE){
        requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-acl", str(S3fsCurl::default_acl));
    }
    if(strcasecmp(GetStorageClass().c_str(), "STANDARD") != 0){
        requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-storage-class", GetStorageClass().c_str());
    }
    // SSE
    if(S3fsCurl::GetSseType() != sse_type_t::SSE_DISABLE){
        std::string ssevalue;
        if(!AddSseRequestHead(S3fsCurl::GetSseType(), ssevalue, false)){
            S3FS_PRN_WARN("Failed to set SSE header, but continue...");
        }
    }
    if(is_use_ahbe){
        // set additional header by ahbe conf
        requestHeaders = AdditionalHeader::get()->AddHeader(requestHeaders, tpath);
    }

    op = "PUT";
    type = REQTYPE::PUTHEAD;

    // setopt
    if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str())){
        return -EIO;
    }
    if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_UPLOAD, true)){                // HTTP PUT
        return -EIO;
    }
    if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, reinterpret_cast<void*>(&bodydata))){
        return -EIO;
    }
    if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback)){
        return -EIO;
    }
    if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_INFILESIZE, 0)){               // Content-Length
        return -EIO;
    }
    if(!S3fsCurl::AddUserAgent(hCurl)){                            // put User-Agent
        return -EIO;
    }

    S3FS_PRN_INFO3("copying... [path=%s]", tpath);

    int result = RequestPerform();
    result = MapPutErrorResponse(result);
    bodydata.clear();

    return result;
}

int S3fsCurl::PutRequest(const char* tpath, headers_t& meta, int fd)
{
    struct stat st;
    std::unique_ptr<FILE, decltype(&s3fs_fclose)> file(nullptr, &s3fs_fclose);

    S3FS_PRN_INFO3("[tpath=%s]", SAFESTRPTR(tpath));

    if(!tpath){
        return -EINVAL;
    }
    if(-1 != fd){
        // duplicate fd
        //
        // [NOTE]
        // This process requires FILE*, then it is linked to fd with fdopen.
        // After processing, the FILE* is closed with fclose, and fd is closed together.
        // The fd should not be closed here, so call dup here to duplicate it.
        //
        int fd2;
        if(-1 == (fd2 = dup(fd)) || -1 == fstat(fd2, &st) || 0 != lseek(fd2, 0, SEEK_SET) || nullptr == (file = {fdopen(fd2, "rb"), &s3fs_fclose})){
            S3FS_PRN_ERR("Could not duplicate file descriptor(errno=%d)", errno);
            if(-1 != fd2){
                close(fd2);
            }
            return -errno;
        }
        b_infile = file.get();
    }else{
        // This case is creating zero byte object.(calling by create_file_object())
        S3FS_PRN_INFO3("create zero byte file object.");
    }

    if(!CreateCurlHandle()){
        return -EIO;
    }
    std::string resource;
    std::string turl;
    MakeUrlResource(get_realpath(tpath).c_str(), resource, turl);

    url             = prepare_url(turl.c_str());
    path            = get_realpath(tpath);
    requestHeaders  = nullptr;
    responseHeaders.clear();
    bodydata.clear();

    // Make request headers
    if(S3fsCurl::is_content_md5){
        std::string strMD5;
        if(-1 != fd){
            strMD5 = s3fs_get_content_md5(fd);
            if(0 == strMD5.length()){
                S3FS_PRN_ERR("Failed to make MD5.");
                return -EIO;
            }
        }else{
            strMD5 = EMPTY_MD5_BASE64_HASH;
        }
        requestHeaders = curl_slist_sort_insert(requestHeaders, "Content-MD5", strMD5.c_str());
    }

    std::string contype = S3fsCurl::LookupMimeType(tpath);
    requestHeaders = curl_slist_sort_insert(requestHeaders, "Content-Type", contype.c_str());

    for(headers_t::iterator iter = meta.begin(); iter != meta.end(); ++iter){
        std::string key   = lower(iter->first);
        std::string value = iter->second;
        if(is_prefix(key.c_str(), "x-amz-acl")){
            // not set value, but after set it.
        }else if(is_prefix(key.c_str(), "x-amz-meta")){
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
    if(S3fsCurl::default_acl != acl_t::PRIVATE){
        requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-acl", str(S3fsCurl::default_acl));
    }
    if(strcasecmp(GetStorageClass().c_str(), "STANDARD") != 0){
        requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-storage-class", GetStorageClass().c_str());
    }
    // SSE
    // do not add SSE for create bucket
    if(0 != strcmp(tpath, "/")){
        std::string ssevalue;
        if(!AddSseRequestHead(S3fsCurl::GetSseType(), ssevalue, false)){
            S3FS_PRN_WARN("Failed to set SSE header, but continue...");
        }
    }
    if(is_use_ahbe){
        // set additional header by ahbe conf
        requestHeaders = AdditionalHeader::get()->AddHeader(requestHeaders, tpath);
    }

    op = "PUT";
    type = REQTYPE::PUT;

    // setopt
    if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str())){
        return -EIO;
    }
    if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_UPLOAD, true)){                // HTTP PUT
        return -EIO;
    }
    if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, reinterpret_cast<void*>(&bodydata))){
        return -EIO;
    }
    if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback)){
        return -EIO;
    }
    if(file){
        if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_INFILESIZE_LARGE, static_cast<curl_off_t>(st.st_size))){ // Content-Length
            return -EIO;
        }
        if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_INFILE, file.get())){
            return -EIO;
        }
    }else{
        if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_INFILESIZE, 0)){             // Content-Length: 0
            return -EIO;
        }
    }
    if(!S3fsCurl::AddUserAgent(hCurl)){                            // put User-Agent
        return -EIO;
    }

    S3FS_PRN_INFO3("uploading... [path=%s][fd=%d][size=%lld]", tpath, fd, static_cast<long long int>(-1 != fd ? st.st_size : 0));

    int result = RequestPerform();
    result = MapPutErrorResponse(result);
    bodydata.clear();
    return result;
}

int S3fsCurl::PreGetObjectRequest(const char* tpath, int fd, off_t start, off_t size, sse_type_t ssetype, const std::string& ssevalue)
{
    S3FS_PRN_INFO3("[tpath=%s][start=%lld][size=%lld]", SAFESTRPTR(tpath), static_cast<long long>(start), static_cast<long long>(size));

    if(!tpath || -1 == fd || 0 > start || 0 > size){
        return -EINVAL;
    }

    std::string resource;
    std::string turl;
    MakeUrlResource(get_realpath(tpath).c_str(), resource, turl);

    url             = prepare_url(turl.c_str());
    path            = get_realpath(tpath);
    requestHeaders  = nullptr;
    responseHeaders.clear();

    if(0 < size){
        std::string range = "bytes=";
        range       += std::to_string(start);
        range       += "-";
        range       += std::to_string(start + size - 1);
        requestHeaders = curl_slist_sort_insert(requestHeaders, "Range", range.c_str());
    }
    // SSE-C
    if(sse_type_t::SSE_C == ssetype){
        if(!AddSseRequestHead(ssetype, ssevalue, false)){
            S3FS_PRN_WARN("Failed to set SSE header, but continue...");
        }
    }

    op = "GET";
    type = REQTYPE::GET;

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

int S3fsCurl::GetObjectRequest(const char* tpath, int fd, off_t start, off_t size)
{
    int result;

    S3FS_PRN_INFO3("[tpath=%s][start=%lld][size=%lld]", SAFESTRPTR(tpath), static_cast<long long>(start), static_cast<long long>(size));

    if(!tpath){
        return -EINVAL;
    }
    sse_type_t local_ssetype = sse_type_t::SSE_DISABLE;
    std::string ssevalue;
    if(!get_object_sse_type(tpath, local_ssetype, ssevalue)){
        S3FS_PRN_WARN("Failed to get SSE type for file(%s).", SAFESTRPTR(tpath));
    }

    if(0 != (result = PreGetObjectRequest(tpath, fd, start, size, local_ssetype, ssevalue))){
        return result;
    }
    if(!fpLazySetup || !fpLazySetup(this)){
        S3FS_PRN_ERR("Failed to lazy setup in single get object request.");
        return -EIO;
    }

    S3FS_PRN_INFO3("downloading... [path=%s][fd=%d]", tpath, fd);

    result = RequestPerform();
    partdata.clear();

    return result;
}

int S3fsCurl::CheckBucket(const char* check_path, bool compat_dir)
{
    S3FS_PRN_INFO3("check a bucket path(%s)%s.", (check_path && 0 < strlen(check_path)) ? check_path : "", compat_dir ? " containing compatible directory paths" : "");

    if(!check_path || 0 == strlen(check_path)){
        return -EIO;
    }
    if(!CreateCurlHandle()){
        return -EIO;
    }

    std::string strCheckPath;
    std::string urlargs;
    if(S3fsCurl::IsListObjectsV2()){
        query_string = "list-type=2";
    }else{
        query_string.clear();
    }
    if(!compat_dir){
        // do not check compatibility directories
        strCheckPath = check_path;

    }else{
        // check path including compatibility directory
        strCheckPath = "/";

        if(1 < strlen(check_path)){         // for directory path ("/...") not root path("/")
            if(!query_string.empty()){
                query_string += '&';
            }
            query_string += "prefix=";
            query_string += &check_path[1]; // skip first '/' charactor
        }
    }
    if(!query_string.empty()){
        urlargs = "?" + query_string;
    }

    std::string resource;
    std::string turl;
    MakeUrlResource(strCheckPath.c_str(), resource, turl);

    turl           += urlargs;
    url             = prepare_url(turl.c_str());
    path            = strCheckPath;
    requestHeaders  = nullptr;
    responseHeaders.clear();
    bodydata.clear();

    // SSE
    if(S3fsCurl::GetSseType() != sse_type_t::SSE_DISABLE){
        std::string ssevalue;
        if(!AddSseRequestHead(S3fsCurl::GetSseType(), ssevalue, false)){
            S3FS_PRN_WARN("Failed to set SSE header, but continue...");
        }
    }
    
    op = "GET";
    type = REQTYPE::CHKBUCKET;

    // setopt
    if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str())){
        return -EIO;
    }
    if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, reinterpret_cast<void*>(&bodydata))){
        return -EIO;
    }
    if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback)){
        return -EIO;
    }
    if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_UNRESTRICTED_AUTH, 1L)){
        return -EIO;
    }
    if(!S3fsCurl::AddUserAgent(hCurl)){                            // put User-Agent
        return -EIO;
    }

    int result = RequestPerform();
    if (result != 0) {
        S3FS_PRN_ERR("Check bucket failed, S3 response: %s", bodydata.c_str());
    }
    return result;
}

int S3fsCurl::ListBucketRequest(const char* tpath, const char* query)
{
    S3FS_PRN_INFO3("[tpath=%s]", SAFESTRPTR(tpath));

    if(!tpath){
        return -EINVAL;
    }
    if(!CreateCurlHandle()){
        return -EIO;
    }
    std::string resource;
    std::string turl;
    MakeUrlResource("", resource, turl);    // NOTICE: path is "".
    if(query){
        turl += "?";
        turl += query;
        query_string = query;
    }

    url             = prepare_url(turl.c_str());
    path            = get_realpath(tpath);
    requestHeaders  = nullptr;
    responseHeaders.clear();
    bodydata.clear();

    op = "GET";
    type = REQTYPE::LISTBUCKET;

    // setopt
    if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str())){
        return -EIO;
    }
    if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, reinterpret_cast<void*>(&bodydata))){
        return -EIO;
    }
    if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback)){
        return -EIO;
    }
    if(S3fsCurl::is_verbose){
        if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_DEBUGFUNCTION, S3fsCurl::CurlDebugBodyInFunc)){     // replace debug function
            return -EIO;
        }
    }
    if(!S3fsCurl::AddUserAgent(hCurl)){                            // put User-Agent
        return -EIO;
    }

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
int S3fsCurl::PreMultipartPostRequest(const char* tpath, headers_t& meta, std::string& upload_id, bool is_copy)
{
    S3FS_PRN_INFO3("[tpath=%s]", SAFESTRPTR(tpath));

    if(!tpath){
        return -EINVAL;
    }
    if(!CreateCurlHandle()){
        return -EIO;
    }
    std::string resource;
    std::string turl;
    MakeUrlResource(get_realpath(tpath).c_str(), resource, turl);

    query_string   = "uploads";
    turl          += "?" + query_string;
    url            = prepare_url(turl.c_str());
    path           = get_realpath(tpath);
    requestHeaders = nullptr;
    bodydata.clear();
    responseHeaders.clear();

    std::string contype = S3fsCurl::LookupMimeType(tpath);

    for(headers_t::iterator iter = meta.begin(); iter != meta.end(); ++iter){
        std::string key   = lower(iter->first);
        std::string value = iter->second;
        if(is_prefix(key.c_str(), "x-amz-acl")){
            // not set value, but after set it.
        }else if(is_prefix(key.c_str(), "x-amz-meta")){
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
    if(S3fsCurl::default_acl != acl_t::PRIVATE){
        requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-acl", str(S3fsCurl::default_acl));
    }
    if(strcasecmp(GetStorageClass().c_str(), "STANDARD") != 0){
        requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-storage-class", GetStorageClass().c_str());
    }
    // SSE
    if(S3fsCurl::GetSseType() != sse_type_t::SSE_DISABLE){
        std::string ssevalue;
        if(!AddSseRequestHead(S3fsCurl::GetSseType(), ssevalue, false)){
            S3FS_PRN_WARN("Failed to set SSE header, but continue...");
        }
    }
    if(is_use_ahbe){
        // set additional header by ahbe conf
        requestHeaders = AdditionalHeader::get()->AddHeader(requestHeaders, tpath);
    }

    requestHeaders = curl_slist_sort_insert(requestHeaders, "Accept", nullptr);
    requestHeaders = curl_slist_sort_insert(requestHeaders, "Content-Type", contype.c_str());

    op = "POST";
    type = REQTYPE::PREMULTIPOST;

    // setopt
    if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str())){
        return -EIO;
    }
    if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_POST, true)){              // POST
        return -EIO;
    }
    if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, reinterpret_cast<void*>(&bodydata))){
        return -EIO;
    }
    if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback)){
        return -EIO;
    }
    if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_POSTFIELDSIZE, 0)){
        return -EIO;
    }
    if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_INFILESIZE, 0)){           // Content-Length
        return -EIO;
    }
    if(!S3fsCurl::AddUserAgent(hCurl)){                            // put User-Agent
        return -EIO;
    }

    // request
    int result;
    if(0 != (result = RequestPerform())){
        bodydata.clear();
        return result;
    }

    if(!simple_parse_xml(bodydata.c_str(), bodydata.size(), "UploadId", upload_id)){
        bodydata.clear();
        return -EIO;
    }

    bodydata.clear();
    return 0;
}

int S3fsCurl::CompleteMultipartPostRequest(const char* tpath, const std::string& upload_id, etaglist_t& parts)
{
    S3FS_PRN_INFO3("[tpath=%s][parts=%zu]", SAFESTRPTR(tpath), parts.size());

    if(!tpath){
        return -EINVAL;
    }

    // make contents
    std::string postContent;
    postContent += "<CompleteMultipartUpload>\n";
    for(etaglist_t::iterator it = parts.begin(); it != parts.end(); ++it){
        if(it->etag.empty()){
            S3FS_PRN_ERR("%d file part is not finished uploading.", it->part_num);
            return -EIO;
        }
        postContent += "<Part>\n";
        postContent += "  <PartNumber>" + std::to_string(it->part_num) + "</PartNumber>\n";
        postContent += "  <ETag>" + it->etag + "</ETag>\n";
        postContent += "</Part>\n";
    }
    postContent += "</CompleteMultipartUpload>\n";

    // set postdata
    postdata             = reinterpret_cast<const unsigned char*>(postContent.c_str());
    b_postdata           = postdata;
    postdata_remaining   = postContent.size(); // without null
    b_postdata_remaining = postdata_remaining;

    if(!CreateCurlHandle()){
        postdata   = nullptr;
        b_postdata = nullptr;
        return -EIO;
    }
    std::string resource;
    std::string turl;
    MakeUrlResource(get_realpath(tpath).c_str(), resource, turl);

    // [NOTE]
    // Encode the upload_id here.
    // In compatible S3 servers(Cloudflare, etc), there are cases where characters that require URL encoding are included.
    //
    query_string         = "uploadId=" + urlEncodeGeneral(upload_id);
    turl                += "?" + query_string;
    url                  = prepare_url(turl.c_str());
    path                 = get_realpath(tpath);
    requestHeaders       = nullptr;
    bodydata.clear();
    responseHeaders.clear();
    std::string contype  = "application/xml";

    requestHeaders = curl_slist_sort_insert(requestHeaders, "Accept", nullptr);
    requestHeaders = curl_slist_sort_insert(requestHeaders, "Content-Type", contype.c_str());

    if(sse_type_t::SSE_C == S3fsCurl::GetSseType()){
        std::string ssevalue;
        if(!AddSseRequestHead(S3fsCurl::GetSseType(), ssevalue, false)){
            S3FS_PRN_WARN("Failed to set SSE header, but continue...");
        }
    }

    op = "POST";
    type = REQTYPE::COMPLETEMULTIPOST;

    // setopt
    if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str())){
        return -EIO;
    }
    if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_POST, true)){              // POST
        return -EIO;
    }
    if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, reinterpret_cast<void*>(&bodydata))){
        return -EIO;
    }
    if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback)){
        return -EIO;
    }
    if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_POSTFIELDSIZE, static_cast<curl_off_t>(postdata_remaining))){
        return -EIO;
    }
    if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_READDATA, reinterpret_cast<void*>(this))){
        return -EIO;
    }
    if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_READFUNCTION, S3fsCurl::ReadCallback)){
        return -EIO;
    }
    if(S3fsCurl::is_verbose){
        if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_DEBUGFUNCTION, S3fsCurl::CurlDebugBodyOutFunc)){     // replace debug function
            return -EIO;
        }
    }
    if(!S3fsCurl::AddUserAgent(hCurl)){                            // put User-Agent
        return -EIO;
    }

    // request
    int result = RequestPerform();
    bodydata.clear();
    postdata   = nullptr;
    b_postdata = nullptr;

    return result;
}

int S3fsCurl::MultipartListRequest(std::string& body)
{
    S3FS_PRN_INFO3("list request(multipart)");

    if(!CreateCurlHandle()){
        return -EIO;
    }
    std::string resource;
    std::string turl;
    path            = get_realpath("/");
    MakeUrlResource(path.c_str(), resource, turl);

    query_string    = "uploads";
    turl           += "?" + query_string;
    url             = prepare_url(turl.c_str());
    requestHeaders  = nullptr;
    responseHeaders.clear();
    bodydata.clear();

    requestHeaders = curl_slist_sort_insert(requestHeaders, "Accept", nullptr);

    op = "GET";
    type = REQTYPE::MULTILIST;

    // setopt
    if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str())){
        return -EIO;
    }
    if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, reinterpret_cast<void*>(&bodydata))){
        return -EIO;
    }
    if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback)){
        return -EIO;
    }
    if(!S3fsCurl::AddUserAgent(hCurl)){                            // put User-Agent
        return -EIO;
    }

    int result;
    if(0 == (result = RequestPerform()) && !bodydata.empty()){
        body.swap(bodydata);
    }else{
        body = "";
    }
    bodydata.clear();

    return result;
}

int S3fsCurl::AbortMultipartUpload(const char* tpath, const std::string& upload_id)
{
    S3FS_PRN_INFO3("[tpath=%s]", SAFESTRPTR(tpath));

    if(!tpath){
        return -EINVAL;
    }
    if(!CreateCurlHandle()){
        return -EIO;
    }
    std::string resource;
    std::string turl;
    MakeUrlResource(get_realpath(tpath).c_str(), resource, turl);

    // [NOTE]
    // Encode the upload_id here.
    // In compatible S3 servers(Cloudflare, etc), there are cases where characters that require URL encoding are included.
    //
    query_string    = "uploadId=" + urlEncodeGeneral(upload_id);
    turl           += "?" + query_string;
    url             = prepare_url(turl.c_str());
    path            = get_realpath(tpath);
    requestHeaders  = nullptr;
    responseHeaders.clear();

    op = "DELETE";
    type = REQTYPE::ABORTMULTIUPLOAD;

    if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str())){
        return -EIO;
    }
    if(CURLE_OK != curl_easy_setopt(hCurl, CURLOPT_CUSTOMREQUEST, "DELETE")){
        return -EIO;
    }
    if(!S3fsCurl::AddUserAgent(hCurl)){                            // put User-Agent
        return -EIO;
    }

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
int S3fsCurl::UploadMultipartPostSetup(const char* tpath, int part_num, const std::string& upload_id)
{
    S3FS_PRN_INFO3("[tpath=%s][start=%lld][size=%lld][part=%d]", SAFESTRPTR(tpath), static_cast<long long int>(partdata.startpos), static_cast<long long int>(partdata.size), part_num);

    if(-1 == partdata.fd || -1 == partdata.startpos || -1 == partdata.size){
        return -EINVAL;
    }

    requestHeaders = nullptr;

    // make md5 and file pointer
    if(S3fsCurl::is_content_md5){
        md5_t md5raw;
        if(!s3fs_md5_fd(partdata.fd, partdata.startpos, partdata.size, &md5raw)){
            S3FS_PRN_ERR("Could not make md5 for file(part %d)", part_num);
            return -EIO;
        }
        partdata.etag = s3fs_hex_lower(md5raw.data(), md5raw.size());
        std::string md5base64 = s3fs_base64(md5raw.data(), md5raw.size());
        requestHeaders = curl_slist_sort_insert(requestHeaders, "Content-MD5", md5base64.c_str());
    }

    // make request
    //
    // [NOTE]
    // Encode the upload_id here.
    // In compatible S3 servers(Cloudflare, etc), there are cases where characters that require URL encoding are included.
    //
    query_string        = "partNumber=" + std::to_string(part_num) + "&uploadId=" + urlEncodeGeneral(upload_id);
    std::string urlargs = "?" + query_string;
    std::string resource;
    std::string turl;
    MakeUrlResource(get_realpath(tpath).c_str(), resource, turl);

    turl              += urlargs;
    url                = prepare_url(turl.c_str());
    path               = get_realpath(tpath);
    bodydata.clear();
    headdata.clear();
    responseHeaders.clear();

    // SSE-C
    if(sse_type_t::SSE_C == S3fsCurl::GetSseType()){
        std::string ssevalue;
        if(!AddSseRequestHead(S3fsCurl::GetSseType(), ssevalue, false)){
            S3FS_PRN_WARN("Failed to set SSE header, but continue...");
        }
    }

    requestHeaders = curl_slist_sort_insert(requestHeaders, "Accept", nullptr);

    op = "PUT";
    type = REQTYPE::UPLOADMULTIPOST;

    // set lazy function
    fpLazySetup = UploadMultipartPostSetCurlOpts;

    return 0;
}

int S3fsCurl::UploadMultipartPostRequest(const char* tpath, int part_num, const std::string& upload_id)
{
    int result;

    S3FS_PRN_INFO3("[tpath=%s][start=%lld][size=%lld][part=%d]", SAFESTRPTR(tpath), static_cast<long long int>(partdata.startpos), static_cast<long long int>(partdata.size), part_num);

    // setup
    if(0 != (result = S3fsCurl::UploadMultipartPostSetup(tpath, part_num, upload_id))){
        return result;
    }

    if(!fpLazySetup || !fpLazySetup(this)){
        S3FS_PRN_ERR("Failed to lazy setup in multipart upload post request.");
        return -EIO;
    }

    // request
    if(0 == (result = RequestPerform())){
        // UploadMultipartPostComplete returns true on success -> convert to 0
        result = !UploadMultipartPostComplete();
    }

    // closing
    bodydata.clear();
    headdata.clear();

    return result;
}

int S3fsCurl::CopyMultipartPostSetup(const char* from, const char* to, int part_num, const std::string& upload_id, headers_t& meta)
{
    S3FS_PRN_INFO3("[from=%s][to=%s][part=%d]", SAFESTRPTR(from), SAFESTRPTR(to), part_num);

    if(!from || !to){
        return -EINVAL;
    }
    // [NOTE]
    // Encode the upload_id here.
    // In compatible S3 servers(Cloudflare, etc), there are cases where characters that require URL encoding are included.
    //
    query_string = "partNumber=" + std::to_string(part_num) + "&uploadId=" + urlEncodeGeneral(upload_id);
    std::string urlargs = "?" + query_string;
    std::string resource;
    std::string turl;
    MakeUrlResource(get_realpath(to).c_str(), resource, turl);

    turl           += urlargs;
    url             = prepare_url(turl.c_str());
    path            = get_realpath(to);
    requestHeaders  = nullptr;
    responseHeaders.clear();
    bodydata.clear();
    headdata.clear();

    std::string contype = S3fsCurl::LookupMimeType(to);
    requestHeaders = curl_slist_sort_insert(requestHeaders, "Content-Type", contype.c_str());

    // Make request headers
    for(headers_t::iterator iter = meta.begin(); iter != meta.end(); ++iter){
        std::string key   = lower(iter->first);
        std::string value = iter->second;
        if(key == "x-amz-copy-source"){
            requestHeaders = curl_slist_sort_insert(requestHeaders, iter->first.c_str(), value.c_str());
        }else if(key == "x-amz-copy-source-range"){
            requestHeaders = curl_slist_sort_insert(requestHeaders, iter->first.c_str(), value.c_str());
        }else if(key == "x-amz-server-side-encryption" && value != "aws:kms"){
            // skip this header
        }else if(key == "x-amz-server-side-encryption-aws-kms-key-id"){
            // skip this header
        }else if(key == "x-amz-server-side-encryption-customer-key-md5"){
            if(!AddSseRequestHead(sse_type_t::SSE_C, value, true)){
                S3FS_PRN_WARN("Failed to insert SSE-C header.");
            }
        }
    }
    // SSE-C
    if(sse_type_t::SSE_C == S3fsCurl::GetSseType()){
        std::string ssevalue;
        if(!AddSseRequestHead(S3fsCurl::GetSseType(), ssevalue, false)){
            S3FS_PRN_WARN("Failed to set SSE header, but continue...");
        }
    }

    op = "PUT";
    type = REQTYPE::COPYMULTIPOST;

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
    std::string etag = peeloff(it->second);

    // check etag(md5);
    //
    // The ETAG when using SSE_C and SSE_KMS does not reflect the MD5 we sent  
    // SSE_C: https://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectPUT.html
    // SSE_KMS is ignored in the above, but in the following it states the same in the highlights:  
    // https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingKMSEncryption.html
    //
    if(S3fsCurl::is_content_md5 && sse_type_t::SSE_C != S3fsCurl::GetSseType() && sse_type_t::SSE_KMS != S3fsCurl::GetSseType()){
        if(!etag_equals(etag, partdata.etag)){
            return false;
        }
    }
    partdata.petag->etag = etag;
    partdata.uploaded = true;

    return true;
}

// cppcheck-suppress unmatchedSuppression
// cppcheck-suppress constParameter
// cppcheck-suppress constParameterCallback
bool S3fsCurl::CopyMultipartPostCallback(S3fsCurl* s3fscurl, void* param)
{
    if(!s3fscurl || param){     // this callback does not need a parameter
        return false;
    }

    // cppcheck-suppress unmatchedSuppression
    // cppcheck-suppress knownConditionTrueFalse
    return s3fscurl->CopyMultipartPostComplete();
}

bool S3fsCurl::CopyMultipartPostComplete()
{
    std::string etag;
    partdata.uploaded = simple_parse_xml(bodydata.c_str(), bodydata.size(), "ETag", etag);
    partdata.petag->etag = peeloff(etag);

    bodydata.clear();
    headdata.clear();

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
    std::string    upload_id;
    off_t          chunk;
    off_t          bytes_remaining;
    etaglist_t     list;

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
        chunk = bytes_remaining > GetMultipartCopySize() ? GetMultipartCopySize() : bytes_remaining;

        std::ostringstream strrange;
        strrange << "bytes=" << (size - bytes_remaining) << "-" << (size - bytes_remaining + chunk - 1);
        meta["x-amz-copy-source-range"] = strrange.str();

        // s3fscurl sub object
        std::unique_ptr<S3fsCurl> s3fscurl_para(new S3fsCurl(true));
        s3fscurl_para->b_from   = SAFESTRPTR(tpath);
        s3fscurl_para->b_meta   = meta;
        s3fscurl_para->partdata.add_etag_list(list);

        // initiate upload part for parallel
        if(0 != (result = s3fscurl_para->CopyMultipartPostSetup(tpath, tpath, s3fscurl_para->partdata.get_part_number(), upload_id, meta))){
            S3FS_PRN_ERR("failed uploading part setup(%d)", result);
            return result;
        }

        // set into parallel object
        if(!curlmulti.SetS3fsCurlObject(std::move(s3fscurl_para))){
            S3FS_PRN_ERR("Could not make curl object into multi curl(%s).", tpath);
            return -EIO;
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

int S3fsCurl::MultipartUploadRequest(const std::string& upload_id, const char* tpath, int fd, off_t offset, off_t size, etagpair* petagpair)
{
    S3FS_PRN_INFO3("[upload_id=%s][tpath=%s][fd=%d][offset=%lld][size=%lld]", upload_id.c_str(), SAFESTRPTR(tpath), fd, static_cast<long long int>(offset), static_cast<long long int>(size));

    // set
    partdata.fd         = fd;
    partdata.startpos   = offset;
    partdata.size       = size;
    b_partdata_startpos = partdata.startpos;
    b_partdata_size     = partdata.size;
    partdata.set_etag(petagpair);

    // upload part
    int   result;
    if(0 != (result = UploadMultipartPostRequest(tpath, petagpair->part_num, upload_id))){
        S3FS_PRN_ERR("failed uploading %d part by error(%d)", petagpair->part_num, result);
        return result;
    }
    DestroyCurlHandle();

    return 0;
}

int S3fsCurl::MultipartRenameRequest(const char* from, const char* to, headers_t& meta, off_t size)
{
    int            result;
    std::string    upload_id;
    off_t          chunk;
    off_t          bytes_remaining;
    etaglist_t     list;

    S3FS_PRN_INFO3("[from=%s][to=%s]", SAFESTRPTR(from), SAFESTRPTR(to));

    std::string srcresource;
    std::string srcurl;
    MakeUrlResource(get_realpath(from).c_str(), srcresource, srcurl);

    meta["Content-Type"]      = S3fsCurl::LookupMimeType(to);
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
        chunk = bytes_remaining > GetMultipartCopySize() ? GetMultipartCopySize() : bytes_remaining;

        std::ostringstream strrange;
        strrange << "bytes=" << (size - bytes_remaining) << "-" << (size - bytes_remaining + chunk - 1);
        meta["x-amz-copy-source-range"] = strrange.str();

        // s3fscurl sub object
        std::unique_ptr<S3fsCurl> s3fscurl_para(new S3fsCurl(true));
        s3fscurl_para->b_from   = SAFESTRPTR(from);
        s3fscurl_para->b_meta   = meta;
        s3fscurl_para->partdata.add_etag_list(list);

        // initiate upload part for parallel
        if(0 != (result = s3fscurl_para->CopyMultipartPostSetup(from, to, s3fscurl_para->partdata.get_part_number(), upload_id, meta))){
            S3FS_PRN_ERR("failed uploading part setup(%d)", result);
            return result;
        }

        // set into parallel object
        if(!curlmulti.SetS3fsCurlObject(std::move(s3fscurl_para))){
            S3FS_PRN_ERR("Could not make curl object into multi curl(%s).", to);
            return -EIO;
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

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
