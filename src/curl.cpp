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
#include <unistd.h>
#include <fstream>
#include <sstream>
#include <algorithm>

#include "common.h"
#include "s3fs.h"
#include "curl.h"
#include "curl_multi.h"
#include "curl_util.h"
#include "s3fs_auth.h"
#include "autolock.h"
#include "s3fs_util.h"
#include "string_util.h"
#include "addhead.h"

//-------------------------------------------------------------------
// Symbols
//-------------------------------------------------------------------
static const std::string empty_payload_hash         = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

//-------------------------------------------------------------------
// Class S3fsCurl
//-------------------------------------------------------------------
static const int MULTIPART_SIZE                     = 10 * 1024 * 1024;

static const int IAM_EXPIRE_MERGIN                  = 20 * 60;  // update timing
static const std::string ECS_IAM_ENV_VAR            = "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI";
static const std::string IAMCRED_ACCESSKEYID        = "AccessKeyId";
static const std::string IAMCRED_SECRETACCESSKEY    = "SecretAccessKey";
static const std::string IAMCRED_ROLEARN            = "RoleArn";

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
static const char* DEFAULT_MIME_FILE                = "/etc/mime.types";
static const char* SPECIAL_DARWIN_MIME_FILE         = "/etc/apache2/mime.types";

// [NOTICE]
// This symbol is for libcurl under 7.23.0
#ifndef CURLSHE_NOT_BUILT_IN
#define CURLSHE_NOT_BUILT_IN                        5
#endif

//-------------------------------------------------------------------
// Class S3fsCurl
//-------------------------------------------------------------------
const long       S3fsCurl::S3FSCURL_RESPONSECODE_NOTSET;
const long       S3fsCurl::S3FSCURL_RESPONSECODE_FATAL_ERROR;
const int        S3fsCurl::S3FSCURL_PERFORM_RESULT_NOTSET;
pthread_mutex_t  S3fsCurl::curl_warnings_lock;
pthread_mutex_t  S3fsCurl::curl_handles_lock;
S3fsCurl::callback_locks_t S3fsCurl::callback_locks;
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
acl_t            S3fsCurl::default_acl         = acl_t::PRIVATE;
storage_class_t  S3fsCurl::storage_class       = storage_class_t::STANDARD;
sseckeylist_t    S3fsCurl::sseckeys;
std::string      S3fsCurl::ssekmsid;
sse_type_t       S3fsCurl::ssetype             = sse_type_t::SSE_DISABLE;
bool             S3fsCurl::is_content_md5      = false;
bool             S3fsCurl::is_verbose          = false;
bool             S3fsCurl::is_dump_body        = false;
std::string      S3fsCurl::AWSAccessKeyId;
std::string      S3fsCurl::AWSSecretAccessKey;
std::string      S3fsCurl::AWSAccessToken;
time_t           S3fsCurl::AWSAccessTokenExpire= 0;
bool             S3fsCurl::is_ecs              = false;
bool             S3fsCurl::is_ibm_iam_auth     = false;
std::string      S3fsCurl::IAM_cred_url        = "http://169.254.169.254/latest/meta-data/iam/security-credentials/";
std::string      S3fsCurl::IAMv2_token_url     = "http://169.254.169.254/latest/api/token";
std::string      S3fsCurl::IAMv2_token_ttl_hdr = "X-aws-ec2-metadata-token-ttl-seconds";
std::string      S3fsCurl::IAMv2_token_hdr     = "X-aws-ec2-metadata-token";
int              S3fsCurl::IAMv2_token_ttl     = 21600;
size_t           S3fsCurl::IAM_field_count     = 4;
std::string      S3fsCurl::IAM_token_field     = "Token";
std::string      S3fsCurl::IAM_expiry_field    = "Expiration";
std::string      S3fsCurl::IAM_role;
std::string      S3fsCurl::IAMv2_api_token;
int              S3fsCurl::IAM_api_version     = 2;
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
signature_type_t S3fsCurl::signature_type      = V2_OR_V4;       // default
bool             S3fsCurl::is_ua               = true;           // default
bool             S3fsCurl::listobjectsv2       = false;          // default
bool             S3fsCurl::is_use_session_token= false;          // default
bool             S3fsCurl::requester_pays      = false;          // default

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
    sCurlPool = NULL;
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
    S3fsCurl::hCurlShare = NULL;
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
    time_t     now = time(0);
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
            // for macos, search another default file.
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

    std::string line;
    std::ifstream MT(MimeFile.c_str());
    if(MT.good()){
        S3FS_PRN_DBG("The old mime types are cleared to load new mime types.");
        S3fsCurl::mimeTypes.clear();

        while(getline(MT, line)){
            if(line[0]=='#'){
                continue;
            }
            if(line.empty()){
                continue;
            }

            std::istringstream tmp(line);
            std::string mimeType;
            tmp >> mimeType;
            while(tmp){
                std::string ext;
                tmp >> ext;
                if(ext.empty()){
                    continue;
                }
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
        if(CURL_CA_BUNDLE != NULL)  {
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
    S3fsCurl* pCurl = static_cast<S3fsCurl*>(userp);

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
    S3fsCurl* pCurl = static_cast<S3fsCurl*>(userp);

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

storage_class_t S3fsCurl::SetStorageClass(storage_class_t storage_class)
{
    storage_class_t old = S3fsCurl::storage_class;
    S3fsCurl::storage_class = storage_class;
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
        char* p_key;
        size_t keylength;

        if(NULL != (p_key = (char *)s3fs_decode64(onekey.c_str(), &keylength))) {
            raw_key = std::string(p_key, keylength);
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
            if(S3fsCurl::GetSignatureType() == V2_ONLY){
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
    if(NULL == envkeys){
        // nothing to do
        return true;
    }
    S3fsCurl::sseckeys.clear();

    std::istringstream fullkeys(envkeys);
    std::string        onekey;
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
bool S3fsCurl::GetSseKey(std::string& md5, std::string& ssekey)
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

bool S3fsCurl::GetSseKeyMd5(int pos, std::string& md5)
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

bool S3fsCurl::SetDumpBody(bool flag)
{
    bool old = S3fsCurl::is_dump_body;
    S3fsCurl::is_dump_body = flag;
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

std::string S3fsCurl::SetIAMRole(const char* role)
{
    std::string old = S3fsCurl::IAM_role;
    S3fsCurl::IAM_role = role ? role : "";
    return old;
}

size_t S3fsCurl::SetIAMFieldCount(size_t field_count)
{
    size_t old = S3fsCurl::IAM_field_count;
    S3fsCurl::IAM_field_count = field_count;
    return old;
}

std::string S3fsCurl::SetIAMCredentialsURL(const char* url)
{
    std::string old = S3fsCurl::IAM_cred_url;
    S3fsCurl::IAM_cred_url = url ? url : "";
    return old;
}

std::string S3fsCurl::SetIAMTokenField(const char* token_field)
{
    std::string old = S3fsCurl::IAM_token_field;
    S3fsCurl::IAM_token_field = token_field ? token_field : "";
    return old;
}

std::string S3fsCurl::SetIAMExpiryField(const char* expiry_field)
{
    std::string old = S3fsCurl::IAM_expiry_field;
    S3fsCurl::IAM_expiry_field = expiry_field ? expiry_field : "";
    return old;
}

bool S3fsCurl::SetIMDSVersion(int version)
{
    S3fsCurl::IAM_api_version = version;
    return true;
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
    std::string upload_id;
    std::string part_num_str;
    int    part_num;
    off_t  tmp_part_num = 0;
    if(!get_keyword_value(s3fscurl->url, "uploadId", upload_id)){
        return NULL;
    }
    if(!get_keyword_value(s3fscurl->url, "partNumber", part_num_str)){
        return NULL;
    }
    if(!s3fs_strtoofft(&tmp_part_num, part_num_str.c_str(), /*base=*/ 10)){
        return NULL;
    }
    part_num = static_cast<off_t>(tmp_part_num);

    if(s3fscurl->retry_count >= S3fsCurl::retries){
        S3FS_PRN_ERR("Over retry count(%d) limit(%s:%d).", s3fscurl->retry_count, s3fscurl->path.c_str(), part_num);
        return NULL;
    }

    // duplicate request
    S3fsCurl* newcurl            = new S3fsCurl(s3fscurl->IsUseAhbe());
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
    std::string upload_id;
    std::string part_num_str;
    int    part_num;
    off_t  tmp_part_num = 0;
    if(!get_keyword_value(s3fscurl->url, "uploadId", upload_id)){
        return NULL;
    }
    if(!get_keyword_value(s3fscurl->url, "partNumber", part_num_str)){
        return NULL;
    }
    if(!s3fs_strtoofft(&tmp_part_num, part_num_str.c_str(), /*base=*/ 10)){
        return NULL;
    }
    part_num = static_cast<off_t>(tmp_part_num);

    if(s3fscurl->retry_count >= S3fsCurl::retries){
        S3FS_PRN_ERR("Over retry count(%d) limit(%s:%d).", s3fscurl->retry_count, s3fscurl->path.c_str(), part_num);
        return NULL;
    }

    // duplicate request
    S3fsCurl* newcurl            = new S3fsCurl(s3fscurl->IsUseAhbe());
    newcurl->partdata.petag      = s3fscurl->partdata.petag;
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
    std::string    upload_id;
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

    close(fd2);

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
    int            fd2;
    etaglist_t     list;
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

    if(0 != (result = s3fscurl.PreMultipartPostRequest(tpath, meta, upload_id, true))){
        close(fd2);
        return result;
    }
    s3fscurl.DestroyCurlHandle();

    // for copy multipart
    std::string srcresource;
    std::string srcurl;
    MakeUrlResource(get_realpath(tpath).c_str(), srcresource, srcurl);
    meta["Content-Type"]      = S3fsCurl::LookupMimeType(std::string(tpath));
    meta["x-amz-copy-source"] = srcresource;

    // Initialize S3fsMultiCurl
    S3fsMultiCurl curlmulti(GetMaxParallelCount());
    curlmulti.SetSuccessCallback(S3fsCurl::MixMultipartPostCallback);
    curlmulti.SetRetryCallback(S3fsCurl::MixMultipartPostRetryCallback);

    for(fdpage_list_t::const_iterator iter = mixuppages.begin(); iter != mixuppages.end(); ++iter){
        if(iter->modified){
            // Multipart upload
            S3fsCurl* s3fscurl_para              = new S3fsCurl(true);

            s3fscurl_para->partdata.fd         = fd2;
            s3fscurl_para->partdata.startpos   = iter->offset;
            s3fscurl_para->partdata.size       = iter->bytes;
            s3fscurl_para->b_partdata_startpos = s3fscurl_para->partdata.startpos;
            s3fscurl_para->b_partdata_size     = s3fscurl_para->partdata.size;
            s3fscurl_para->partdata.add_etag_list(&list);

            S3FS_PRN_INFO3("Upload Part [tpath=%s][start=%lld][size=%lld][part=%zu]", SAFESTRPTR(tpath), static_cast<long long>(iter->offset), static_cast<long long>(iter->bytes), list.size());

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
                return -EIO;
            }
        }else{
            // Multipart copy
            for(off_t i = 0; i < iter->bytes; i += GetMultipartCopySize()){
                S3fsCurl* s3fscurl_para              = new S3fsCurl(true);

                off_t bytes = std::min(static_cast<off_t>(GetMultipartCopySize()), iter->bytes - i);
                std::ostringstream strrange;
                strrange << "bytes=" << (iter->offset + i) << "-" << (iter->offset + i + bytes - 1);
                meta["x-amz-copy-source-range"] = strrange.str();

                s3fscurl_para->b_from   = SAFESTRPTR(tpath);
                s3fscurl_para->b_meta   = meta;
                s3fscurl_para->partdata.add_etag_list(&list);

                S3FS_PRN_INFO3("Copy Part [tpath=%s][start=%lld][size=%lld][part=%zu]", SAFESTRPTR(tpath), static_cast<long long>(iter->offset + i), static_cast<long long>(bytes), list.size());

                // initiate upload part for parallel
                if(0 != (result = s3fscurl_para->CopyMultipartPostSetup(tpath, tpath, list.size(), upload_id, meta))){
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
    
    if(0 != (result = newcurl->PreGetObjectRequest(s3fscurl->path.c_str(), s3fscurl->partdata.fd, s3fscurl->partdata.startpos, s3fscurl->partdata.size, s3fscurl->b_ssetype, s3fscurl->b_ssevalue))){
        S3FS_PRN_ERR("failed downloading part setup(%d)", result);
        delete newcurl;
        return NULL;;
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
    std::istringstream sscred(response);
    std::string        oneline;
    keyval.clear();
    while(getline(sscred, oneline, ',')){
        std::string::size_type pos;
        std::string            key;
        std::string            val;
        if(std::string::npos != (pos = oneline.find(IAMCRED_ACCESSKEYID))){
            key = IAMCRED_ACCESSKEYID;
        }else if(std::string::npos != (pos = oneline.find(IAMCRED_SECRETACCESSKEY))){
            key = IAMCRED_SECRETACCESSKEY;
        }else if(std::string::npos != (pos = oneline.find(S3fsCurl::IAM_token_field))){
            key = S3fsCurl::IAM_token_field;
        }else if(std::string::npos != (pos = oneline.find(S3fsCurl::IAM_expiry_field))){
            key = S3fsCurl::IAM_expiry_field;
        }else if(std::string::npos != (pos = oneline.find(IAMCRED_ROLEARN))){
            key = IAMCRED_ROLEARN;
        }else{
            continue;
        }
        if(std::string::npos == (pos = oneline.find(':', pos + key.length()))){
            continue;
        }

        if(S3fsCurl::is_ibm_iam_auth && key == S3fsCurl::IAM_expiry_field){
            // parse integer value
            if(std::string::npos == (pos = oneline.find_first_of("0123456789", pos))){
                continue;
            }
            oneline.erase(0, pos);
            if(std::string::npos == (pos = oneline.find_last_of("0123456789"))){
                continue;
            }
            val = oneline.substr(0, pos+1);
        }else{
            // parse std::string value (starts and ends with quotes)
            if(std::string::npos == (pos = oneline.find('\"', pos))){
                continue;
            }
            oneline.erase(0, pos+1);
            if(std::string::npos == (pos = oneline.find('\"'))){
                continue;
            }
            val = oneline.substr(0, pos);
        }
        keyval[key] = val;
    }
    return true;
}

bool S3fsCurl::SetIAMv2APIToken(const char* response)
{
    S3FS_PRN_INFO3("Setting AWS IMDSv2 API token to %s", response);
    S3fsCurl::IAMv2_api_token = std::string(response);
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

    S3fsCurl::AWSAccessToken       = keyval[std::string(S3fsCurl::IAM_token_field)];

    if(S3fsCurl::is_ibm_iam_auth){
        off_t tmp_expire = 0;
        if(!s3fs_strtoofft(&tmp_expire, keyval[std::string(S3fsCurl::IAM_expiry_field)].c_str(), /*base=*/ 10)){
            return false;
        }
        S3fsCurl::AWSAccessTokenExpire = static_cast<time_t>(tmp_expire);
    }else{
        S3fsCurl::AWSAccessKeyId       = keyval[std::string(IAMCRED_ACCESSKEYID)];
        S3fsCurl::AWSSecretAccessKey   = keyval[std::string(IAMCRED_SECRETACCESSKEY)];
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
    S3FS_PRN_INFO("IAM Access Token refreshing...");
    // update
    S3fsCurl s3fscurl;
    if(0 != s3fscurl.GetIAMCredentials()){
        S3FS_PRN_ERR("IAM Access Token refresh failed");
        return false;
    }
    S3FS_PRN_INFO("IAM Access Token refreshed");
    return true;
}

bool S3fsCurl::ParseIAMRoleFromMetaDataResponse(const char* response, std::string& rolename)
{
    if(!response){
        return false;
    }
    // [NOTE]
    // expected following strings.
    // 
    // myrolename
    //
    std::istringstream ssrole(response);
    std::string        oneline;
    if (getline(ssrole, oneline, '\n')){
        rolename = oneline;
        return !rolename.empty();
    }
    return false;
}

bool S3fsCurl::SetIAMRoleFromMetaData(const char* response)
{
    S3FS_PRN_INFO3("IAM role name response = \"%s\"", response);

    std::string rolename;

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
    return S3fsCurl::RawCurlDebugFunc(hcurl, type, data, size, userptr, CURLINFO_END);
}

int S3fsCurl::CurlDebugBodyInFunc(CURL* hcurl, curl_infotype type, char* data, size_t size, void* userptr)
{
    return S3fsCurl::RawCurlDebugFunc(hcurl, type, data, size, userptr, CURLINFO_DATA_IN);
}

int S3fsCurl::CurlDebugBodyOutFunc(CURL* hcurl, curl_infotype type, char* data, size_t size, void* userptr)
{
    return S3fsCurl::RawCurlDebugFunc(hcurl, type, data, size, userptr, CURLINFO_DATA_OUT);
}

int S3fsCurl::RawCurlDebugFunc(CURL* hcurl, curl_infotype type, char* data, size_t size, void* userptr, curl_infotype datatype)
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
                S3FS_PRN_CURL("%s %.*s", getCurlDebugHead(type), (int)length - newline, p);
                remaining -= length;
                p = eol;
            } while (p != NULL && remaining > 0);
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
    hCurl(NULL), type(REQTYPE_UNSET), requestHeaders(NULL),
    LastResponseCode(S3FSCURL_RESPONSECODE_NOTSET), postdata(NULL), postdata_remaining(0), is_use_ahbe(ahbe),
    retry_count(0), b_infile(NULL), b_postdata(NULL), b_postdata_remaining(0), b_partdata_startpos(0), b_partdata_size(0),
    b_ssekey_pos(-1), b_ssetype(sse_type_t::SSE_DISABLE),
    sem(NULL), completed_tids_lock(NULL), completed_tids(NULL), fpLazySetup(NULL)
{
}

S3fsCurl::~S3fsCurl()
{
    DestroyCurlHandle();
}

bool S3fsCurl::ResetHandle(bool lock_already_held)
{
    bool run_once;
    {
        AutoLock lock(&S3fsCurl::curl_warnings_lock);
        run_once = curl_warnings_once;
        curl_warnings_once = true;
    }

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
        curl_easy_setopt(hCurl, CURLOPT_DEBUGFUNCTION, S3fsCurl::CurlDebugFunc);
    }
    if(!cipher_suites.empty()) {
        curl_easy_setopt(hCurl, CURLOPT_SSL_CIPHER_LIST, cipher_suites.c_str());
    }

    AutoLock lock(&S3fsCurl::curl_handles_lock, lock_already_held ? AutoLock::ALREADY_LOCKED : AutoLock::NONE);
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
    ResetHandle(/*lock_already_held=*/ true);

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
    requestHeaders = curl_slist_remove(requestHeaders, "Authorization");
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
int S3fsCurl::RequestPerform(bool dontAddAuthHeaders /*=false*/)
{
    if(S3fsLog::IsS3fsLogDbg()){
        char* ptr_url = NULL;
        curl_easy_getinfo(hCurl, CURLINFO_EFFECTIVE_URL , &ptr_url);
        S3FS_PRN_DBG("connecting to URL %s", SAFESTRPTR(ptr_url));
    }

    LastResponseCode  = S3FSCURL_RESPONSECODE_NOTSET;
    long responseCode;
    int result        = S3FSCURL_PERFORM_RESULT_NOTSET;

    // 1 attempt + retries...
    for(int retrycnt = 0; S3FSCURL_PERFORM_RESULT_NOTSET == result && retrycnt < S3fsCurl::retries; ++retrycnt){
        // Reset response code
        responseCode = S3FSCURL_RESPONSECODE_NOTSET;
        
        // Insert headers
        if(!dontAddAuthHeaders) {
             insertAuthHeaders();
        }

        curl_easy_setopt(hCurl, CURLOPT_HTTPHEADER, requestHeaders);

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
                    if(simple_parse_xml(bodydata.str(), bodydata.size(), "Code", value)){
                        // TODO: other error codes
                        if(value == "EntityTooLarge"){
                            result = -EFBIG;
                            break;
                        }
                    }
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
                        if(op == "HEAD"){
                            S3FS_PRN_ERR("HEAD HTTP response code %ld, returning EPERM. Body Text: %s", responseCode, bodydata.str());
                            result = -EPERM;
                        }else{
                            S3FS_PRN_ERR("HTTP response code %ld, returning EIO. Body Text: %s", responseCode, bodydata.str());
                            result = -EIO;
                        }
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

                    case 416:
                        S3FS_PRN_INFO3("HTTP response code 416 was returned, returning EIO");
                        result = -EIO;
                        break;

                    case 501:
                        S3FS_PRN_INFO3("HTTP response code 501 was returned, returning ENOTSUP");
                        S3FS_PRN_DBG("Body Text: %s", bodydata.str());
                        result = -ENOTSUP;
                        break;

                    case 500:
                    case 503:
                        S3FS_PRN_INFO3("HTTP response code %ld was returned, slowing down", responseCode);
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
                {
                    AutoLock lock(&S3fsCurl::curl_handles_lock);
                    S3fsCurl::curl_times[hCurl] = time(0);
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

                first_pos = bucket.find_first_of('.');
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
std::string S3fsCurl::CalcSignatureV2(const std::string& method, const std::string& strMD5, const std::string& content_type, const std::string& date, const std::string& resource)
{
    std::string Signature;
    std::string StringToSign;

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
        return std::string("");  // ENOMEM
    }
    delete[] md;

    Signature = base64;
    delete[] base64;

    return Signature;
}

std::string S3fsCurl::CalcSignature(const std::string& method, const std::string& canonical_uri, const std::string& query_string, const std::string& strdate, const std::string& payload_hash, const std::string& date8601)
{
    std::string Signature, StringCQ, StringToSign;
    std::string uriencode;

    if(!S3fsCurl::IAM_role.empty()  || S3fsCurl::is_ecs || S3fsCurl::is_use_session_token){
        requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-security-token", S3fsCurl::AWSAccessToken.c_str());
    }

    uriencode = urlEncode(canonical_uri);
    StringCQ  = method + "\n";
    if(method == "HEAD" || method == "PUT" || method == "DELETE"){
        StringCQ += uriencode + "\n";
    }else if(method == "GET" && uriencode.empty()){
        StringCQ +="/\n";
    }else if(method == "GET" && is_prefix(uriencode.c_str(), "/")){
        StringCQ += uriencode +"\n";
    }else if(method == "GET" && !is_prefix(uriencode.c_str(), "/")){
        StringCQ += "/\n" + urlEncode2(canonical_uri) +"\n";
    }else if(method == "POST"){
        StringCQ += uriencode + "\n";
    }
    StringCQ += urlEncode2(query_string) + "\n";
    StringCQ += get_canonical_headers(requestHeaders) + "\n";
    StringCQ += get_sorted_header_keys(requestHeaders) + "\n";
    StringCQ += payload_hash;

    char          kSecret[128];
    unsigned char *kDate, *kRegion, *kService, *kSigning, *sRequest               = NULL;
    unsigned int  kDate_len,kRegion_len, kService_len, kSigning_len, sRequest_len = 0;
    int           kSecret_len = snprintf(kSecret, sizeof(kSecret), "AWS4%s", S3fsCurl::AWSSecretAccessKey.c_str());

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

    StringToSign  = "AWS4-HMAC-SHA256\n";
    StringToSign += date8601 + "\n";
    StringToSign += strdate + "/" + endpoint + "/s3/aws4_request\n";
    StringToSign += s3fs_hex(sRequest, sRequest_len);
    delete[] sRequest;

    const unsigned char* cscope     = reinterpret_cast<const unsigned char*>(StringToSign.c_str());
    unsigned int         cscope_len = StringToSign.size();
    unsigned char*       md         = NULL;
    unsigned int         md_len     = 0;

    s3fs_HMAC256(kSigning, kSigning_len, cscope, cscope_len, &md, &md_len);
    delete[] kSigning;

    Signature = s3fs_hex(md, md_len);
    delete[] md;

    return Signature;
}

void S3fsCurl::insertV4Headers()
{
    std::string server_path = type == REQTYPE_LISTBUCKET ? "/" : path;
    std::string payload_hash;
    switch (type) {
        case REQTYPE_PUT:
            payload_hash = s3fs_sha256_hex_fd(b_infile == NULL ? -1 : fileno(b_infile), 0, -1);
            break;

        case REQTYPE_COMPLETEMULTIPOST:
            {
                unsigned int    cRequest_len = strlen(reinterpret_cast<const char *>(b_postdata));
                unsigned char*  sRequest     = NULL;
                unsigned int    sRequest_len = 0;
                s3fs_sha256(b_postdata, cRequest_len, &sRequest, &sRequest_len);
                payload_hash = s3fs_hex(sRequest, sRequest_len);
                delete[] sRequest;
                break;
            }

        case REQTYPE_UPLOADMULTIPOST:
            payload_hash = s3fs_sha256_hex_fd(partdata.fd, partdata.startpos, partdata.size);
            break;
        default:
            break;
    }

    if(b_infile != NULL && 0 == payload_hash.length()){
        S3FS_PRN_ERR("Failed to make SHA256.");
        // TODO: propagate error
    }

    S3FS_PRN_INFO3("computing signature [%s] [%s] [%s] [%s]", op.c_str(), server_path.c_str(), query_string.c_str(), payload_hash.c_str());
    std::string strdate;
    std::string date8601;
    get_date_sigv3(strdate, date8601);

    std::string contentSHA256 = payload_hash.empty() ? empty_payload_hash : payload_hash;
    const std::string realpath = pathrequeststyle ? "/" + bucket + server_path : server_path;

    //string canonical_headers, signed_headers;
    requestHeaders = curl_slist_sort_insert(requestHeaders, "host", get_bucket_host().c_str());
    requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-content-sha256", contentSHA256.c_str());
    requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-date", date8601.c_str());

    if (S3fsCurl::IsRequesterPays()) {
        requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-request-payer", "requester");
    }

    if(!S3fsCurl::IsPublicBucket()){
        std::string Signature = CalcSignature(op, realpath, query_string + (type == REQTYPE_PREMULTIPOST || type == REQTYPE_MULTILIST ? "=" : ""), strdate, contentSHA256, date8601);
        std::string auth = "AWS4-HMAC-SHA256 Credential=" + AWSAccessKeyId + "/" + strdate + "/" + endpoint + "/s3/aws4_request, SignedHeaders=" + get_sorted_header_keys(requestHeaders) + ", Signature=" + Signature;
        requestHeaders = curl_slist_sort_insert(requestHeaders, "Authorization", auth.c_str());
    }
}

void S3fsCurl::insertV2Headers()
{
    std::string resource;
    std::string turl;
    std::string server_path = type == REQTYPE_LISTBUCKET ? "/" : path;
    MakeUrlResource(server_path.c_str(), resource, turl);
    if(!query_string.empty() && type != REQTYPE_CHKBUCKET && type != REQTYPE_LISTBUCKET){
        resource += "?" + query_string;
    }

    std::string date = get_date_rfc850();
    requestHeaders = curl_slist_sort_insert(requestHeaders, "Date", date.c_str());
    if(op != "PUT" && op != "POST"){
        requestHeaders = curl_slist_sort_insert(requestHeaders, "Content-Type", NULL);
    }

    if(!S3fsCurl::IsPublicBucket()){
        std::string Signature = CalcSignatureV2(op, get_header_value(requestHeaders, "Content-MD5"), get_header_value(requestHeaders, "Content-Type"), date, resource);
        requestHeaders   = curl_slist_sort_insert(requestHeaders, "Authorization", std::string("AWS " + AWSAccessKeyId + ":" + Signature).c_str());
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
    }else if(S3fsCurl::signature_type == V2_ONLY){
        insertV2Headers();
    }else{
        insertV4Headers();
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
// Get the token that we need to pass along with AWS IMDSv2 API requests
//
int S3fsCurl::GetIAMv2ApiToken()
{
    url = std::string(S3fsCurl::IAMv2_token_url);
    if(!CreateCurlHandle()){
        return -EIO;
    }
    requestHeaders  = NULL;
    responseHeaders.clear();
    bodydata.Clear();

    // maximum allowed value is 21600, so 6 bytes for the C string
    char ttlstr[6];
    snprintf(ttlstr, sizeof(ttlstr), "%d", S3fsCurl::IAMv2_token_ttl);
    requestHeaders = curl_slist_sort_insert(requestHeaders, S3fsCurl::IAMv2_token_ttl_hdr.c_str(),
                                            ttlstr);
    curl_easy_setopt(hCurl, CURLOPT_PUT, true);
    curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, (void*)&bodydata);
    curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    S3fsCurl::AddUserAgent(hCurl);

    int result = RequestPerform(true);

    if(0 == result && !S3fsCurl::SetIAMv2APIToken(bodydata.str())){
        S3FS_PRN_ERR("Error storing IMDSv2 API token.");
        result = -EIO;
    }
    bodydata.Clear();
    curl_easy_setopt(hCurl, CURLOPT_PUT, false);

    return result;
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
    if(is_ecs){
        const char *env = std::getenv(ECS_IAM_ENV_VAR.c_str());
        if(env == NULL){
            S3FS_PRN_ERR("%s is not set.", ECS_IAM_ENV_VAR.c_str());
            return -EIO;
        }
        url = std::string(S3fsCurl::IAM_cred_url) + env;
    }else{
        if(S3fsCurl::IAM_api_version > 1){
            int result = GetIAMv2ApiToken();
            if(-ENOENT == result){
                // If we get a 404 back when requesting the token service,
                // then it's highly likely we're running in an environment
                // that doesn't support the AWS IMDSv2 API, so we'll skip
                // the token retrieval in the future.
                SetIMDSVersion(1);
            }else if(result != 0){
                // If we get an unexpected error when retrieving the API
                // token, log it but continue.  Requirement for including
                // an API token with the metadata request may or may not
                // be required, so we should not abort here.
                S3FS_PRN_ERR("AWS IMDSv2 token retrieval failed: %d", result);
            }
        }
        
        url = std::string(S3fsCurl::IAM_cred_url) + S3fsCurl::IAM_role;
    }

    requestHeaders  = NULL;
    responseHeaders.clear();
    bodydata.Clear();
    std::string postContent;

    if(S3fsCurl::is_ibm_iam_auth){
        url = std::string(S3fsCurl::IAM_cred_url);

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

    if(S3fsCurl::IAM_api_version > 1){
        requestHeaders = curl_slist_sort_insert(requestHeaders, S3fsCurl::IAMv2_token_hdr.c_str(), S3fsCurl::IAMv2_api_token.c_str());
    }

    curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, (void*)&bodydata);
    curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    S3fsCurl::AddUserAgent(hCurl);        // put User-Agent

    int result = RequestPerform(true);

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
    url             = std::string(S3fsCurl::IAM_cred_url);
    requestHeaders  = NULL;
    responseHeaders.clear();
    bodydata.Clear();

    curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, (void*)&bodydata);
    curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    S3fsCurl::AddUserAgent(hCurl);        // put User-Agent

    int result = RequestPerform(true);

    // analyzing response
    if(0 == result && !S3fsCurl::SetIAMRoleFromMetaData(bodydata.str())){
        S3FS_PRN_ERR("Something error occurred, could not get IAM role name.");
        result = -EIO;
    }
    bodydata.Clear();

    return (0 == result);
}

bool S3fsCurl::AddSseRequestHead(sse_type_t ssetype, const std::string& input, bool is_only_c, bool is_copy)
{
    std::string ssevalue = input;
    switch(ssetype){
        case sse_type_t::SSE_DISABLE:
            return true;
        case sse_type_t::SSE_S3:
            if(!is_only_c){
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
            if(!is_only_c){
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
bool S3fsCurl::PreHeadRequest(const char* tpath, const char* bpath, const char* savedpath, int ssekey_pos)
{
    S3FS_PRN_INFO3("[tpath=%s][bpath=%s][save=%s][sseckeypos=%d]", SAFESTRPTR(tpath), SAFESTRPTR(bpath), SAFESTRPTR(savedpath), ssekey_pos);

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
    requestHeaders  = NULL;
    responseHeaders.clear();

    // requestHeaders
    if(0 <= ssekey_pos){
        std::string md5;
        if(!S3fsCurl::GetSseKeyMd5(ssekey_pos, md5) || !AddSseRequestHead(sse_type_t::SSE_C, md5, true, false)){
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
    requestHeaders  = NULL;
    responseHeaders.clear();
    bodydata.Clear();

    std::string contype = S3fsCurl::LookupMimeType(std::string(tpath));
    requestHeaders = curl_slist_sort_insert(requestHeaders, "Content-Type", contype.c_str());

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
            // Only copy mode.
            if(is_copy && !AddSseRequestHead(sse_type_t::SSE_S3, value, false, true)){
                S3FS_PRN_WARN("Failed to insert SSE-S3 header.");
            }
        }else if(key == "x-amz-server-side-encryption-aws-kms-key-id"){
            // Only copy mode.
            if(is_copy && !value.empty() && !AddSseRequestHead(sse_type_t::SSE_KMS, value, false, true)){
                S3FS_PRN_WARN("Failed to insert SSE-KMS header.");
            }
        }else if(key == "x-amz-server-side-encryption-customer-key-md5"){
            // Only copy mode.
            if(is_copy){
                if(!AddSseRequestHead(sse_type_t::SSE_C, value, true, true) || !AddSseRequestHead(sse_type_t::SSE_C, value, true, false)){
                    S3FS_PRN_WARN("Failed to insert SSE-C header.");
                }
            }
        }
    }

    // "x-amz-acl", storage class, sse
    if(S3fsCurl::default_acl != acl_t::PRIVATE){
        requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-acl", S3fsCurl::default_acl.str());
    }
    if(GetStorageClass() != storage_class_t::STANDARD){
        requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-storage-class", GetStorageClass().str());
    }
    // SSE
    if(!is_copy){
        std::string ssevalue;
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
        return -EINVAL;
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
        return -EIO;
    }
    std::string resource;
    std::string turl;
    MakeUrlResource(get_realpath(tpath).c_str(), resource, turl);

    url             = prepare_url(turl.c_str());
    path            = get_realpath(tpath);
    requestHeaders  = NULL;
    responseHeaders.clear();
    bodydata.Clear();

    // Make request headers
    std::string strMD5;
    if(-1 != fd && S3fsCurl::is_content_md5){
        strMD5         = s3fs_get_content_md5(fd);
        if(0 == strMD5.length()){
            S3FS_PRN_ERR("Failed to make MD5.");
            return -EIO;
        }
        requestHeaders = curl_slist_sort_insert(requestHeaders, "Content-MD5", strMD5.c_str());
    }

    std::string contype = S3fsCurl::LookupMimeType(std::string(tpath));
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
        requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-acl", S3fsCurl::default_acl.str());
    }
    if(GetStorageClass() != storage_class_t::STANDARD){
        requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-storage-class", GetStorageClass().str());
    }
    // SSE
    std::string ssevalue;
    // do not add SSE for create bucket
    if(0 != strcmp(tpath, "/")){
        if(!AddSseRequestHead(S3fsCurl::GetSseType(), ssevalue, false, false)){
            S3FS_PRN_WARN("Failed to set SSE header, but continue...");
        }
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
    requestHeaders  = NULL;
    responseHeaders.clear();

    if(-1 != start && 0 < size){
        std::string range = "bytes=";
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

int S3fsCurl::GetObjectRequest(const char* tpath, int fd, off_t start, off_t size)
{
    int result;

    S3FS_PRN_INFO3("[tpath=%s][start=%lld][size=%lld]", SAFESTRPTR(tpath), static_cast<long long>(start), static_cast<long long>(size));

    if(!tpath){
        return -EINVAL;
    }
    sse_type_t ssetype = sse_type_t::SSE_DISABLE;
    std::string ssevalue;
    if(!get_object_sse_type(tpath, ssetype, ssevalue)){
        S3FS_PRN_WARN("Failed to get SSE type for file(%s).", SAFESTRPTR(tpath));
    }

    if(0 != (result = PreGetObjectRequest(tpath, fd, start, size, ssetype, ssevalue))){
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

int S3fsCurl::CheckBucket()
{
    S3FS_PRN_INFO3("check a bucket.");

    if(!CreateCurlHandle()){
        return -EIO;
    }
    std::string urlargs;
    if(S3fsCurl::IsListObjectsV2()){
        query_string = "list-type=2";
        urlargs = "?" + query_string;
    }
    std::string resource;
    std::string turl;
    MakeUrlResource(get_realpath("/").c_str(), resource, turl);

    turl           += urlargs;
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
    requestHeaders  = NULL;
    responseHeaders.clear();
    bodydata.Clear();

    op = "GET";
    type = REQTYPE_LISTBUCKET;

    // setopt
    curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, (void*)&bodydata);
    curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    if(S3fsCurl::is_verbose){
        curl_easy_setopt(hCurl, CURLOPT_DEBUGFUNCTION, S3fsCurl::CurlDebugBodyInFunc);     // replace debug function
    }
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
    requestHeaders = NULL;
    bodydata.Clear();
    responseHeaders.clear();

    std::string contype = S3fsCurl::LookupMimeType(std::string(tpath));

    for(headers_t::iterator iter = meta.begin(); iter != meta.end(); ++iter){
        std::string key   = lower(iter->first);
        std::string value = iter->second;
        if(is_prefix(key.c_str(), "x-amz-acl")){
            // not set value, but after set it.
        }else if(is_prefix(key.c_str(), "x-amz-meta")){
            requestHeaders = curl_slist_sort_insert(requestHeaders, iter->first.c_str(), value.c_str());
        }else if(key == "x-amz-server-side-encryption" && value != "aws:kms"){
            // Only copy mode.
            if(is_copy && !AddSseRequestHead(sse_type_t::SSE_S3, value, false, true)){
                S3FS_PRN_WARN("Failed to insert SSE-S3 header.");
            }
        }else if(key == "x-amz-server-side-encryption-aws-kms-key-id"){
            // Only copy mode.
            if(is_copy && !value.empty() && !AddSseRequestHead(sse_type_t::SSE_KMS, value, false, true)){
                S3FS_PRN_WARN("Failed to insert SSE-KMS header.");
            }
        }else if(key == "x-amz-server-side-encryption-customer-key-md5"){
            // Only copy mode.
            if(is_copy){
                if(!AddSseRequestHead(sse_type_t::SSE_C, value, true, true) || !AddSseRequestHead(sse_type_t::SSE_C, value, true, false)){
                    S3FS_PRN_WARN("Failed to insert SSE-C header.");
                }
            }
        }
    }
    // "x-amz-acl", storage class, sse
    if(S3fsCurl::default_acl != acl_t::PRIVATE){
        requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-acl", S3fsCurl::default_acl.str());
    }
    if(GetStorageClass() != storage_class_t::STANDARD){
        requestHeaders = curl_slist_sort_insert(requestHeaders, "x-amz-storage-class", GetStorageClass().str());
    }
    // SSE
    if(!is_copy){
        std::string ssevalue;
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
        return -EIO;
    }

    bodydata.Clear();
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
    int cnt = 0;
    for(etaglist_t::iterator it = parts.begin(); it != parts.end(); ++it, ++cnt){
        if(it->empty()){
            S3FS_PRN_ERR("%d file part is not finished uploading.", cnt + 1);
            return -EIO;
        }
        postContent += "<Part>\n";
        postContent += "  <PartNumber>" + str(cnt + 1) + "</PartNumber>\n";
        postContent += "  <ETag>" + *it + "</ETag>\n";
        postContent += "</Part>\n";
    }
    postContent += "</CompleteMultipartUpload>\n";

    // set postdata
    postdata             = reinterpret_cast<const unsigned char*>(postContent.c_str());
    b_postdata           = postdata;
    postdata_remaining   = postContent.size(); // without null
    b_postdata_remaining = postdata_remaining;

    if(!CreateCurlHandle()){
        return -EIO;
    }
    std::string resource;
    std::string turl;
    MakeUrlResource(get_realpath(tpath).c_str(), resource, turl);

    query_string         = "uploadId=" + upload_id;
    turl                += "?" + query_string;
    url                  = prepare_url(turl.c_str());
    path                 = get_realpath(tpath);
    requestHeaders       = NULL;
    bodydata.Clear();
    responseHeaders.clear();
    std::string contype  = "application/xml";

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
    if(S3fsCurl::is_verbose){
        curl_easy_setopt(hCurl, CURLOPT_DEBUGFUNCTION, S3fsCurl::CurlDebugBodyOutFunc);     // replace debug function
    }
    S3fsCurl::AddUserAgent(hCurl);                            // put User-Agent

    // request
    int result = RequestPerform();
    bodydata.Clear();
    postdata = NULL;

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
int S3fsCurl::UploadMultipartPostSetup(const char* tpath, int part_num, const std::string& upload_id)
{
    S3FS_PRN_INFO3("[tpath=%s][start=%lld][size=%lld][part=%d]", SAFESTRPTR(tpath), static_cast<long long int>(partdata.startpos), static_cast<long long int>(partdata.size), part_num);

    if(-1 == partdata.fd || -1 == partdata.startpos || -1 == partdata.size){
        return -EINVAL;
    }

    requestHeaders = NULL;

    // make md5 and file pointer
    if(S3fsCurl::is_content_md5){
        unsigned char *md5raw = s3fs_md5_fd(partdata.fd, partdata.startpos, partdata.size);
        if(md5raw == NULL){
            S3FS_PRN_ERR("Could not make md5 for file(part %d)", part_num);
            return -EIO;
        }
        partdata.etag = s3fs_hex(md5raw, get_md5_digest_length());
        char* md5base64p = s3fs_base64(md5raw, get_md5_digest_length());
        requestHeaders = curl_slist_sort_insert(requestHeaders, "Content-MD5", md5base64p);
        delete[] md5base64p;
        delete[] md5raw;
    }

    // make request
    query_string        = "partNumber=" + str(part_num) + "&uploadId=" + upload_id;
    std::string urlargs = "?" + query_string;
    std::string resource;
    std::string turl;
    MakeUrlResource(get_realpath(tpath).c_str(), resource, turl);

    turl              += urlargs;
    url                = prepare_url(turl.c_str());
    path               = get_realpath(tpath);
    bodydata.Clear();
    headdata.Clear();
    responseHeaders.clear();

    // SSE
    if(sse_type_t::SSE_C == S3fsCurl::GetSseType()){
        std::string ssevalue;
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
    bodydata.Clear();
    headdata.Clear();

    return result;
}

int S3fsCurl::CopyMultipartPostSetup(const char* from, const char* to, int part_num, const std::string& upload_id, headers_t& meta)
{
    S3FS_PRN_INFO3("[from=%s][to=%s][part=%d]", SAFESTRPTR(from), SAFESTRPTR(to), part_num);

    if(!from || !to){
        return -EINVAL;
    }
    query_string = "partNumber=" + str(part_num) + "&uploadId=" + upload_id;
    std::string urlargs = "?" + query_string;
    std::string resource;
    std::string turl;
    MakeUrlResource(get_realpath(to).c_str(), resource, turl);

    turl           += urlargs;
    url             = prepare_url(turl.c_str());
    path            = get_realpath(to);
    requestHeaders  = NULL;
    responseHeaders.clear();
    bodydata.Clear();
    headdata.Clear();

    std::string contype = S3fsCurl::LookupMimeType(std::string(to));
    requestHeaders = curl_slist_sort_insert(requestHeaders, "Content-Type", contype.c_str());

    // Make request headers
    for(headers_t::iterator iter = meta.begin(); iter != meta.end(); ++iter){
        std::string key   = lower(iter->first);
        std::string value = iter->second;
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
    if(S3fsCurl::is_content_md5 && sse_type_t::SSE_C != S3fsCurl::GetSseType() && sse_type_t::SSE_KMS != S3fsCurl::GetSseType()){
        if(!etag_equals(it->second, partdata.etag)){
            return false;
        }
    }
    (*partdata.petag) = it->second;
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
        etag.erase(etag.size() - 1);
        etag.erase(0, 1);
    }
    (*partdata.petag) = etag;

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

int S3fsCurl::MultipartUploadRequest(const char* tpath, headers_t& meta, int fd, bool is_copy)
{
    int            result;
    std::string    upload_id;
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

int S3fsCurl::MultipartUploadRequest(const std::string& upload_id, const char* tpath, int fd, off_t offset, off_t size, etaglist_t& list)
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
    std::string    upload_id;
    off_t          chunk;
    off_t          bytes_remaining;
    etaglist_t     list;

    S3FS_PRN_INFO3("[from=%s][to=%s]", SAFESTRPTR(from), SAFESTRPTR(to));

    std::string srcresource;
    std::string srcurl;
    MakeUrlResource(get_realpath(from).c_str(), srcresource, srcurl);

    meta["Content-Type"]      = S3fsCurl::LookupMimeType(std::string(to));
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
