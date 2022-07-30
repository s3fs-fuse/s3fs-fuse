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

#ifndef S3FS_CURL_H_
#define S3FS_CURL_H_

#include <curl/curl.h>
#include <list>
#include <map>
#include <vector>

#include "autolock.h"
#include "bodydata.h"
#include "metaheader.h"
#include "fdcache_page.h"

//----------------------------------------------
// Avoid dependency on libcurl version
//----------------------------------------------
// [NOTE]
// The following symbols (enum) depend on the version of libcurl.
//  CURLOPT_TCP_KEEPALIVE           7.25.0 and later
//  CURLOPT_SSL_ENABLE_ALPN         7.36.0 and later
//  CURLOPT_KEEP_SENDING_ON_ERROR   7.51.0 and later
//
// s3fs uses these, if you build s3fs with the old libcurl,
// substitute the following symbols to avoid errors.
// If the version of libcurl linked at runtime is old,
// curl_easy_setopt results in an error(CURLE_UNKNOWN_OPTION) and
// a message is output.
//
#if defined(HAVE_CURLOPT_TCP_KEEPALIVE) && (HAVE_CURLOPT_TCP_KEEPALIVE == 1)
    #define   S3FS_CURLOPT_TCP_KEEPALIVE          CURLOPT_TCP_KEEPALIVE
#else
    #define   S3FS_CURLOPT_TCP_KEEPALIVE          static_cast<CURLoption>(213)
#endif

#if defined(HAVE_CURLOPT_SSL_ENABLE_ALPN) && (HAVE_CURLOPT_SSL_ENABLE_ALPN == 1)
    #define   S3FS_CURLOPT_SSL_ENABLE_ALPN        CURLOPT_SSL_ENABLE_ALPN
#else
    #define   S3FS_CURLOPT_SSL_ENABLE_ALPN        static_cast<CURLoption>(226)
#endif

#if defined(HAVE_CURLOPT_KEEP_SENDING_ON_ERROR) && (HAVE_CURLOPT_KEEP_SENDING_ON_ERROR == 1)
    #define   S3FS_CURLOPT_KEEP_SENDING_ON_ERROR  CURLOPT_KEEP_SENDING_ON_ERROR
#else
    #define   S3FS_CURLOPT_KEEP_SENDING_ON_ERROR  static_cast<CURLoption>(245)
#endif

//----------------------------------------------
// Structure / Typedefs
//----------------------------------------------
typedef std::pair<double, double>   progress_t;
typedef std::map<CURL*, time_t>     curltime_t;
typedef std::map<CURL*, progress_t> curlprogress_t;

//----------------------------------------------
// class S3fsCurl
//----------------------------------------------
class CurlHandlerPool;
class S3fsCred;
class S3fsCurl;
class Semaphore;

// Prototype function for lazy setup options for curl handle
typedef bool (*s3fscurl_lazy_setup)(S3fsCurl* s3fscurl);

typedef std::map<std::string, std::string> sseckeymap_t;
typedef std::list<sseckeymap_t>            sseckeylist_t;

// Class for lapping curl
//
class S3fsCurl
{
    friend class S3fsMultiCurl;

    private:
        enum REQTYPE {
            REQTYPE_UNSET  = -1,
            REQTYPE_DELETE = 0,
            REQTYPE_HEAD,
            REQTYPE_PUTHEAD,
            REQTYPE_PUT,
            REQTYPE_GET,
            REQTYPE_CHKBUCKET,
            REQTYPE_LISTBUCKET,
            REQTYPE_PREMULTIPOST,
            REQTYPE_COMPLETEMULTIPOST,
            REQTYPE_UPLOADMULTIPOST,
            REQTYPE_COPYMULTIPOST,
            REQTYPE_MULTILIST,
            REQTYPE_IAMCRED,
            REQTYPE_ABORTMULTIUPLOAD,
            REQTYPE_IAMROLE
        };

        // class variables
        static pthread_mutex_t  curl_warnings_lock;
        static bool             curl_warnings_once;  // emit older curl warnings only once
        static pthread_mutex_t  curl_handles_lock;
        static struct callback_locks_t {
            pthread_mutex_t dns;
            pthread_mutex_t ssl_session;
        } callback_locks;
        static bool             is_initglobal_done;
        static CurlHandlerPool* sCurlPool;
        static int              sCurlPoolSize;
        static CURLSH*          hCurlShare;
        static bool             is_cert_check;
        static bool             is_dns_cache;
        static bool             is_ssl_session_cache;
        static long             connect_timeout;
        static time_t           readwrite_timeout;
        static int              retries;
        static bool             is_public_bucket;
        static acl_t            default_acl;
        static std::string      storage_class;
        static sseckeylist_t    sseckeys;
        static std::string      ssekmsid;
        static sse_type_t       ssetype;
        static bool             is_content_md5;
        static bool             is_verbose;
        static bool             is_dump_body;
        static S3fsCred*        ps3fscred;
        static long             ssl_verify_hostname;
        static curltime_t       curl_times;
        static curlprogress_t   curl_progress;
        static std::string      curl_ca_bundle;
        static mimes_t          mimeTypes;
        static std::string      userAgent;
        static int              max_parallel_cnt;
        static int              max_multireq;
        static off_t            multipart_size;
        static off_t            multipart_copy_size;
        static signature_type_t signature_type;
        static bool             is_unsigned_payload;
        static bool             is_ua;             // User-Agent
        static bool             listobjectsv2;
        static bool             requester_pays;

        // variables
        CURL*                hCurl;
        REQTYPE              type;                 // type of request
        std::string          path;                 // target object path
        std::string          base_path;            // base path (for multi curl head request)
        std::string          saved_path;           // saved path = cache key (for multi curl head request)
        std::string          url;                  // target object path(url)
        struct curl_slist*   requestHeaders;
        headers_t            responseHeaders;      // header data by HeaderCallback
        BodyData             bodydata;             // body data by WriteMemoryCallback
        BodyData             headdata;             // header data by WriteMemoryCallback
        long                 LastResponseCode;
        const unsigned char* postdata;             // use by post method and read callback function.
        off_t                postdata_remaining;   // use by post method and read callback function.
        filepart             partdata;             // use by multipart upload/get object callback
        bool                 is_use_ahbe;          // additional header by extension
        int                  retry_count;          // retry count for multipart
        FILE*                b_infile;             // backup for retrying
        const unsigned char* b_postdata;           // backup for retrying
        off_t                b_postdata_remaining; // backup for retrying
        off_t                b_partdata_startpos;  // backup for retrying
        off_t                b_partdata_size;      // backup for retrying
        size_t               b_ssekey_pos;         // backup for retrying
        std::string          b_ssevalue;           // backup for retrying
        sse_type_t           b_ssetype;            // backup for retrying
        std::string          b_from;               // backup for retrying(for copy request)
        headers_t            b_meta;               // backup for retrying(for copy request)
        std::string          op;                   // the HTTP verb of the request ("PUT", "GET", etc.)
        std::string          query_string;         // request query string
        Semaphore            *sem;
        pthread_mutex_t      *completed_tids_lock;
        std::vector<pthread_t> *completed_tids;
        s3fscurl_lazy_setup  fpLazySetup;          // curl options for lazy setting function
        CURLcode             curlCode;             // handle curl return

    public:
        static const long S3FSCURL_RESPONSECODE_NOTSET      = -1;
        static const long S3FSCURL_RESPONSECODE_FATAL_ERROR = -2;
        static const int  S3FSCURL_PERFORM_RESULT_NOTSET    = 1;

    public:
        // constructor/destructor
        explicit S3fsCurl(bool ahbe = false);
        ~S3fsCurl();

    private:
        // class methods
        static bool InitGlobalCurl();
        static bool DestroyGlobalCurl();
        static bool InitShareCurl();
        static bool DestroyShareCurl();
        static void LockCurlShare(CURL* handle, curl_lock_data nLockData, curl_lock_access laccess, void* useptr);
        static void UnlockCurlShare(CURL* handle, curl_lock_data nLockData, void* useptr);
        static bool InitCryptMutex();
        static bool DestroyCryptMutex();
        static int CurlProgress(void *clientp, double dltotal, double dlnow, double ultotal, double ulnow);

        static bool LocateBundle();
        static size_t HeaderCallback(void *data, size_t blockSize, size_t numBlocks, void *userPtr);
        static size_t WriteMemoryCallback(void *ptr, size_t blockSize, size_t numBlocks, void *data);
        static size_t ReadCallback(void *ptr, size_t size, size_t nmemb, void *userp);
        static size_t UploadReadCallback(void *ptr, size_t size, size_t nmemb, void *userp);
        static size_t DownloadWriteCallback(void* ptr, size_t size, size_t nmemb, void* userp);

        static bool UploadMultipartPostCallback(S3fsCurl* s3fscurl, void* param);
        static bool CopyMultipartPostCallback(S3fsCurl* s3fscurl, void* param);
        static bool MixMultipartPostCallback(S3fsCurl* s3fscurl, void* param);
        static S3fsCurl* UploadMultipartPostRetryCallback(S3fsCurl* s3fscurl);
        static S3fsCurl* CopyMultipartPostRetryCallback(S3fsCurl* s3fscurl);
        static S3fsCurl* MixMultipartPostRetryCallback(S3fsCurl* s3fscurl);
        static S3fsCurl* ParallelGetObjectRetryCallback(S3fsCurl* s3fscurl);

        // lazy functions for set curl options
        static bool CopyMultipartPostSetCurlOpts(S3fsCurl* s3fscurl);
        static bool PreGetObjectRequestSetCurlOpts(S3fsCurl* s3fscurl);
        static bool PreHeadRequestSetCurlOpts(S3fsCurl* s3fscurl);

        static bool LoadEnvSseCKeys();
        static bool LoadEnvSseKmsid();
        static bool PushbackSseKeys(const std::string& onekey);
        static bool AddUserAgent(CURL* hCurl);

        static int CurlDebugFunc(const CURL* hcurl, curl_infotype type, char* data, size_t size, void* userptr);
        static int CurlDebugBodyInFunc(const CURL* hcurl, curl_infotype type, char* data, size_t size, void* userptr);
        static int CurlDebugBodyOutFunc(const CURL* hcurl, curl_infotype type, char* data, size_t size, void* userptr);
        static int RawCurlDebugFunc(const CURL* hcurl, curl_infotype type, char* data, size_t size, void* userptr, curl_infotype datatype);

        // methods
        bool ResetHandle(AutoLock::Type locktype = AutoLock::NONE);
        bool RemakeHandle();
        bool ClearInternalData();
        void insertV4Headers(const std::string& access_key_id, const std::string& secret_access_key, const std::string& access_token);
        void insertV2Headers(const std::string& access_key_id, const std::string& secret_access_key, const std::string& access_token);
        void insertIBMIAMHeaders(const std::string& access_key_id, const std::string& access_token);
        void insertAuthHeaders();
        std::string CalcSignatureV2(const std::string& method, const std::string& strMD5, const std::string& content_type, const std::string& date, const std::string& resource, const std::string& secret_access_key, const std::string& access_token);
        std::string CalcSignature(const std::string& method, const std::string& canonical_uri, const std::string& query_string, const std::string& strdate, const std::string& payload_hash, const std::string& date8601, const std::string& secret_access_key, const std::string& access_token);
        int UploadMultipartPostSetup(const char* tpath, int part_num, const std::string& upload_id);
        int CopyMultipartPostSetup(const char* from, const char* to, int part_num, const std::string& upload_id, headers_t& meta);
        bool UploadMultipartPostComplete();
        bool CopyMultipartPostComplete();
        int MapPutErrorResponse(int result);

    public:
        // class methods
        static bool InitS3fsCurl();
        static bool InitCredentialObject(S3fsCred* pcredobj);
        static bool InitMimeType(const std::string& strFile);
        static bool DestroyS3fsCurl();
        static S3fsCurl* CreateParallelS3fsCurl(const char* tpath, int fd, off_t start, off_t size, int part_num, bool is_copy, etagpair* petag, const std::string& upload_id, int& result);
        static int ParallelMultipartUploadRequest(const char* tpath, headers_t& meta, int fd);
        static int ParallelMixMultipartUploadRequest(const char* tpath, headers_t& meta, int fd, const fdpage_list_t& mixuppages);
        static int ParallelGetObjectRequest(const char* tpath, int fd, off_t start, off_t size);

        // lazy functions for set curl options(public)
        static bool UploadMultipartPostSetCurlOpts(S3fsCurl* s3fscurl);

        // class methods(variables)
        static std::string LookupMimeType(const std::string& name);
        static bool SetCheckCertificate(bool isCertCheck);
        static bool SetDnsCache(bool isCache);
        static bool SetSslSessionCache(bool isCache);
        static long SetConnectTimeout(long timeout);
        static time_t SetReadwriteTimeout(time_t timeout);
        static time_t GetReadwriteTimeout() { return S3fsCurl::readwrite_timeout; }
        static int SetRetries(int count);
        static bool SetPublicBucket(bool flag);
        static bool IsPublicBucket() { return S3fsCurl::is_public_bucket; }
        static acl_t SetDefaultAcl(acl_t acl);
        static acl_t GetDefaultAcl();
        static std::string SetStorageClass(const std::string& storage_class);
        static std::string GetStorageClass() { return S3fsCurl::storage_class; }
        static bool LoadEnvSse() { return (S3fsCurl::LoadEnvSseCKeys() && S3fsCurl::LoadEnvSseKmsid()); }
        static sse_type_t SetSseType(sse_type_t type);
        static sse_type_t GetSseType() { return S3fsCurl::ssetype; }
        static bool IsSseDisable() { return (sse_type_t::SSE_DISABLE == S3fsCurl::ssetype); }
        static bool IsSseS3Type() { return (sse_type_t::SSE_S3 == S3fsCurl::ssetype); }
        static bool IsSseCType() { return (sse_type_t::SSE_C == S3fsCurl::ssetype); }
        static bool IsSseKmsType() { return (sse_type_t::SSE_KMS == S3fsCurl::ssetype); }
        static bool FinalCheckSse();
        static bool SetSseCKeys(const char* filepath);
        static bool SetSseKmsid(const char* kmsid);
        static bool IsSetSseKmsId() { return !S3fsCurl::ssekmsid.empty(); }
        static const char* GetSseKmsId() { return S3fsCurl::ssekmsid.c_str(); }
        static bool GetSseKey(std::string& md5, std::string& ssekey);
        static bool GetSseKeyMd5(size_t pos, std::string& md5);
        static size_t GetSseKeyCount();
        static bool SetContentMd5(bool flag);
        static bool SetVerbose(bool flag);
        static bool GetVerbose() { return S3fsCurl::is_verbose; }
        static bool SetDumpBody(bool flag);
        static bool IsDumpBody() { return S3fsCurl::is_dump_body; }
        static long SetSslVerifyHostname(long value);
        static long GetSslVerifyHostname() { return S3fsCurl::ssl_verify_hostname; }
        static void ResetOffset(S3fsCurl* pCurl);
        // maximum parallel GET and PUT requests
        static int SetMaxParallelCount(int value);
        static int GetMaxParallelCount() { return S3fsCurl::max_parallel_cnt; }
        // maximum parallel HEAD requests
        static int SetMaxMultiRequest(int max);
        static int GetMaxMultiRequest() { return S3fsCurl::max_multireq; }
        static bool SetMultipartSize(off_t size);
        static off_t GetMultipartSize() { return S3fsCurl::multipart_size; }
        static bool SetMultipartCopySize(off_t size);
        static off_t GetMultipartCopySize() { return S3fsCurl::multipart_copy_size; }
        static signature_type_t SetSignatureType(signature_type_t signature_type) { signature_type_t bresult = S3fsCurl::signature_type; S3fsCurl::signature_type = signature_type; return bresult; }
        static signature_type_t GetSignatureType() { return S3fsCurl::signature_type; }
        static bool SetUnsignedPayload(bool issset) { bool bresult = S3fsCurl::is_unsigned_payload; S3fsCurl::is_unsigned_payload = issset; return bresult; }
        static bool GetUnsignedPayload() { return S3fsCurl::is_unsigned_payload; }
        static bool SetUserAgentFlag(bool isset) { bool bresult = S3fsCurl::is_ua; S3fsCurl::is_ua = isset; return bresult; }
        static bool IsUserAgentFlag() { return S3fsCurl::is_ua; }
        static void InitUserAgent();
        static bool SetListObjectsV2(bool isset) { bool bresult = S3fsCurl::listobjectsv2; S3fsCurl::listobjectsv2 = isset; return bresult; }
        static bool IsListObjectsV2() { return S3fsCurl::listobjectsv2; }
        static bool SetRequesterPays(bool flag) { bool old_flag = S3fsCurl::requester_pays; S3fsCurl::requester_pays = flag; return old_flag; }
        static bool IsRequesterPays() { return S3fsCurl::requester_pays; }

        // methods
        bool CreateCurlHandle(bool only_pool = false, bool remake = false);
        bool DestroyCurlHandle(bool restore_pool = true, bool clear_internal_data = true, AutoLock::Type locktype = AutoLock::NONE);

        bool GetIAMCredentials(const char* cred_url, const char* iam_v2_token, const char* ibm_secret_access_key, std::string& response);
        bool GetIAMRoleFromMetaData(const char* cred_url, const char* iam_v2_token, std::string& token);
        bool AddSseRequestHead(sse_type_t ssetype, const std::string& ssevalue, bool is_only_c, bool is_copy);
        bool GetResponseCode(long& responseCode, bool from_curl_handle = true);
        int RequestPerform(bool dontAddAuthHeaders=false);
        int DeleteRequest(const char* tpath);
        int GetIAMv2ApiToken(const char* token_url, int token_ttl, const char* token_ttl_hdr, std::string& response);
        bool PreHeadRequest(const char* tpath, const char* bpath = NULL, const char* savedpath = NULL, size_t ssekey_pos = -1);
        bool PreHeadRequest(const std::string& tpath, const std::string& bpath, const std::string& savedpath, size_t ssekey_pos = -1) {
          return PreHeadRequest(tpath.c_str(), bpath.c_str(), savedpath.c_str(), ssekey_pos);
        }
        int HeadRequest(const char* tpath, headers_t& meta);
        int PutHeadRequest(const char* tpath, headers_t& meta, bool is_copy);
        int PutRequest(const char* tpath, headers_t& meta, int fd);
        int PreGetObjectRequest(const char* tpath, int fd, off_t start, off_t size, sse_type_t ssetype, const std::string& ssevalue);
        int GetObjectRequest(const char* tpath, int fd, off_t start = -1, off_t size = -1);
        int CheckBucket();
        int ListBucketRequest(const char* tpath, const char* query);
        int PreMultipartPostRequest(const char* tpath, headers_t& meta, std::string& upload_id, bool is_copy);
        int CompleteMultipartPostRequest(const char* tpath, const std::string& upload_id, etaglist_t& parts);
        int UploadMultipartPostRequest(const char* tpath, int part_num, const std::string& upload_id);
        bool MixMultipartPostComplete();
        int MultipartListRequest(std::string& body);
        int AbortMultipartUpload(const char* tpath, const std::string& upload_id);
        int MultipartHeadRequest(const char* tpath, off_t size, headers_t& meta, bool is_copy);
        int MultipartUploadRequest(const std::string& upload_id, const char* tpath, int fd, off_t offset, off_t size, etagpair* petagpair);
        int MultipartRenameRequest(const char* from, const char* to, headers_t& meta, off_t size);

        // methods(variables)
        CURL* GetCurlHandle() const { return hCurl; }
        std::string GetPath() const { return path; }
        std::string GetBasePath() const { return base_path; }
        std::string GetSpecialSavedPath() const { return saved_path; }
        std::string GetUrl() const { return url; }
        std::string GetOp() const { return op; }
        headers_t* GetResponseHeaders() { return &responseHeaders; }
        BodyData* GetBodyData() { return &bodydata; }
        BodyData* GetHeadData() { return &headdata; }
        CURLcode GetCurlCode() const { return curlCode; }
        long GetLastResponseCode() const { return LastResponseCode; }
        bool SetUseAhbe(bool ahbe);
        bool EnableUseAhbe() { return SetUseAhbe(true); }
        bool DisableUseAhbe() { return SetUseAhbe(false); }
        bool IsUseAhbe() const { return is_use_ahbe; }
        int GetMultipartRetryCount() const { return retry_count; }
        void SetMultipartRetryCount(int retrycnt) { retry_count = retrycnt; }
        bool IsOverMultipartRetryCount() const { return (retry_count >= S3fsCurl::retries); }
        size_t GetLastPreHeadSeecKeyPos() const { return b_ssekey_pos; }
};

#endif // S3FS_CURL_H_

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
