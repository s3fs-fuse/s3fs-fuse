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

#include <atomic>
#include <cstdint>
#include <curl/curl.h>
#include <map>
#include <memory>
#include <mutex>
#include <string>

#include "common.h"
#include "metaheader.h"
#include "s3fs_util.h"
#include "types.h"

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
struct curlprogress {
    time_t time;
    double dl_progress;
    double ul_progress;
};
typedef std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> CurlUniquePtr;

//----------------------------------------------
// class S3fsCurl
//----------------------------------------------
class S3fsCred;
class S3fsCurl;

// Prototype function for lazy setup options for curl handle
typedef bool (*s3fscurl_lazy_setup)(S3fsCurl* s3fscurl);

typedef std::map<std::string, std::string> sseckeymap_t;
typedef std::vector<sseckeymap_t>          sseckeylist_t;

// Class for lapping curl
//
class S3fsCurl
{
    private:
        enum class REQTYPE : int8_t {
            UNSET  = -1,
            DELETE,
            HEAD,
            PUTHEAD,
            PUT,
            GET,
            CHKBUCKET,
            LISTBUCKET,
            PREMULTIPOST,
            COMPLETEMULTIPOST,
            UPLOADMULTIPOST,
            COPYMULTIPOST,
            MULTILIST,
            IAMCRED,
            ABORTMULTIUPLOAD,
            IAMROLE
        };

        // Environment name
        static constexpr char   S3FS_SSL_PRIVKEY_PASSWORD[] = "S3FS_SSL_PRIVKEY_PASSWORD";

        // class variables
        static std::atomic<bool> curl_warnings_once;  // emit older curl warnings only once
        static std::mutex       curl_handles_lock;
        static struct callback_locks_t {
            std::mutex      dns;
            std::mutex      ssl_session;
        } callback_locks;
        static bool             is_initglobal_done;
        static bool             is_cert_check;
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
        static std::string      client_cert;
        static std::string      client_cert_type;
        static std::string      client_priv_key;
        static std::string      client_priv_key_type;
        static std::string      client_key_password;
        static std::map<const CURL*, curlprogress> curl_progress;
        static std::string      curl_ca_bundle;
        static mimes_t          mimeTypes;
        static std::string      userAgent;
        static int              max_multireq;
        static off_t            multipart_size;
        static off_t            multipart_copy_size;
        static signature_type_t signature_type;
        static bool             is_unsigned_payload;
        static bool             is_ua;             // User-Agent
        static bool             listobjectsv2;
        static bool             requester_pays;
        static std::string      proxy_url;
        static bool             proxy_http;
        static std::string      proxy_userpwd;     // load from file(<username>:<passphrase>)
        static long             ipresolve_type;    // this value is a libcurl symbol.

        // variables
        CurlUniquePtr        hCurl PT_GUARDED_BY(curl_handles_lock) = {nullptr, curl_easy_cleanup};
        REQTYPE              type;                 // type of request
        std::string          path;                 // target object path
        std::string          url;                  // target object path(url)
        struct curl_slist*   requestHeaders;
        headers_t            responseHeaders;      // header data by HeaderCallback
        std::string          bodydata;             // body data by WriteMemoryCallback
        std::string          headdata;             // header data by WriteMemoryCallback
        long                 LastResponseCode;
        const unsigned char* postdata;             // use by post method and read callback function.
        off_t                postdata_remaining;   // use by post method and read callback function.
        filepart             partdata;             // use by multipart upload/get object callback
        bool                 is_use_ahbe;          // additional header by extension
        int                  retry_count;          // retry count, this is used only sleep time before retrying
        std::unique_ptr<FILE, decltype(&s3fs_fclose)> b_infile = {nullptr, &s3fs_fclose};  // backup for retrying
        const unsigned char* b_postdata;           // backup for retrying
        off_t                b_postdata_remaining; // backup for retrying
        off_t                b_partdata_startpos;  // backup for retrying
        off_t                b_partdata_size;      // backup for retrying
        std::string          op;                   // the HTTP verb of the request ("PUT", "GET", etc.)
        std::string          query_string;         // request query string
        s3fscurl_lazy_setup  fpLazySetup;          // curl options for lazy setting function
        CURLcode             curlCode;             // handle curl return

    public:
        static constexpr long S3FSCURL_RESPONSECODE_NOTSET      = -1;
        static constexpr long S3FSCURL_RESPONSECODE_FATAL_ERROR = -2;
        static constexpr int  S3FSCURL_PERFORM_RESULT_NOTSET    = 1;

    public:
        // constructor/destructor
        explicit S3fsCurl(bool ahbe = false);
        ~S3fsCurl();
        S3fsCurl(const S3fsCurl&) = delete;
        S3fsCurl(S3fsCurl&&) = delete;
        S3fsCurl& operator=(const S3fsCurl&) = delete;
        S3fsCurl& operator=(S3fsCurl&&) = delete;

    private:
        // class methods
        static bool InitGlobalCurl();
        static bool DestroyGlobalCurl();
        static bool InitCryptMutex();
        static bool DestroyCryptMutex();
        static int CurlProgress(void *clientp, double dltotal, double dlnow, double ultotal, double ulnow);
        static std::string extractURI(const std::string& url);

        static bool LocateBundle();
        static size_t HeaderCallback(void *data, size_t blockSize, size_t numBlocks, void *userPtr);
        static size_t WriteMemoryCallback(void *ptr, size_t blockSize, size_t numBlocks, void *data);
        static size_t ReadCallback(void *ptr, size_t size, size_t nmemb, void *userp);
        static size_t UploadReadCallback(void *ptr, size_t size, size_t nmemb, void *userp);
        static size_t DownloadWriteCallback(void* ptr, size_t size, size_t nmemb, void* userp);

        // lazy functions for set curl options
        static bool MultipartUploadPartSetCurlOpts(S3fsCurl* s3fscurl);
        static bool CopyMultipartUploadSetCurlOpts(S3fsCurl* s3fscurl);
        static bool PreGetObjectRequestSetCurlOpts(S3fsCurl* s3fscurl);
        static bool PreHeadRequestSetCurlOpts(S3fsCurl* s3fscurl);

        static bool LoadEnvSseCKeys();
        static bool LoadEnvSseKmsid();
        static bool PushbackSseKeys(const std::string& onekey);
        static bool AddUserAgent(const CurlUniquePtr& hCurl);

        static int CurlDebugFunc(const CURL* hcurl, curl_infotype type, char* data, size_t size, void* userptr);
        static int CurlDebugBodyInFunc(const CURL* hcurl, curl_infotype type, char* data, size_t size, void* userptr);
        static int CurlDebugBodyOutFunc(const CURL* hcurl, curl_infotype type, char* data, size_t size, void* userptr);
        static int RawCurlDebugFunc(const CURL* hcurl, curl_infotype type, char* data, size_t size, void* userptr, curl_infotype datatype);

        // methods
        bool ResetHandle() REQUIRES(S3fsCurl::curl_handles_lock);
        bool RemakeHandle();
        bool ClearInternalData();
        bool insertV4Headers(const std::string& access_key_id, const std::string& secret_access_key, const std::string& access_token);
        void insertV2Headers(const std::string& access_key_id, const std::string& secret_access_key, const std::string& access_token);
        void insertIBMIAMHeaders(const std::string& access_key_id, const std::string& access_token);
        bool insertAuthHeaders();
        bool AddSseRequestHead(sse_type_t ssetype, const std::string& ssevalue, bool is_copy);
        bool PreHeadRequest(const char* tpath, size_t ssekey_pos = -1);
        bool PreHeadRequest(const std::string& tpath, size_t ssekey_pos = -1) {
            return PreHeadRequest(tpath.c_str(), ssekey_pos);
        }
        std::string CalcSignatureV2(const std::string& method, const std::string& strMD5, const std::string& content_type, const std::string& date, const std::string& resource, const std::string& secret_access_key, const std::string& access_token);
        std::string CalcSignature(const std::string& method, const std::string& canonical_uri, const std::string& query_string, const std::string& strdate, const std::string& payload_hash, const std::string& date8601, const std::string& secret_access_key, const std::string& access_token);
        int MultipartUploadContentPartSetup(const char* tpath, int part_num, const std::string& upload_id);
        int MultipartUploadCopyPartSetup(const char* from, const char* to, int part_num, const std::string& upload_id, const headers_t& meta);
        bool MultipartUploadContentPartComplete();
        bool MultipartUploadCopyPartComplete();
        int MapPutErrorResponse(int result) const;

    public:
        // class methods
        static bool InitS3fsCurl();
        static bool InitCredentialObject(S3fsCred* pcredobj);
        static bool InitMimeType(const std::string& strFile);
        static bool DestroyS3fsCurl();

        // class methods(variables)
        static std::string LookupMimeType(const std::string& name);
        static bool SetCheckCertificate(bool isCertCheck);
        static long SetConnectTimeout(long timeout);
        static time_t SetReadwriteTimeout(time_t timeout);
        static time_t GetReadwriteTimeout() { return S3fsCurl::readwrite_timeout; }
        static int SetRetries(int count);
        static int GetRetries();
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
        static bool SetSSLClientCertOptions(const std::string& values);
        static void ResetOffset(S3fsCurl* pCurl);
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
        static bool SetProxy(const char* url);
        static bool SetProxyUserPwd(const char* userpwd);
        static bool SetIPResolveType(const char* value);

        // methods
        bool CreateCurlHandle(bool remake = false);
        bool DestroyCurlHandle(bool clear_internal_data = true);
        bool DestroyCurlHandleHasLock(bool clear_internal_data = true) REQUIRES(S3fsCurl::curl_handles_lock);

        bool GetIAMCredentials(const char* cred_url, const char* iam_v2_token, const char* ibm_secret_access_key, std::string& response);
        bool GetIAMRoleFromMetaData(const char* cred_url, const char* iam_v2_token, std::string& token);
        bool GetResponseCode(long& responseCode, bool from_curl_handle = true) const;
        bool GetCurlErrorString(std::string& strError) const;
        int RequestPerform(bool dontAddAuthHeaders=false);
        int DeleteRequest(const char* tpath);
        int GetIAMv2ApiToken(const char* token_url, int token_ttl, const char* token_ttl_hdr, std::string& response);
        int HeadRequest(const char* tpath, headers_t& meta);
        int PutHeadRequest(const char* tpath, const headers_t& meta, bool is_copy);
        int PutRequest(const char* tpath, headers_t& meta, int fd);
        int PreGetObjectRequest(const char* tpath, int fd, off_t start, off_t size, sse_type_t ssetype, const std::string& ssevalue);
        int GetObjectRequest(const char* tpath, int fd, off_t start, off_t size, sse_type_t ssetype, const std::string& ssevalue);
        int CheckBucket(const char* check_path, bool compat_dir, bool force_no_sse);
        int ListBucketRequest(const char* tpath, const char* query);
        int PreMultipartUploadRequest(const char* tpath, const headers_t& meta, std::string& upload_id);
        int MultipartUploadPartSetup(const char* tpath, int upload_fd, off_t start, off_t size, int part_num, const std::string& upload_id, etagpair* petag, bool is_copy);
        int MultipartUploadComplete(const char* tpath, const std::string& upload_id, const etaglist_t& parts);
        bool MultipartUploadPartComplete();
        int MultipartListRequest(std::string& body);
        int AbortMultipartUpload(const char* tpath, const std::string& upload_id);
        int MultipartPutHeadRequest(const std::string& from, const std::string& to, int part_number, const std::string& upload_id, const headers_t& meta);
        int MultipartUploadPartRequest(const char* tpath, int upload_fd, off_t start, off_t size, int part_num, const std::string& upload_id, etagpair* petag, bool is_copy);

        // methods(variables)
        const std::string& GetPath() const { return path; }
        const std::string& GetUrl() const { return url; }
        const std::string& GetOp() const { return op; }
        const headers_t* GetResponseHeaders() const { return &responseHeaders; }
        const std::string& GetBodyData() const { return bodydata; }
        const std::string& GetHeadData() const { return headdata; }
        CURLcode GetCurlCode() const { return curlCode; }
        long GetLastResponseCode() const { return LastResponseCode; }
        bool SetUseAhbe(bool ahbe);
        bool EnableUseAhbe() { return SetUseAhbe(true); }
        bool DisableUseAhbe() { return SetUseAhbe(false); }
        bool IsUseAhbe() const { return is_use_ahbe; }
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
