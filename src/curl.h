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

#include <cassert>

//----------------------------------------------
// Symbols
//----------------------------------------------
static const int MIN_MULTIPART_SIZE = 5 * 1024 * 1024;

//----------------------------------------------
// class BodyData
//----------------------------------------------
// memory class for curl write memory callback 
//
class BodyData
{
  private:
    char* text;    
    size_t lastpos;
    size_t bufsize;

  private:
    bool IsSafeSize(size_t addbytes) const {
      return ((lastpos + addbytes + 1) > bufsize ? false : true);
    }
    bool Resize(size_t addbytes);

  public:
    BodyData() : text(NULL), lastpos(0), bufsize(0) {}
    ~BodyData() {
      Clear();
    }

    void Clear(void);
    bool Append(void* ptr, size_t bytes);
    bool Append(void* ptr, size_t blockSize, size_t numBlocks) {
      return Append(ptr, (blockSize * numBlocks));
    }
    const char* str() const;
    size_t size() const {
      return lastpos;
    }
};

//----------------------------------------------
// Utility structs & typedefs
//----------------------------------------------
typedef std::vector<std::string> etaglist_t;

// Each part information for Multipart upload
struct filepart
{
  bool        uploaded;     // does finish uploading
  std::string etag;         // expected etag value
  int         fd;           // base file(temporary full file) descriptor
  off_t       startpos;     // seek fd point for uploading
  ssize_t     size;         // uploading size
  etaglist_t* etaglist;     // use only parallel upload
  int         etagpos;      // use only parallel upload

  filepart() : uploaded(false), fd(-1), startpos(0), size(-1), etaglist(NULL), etagpos(-1) {}
  ~filepart()
  {
    clear();
  }

  void clear(void)
  {
    uploaded = false;
    etag     = "";
    fd       = -1;
    startpos = 0;
    size     = -1;
    etaglist = NULL;
    etagpos  = - 1;
  }

  void add_etag_list(etaglist_t* list)
  {
    if(list){
      list->push_back(std::string(""));
      etaglist = list;
      etagpos  = list->size() - 1;
    }else{
      etaglist = NULL;
      etagpos  = - 1;
    }
  }
};

// for progress
struct case_insensitive_compare_func
{
  bool operator()(const std::string& a, const std::string& b) const {
    return strcasecmp(a.c_str(), b.c_str()) < 0;
  }
};
typedef std::map<std::string, std::string, case_insensitive_compare_func> mimes_t;
typedef std::pair<double, double>   progress_t;
typedef std::map<CURL*, time_t>     curltime_t;
typedef std::map<CURL*, progress_t> curlprogress_t;

class S3fsMultiCurl;

//----------------------------------------------
// class CurlHandlerPool
//----------------------------------------------

class CurlHandlerPool
{
public:
  explicit CurlHandlerPool(int maxHandlers)
    : mMaxHandlers(maxHandlers)
    , mHandlers(NULL)
    , mIndex(-1)
  {
    assert(maxHandlers > 0);
  }

  bool Init();
  bool Destroy();

  CURL* GetHandler();
  void ReturnHandler(CURL* h);

private:
  int mMaxHandlers;

  pthread_mutex_t mLock;
  CURL** mHandlers;
  int mIndex;
};

//----------------------------------------------
// class S3fsCurl
//----------------------------------------------
typedef std::map<std::string, std::string> iamcredmap_t;
typedef std::map<std::string, std::string> sseckeymap_t;
typedef std::list<sseckeymap_t>            sseckeylist_t;

// storage class(rrs)
enum storage_class_t {
  STANDARD,
  STANDARD_IA,
  REDUCED_REDUNDANCY
};

// sse type
enum sse_type_t {
  SSE_DISABLE = 0,      // not use server side encrypting
  SSE_S3,               // server side encrypting by S3 key
  SSE_C,                // server side encrypting by custom key
  SSE_KMS               // server side encrypting by kms id
};

// share
enum {
  SHARE_MUTEX_DNS = 0,
  SHARE_MUTEX_SSL_SESSION = 1,
  SHARE_MUTEX_MAX = 2,
};

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
    static pthread_mutex_t  curl_handles_lock;
    static pthread_mutex_t  curl_share_lock[SHARE_MUTEX_MAX];
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
    static std::string      default_acl;             // TODO: to enum
    static storage_class_t  storage_class;
    static sseckeylist_t    sseckeys;
    static std::string      ssekmsid;
    static sse_type_t       ssetype;
    static bool             is_content_md5;
    static bool             is_verbose;
    static std::string      AWSAccessKeyId;
    static std::string      AWSSecretAccessKey;
    static std::string      AWSAccessToken;
    static time_t           AWSAccessTokenExpire;
    static bool             is_ecs;
    static bool             is_ibm_iam_auth;
    static std::string      IAM_cred_url;
    static size_t           IAM_field_count;
    static std::string      IAM_token_field;
    static std::string      IAM_expiry_field;
    static std::string      IAM_role;
    static long             ssl_verify_hostname;
    static curltime_t       curl_times;
    static curlprogress_t   curl_progress;
    static std::string      curl_ca_bundle;
    static mimes_t          mimeTypes;
    static std::string      userAgent;
    static int              max_parallel_cnt;
    static off_t            multipart_size;
    static bool             is_sigv4;
    static bool             is_ua;             // User-Agent

    // variables
    CURL*                hCurl;
    REQTYPE              type;                 // type of request
    std::string          path;                 // target object path
    std::string          base_path;            // base path (for multi curl head request)
    std::string          saved_path;           // saved path = cache key (for multi curl head request)
    std::string          url;                  // target object path(url)
    struct curl_slist*   requestHeaders;
    headers_t            responseHeaders;      // header data by HeaderCallback
    BodyData*            bodydata;             // body data by WriteMemoryCallback
    BodyData*            headdata;             // header data by WriteMemoryCallback
    long                 LastResponseCode;
    const unsigned char* postdata;             // use by post method and read callback function.
    int                  postdata_remaining;   // use by post method and read callback function.
    filepart             partdata;             // use by multipart upload/get object callback
    bool                 is_use_ahbe;          // additional header by extension
    int                  retry_count;          // retry count for multipart
    FILE*                b_infile;             // backup for retrying
    const unsigned char* b_postdata;           // backup for retrying
    int                  b_postdata_remaining; // backup for retrying
    off_t                b_partdata_startpos;  // backup for retrying
    ssize_t              b_partdata_size;      // backup for retrying
    int                  b_ssekey_pos;         // backup for retrying
    std::string          b_ssevalue;           // backup for retrying
    sse_type_t           b_ssetype;            // backup for retrying
    std::string          op;                   // the HTTP verb of the request ("PUT", "GET", etc.)
    std::string          query_string;         // request query string

  public:
    // constructor/destructor
    explicit S3fsCurl(bool ahbe = false);
    ~S3fsCurl();

  private:
    // class methods
    static bool InitGlobalCurl(void);
    static bool DestroyGlobalCurl(void);
    static bool InitShareCurl(void);
    static bool DestroyShareCurl(void);
    static void LockCurlShare(CURL* handle, curl_lock_data nLockData, curl_lock_access laccess, void* useptr);
    static void UnlockCurlShare(CURL* handle, curl_lock_data nLockData, void* useptr);
    static bool InitCryptMutex(void);
    static bool DestroyCryptMutex(void);
    static int CurlProgress(void *clientp, double dltotal, double dlnow, double ultotal, double ulnow);

    static bool InitMimeType(const char* MimeFile = NULL);
    static bool LocateBundle(void);
    static size_t HeaderCallback(void *data, size_t blockSize, size_t numBlocks, void *userPtr);
    static size_t WriteMemoryCallback(void *ptr, size_t blockSize, size_t numBlocks, void *data);
    static size_t ReadCallback(void *ptr, size_t size, size_t nmemb, void *userp);
    static size_t UploadReadCallback(void *ptr, size_t size, size_t nmemb, void *userp);
    static size_t DownloadWriteCallback(void* ptr, size_t size, size_t nmemb, void* userp);

    static bool UploadMultipartPostCallback(S3fsCurl* s3fscurl);
    static S3fsCurl* UploadMultipartPostRetryCallback(S3fsCurl* s3fscurl);
    static S3fsCurl* ParallelGetObjectRetryCallback(S3fsCurl* s3fscurl);

    static bool ParseIAMCredentialResponse(const char* response, iamcredmap_t& keyval);
    static bool SetIAMCredentials(const char* response);
    static bool ParseIAMRoleFromMetaDataResponse(const char* response, std::string& rolename);
    static bool SetIAMRoleFromMetaData(const char* response);
    static bool LoadEnvSseCKeys(void);
    static bool LoadEnvSseKmsid(void);
    static bool PushbackSseKeys(std::string& onekey);
    static bool AddUserAgent(CURL* hCurl);

    static int CurlDebugFunc(CURL* hcurl, curl_infotype type, char* data, size_t size, void* userptr);

    // methods
    bool ResetHandle(void);
    bool RemakeHandle(void);
    bool ClearInternalData(void);
    void insertV4Headers();
    void insertV2Headers();
    void insertIBMIAMHeaders();
    void insertAuthHeaders();
    std::string CalcSignatureV2(const std::string& method, const std::string& strMD5, const std::string& content_type, const std::string& date, const std::string& resource);
    std::string CalcSignature(const std::string& method, const std::string& canonical_uri, const std::string& query_string, const std::string& strdate, const std::string& payload_hash, const std::string& date8601);
    bool GetUploadId(std::string& upload_id);
    int GetIAMCredentials(void);

    int UploadMultipartPostSetup(const char* tpath, int part_num, const std::string& upload_id);
    int CopyMultipartPostRequest(const char* from, const char* to, int part_num, std::string& upload_id, headers_t& meta);
    bool UploadMultipartPostComplete();

  public:
    // class methods
    static bool InitS3fsCurl(const char* MimeFile = NULL);
    static bool DestroyS3fsCurl(void);
    static int ParallelMultipartUploadRequest(const char* tpath, headers_t& meta, int fd);
    static int ParallelGetObjectRequest(const char* tpath, int fd, off_t start, ssize_t size);
    static bool CheckIAMCredentialUpdate(void);

    // class methods(variables)
    static std::string LookupMimeType(const std::string& name);
    static bool SetCheckCertificate(bool isCertCheck);
    static bool SetDnsCache(bool isCache);
    static bool SetSslSessionCache(bool isCache);
    static long SetConnectTimeout(long timeout);
    static time_t SetReadwriteTimeout(time_t timeout);
    static time_t GetReadwriteTimeout(void) { return S3fsCurl::readwrite_timeout; }
    static int SetRetries(int count);
    static bool SetPublicBucket(bool flag);
    static bool IsPublicBucket(void) { return S3fsCurl::is_public_bucket; }
    static std::string SetDefaultAcl(const char* acl);
    static std::string GetDefaultAcl();
    static storage_class_t SetStorageClass(storage_class_t storage_class);
    static storage_class_t GetStorageClass() { return S3fsCurl::storage_class; }
    static bool LoadEnvSse(void) { return (S3fsCurl::LoadEnvSseCKeys() && S3fsCurl::LoadEnvSseKmsid()); }
    static sse_type_t SetSseType(sse_type_t type);
    static sse_type_t GetSseType(void) { return S3fsCurl::ssetype; }
    static bool IsSseDisable(void) { return (SSE_DISABLE == S3fsCurl::ssetype); }
    static bool IsSseS3Type(void) { return (SSE_S3 == S3fsCurl::ssetype); }
    static bool IsSseCType(void) { return (SSE_C == S3fsCurl::ssetype); }
    static bool IsSseKmsType(void) { return (SSE_KMS == S3fsCurl::ssetype); }
    static bool FinalCheckSse(void);
    static bool SetSseCKeys(const char* filepath);
    static bool SetSseKmsid(const char* kmsid);
    static bool IsSetSseKmsId(void) { return !S3fsCurl::ssekmsid.empty(); }
    static const char* GetSseKmsId(void) { return S3fsCurl::ssekmsid.c_str(); }
    static bool GetSseKey(std::string& md5, std::string& ssekey);
    static bool GetSseKeyMd5(int pos, std::string& md5);
    static int GetSseKeyCount(void);
    static bool SetContentMd5(bool flag);
    static bool SetVerbose(bool flag);
    static bool GetVerbose(void) { return S3fsCurl::is_verbose; }
    static bool SetAccessKey(const char* AccessKeyId, const char* SecretAccessKey);
    static bool IsSetAccessKeyID(void){
                  return (0 < S3fsCurl::AWSAccessKeyId.size());
                }
    static bool IsSetAccessKeys(void){
                  return (0 < S3fsCurl::IAM_role.size() || ((0 < S3fsCurl::AWSAccessKeyId.size() || S3fsCurl::is_ibm_iam_auth) && 0 < S3fsCurl::AWSSecretAccessKey.size()));
                }
    static long SetSslVerifyHostname(long value);
    static long GetSslVerifyHostname(void) { return S3fsCurl::ssl_verify_hostname; }
    static int SetMaxParallelCount(int value);
    static int GetMaxParallelCount(void) { return S3fsCurl::max_parallel_cnt; }
    static bool SetIsECS(bool flag);
    static bool SetIsIBMIAMAuth(bool flag);
    static size_t SetIAMFieldCount(size_t field_count);
    static std::string SetIAMCredentialsURL(const char* url);
    static std::string SetIAMTokenField(const char* token_field);
    static std::string SetIAMExpiryField(const char* expiry_field);
    static std::string SetIAMRole(const char* role);
    static const char* GetIAMRole(void) { return S3fsCurl::IAM_role.c_str(); }
    static bool SetMultipartSize(off_t size);
    static off_t GetMultipartSize(void) { return S3fsCurl::multipart_size; }
    static bool SetSignatureV4(bool isset) { bool bresult = S3fsCurl::is_sigv4; S3fsCurl::is_sigv4 = isset; return bresult; }
    static bool IsSignatureV4(void) { return S3fsCurl::is_sigv4; }
    static bool SetUserAgentFlag(bool isset) { bool bresult = S3fsCurl::is_ua; S3fsCurl::is_ua = isset; return bresult; }
    static bool IsUserAgentFlag(void) { return S3fsCurl::is_ua; }
    static void InitUserAgent(void);

    // methods
    bool CreateCurlHandle(bool force = false);
    bool DestroyCurlHandle(bool force = false);

    bool LoadIAMRoleFromMetaData(void);
    bool AddSseRequestHead(sse_type_t ssetype, std::string& ssevalue, bool is_only_c, bool is_copy);
    bool GetResponseCode(long& responseCode);
    int RequestPerform(void);
    int DeleteRequest(const char* tpath);
    bool PreHeadRequest(const char* tpath, const char* bpath = NULL, const char* savedpath = NULL, int ssekey_pos = -1);
    bool PreHeadRequest(std::string& tpath, std::string& bpath, std::string& savedpath, int ssekey_pos = -1) {
      return PreHeadRequest(tpath.c_str(), bpath.c_str(), savedpath.c_str(), ssekey_pos);
    }
    int HeadRequest(const char* tpath, headers_t& meta);
    int PutHeadRequest(const char* tpath, headers_t& meta, bool is_copy);
    int PutRequest(const char* tpath, headers_t& meta, int fd);
    int PreGetObjectRequest(const char* tpath, int fd, off_t start, ssize_t size, sse_type_t ssetype, std::string& ssevalue);
    int GetObjectRequest(const char* tpath, int fd, off_t start = -1, ssize_t size = -1);
    int CheckBucket(void);
    int ListBucketRequest(const char* tpath, const char* query);
    int PreMultipartPostRequest(const char* tpath, headers_t& meta, std::string& upload_id, bool is_copy);
    int CompleteMultipartPostRequest(const char* tpath, std::string& upload_id, etaglist_t& parts);
    int UploadMultipartPostRequest(const char* tpath, int part_num, const std::string& upload_id);
    int MultipartListRequest(std::string& body);
    int AbortMultipartUpload(const char* tpath, std::string& upload_id);
    int MultipartHeadRequest(const char* tpath, off_t size, headers_t& meta, bool is_copy);
    int MultipartUploadRequest(const char* tpath, headers_t& meta, int fd, bool is_copy);
    int MultipartUploadRequest(const std::string& upload_id, const char* tpath, int fd, off_t offset, size_t size, etaglist_t& list);
    int MultipartRenameRequest(const char* from, const char* to, headers_t& meta, off_t size);

    // methods(variables)
    CURL* GetCurlHandle(void) const { return hCurl; }
    std::string GetPath(void) const { return path; }
    std::string GetBasePath(void) const { return base_path; }
    std::string GetSpacialSavedPath(void) const { return saved_path; }
    std::string GetUrl(void) const { return url; }
    std::string GetOp(void) const { return op; }
    headers_t* GetResponseHeaders(void) { return &responseHeaders; }
    BodyData* GetBodyData(void) const { return bodydata; }
    BodyData* GetHeadData(void) const { return headdata; }
    long GetLastResponseCode(void) const { return LastResponseCode; }
    bool SetUseAhbe(bool ahbe);
    bool EnableUseAhbe(void) { return SetUseAhbe(true); }
    bool DisableUseAhbe(void) { return SetUseAhbe(false); }
    bool IsUseAhbe(void) const { return is_use_ahbe; }
    int GetMultipartRetryCount(void) const { return retry_count; }
    void SetMultipartRetryCount(int retrycnt) { retry_count = retrycnt; }
    bool IsOverMultipartRetryCount(void) const { return (retry_count >= S3fsCurl::retries); }
    int GetLastPreHeadSeecKeyPos(void) const { return b_ssekey_pos; }
};

//----------------------------------------------
// class S3fsMultiCurl
//----------------------------------------------
// Class for lapping multi curl
//
typedef std::map<CURL*, S3fsCurl*> s3fscurlmap_t;
typedef bool (*S3fsMultiSuccessCallback)(S3fsCurl* s3fscurl);    // callback for succeed multi request
typedef S3fsCurl* (*S3fsMultiRetryCallback)(S3fsCurl* s3fscurl); // callback for failure and retrying

class S3fsMultiCurl
{
  private:
    static int    max_multireq;

    s3fscurlmap_t cMap_all;  // all of curl requests
    s3fscurlmap_t cMap_req;  // curl requests are sent

    S3fsMultiSuccessCallback SuccessCallback;
    S3fsMultiRetryCallback   RetryCallback;

  private:
    bool ClearEx(bool is_all);
    int MultiPerform(void);
    int MultiRead(void);

    static void* RequestPerformWrapper(void* arg);

  public:
    S3fsMultiCurl();
    ~S3fsMultiCurl();

    static int SetMaxMultiRequest(int max);
    static int GetMaxMultiRequest(void) { return S3fsMultiCurl::max_multireq; }

    S3fsMultiSuccessCallback SetSuccessCallback(S3fsMultiSuccessCallback function);
    S3fsMultiRetryCallback SetRetryCallback(S3fsMultiRetryCallback function);
    bool Clear(void) { return ClearEx(true); }
    bool SetS3fsCurlObject(S3fsCurl* s3fscurl);
    int Request(void);
};

//----------------------------------------------
// Utility Functions
//----------------------------------------------
std::string GetContentMD5(int fd);
unsigned char* md5hexsum(int fd, off_t start, ssize_t size);
std::string md5sum(int fd, off_t start, ssize_t size);
struct curl_slist* curl_slist_sort_insert(struct curl_slist* list, const char* data);
struct curl_slist* curl_slist_sort_insert(struct curl_slist* list, const char* key, const char* value);
std::string get_sorted_header_keys(const struct curl_slist* list);
std::string get_canonical_headers(const struct curl_slist* list, bool only_amz = false);
std::string get_header_value(const struct curl_slist* list, const std::string &key);
bool MakeUrlResource(const char* realpath, std::string& resourcepath, std::string& url);
std::string prepare_url(const char* url);
bool get_object_sse_type(const char* path, sse_type_t& ssetype, std::string& ssevalue);   // implement in s3fs.cpp

#endif // S3FS_CURL_H_

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: noet sw=4 ts=4 fdm=marker
* vim<600: noet sw=4 ts=4
*/
