#ifndef S3FS_CURL_H_
#define S3FS_CURL_H_

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
  int         fd;           // base file(temporary full file) discriptor
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
  bool operator()(const std::string& a, const std::string& b){
    return strcasecmp(a.c_str(), b.c_str()) < 0;
  }
};
typedef std::map<std::string, std::string, case_insensitive_compare_func> mimes_t;
typedef std::pair<double, double>   progress_t;
typedef std::map<CURL*, time_t>     curltime_t;
typedef std::map<CURL*, progress_t> curlprogress_t;

class S3fsMultiCurl;

//----------------------------------------------
// class S3fsCurl
//----------------------------------------------
typedef std::map<std::string, std::string> iamcredmap_t;

// share
#define	SHARE_MUTEX_DNS         0
#define	SHARE_MUTEX_SSL_SESSION 1
#define	SHARE_MUTEX_MAX         2

// internal use struct for openssl
struct CRYPTO_dynlock_value
{
  pthread_mutex_t dyn_mutex;
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
      REQTYPE_ABORTMULTIUPLOAD
    };

    // class variables
    static pthread_mutex_t  curl_handles_lock;
    static pthread_mutex_t  curl_share_lock[SHARE_MUTEX_MAX];
    static pthread_mutex_t* crypt_mutex;
    static bool             is_initglobal_done;
    static CURLSH*          hCurlShare;
    static bool             is_dns_cache;
    static bool             is_ssl_session_cache;
    static long             connect_timeout;
    static time_t           readwrite_timeout;
    static int              retries;
    static bool             is_public_bucket;
    static std::string      default_acl;             // TODO: to enum
    static bool             is_use_rrs;
    static bool             is_use_sse;
    static bool             is_content_md5;
    static bool             is_verbose;
    static std::string      AWSAccessKeyId;
    static std::string      AWSSecretAccessKey;
    static std::string      AWSAccessToken;
    static time_t           AWSAccessTokenExpire;
    static std::string      IAM_role;
    static long             ssl_verify_hostname;
    static const EVP_MD*    evp_md;
    static curltime_t       curl_times;
    static curlprogress_t   curl_progress;
    static std::string      curl_ca_bundle;
    static mimes_t          mimeTypes;
    static int              max_parallel_cnt;

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

  public:
    // constructor/destructor
    S3fsCurl(bool ahbe = false);
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
    static void CryptMutexLock(int mode, int pos, const char* file, int line);
    static unsigned long CryptGetThreadid(void);
    static struct CRYPTO_dynlock_value* CreateDynCryptMutex(const char* file, int line);
    static void DynCryptMutexLock(int mode, struct CRYPTO_dynlock_value* dyndata, const char* file, int line);
    static void DestoryDynCryptMutex(struct CRYPTO_dynlock_value* dyndata, const char* file, int line);
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

    // methods
    bool ResetHandle(void);
    bool RemakeHandle(void);
    bool ClearInternalData(void);
    std::string CalcSignature(std::string method, std::string strMD5, std::string content_type, std::string date, std::string resource);
    bool GetUploadId(std::string& upload_id);
    int GetIAMCredentials(void);

    int PreMultipartPostRequest(const char* tpath, headers_t& meta, std::string& upload_id, bool ow_sse_flg);
    int CompleteMultipartPostRequest(const char* tpath, std::string& upload_id, etaglist_t& parts);
    int UploadMultipartPostSetup(const char* tpath, int part_num, std::string& upload_id);
    int UploadMultipartPostRequest(const char* tpath, int part_num, std::string& upload_id);
    int CopyMultipartPostRequest(const char* from, const char* to, int part_num, std::string& upload_id, headers_t& meta);

  public:
    // class methods
    static bool InitS3fsCurl(const char* MimeFile = NULL);
    static bool DestroyS3fsCurl(void);
    static int ParallelMultipartUploadRequest(const char* tpath, headers_t& meta, int fd, bool ow_sse_flg);
    static int ParallelGetObjectRequest(const char* tpath, int fd, off_t start, ssize_t size);
    static bool CheckIAMCredentialUpdate(void);

    // class methods(valiables)
    static std::string LookupMimeType(std::string name);
    static bool SetDnsCache(bool isCache);
    static bool SetSslSessionCache(bool isCache);
    static long SetConnectTimeout(long timeout);
    static time_t SetReadwriteTimeout(time_t timeout);
    static time_t GetReadwriteTimeout(void) { return S3fsCurl::readwrite_timeout; }
    static int SetRetries(int count);
    static bool SetPublicBucket(bool flag);
    static bool IsPublicBucket(void) { return S3fsCurl::is_public_bucket; }
    static std::string SetDefaultAcl(const char* acl);
    static bool SetUseRrs(bool flag);
    static bool GetUseRrs(void) { return S3fsCurl::is_use_rrs; }
    static bool SetUseSse(bool flag);
    static bool GetUseSse(void) { return S3fsCurl::is_use_sse; }
    static bool SetContentMd5(bool flag);
    static bool SetVerbose(bool flag);
    static bool GetVerbose(void) { return S3fsCurl::is_verbose; }
    static bool SetAccessKey(const char* AccessKeyId, const char* SecretAccessKey);
    static bool IsSetAccessKeyId(void){
                  return (0 < S3fsCurl::IAM_role.size() || (0 < S3fsCurl::AWSAccessKeyId.size() && 0 < S3fsCurl::AWSSecretAccessKey.size()));
                }
    static long SetSslVerifyHostname(long value);
    static long GetSslVerifyHostname(void) { return S3fsCurl::ssl_verify_hostname; }
    static int SetMaxParallelCount(int value);
    static std::string SetIAMRole(const char* role);
    static const char* GetIAMRole(void) { return S3fsCurl::IAM_role.c_str(); }

    // methods
    bool CreateCurlHandle(bool force = false);
    bool DestroyCurlHandle(void);

    bool GetResponseCode(long& responseCode);
    int RequestPerform(void);
    int DeleteRequest(const char* tpath);
    bool PreHeadRequest(const char* tpath, const char* bpath = NULL, const char* savedpath = NULL);
    bool PreHeadRequest(std::string& tpath, std::string& bpath, std::string& savedpath) {
      return PreHeadRequest(tpath.c_str(), bpath.c_str(), savedpath.c_str());
    }
    int HeadRequest(const char* tpath, headers_t& meta);
    int PutHeadRequest(const char* tpath, headers_t& meta, bool ow_sse_flg);
    int PutRequest(const char* tpath, headers_t& meta, int fd, bool ow_sse_flg);
    int PreGetObjectRequest(const char* tpath, int fd, off_t start, ssize_t size);
    int GetObjectRequest(const char* tpath, int fd, off_t start = -1, ssize_t size = -1);
    int CheckBucket(void);
    int ListBucketRequest(const char* tpath, const char* query);
    int MultipartListRequest(std::string& body);
    int AbortMultipartUpload(const char* tpath, std::string& upload_id);
    int MultipartHeadRequest(const char* tpath, off_t size, headers_t& meta);
    int MultipartUploadRequest(const char* tpath, headers_t& meta, int fd, bool ow_sse_flg);
    int MultipartRenameRequest(const char* from, const char* to, headers_t& meta, off_t size);

    // methods(valiables)
    CURL* GetCurlHandle(void) const { return hCurl; }
    std::string GetPath(void) const { return path; }
    std::string GetBasePath(void) const { return base_path; }
    std::string GetSpacialSavedPath(void) const { return saved_path; }
    std::string GetUrl(void) const { return url; }
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
};

//----------------------------------------------
// class S3fsMultiCurl
//----------------------------------------------
// Class for lapping multi curl
//
typedef std::map<CURL*, S3fsCurl*> s3fscurlmap_t;
typedef bool (*S3fsMultiSuccessCallback)(S3fsCurl* s3fscurl);    // callback for succeed multi request
typedef S3fsCurl* (*S3fsMultiRetryCallback)(S3fsCurl* s3fscurl); // callback for failuer and retrying

class S3fsMultiCurl
{
  private:
    static int    max_multireq;

    CURLM*        hMulti;
    s3fscurlmap_t cMap_all;  // all of curl requests
    s3fscurlmap_t cMap_req;  // curl requests are sent

    S3fsMultiSuccessCallback SuccessCallback;
    S3fsMultiRetryCallback   RetryCallback;

  private:
    bool ClearEx(bool is_all);
    int MultiPerform(void);
    int MultiRead(void);

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
// class AdditionalHeader
//----------------------------------------------
typedef std::list<int> charcnt_list_t;
typedef std::map<std::string, std::string> headerpair_t;
typedef std::map<std::string, headerpair_t> addheader_t;

class AdditionalHeader
{
  private:
    static AdditionalHeader singleton;
    bool                    is_enable;
    charcnt_list_t          charcntlist;
    addheader_t             addheader;

  public:
    // Reference singleton
    static AdditionalHeader* get(void) { return &singleton; }

    AdditionalHeader();
    ~AdditionalHeader();

    bool Load(const char* file);
    void Unload(void);

    bool AddHeader(headers_t& meta, const char* path) const;
    struct curl_slist* AddHeader(struct curl_slist* list, const char* path) const;
    bool Dump(void) const;
};

//----------------------------------------------
// Utility Functions
//----------------------------------------------
std::string GetContentMD5(int fd);
unsigned char* md5hexsum(int fd, off_t start, ssize_t size);
std::string md5sum(int fd, off_t start, ssize_t size);
struct curl_slist* curl_slist_sort_insert(struct curl_slist* list, const char* data);
bool MakeUrlResource(const char* realpath, std::string& resourcepath, std::string& url);

#endif // S3FS_CURL_H_
