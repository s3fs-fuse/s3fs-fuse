#ifndef S3FS_CURL_H_
#define S3FS_CURL_H_

// memory class for curl write memory callback 
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

// memory structure for POST
struct WriteThis {
  const char *readptr;
  int sizeleft;
};

class auto_curl_slist {
 public:
  auto_curl_slist() : slist(0) { }
  ~auto_curl_slist() { curl_slist_free_all(slist); }

  struct curl_slist* get() const { return slist; }

  void append(const std::string& s) {
    slist = curl_slist_append(slist, s.c_str());
  }

 private:
  struct curl_slist* slist;
};

// header data
struct head_data {
  std::string path;
  std::string *url;
  struct curl_slist *requestHeaders;
  headers_t *responseHeaders;
};

typedef std::map<CURL*, head_data> headMap_t;

void destroy_curl_handle(CURL *curl_handle);

struct cleanup_head_data {
  void operator()(std::pair<CURL*, head_data> qqq) {
    CURL* curl_handle  = qqq.first;

    head_data response = qqq.second;
    delete response.url;
    curl_slist_free_all(response.requestHeaders);
    delete response.responseHeaders;
    destroy_curl_handle(curl_handle);
  }
};

class auto_head {
 public:
  auto_head() {}
  ~auto_head() {
    for_each(headMap.begin(), headMap.end(), cleanup_head_data());
  }

  headMap_t& get() { return headMap; }

  void remove(CURL* curl_handle) {
    headMap_t::iterator iter = headMap.find(curl_handle);
    if(iter == headMap.end()){
      return;
    }

    head_data response = iter->second;
    delete response.url;
    curl_slist_free_all(response.requestHeaders);
    delete response.responseHeaders;
    destroy_curl_handle(curl_handle);

    headMap.erase(iter);
  }

  private:
    headMap_t headMap;
};

//
// Functions
//
int init_curl_handles_mutex(void);
int destroy_curl_handles_mutex(void);
size_t header_callback(void *data, size_t blockSize, size_t numBlocks, void *userPtr);
CURL *create_curl_handle(void);
int curl_delete(const char *path);
int curl_get_headers(const char *path, headers_t &meta);
CURL *create_head_handle(struct head_data *request);
int my_curl_easy_perform(CURL* curl, BodyData* body = NULL, BodyData* head = NULL, FILE* f = 0);
size_t WriteMemoryCallback(void *ptr, size_t blockSize, size_t numBlocks, void *data);
size_t read_callback(void *ptr, size_t size, size_t nmemb, void *userp);
int my_curl_progress(
    void *clientp, double dltotal, double dlnow, double ultotal, double ulnow);
std::string calc_signature(
    std::string method, std::string content_type, std::string date, curl_slist* headers, std::string resource);
void locate_bundle(void);
std::string md5sum(int fd);
bool InitMimeType(const char* file);
std::string lookupMimeType(std::string);

#endif // S3FS_CURL_H_
