#ifndef S3FS_CURL_H_
#define S3FS_CURL_H_

// memory structure for curl write memory callback 
struct BodyStruct {
  char *text;    
  size_t size;
};

// memory structure for POST
struct WriteThis {
  const char *readptr;
  int sizeleft;
};

typedef struct curlhll {
  CURL *handle;
  struct curlhll *next;
} CURLHLL;

typedef struct curlmhll {
   CURLM *handle;
   struct curlhll *curlhll_head;
   struct curlmhll * next;
} CURLMHLL;

typedef std::pair<double, double> progress_t;

extern int retries;
extern long connect_timeout;
extern time_t readwrite_timeout;
extern bool debug;
extern std::string program_name;
extern std::string ssl_verify_hostname;

CURL *create_curl_handle(void);
void destroy_curl_handle(CURL *curl_handle);
int my_curl_easy_perform(CURL* curl, BodyStruct* body = NULL, FILE* f = 0);
size_t WriteMemoryCallback(void *ptr, size_t blockSize, size_t numBlocks, void *data);
size_t read_callback(void *ptr, size_t size, size_t nmemb, void *userp);
int my_curl_progress(
    void *clientp, double dltotal, double dlnow, double ultotal, double ulnow);
void locate_bundle(void);

CURLHLL *create_h_element(CURL *handle);
CURLMHLL *create_mh_element(CURLM *handle);
CURLMHLL *add_mh_element(CURLMHLL *head, CURLM *handle);
void add_h_element(CURLHLL *head, CURL *handle);
void add_h_to_mh(CURL *h, CURLMHLL *mh);
void cleanup_multi_stuff(CURLMHLL *mhhead);

#endif // S3FS_CURL_H_
