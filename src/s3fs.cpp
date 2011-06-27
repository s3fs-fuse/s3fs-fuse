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
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <time.h>
#include <utime.h>
#include <sys/stat.h>
#include <libgen.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <openssl/md5.h>
#include <pwd.h>
#include <grp.h>
#include <syslog.h>
#include <getopt.h>

#include <fstream>
#include <iostream>
#include <vector>
#include <algorithm>
#include <string>

#include "s3fs.h"
#include "curl.h"
#include "cache.h"
#include "string_util.h"

using namespace std;

class auto_curl_slist {
 public:
  auto_curl_slist() : slist(0) { }
  ~auto_curl_slist() { curl_slist_free_all(slist); }

  struct curl_slist* get() const { return slist; }

  void append(const string& s) {
    slist = curl_slist_append(slist, s.c_str());
  }

 private:
  struct curl_slist* slist;
};

typedef struct mvnode {
   char *old_path;
   char *new_path;
   bool is_dir;
   struct mvnode *prev;
   struct mvnode *next;
} MVNODE;

// All this "stuff" stuff is kinda ugly... it works though... needs cleanup
struct stuff_t {
  // default ctor works
  string path;
  string* url;
  struct curl_slist* requestHeaders;
  headers_t* responseHeaders;
};

typedef map<CURL*, stuff_t> stuffMap_t;

struct cleanup_stuff {
  void operator()(pair<CURL*, stuff_t> qqq) {
    stuff_t stuff = qqq.second;
    delete stuff.url;
    curl_slist_free_all(stuff.requestHeaders);
    delete stuff.responseHeaders;
  }
};

struct case_insensitive_compare_func {
  bool operator ()(const string &a, const string &b) {
    return strcasecmp(a.c_str(), b.c_str()) < 0;
  }
};

typedef map<string, string, case_insensitive_compare_func> mimes_t;

static mimes_t mimeTypes;

class auto_stuff {
 public:
  auto_stuff() { }
  ~auto_stuff() {
    for_each(stuffMap.begin(), stuffMap.end(), cleanup_stuff());
  }

  stuffMap_t& get() { return stuffMap; }

private:
  stuffMap_t stuffMap;
};

MVNODE *create_mvnode(char *old_path, char *new_path, bool is_dir) {
  MVNODE *p;
  char *p_old_path;
  char *p_new_path;

  p = (MVNODE *) malloc(sizeof(MVNODE));
  if (p == NULL) {
     printf("create_mvnode: could not allocation memory for p\n");
     exit(EXIT_FAILURE);
  }

  p_old_path = (char *)malloc(strlen(old_path)+1); 
  if (p_old_path == NULL) {
    printf("create_mvnode: could not allocation memory for p_old_path\n");
    exit(EXIT_FAILURE);
  }

  strcpy(p_old_path, old_path);
 
  p_new_path = (char *)malloc(strlen(new_path)+1); 
  if (p_new_path == NULL) {
    printf("create_mvnode: could not allocation memory for p_new_path\n");
    exit(EXIT_FAILURE);
  }

  strcpy(p_new_path, new_path);

  p->old_path = p_old_path;
  p->new_path = p_new_path;
  p->is_dir = is_dir;
  p->prev = NULL;
  p->next = NULL;
  return p;
}

MVNODE *add_mvnode(MVNODE *head, char *old_path, char *new_path, bool is_dir) {
  MVNODE *p;
  MVNODE *tail;

  tail = create_mvnode(old_path, new_path, is_dir);

  for (p = head; p->next != NULL; p = p->next);
    ;

  p->next = tail;
  tail->prev = p;
  return tail;
}

void free_mvnodes(MVNODE *head) {
  MVNODE *my_head;
  MVNODE *next;
  char *p_old_path;
  char *p_new_path;

  if(head == NULL) {
     return;
  }

  my_head = head;
  next = NULL;
 
  do {
    next = my_head->next;
    p_old_path = my_head->old_path;
    p_new_path = my_head->new_path;

    free(p_old_path);
    free(p_new_path);
    free(my_head);

    my_head = next;
  } while(my_head != NULL);

  return;
}
 
/**
 * Returns the Amazon AWS signature for the given parameters.
 *
 * @param method e.g., "GET"
 * @param content_type e.g., "application/x-directory"
 * @param date e.g., get_date()
 * @param resource e.g., "/pub"
 */
string calc_signature(
    string method, string content_type, string date, curl_slist* headers, string resource) {
  int ret;
  int bytes_written;
  int offset;
  int write_attempts = 0;

  string Signature;
  string StringToSign;
  StringToSign += method + "\n";
  StringToSign += "\n"; // md5
  StringToSign += content_type + "\n";
  StringToSign += date + "\n";
  int count = 0;
  if (headers != 0) {
    do {
      //###cout << headers->data << endl;
      if (strncmp(headers->data, "x-amz", 5) == 0) {
        ++count;
        StringToSign += headers->data;
        StringToSign += 10; // linefeed
      }
    } while ((headers = headers->next) != 0);
  }

  StringToSign += resource;

  const void* key = AWSSecretAccessKey.data();
  int key_len = AWSSecretAccessKey.size();
  const unsigned char* d = reinterpret_cast<const unsigned char*>(StringToSign.data());
  int n = StringToSign.size();
  unsigned int md_len;
  unsigned char md[EVP_MAX_MD_SIZE];

  HMAC(evp_md, key, key_len, d, n, md, &md_len);

  BIO* b64 = BIO_new(BIO_f_base64());
  BIO* bmem = BIO_new(BIO_s_mem());
  b64 = BIO_push(b64, bmem);

  offset = 0;
  for (;;) {
    bytes_written = BIO_write(b64, &(md[offset]), md_len);
    write_attempts++;
    //  -1 indicates that an error occurred, or a temporary error, such as
    //  the server is busy, occurred and we need to retry later.
    //  BIO_write can do a short write, this code addresses this condition
    if (bytes_written <= 0) {
      //  Indicates whether a temporary error occurred or a failure to
      //  complete the operation occurred
      if ((ret = BIO_should_retry(b64))) {
  
        // Wait until the write can be accomplished
        if(write_attempts <= 10) {
          continue;
        } else {
          // Too many write attempts
          syslog(LOG_ERR, "Failure during BIO_write, returning null String");  
          BIO_free_all(b64);
          Signature.clear();
          return Signature;
        }
      } else {
        // If not a retry then it is an error
        syslog(LOG_ERR, "Failure during BIO_write, returning null String");  
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
    if (md_len <= 0) {
      break;
    }
  }

  // Flush the data
  ret = BIO_flush(b64);
  if ( ret <= 0) { 
    syslog(LOG_ERR, "Failure during BIO_flush, returning null String");  
    BIO_free_all(b64);
    Signature.clear();
    return Signature;
  } 

  BUF_MEM *bptr;

  BIO_get_mem_ptr(b64, &bptr);

  Signature.resize(bptr->length - 1);
  memcpy(&Signature[0], bptr->data, bptr->length-1);

  BIO_free_all(b64);

  return Signature;
}

static size_t header_callback(void *data, size_t blockSize, size_t numBlocks, void *userPtr) {
  headers_t* headers = reinterpret_cast<headers_t*>(userPtr);
  string header(reinterpret_cast<char*>(data), blockSize * numBlocks);
  string key;
  stringstream ss(header);
  if (getline(ss, key, ':')) {
    string value;
    getline(ss, value);
    (*headers)[key] = trim(value);
  }
  return blockSize * numBlocks;
}

// safe variant of dirname
static string mydirname(string path) {
  // dirname clobbers path so let it operate on a tmp copy
  return dirname(&path[0]);
}

// safe variant of basename
static string mybasename(string path) {
  // basename clobbers path so let it operate on a tmp copy
  return basename(&path[0]);
}

// mkdir --parents
static int mkdirp(const string& path, mode_t mode) {
  string base;
  string component;
  stringstream ss(path);
  while (getline(ss, component, '/')) {
    base += "/" + component;
    /*if (*/mkdir(base.c_str(), mode)/* == -1);
      return -1*/;
  }
  return 0;
}

/**
 * @return fuse return code
 * TODO return pair<int, headers_t>?!?
 */
int get_headers(const char* path, headers_t& meta) {
  int result;
  char *s3_realpath;
  CURL *curl;

  if(foreground) 
    cout << "    calling get_headers [path=" << path << "]" << endl;

  if(debug) 
    syslog(LOG_DEBUG, "get_headers called path=%s", path);

  s3_realpath = get_realpath(path);
  string resource(urlEncode(service_path + bucket + s3_realpath));
  string url(host + resource);

  headers_t responseHeaders;
  curl = create_curl_handle();
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, true);
  curl_easy_setopt(curl, CURLOPT_NOBODY, true); // HEAD
  curl_easy_setopt(curl, CURLOPT_FILETIME, true); // Last-Modified
  curl_easy_setopt(curl, CURLOPT_HEADERDATA, &responseHeaders);
  curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_callback);

  auto_curl_slist headers;
  string date = get_date();
  headers.append("Date: " + date);
  headers.append("Content-Type: ");
  if (public_bucket.substr(0,1) != "1") {
    headers.append("Authorization: AWS " + AWSAccessKeyId + ":" +
      calc_signature("HEAD", "", date, headers.get(), resource));
  }
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers.get());

  string my_url = prepare_url(url.c_str());
  curl_easy_setopt(curl, CURLOPT_URL, my_url.c_str());

  if(debug)
    syslog(LOG_DEBUG, "get_headers: now calling my_curl_easy_perform");

  result = my_curl_easy_perform(curl);
  destroy_curl_handle(curl);
  free(s3_realpath);

  if(result != 0)
     return result;

  if(debug)
    syslog(LOG_DEBUG, "get_headers: now returning from my_curl_easy_perform");

  // at this point we know the file exists in s3
  for (headers_t::iterator iter = responseHeaders.begin(); iter != responseHeaders.end(); ++iter) {
    string key = (*iter).first;
    string value = (*iter).second;
    if(key == "Content-Type")
      meta[key] = value;
    if(key == "Content-Length")
      meta[key] = value;
    if(key == "ETag")
      meta[key] = value;
    if(key == "Last-Modified")
      meta[key] = value;
    if(key.substr(0, 5) == "x-amz")
      meta[key] = value;
  }

  if(debug)
    syslog(LOG_DEBUG, "returning from get_headers, path=%s", path);

  return 0;
}

/**
 * get_local_fd
 */
int get_local_fd(const char* path) {
  int fd = -1;
  int result;
  struct stat st;
  char *s3_realpath;
  CURL *curl = NULL;
  string url;
  string resource;
  string local_md5;
  string baseName = mybasename(path);
  string resolved_path(use_cache + "/" + bucket);
  string cache_path(resolved_path + path);
  headers_t responseHeaders;

  if(foreground) 
    cout << "   get_local_fd[path=" << path << "]" << endl;

  s3_realpath = get_realpath(path);
  resource = urlEncode(service_path + bucket + s3_realpath);
  url = host + resource;

  if(use_cache.size() > 0) {
    result = get_headers(path, responseHeaders);
    if(result != 0)
       return -result;

    fd = open(cache_path.c_str(), O_RDWR); // ### TODO should really somehow obey flags here
    if(fd != -1) {
      if((fstat(fd, &st)) == -1) {
        close(fd);
        YIKES(-errno);
      }

      // if the local and remote mtime/size
      // do not match we have an invalid cache entry
      if(str(st.st_size) != responseHeaders["Content-Length"] || 
        (str(st.st_mtime) != responseHeaders["x-amz-meta-mtime"])) {
        if(close(fd) == -1)
          YIKES(-errno);

        fd = -1;
      }
    }
  }

  // need to download?
  if(fd == -1) {
    mode_t mode = strtoul(responseHeaders["x-amz-meta-mode"].c_str(), (char **)NULL, 10);

    if(use_cache.size() > 0) {
      // only download files, not folders
      if (S_ISREG(mode)) {
        /*if (*/mkdirp(resolved_path + mydirname(path), 0777)/* == -1)
          return -errno*/;
        fd = open(cache_path.c_str(), O_CREAT|O_RDWR|O_TRUNC, mode);
      } else {
        // its a folder; do *not* create anything in local cache... (###TODO do this in a better way)
        fd = fileno(tmpfile());
      }
    } else {
      fd = fileno(tmpfile());
    }

    if(fd == -1)
      YIKES(-errno);

    FILE *f = fdopen(fd, "w+");
    if(f == 0)
      YIKES(-errno);

    if(foreground) 
      cout << "      downloading[path=" << path << "][fd=" << fd << "]" << endl;

    if(debug)
      syslog(LOG_DEBUG, "LOCAL FD");

    auto_curl_slist headers;
    string date = get_date();
    string my_url = prepare_url(url.c_str());
    headers.append("Date: " + date);
    headers.append("Content-Type: ");
    if(public_bucket.substr(0,1) != "1") {
      headers.append("Authorization: AWS " + AWSAccessKeyId + ":" +
        calc_signature("GET", "", date, headers.get(), resource));
    }

    curl = create_curl_handle();
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, true);
    curl_easy_setopt(curl, CURLOPT_FILE, f);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers.get());
    curl_easy_setopt(curl, CURLOPT_URL, my_url.c_str());

    result = my_curl_easy_perform(curl, NULL, f);
    if(result != 0) {
      destroy_curl_handle(curl);
      free(s3_realpath);

      return -result;
    }

    //only one of these is needed...
    fflush(f);
    fsync(fd);

    if(fd == -1)
      YIKES(-errno);

    if(use_cache.size() > 0 && !S_ISLNK(mode)) {
      // make the file's mtime match that of the file on s3
      struct utimbuf n_mtime;
      n_mtime.modtime = strtoul(responseHeaders["x-amz-meta-mtime"].c_str(), (char **) NULL, 10);
      if((utime(cache_path.c_str(), &n_mtime)) == -1) {
        YIKES(-errno);
      }
    }
  }

  free(s3_realpath);
  destroy_curl_handle(curl);

  return fd;
}

/**
 * create or update s3 meta
 * @return fuse return code
 */
static int put_headers(const char *path, headers_t meta) {
  int result;
  char *s3_realpath;
  string url;
  string resource;
  struct BodyStruct body;
  CURL *curl = NULL;

  if(foreground) 
    cout << "   put_headers[path=" << path << "]" << endl;

  s3_realpath = get_realpath(path);
  resource = urlEncode(service_path + bucket + s3_realpath);
  url = host + resource;

  body.text = (char *)malloc(1);
  body.size = 0;

  auto_curl_slist headers;
  string date = get_date();
  headers.append("Date: " + date);

  meta["x-amz-acl"] = default_acl;
  string ContentType = meta["Content-Type"];

  for (headers_t::iterator iter = meta.begin(); iter != meta.end(); ++iter) {
    string key = (*iter).first;
    string value = (*iter).second;
    if (key == "Content-Type")
      headers.append(key + ":" + value);
    if (key.substr(0,9) == "x-amz-acl")
      headers.append(key + ":" + value);
    if (key.substr(0,10) == "x-amz-meta")
      headers.append(key + ":" + value);
    if (key == "x-amz-copy-source")
      headers.append(key + ":" + value);
  }

  if(use_rrs.substr(0,1) == "1")
    headers.append("x-amz-storage-class:REDUCED_REDUNDANCY");

  if(public_bucket.substr(0,1) != "1")
    headers.append("Authorization: AWS " + AWSAccessKeyId + ":" +
      calc_signature("PUT", ContentType, date, headers.get(), resource));

  curl = create_curl_handle();
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, true);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&body);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(curl, CURLOPT_UPLOAD, true); // HTTP PUT
  curl_easy_setopt(curl, CURLOPT_INFILESIZE, 0); // Content-Length
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers.get());

  if(debug)
    syslog(LOG_DEBUG, "copy path=%s", path);

  if(foreground) 
    cout << "      copying[path=" << path << "]" << endl;

  string my_url = prepare_url(url.c_str());
  curl_easy_setopt(curl, CURLOPT_URL, my_url.c_str());

  result = my_curl_easy_perform(curl, &body);

  destroy_curl_handle(curl);
  free(body.text);
  free(s3_realpath);

  if(result != 0)
    return result;

  // Update mtime in local file cache.
  if(meta.count("x-amz-meta-mtime") > 0 && use_cache.size() > 0) {
    struct stat st;
    struct utimbuf n_mtime;
    string cache_path(use_cache + "/" + bucket + path);

    if((stat(cache_path.c_str(), &st)) == 0) {
      n_mtime.modtime = strtoul(meta["x-amz-meta-mtime"].c_str(), (char **) NULL, 10);
      if((utime(cache_path.c_str(), &n_mtime)) == -1) {
        YIKES(-errno);
      }
    }
  }

  return 0;
}

static int put_local_fd_small_file(const char* path, headers_t meta, int fd) {
  string resource;
  string url;
  char *s3_realpath;
  struct stat st;
  CURL *curl = NULL;

  if(foreground) 
    printf("   put_local_fd_small_file[path=%s][fd=%d]\n", path, fd);

  if(fstat(fd, &st) == -1)
    YIKES(-errno);

  s3_realpath = get_realpath(path);
  resource = urlEncode(service_path + bucket + s3_realpath);
  url = host + resource;

  int result;
  struct BodyStruct body;
  auto_curl_slist headers;
  string date = get_date();

  body.text = (char *) malloc(1);
  body.size = 0; 

  curl = create_curl_handle();
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, true);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&body);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(curl, CURLOPT_UPLOAD, true); // HTTP PUT
  curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, static_cast<curl_off_t>(st.st_size)); // Content-Length

  FILE* f = fdopen(fd, "rb");
  if(f == 0)
    YIKES(-errno);

  curl_easy_setopt(curl, CURLOPT_INFILE, f);

  string ContentType = meta["Content-Type"];
  headers.append("Date: " + date);
  meta["x-amz-acl"] = default_acl;

  for (headers_t::iterator iter = meta.begin(); iter != meta.end(); ++iter) {
    string key = (*iter).first;
    string value = (*iter).second;
    if (key == "Content-Type")
      headers.append(key + ":" + value);
    if (key.substr(0,9) == "x-amz-acl")
      headers.append(key + ":" + value);
    if (key.substr(0,10) == "x-amz-meta")
      headers.append(key + ":" + value);
  }

  if(use_rrs.substr(0,1) == "1")
    headers.append("x-amz-storage-class:REDUCED_REDUNDANCY");
  
  if(public_bucket.substr(0,1) != "1")
    headers.append("Authorization: AWS " + AWSAccessKeyId + ":" +
      calc_signature("PUT", ContentType, date, headers.get(), resource));

  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers.get());

  if(foreground) 
    cout << "      uploading[path=" << path << "][fd=" << fd << "][size="<<st.st_size <<"]" << endl;

  string my_url = prepare_url(url.c_str());
  curl_easy_setopt(curl, CURLOPT_URL, my_url.c_str());

  result = my_curl_easy_perform(curl, &body, f);

  free(body.text);
  free(s3_realpath);
  destroy_curl_handle(curl);

  if(result != 0)
    return result;

  return 0;
}

static int put_local_fd_big_file(const char* path, headers_t meta, int fd) {
  struct stat st;
  off_t lSize;
  int partfd = -1;
  FILE* pSourceFile;
  FILE* pPartFile;
  char *buffer;
  unsigned long lBufferSize = 0;
  size_t bytesRead;
  size_t bytesWritten;
  string uploadId;
  vector <file_part> parts;

  if(foreground) 
    printf("   put_local_fd_big_file[path=%s][fd=%d]\n", path, fd);

  if(fstat(fd, &st) == -1)
    YIKES(-errno);

  uploadId = initiate_multipart_upload(path, st.st_size, meta);
  if(uploadId.size() == 0) {
    syslog(LOG_ERR, "Could not determine UploadId");
    return(-EIO);
  }

  // Open the source file
  pSourceFile = fdopen(fd, "rb");
  if(pSourceFile == NULL) {
    syslog(LOG_ERR, "%d###result=%d", __LINE__, errno); \
    return(-errno);
  }

  // Source sucessfully opened, obtain file size:
  lSize = st.st_size;

  lBufferSize = 0;
 
  // cycle through open fd, pulling off 10MB chunks at a time
  while(lSize > 0) {
    file_part part;

    if(lSize >= MULTIPART_SIZE)
       lBufferSize = MULTIPART_SIZE;
    else
       lBufferSize = lSize;

    lSize = lSize - lBufferSize;
      
    if((buffer = (char *) malloc(sizeof(char) * lBufferSize)) == NULL) {
      syslog(LOG_CRIT, "Could not allocate memory for buffer\n");
      exit(EXIT_FAILURE);
    }

    // copy the file portion into the buffer:
    bytesRead = fread(buffer, 1, lBufferSize, pSourceFile);
    if(bytesRead != lBufferSize) {
      syslog(LOG_ERR, "%d ### bytesRead:%zu  does not match lBufferSize: %lu\n", 
                      __LINE__, bytesRead, lBufferSize);

      if(buffer)
        free(buffer);

      return(-EIO);
    } 

    // create uniq temporary file
    strncpy(part.path, "/tmp/s3fs.XXXXXX", sizeof part.path);
    if((partfd = mkstemp(part.path)) == -1) {
      if(buffer) 
        free(buffer);

      YIKES(-errno);
    }

    // open a temporary file for upload
    if((pPartFile = fdopen(partfd, "wb")) == NULL) {
      syslog(LOG_ERR, "%d ### Could not open temporary file: errno %i\n", 
                      __LINE__, errno);
      if(buffer)
        free(buffer);

      return(-errno);
    }

    // copy buffer to temporary file
    bytesWritten = fwrite(buffer, 1, (size_t)lBufferSize, pPartFile);
    if(bytesWritten != lBufferSize) {
      syslog(LOG_ERR, "%d ### bytesWritten:%zu  does not match lBufferSize: %lu\n", 
                      __LINE__, bytesWritten, lBufferSize);

      fclose(pPartFile);
      if(buffer)
        free(buffer);

      return(-EIO);
    } 
   
    fclose(pPartFile);
    if(buffer)
      free(buffer);  
    
    part.etag = upload_part(path, part.path, parts.size() + 1, uploadId);

    // delete temporary part file
    if(remove(part.path) != 0)
      YIKES(-errno);

    parts.push_back(part);
  } // while(lSize > 0)

  return complete_multipart_upload(path, uploadId, parts);
}

/**
 * create or update s3 object
 * @return fuse return code
 */
static int put_local_fd(const char* path, headers_t meta, int fd) {
  int result;
  struct stat st;

  if(foreground) 
    cout << "   put_local_fd[path=" << path << "][fd=" << fd << "]" << endl;

  if(fstat(fd, &st) == -1)
    YIKES(-errno);

  /*
   * Make decision to do multi upload (or not) based upon file size
   * 
   * According to the AWS spec:
   *  - 1 to 10,000 parts are allowed
   *  - minimum size of parts is 5MB (expect for the last part)
   * 
   * For our application, we will define part size to be 10MB (10 * 2^20 Bytes)
   * maximum file size will be ~64 GB - 2 ** 36 
   * 
   * Initially uploads will be done serially
   * 
   * If file is > 20MB, then multipart will kick in
   */
  if(st.st_size > 68719476735LL ) { // 64GB - 1
     // close f ?
     return -ENOTSUP;
  }

  if(st.st_size >= 20971520 && !nomultipart) { // 20MB
     // Additional time is needed for large files
     if(readwrite_timeout < 120)
       readwrite_timeout = 120;

     result = put_local_fd_big_file(path, meta, fd); 
  } else {
     result = put_local_fd_small_file(path, meta, fd); 
  }
  return result;
}

/*
 * initiate_multipart_upload
 *
 * Example :
 *   POST /example-object?uploads HTTP/1.1
 *   Host: example-bucket.s3.amazonaws.com
 *   Date: Mon, 1 Nov 2010 20:34:56 GMT
 *   Authorization: AWS VGhpcyBtZXNzYWdlIHNpZ25lZCBieSBlbHZpbmc=
 */
string initiate_multipart_upload(const char *path, off_t size, headers_t meta) {
  CURL *curl = NULL;
  int result;
  string auth;
  string acl;
  string url;
  string my_url;
  string date;
  string raw_date;
  string resource;
  string upload_id = "";
  string ContentType;
  char *s3_realpath;
  struct BodyStruct body;
  struct curl_slist *slist=NULL;

  if(foreground) 
    cout << "      initiate_multipart_upload [path=" << path << "][size=" << size << "]" << endl;
  
  body.text = (char *)malloc(1);
  body.size = 0; 

  s3_realpath = get_realpath(path);
  resource = urlEncode(service_path + bucket + s3_realpath);
  resource.append("?uploads");
  url = host + resource;
  my_url = prepare_url(url.c_str());

  curl = create_curl_handle();
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, true);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&body);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(curl, CURLOPT_POST, true);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, 0);

  date.assign("Date: ");
  raw_date = get_date();
  date.append(raw_date);

  slist = curl_slist_append(slist, date.c_str());
  slist = curl_slist_append(slist, "Accept:");
  slist = curl_slist_append(slist, "Content-Length:");

  ContentType.assign("Content-Type: ");
  string ctype_data;
  ctype_data.assign(lookupMimeType(path));
  ContentType.append(ctype_data);
  slist = curl_slist_append(slist, ContentType.c_str());

  // x-amz headers: (a) alphabetical order and (b) no spaces after colon
  acl.assign("x-amz-acl:");
  acl.append(default_acl);
  slist = curl_slist_append(slist, acl.c_str());

  for(headers_t::iterator iter = meta.begin(); iter != meta.end(); ++iter) {
    string key = (*iter).first;
    string value = (*iter).second;

    if(key.substr(0,10) == "x-amz-meta") {
      string entry;
      entry.assign(key);
      entry.append(":");
      entry.append(value);
      slist = curl_slist_append(slist, entry.c_str());
    }
  }

  if(use_rrs.substr(0,1) == "1")
    slist = curl_slist_append(slist, "x-amz-storage-class:REDUCED_REDUNDANCY");

  if(public_bucket.substr(0,1) != "1") {
     auth.assign("Authorization: AWS ");
     auth.append(AWSAccessKeyId);
     auth.append(":");
     auth.append(calc_signature("POST", ctype_data, raw_date, slist, resource));
    slist = curl_slist_append(slist, auth.c_str());
  }
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);
  curl_easy_setopt(curl, CURLOPT_URL, my_url.c_str());

  result = my_curl_easy_perform(curl, &body);

  curl_slist_free_all(slist);
  destroy_curl_handle(curl);

  if(result != 0) {
    free(s3_realpath);
    free(body.text);

    return upload_id;
  }

  // XML returns UploadId
  // Parse XML body for UploadId
  upload_id.clear();
  xmlDocPtr doc = xmlReadMemory(body.text, body.size, "", NULL, 0);
  if(doc != NULL && doc->children != NULL) {
    for(xmlNodePtr cur_node = doc->children->children;
         cur_node != NULL;
         cur_node = cur_node->next) {

      // string cur_node_name(reinterpret_cast<const char *>(cur_node->name));
      // printf("cur_node_name: %s\n", cur_node_name.c_str());

      if(cur_node->type == XML_ELEMENT_NODE) {
        string elementName = reinterpret_cast<const char*>(cur_node->name);
        // printf("elementName: %s\n", elementName.c_str());
        if(cur_node->children != NULL) {
          if(cur_node->children->type == XML_TEXT_NODE) {
            if(elementName == "UploadId") {
              upload_id = reinterpret_cast<const char *>(cur_node->children->content);
            }
          }
        }
      } 
    } // for (xmlNodePtr cur_node = doc->children->children;
  } // if (doc != NULL && doc->children != NULL)
  xmlFreeDoc(doc);

  // clean up
  free(s3_realpath);
  free(body.text);
  body.size = 0;

  return upload_id;
}

static int complete_multipart_upload(const char *path, string upload_id,
                                     vector <file_part> parts) {
  CURL *curl = NULL;
  char *pData;
  int result;
  int i, j;
  string auth;
  string date;
  string raw_date;
  string url;
  string my_url;
  string resource;
  string postContent;
  char *s3_realpath;
  struct BodyStruct body;
  struct WriteThis pooh;
  struct curl_slist *slist = NULL;

  if(foreground) 
    cout << "      complete_multipart_upload [path=" << path <<  "]" << endl;

  // initialization of variables
  body.text = (char *)malloc(1);
  body.size = 0; 
  curl = NULL;

  postContent.clear();
  postContent.append("<CompleteMultipartUpload>\n");
  for(i = 0, j = parts.size(); i < j; i++) {
     postContent.append("  <Part>\n");
     postContent.append("    <PartNumber>");
     postContent.append(IntToStr(i+1));
     postContent.append("</PartNumber>\n");
     postContent.append("    <ETag>");
     postContent.append(parts[i].etag.insert(0, "\"").append("\""));
     postContent.append("</ETag>\n");
     postContent.append("  </Part>\n");
  }  
  postContent.append("</CompleteMultipartUpload>\n");

  if((pData = (char *)malloc(postContent.size() + 1)) == NULL)
    YIKES(-errno)

  pooh.readptr = pData;
  pooh.sizeleft = postContent.size();

  strcpy(pData, postContent.c_str());

  postContent.clear();

  s3_realpath = get_realpath(path);
  resource = urlEncode(service_path + bucket + s3_realpath);
  resource.append("?uploadId=");
  resource.append(upload_id);
  url = host + resource;
  my_url = prepare_url(url.c_str());

  body.text = (char *)malloc(1);
  body.size = 0; 

  curl = create_curl_handle();
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, true);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&body);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(curl, CURLOPT_POST, true);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (curl_off_t)pooh.sizeleft);
  curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_callback);
  curl_easy_setopt(curl, CURLOPT_READDATA, &pooh);

  date.assign("Date: ");
  raw_date = get_date();
  date.append(raw_date);
  slist = NULL;
  slist = curl_slist_append(slist, date.c_str());

  slist = curl_slist_append(slist, "Accept:");
  slist = curl_slist_append(slist, "Content-Type:");

  if(public_bucket.substr(0,1) != "1") {
    auth.assign("Authorization: AWS ");
    auth.append(AWSAccessKeyId);
    auth.append(":");
    auth.append(calc_signature("POST", "", raw_date, slist, resource));
    slist = curl_slist_append(slist, auth.c_str());
  }
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);
  curl_easy_setopt(curl, CURLOPT_URL, my_url.c_str());

  result = my_curl_easy_perform(curl, &body);

  curl_slist_free_all(slist);
  destroy_curl_handle(curl);

  free(pData);
  free(body.text);
  free(s3_realpath);

  return result;
}

string upload_part(const char *path, const char *source, int part_number, string upload_id) {
  int fd;
  CURL *curl = NULL;
  FILE *part_file;
  int result;
  string url;
  string my_url;
  string auth;
  string resource;
  string date;
  string raw_date;
  string ETag;
  char *s3_realpath;
  struct stat st;
  struct BodyStruct body;
  struct BodyStruct header;
  struct curl_slist *slist = NULL;

  // Now upload the file as the nth part
  if(foreground) 
    cout << "      multipart upload [path=" << path << "][part=" << part_number << "]" << endl;

  // PUT /ObjectName?partNumber=PartNumber&uploadId=UploadId HTTP/1.1
  // Host: BucketName.s3.amazonaws.com
  // Date: date
  // Content-Length: Size
  // Authorization: Signature

  // PUT /my-movie.m2ts?partNumber=1&uploadId=VCVsb2FkIElEIGZvciBlbZZpbmcncyBteS1tb3ZpZS5tMnRzIHVwbG9hZR HTTP/1.1
  // Host: example-bucket.s3.amazonaws.com
  // Date:  Mon, 1 Nov 2010 20:34:56 GMT
  // Content-Length: 10485760
  // Content-MD5: pUNXr/BjKK5G2UKvaRRrOA==
  // Authorization: AWS VGhpcyBtZXNzYWdlIHNpZ25lZGGieSRlbHZpbmc=

  part_file = fopen(source, "rb");
  if(part_file == NULL) {
    syslog(LOG_ERR, "%d###result=%d", __LINE__, errno); \
    return "";
  }

  if(fstat(fileno(part_file), &st) == -1) {
    syslog(LOG_ERR, "%d###result=%d", __LINE__, errno); \
    return "";
  }

  s3_realpath = get_realpath(path);
  resource = urlEncode(service_path + bucket + s3_realpath);
  resource.append("?partNumber=");
  resource.append(IntToStr(part_number));
  resource.append("&uploadId=");
  resource.append(upload_id);
  url = host + resource;
  my_url = prepare_url(url.c_str());

  body.text = (char *)malloc(1);
  body.size = 0; 

  header.text = (char *)malloc(1);
  header.size = 0; 

  curl = create_curl_handle();
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, true);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&body);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(curl, CURLOPT_HEADERDATA, (void *)&header);
  curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(curl, CURLOPT_UPLOAD, true); // HTTP PUT
  curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, static_cast<curl_off_t>(st.st_size)); // Content-Length
  curl_easy_setopt(curl, CURLOPT_INFILE, part_file);

  date.assign("Date: ");
  raw_date = get_date();
  date.append(raw_date);
  slist = NULL;
  slist = curl_slist_append(slist, date.c_str());
  slist = curl_slist_append(slist, "Accept:");

  if(public_bucket.substr(0,1) != "1") {
    auth.assign("Authorization: AWS ");
    auth.append(AWSAccessKeyId);
    auth.append(":");
    auth.append(calc_signature("PUT", "", raw_date, slist, resource));
    slist = curl_slist_append(slist, auth.c_str());
  }
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);
  curl_easy_setopt(curl, CURLOPT_URL, my_url.c_str());

  result = my_curl_easy_perform(curl, &body, part_file);

  curl_slist_free_all(slist);
  destroy_curl_handle(curl);
  fclose(part_file);

  if(result != 0) {
    free(header.text);
    free(body.text);
    free(s3_realpath);

    return "";
  }

  // calculate local md5sum, if it matches the header
  // ETag value, the upload was successful.
  if((fd = open(source, O_RDONLY)) == -1) {
    free(header.text);
    free(body.text);
    free(s3_realpath);

    syslog(LOG_ERR, "%d###result=%d", __LINE__, -fd);
    
    return "";
  }

  string md5 = md5sum(fd);
  close(fd);
  if(!md5.empty() && strstr(header.text, md5.c_str())) {
    ETag.assign(md5);
  } else {
    free(header.text);
    free(body.text);
    free(s3_realpath);

    return "";
  }

  // clean up
  free(body.text);
  free(header.text);
  free(s3_realpath);

  return ETag;
}

string md5sum(int fd) {
  MD5_CTX c;
  char buf[512];
  char hexbuf[3];
  ssize_t bytes;
  char *md5 = (char *)malloc(2 * MD5_DIGEST_LENGTH + 1);
  unsigned char *result = (unsigned char *) malloc(MD5_DIGEST_LENGTH);
  
  memset(buf, 0, 512);
  MD5_Init(&c);
  while((bytes = read(fd, buf, 512)) > 0) {
    MD5_Update(&c, buf, bytes);
    memset(buf, 0, 512);
  }

  MD5_Final(result, &c);

  memset(md5, 0, 2 * MD5_DIGEST_LENGTH + 1);
  for(int i = 0; i < MD5_DIGEST_LENGTH; i++) {
    snprintf(hexbuf, 3, "%02x", result[i]);
    strncat(md5, hexbuf, 2);
  }

  free(result);
  lseek(fd, 0, 0);

  return md5;
}

static int s3fs_getattr(const char *path, struct stat *stbuf) {
  CURL *curl;
  int result;
  char *s3_realpath;
  struct BodyStruct body;

  if(foreground) 
    cout << "s3fs_getattr[path=" << path << "]" << endl;

  memset(stbuf, 0, sizeof(struct stat));
  if(strcmp(path, "/") == 0) {
    stbuf->st_nlink = 1; // see fuse faq
    stbuf->st_mode = root_mode | S_IFDIR;
    return 0;
  }

  if(get_stat_cache_entry(path, stbuf) == 0)
    return 0;

  s3_realpath = get_realpath(path);

  body.text = (char *)malloc(1);
  body.size = 0;

  string resource = urlEncode(service_path + bucket + s3_realpath);
  string url = host + resource;

  headers_t responseHeaders;
  curl = create_curl_handle();
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&body);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, true);
  curl_easy_setopt(curl, CURLOPT_NOBODY, true); // HEAD
  curl_easy_setopt(curl, CURLOPT_FILETIME, true); // Last-Modified
  curl_easy_setopt(curl, CURLOPT_HEADERDATA, &responseHeaders);
  curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_callback);

  auto_curl_slist headers;
  string date = get_date();
  headers.append("Date: " + date);
  headers.append("Content-Type: ");
  if (public_bucket.substr(0,1) != "1") {
    headers.append("Authorization: AWS " + AWSAccessKeyId + ":" +
      calc_signature("HEAD", "", date, headers.get(), resource));
  }
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers.get());
  string my_url = prepare_url(url.c_str());
  curl_easy_setopt(curl, CURLOPT_URL, my_url.c_str());

  result = my_curl_easy_perform(curl, &body);
  if(result != 0) {
    free(body.text);
    free(s3_realpath);
    destroy_curl_handle(curl);

    return result;
  }

  stbuf->st_nlink = 1; // see fuse faq

  stbuf->st_mtime = strtoul(responseHeaders["x-amz-meta-mtime"].c_str(), (char **)NULL, 10);
  if (stbuf->st_mtime == 0) {
    long LastModified;
    if (curl_easy_getinfo(curl, CURLINFO_FILETIME, &LastModified) == 0)
      stbuf->st_mtime = LastModified;
  }

  stbuf->st_mode = strtoul(responseHeaders["x-amz-meta-mode"].c_str(), (char **)NULL, 10);
  char* ContentType = 0;
  if (curl_easy_getinfo(curl, CURLINFO_CONTENT_TYPE, &ContentType) == 0) {
    if (ContentType)
      stbuf->st_mode |= strcmp(ContentType, "application/x-directory") == 0 ? S_IFDIR : S_IFREG;
  }

  double ContentLength;
  if (curl_easy_getinfo(curl, CURLINFO_CONTENT_LENGTH_DOWNLOAD, &ContentLength) == 0)
    stbuf->st_size = static_cast<off_t>(ContentLength);

  if (S_ISREG(stbuf->st_mode))
    stbuf->st_blocks = stbuf->st_size / 512 + 1;

  stbuf->st_uid = strtoul(responseHeaders["x-amz-meta-uid"].c_str(), (char **)NULL, 10);
  stbuf->st_gid = strtoul(responseHeaders["x-amz-meta-gid"].c_str(), (char **)NULL, 10);

  // update stat cache
  add_stat_cache_entry(path, stbuf);

  free(body.text);
  free(s3_realpath);
  destroy_curl_handle(curl);

  return 0;
}

static int s3fs_readlink(const char *path, char *buf, size_t size) {
  int fd = -1;
  if (size > 0) {
    --size; // reserve nil terminator

    if(foreground) 
      cout << "readlink[path=" << path << "]" << endl;

    fd = get_local_fd(path);
    if(fd < 0) {
      syslog(LOG_ERR, "line %d: get_local_fd: %d", __LINE__, -fd);
      return -EIO;
    }

    struct stat st;

    if(fstat(fd, &st) == -1) {
      syslog(LOG_ERR, "line %d: fstat: %d", __LINE__, -errno);

      if(fd > 0)
        close(fd);

      return -errno;
    }

    if(st.st_size < (off_t)size)
      size = st.st_size;

    if(pread(fd, buf, size, 0) == -1) {
      syslog(LOG_ERR, "line %d: pread: %d", __LINE__, -errno);

      if(fd > 0) 
        close(fd);

      return -errno;
    }

    buf[size] = 0;
  }

  if(fd > 0)
    close(fd);

  return 0;
}

/**
 * @param s e.g., "index.html"
 * @return e.g., "text/html"
 */
string lookupMimeType(string s) {
  string result("application/octet-stream");
  string::size_type last_pos = s.find_last_of('.');
  string::size_type first_pos = s.find_first_of('.');
  string prefix, ext, ext2;

  // No dots in name, just return
  if(last_pos == string::npos)
    return result;

  // extract the last extension
  if(last_pos != string::npos)
    ext = s.substr(1+last_pos, string::npos);
   
  if (last_pos != string::npos) {
     // one dot was found, now look for another
     if (first_pos != string::npos && first_pos < last_pos) {
        prefix = s.substr(0, last_pos);
        // Now get the second to last file extension
        string::size_type next_pos = prefix.find_last_of('.');
        if (next_pos != string::npos) {
           ext2 = prefix.substr(1+next_pos, string::npos);
        }
     }
  }

  // if we get here, then we have an extension (ext)
  mimes_t::const_iterator iter = mimeTypes.find(ext);
  // if the last extension matches a mimeType, then return
  // that mime type
  if (iter != mimeTypes.end()) {
    result = (*iter).second;
    return result;
  }

  // return with the default result if there isn't a second extension
  if(first_pos == last_pos)
     return result;

  // Didn't find a mime-type for the first extension
  // Look for second extension in mimeTypes, return if found
  iter = mimeTypes.find(ext2);
  if (iter != mimeTypes.end()) {
     result = (*iter).second;
     return result;
  }

  // neither the last extension nor the second-to-last extension
  // matched a mimeType, return the default mime type 
  return result;
}

// common function for creation of a plain object
static int create_file_object(const char *path, mode_t mode) {
  int result;
  char *s3_realpath;
  CURL *curl = NULL;

  if(foreground) 
    cout << "   create_file_object[path=" << path << "][mode=" << mode << "]" << endl;

  s3_realpath = get_realpath(path);
  string resource = urlEncode(service_path + bucket + s3_realpath);
  string url = host + resource;

  string date = get_date();
  string my_url = prepare_url(url.c_str());
  auto_curl_slist headers;
  headers.append("Date: " + date);
  string contentType(lookupMimeType(path));
  headers.append("Content-Type: " + contentType);
  // x-amz headers: (a) alphabetical order and (b) no spaces after colon
  headers.append("x-amz-acl:" + default_acl);
  headers.append("x-amz-meta-gid:" + str(getgid()));
  headers.append("x-amz-meta-mode:" + str(mode));
  headers.append("x-amz-meta-mtime:" + str(time(NULL)));
  headers.append("x-amz-meta-uid:" + str(getuid()));
  if(public_bucket.substr(0,1) != "1")
    headers.append("Authorization: AWS " + AWSAccessKeyId + ":" +
      calc_signature("PUT", contentType, date, headers.get(), resource));

  curl = create_curl_handle();
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, true);
  curl_easy_setopt(curl, CURLOPT_UPLOAD, true); // HTTP PUT
  curl_easy_setopt(curl, CURLOPT_INFILESIZE, 0); // Content-Length: 0
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers.get());
  curl_easy_setopt(curl, CURLOPT_URL, my_url.c_str());

  result = my_curl_easy_perform(curl);
  destroy_curl_handle(curl);
  free(s3_realpath);

  if(result != 0)
    return result;

  return 0;
}

static int s3fs_mknod(const char *path, mode_t mode, dev_t rdev) {
  int result;

  if(foreground) 
    cout << "s3fs_mknod[path=" << path << "][mode=" << mode << "]" << endl;

  // see man 2 mknod: if pathname already exists, or is 
  // a symbolic link, this call fails with an EEXIST error.
  result = create_file_object(path, mode);

  if(result != 0)
     return result;

  return 0;
}

static int s3fs_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
  int result;
  headers_t meta;

  if(foreground) 
    cout << "s3fs_create[path=" << path << "][mode=" << mode << "]" << "[flags=" << fi->flags << "]" <<  endl;

  result = create_file_object(path, mode);

  if(result != 0)
     return result;

  // Object is now made, now open it

  //###TODO check fi->fh here...
  fi->fh = get_local_fd(path);

  // remember flags and headers...
  pthread_mutex_lock( &s3fs_descriptors_lock );
  s3fs_descriptors[fi->fh] = fi->flags;
  pthread_mutex_unlock( &s3fs_descriptors_lock );

  return 0;
}

static int s3fs_mkdir(const char *path, mode_t mode) {
  CURL *curl = NULL;
  int result;
  char *s3_realpath;
  string url;
  string resource;
  string date = get_date();
  auto_curl_slist headers;

  if(foreground) 
    cout << "mkdir[path=" << path << "][mode=" << mode << "]" << endl;

  s3_realpath = get_realpath(path);
  resource = urlEncode(service_path + bucket + s3_realpath);
  url = host + resource;

  curl = create_curl_handle();
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, true);
  curl_easy_setopt(curl, CURLOPT_UPLOAD, true); // HTTP PUT
  curl_easy_setopt(curl, CURLOPT_INFILESIZE, 0); // Content-Length: 0

  headers.append("Date: " + date);
  headers.append("Content-Type: application/x-directory");
  // x-amz headers: (a) alphabetical order and (b) no spaces after colon
  headers.append("x-amz-acl:" + default_acl);
  headers.append("x-amz-meta-gid:" + str(getgid()));
  headers.append("x-amz-meta-mode:" + str(mode));
  headers.append("x-amz-meta-mtime:" + str(time(NULL)));
  headers.append("x-amz-meta-uid:" + str(getuid()));
  if (use_rrs.substr(0,1) == "1") {
    headers.append("x-amz-storage-class:REDUCED_REDUNDANCY");
  }
  if (public_bucket.substr(0,1) != "1") {
    headers.append("Authorization: AWS " + AWSAccessKeyId + ":" +
      calc_signature("PUT", "application/x-directory", date, headers.get(), resource));
  }
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers.get());

  string my_url = prepare_url(url.c_str());
  curl_easy_setopt(curl, CURLOPT_URL, my_url.c_str());

  result = my_curl_easy_perform(curl);
 
  destroy_curl_handle(curl);
  free(s3_realpath);

  if(result != 0)
    return result;

  return 0;
}

// aka rm
static int s3fs_unlink(const char *path) {
  int result;
  string date;
  string url;
  string my_url;
  string resource;
  char *s3_realpath;
  auto_curl_slist headers;
  CURL *curl = NULL;

  if(foreground) 
    cout << "unlink[path=" << path << "]" << endl;

  s3_realpath = get_realpath(path);
  resource = urlEncode(service_path + bucket + s3_realpath);
  url = host + resource;
  date = get_date();

  headers.append("Date: " + date);
  headers.append("Content-Type: ");
  if(public_bucket.substr(0,1) != "1")
    headers.append("Authorization: AWS " + AWSAccessKeyId + ":" +
      calc_signature("DELETE", "", date, headers.get(), resource));

  my_url = prepare_url(url.c_str());
  curl = create_curl_handle();
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, true);
  curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers.get());
  curl_easy_setopt(curl, CURLOPT_URL, my_url.c_str());

  result = my_curl_easy_perform(curl);

  destroy_curl_handle(curl);
  free(s3_realpath);

  if(result != 0)
    return result;

  delete_stat_cache_entry(path);

  return 0;
}

static int s3fs_rmdir(const char *path) {
  CURL *curl = NULL;
  CURL *curl_handle = NULL;
  int result;
  char *s3_realpath;
  struct BodyStruct body;

  if(foreground) 
    cout << "rmdir[path=" << path << "]" << endl;

  s3_realpath = get_realpath(path);
  body.text = (char *)malloc(1);
  body.size = 0;

   // need to check if the directory is empty
   {
      string url;
      string my_url;
      string date;
      string resource = urlEncode(service_path + bucket);
      string query = "delimiter=/&prefix=";
      auto_curl_slist headers;

      if(strcmp(path, "/") != 0)
        query += urlEncode(string(s3_realpath).substr(1) + "/");
      else
        query += urlEncode(string(s3_realpath).substr(1));

      query += "&max-keys=1";
      url = host + resource + "?"+ query;

      curl = create_curl_handle();
      my_url = prepare_url(url.c_str());
      curl_easy_setopt(curl, CURLOPT_URL, my_url.c_str());
      curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, true);
      curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&body);
      curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);

      date = get_date();
      headers.append("Date: " + date);
      headers.append("ContentType: ");
      if (public_bucket.substr(0,1) != "1") {
        headers.append("Authorization: AWS " + AWSAccessKeyId + ":" +
          calc_signature("GET", "", date, headers.get(), resource + "/"));
      }

      curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers.get());

      result = my_curl_easy_perform(curl, &body);
      if(result != 0) {
        free(body.text);
        free(s3_realpath);
        destroy_curl_handle(curl);

        return result;
      }

      if(strstr(body.text, "<CommonPrefixes>") != NULL ||
         strstr(body.text, "<ETag>") != NULL ) {
        // directory is not empty

        if(foreground) 
          cout << "[path=" << path << "] not empty" << endl;

        free(body.text);
        free(s3_realpath);
        destroy_curl_handle(curl);

        return -ENOTEMPTY;
      }
   }

   // delete the directory
  string resource = urlEncode(service_path + bucket + s3_realpath);
  string url = host + resource;

  curl_handle = create_curl_handle();
  curl_easy_setopt(curl_handle, CURLOPT_FOLLOWLOCATION, true);
  curl_easy_setopt(curl_handle, CURLOPT_CUSTOMREQUEST, "DELETE");

  auto_curl_slist headers;
  string date = get_date();
  headers.append("Date: " + date);
  headers.append("Content-Type: ");
  if (public_bucket.substr(0,1) != "1") {
    headers.append("Authorization: AWS " + AWSAccessKeyId + ":" +
      calc_signature("DELETE", "", date, headers.get(), resource));
  }
  curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, headers.get());

  string my_url = prepare_url(url.c_str());
  curl_easy_setopt(curl_handle, CURLOPT_URL, my_url.c_str());

  result = my_curl_easy_perform(curl_handle);

  // delete cache entry
  delete_stat_cache_entry(path);

  free(body.text);
  free(s3_realpath);
  destroy_curl_handle(curl);
  destroy_curl_handle(curl_handle);

  if(result != 0)
    return result;

  return 0;
}

static int s3fs_symlink(const char *from, const char *to) {
  int result;
  int fd = -1;

  if(foreground) 
    cout << "s3fs_symlink[from=" << from << "][to=" << to << "]" << endl;

  headers_t headers;
  headers["x-amz-meta-mode"] = str(S_IFLNK);
  headers["x-amz-meta-mtime"] = str(time(NULL));

  fd = fileno(tmpfile());
  if(fd == -1) {
    syslog(LOG_ERR, "line %d: error: fileno(tmpfile()): %d", __LINE__, -errno);
    return -errno;
  }

  if(pwrite(fd, from, strlen(from), 0) == -1) {
    syslog(LOG_ERR, "line %d: error: pwrite: %d", __LINE__, -errno);
    if(fd > 0)
      close(fd);

    return -errno;
  }

  result = put_local_fd(to, headers, fd);
  if(result != 0) {
    if(fd > 0)
      close(fd);

    return result;
  }

  if(fd > 0)
    close(fd);

  return 0;
}

static int rename_object(const char *from, const char *to) {
  int result;
  char *s3_realpath;
  headers_t meta;

  if(foreground)
    cout << "rename_object[from=" << from << "][to=" << to << "]" << endl; 

  if(debug)
    syslog(LOG_DEBUG, "rename_object [from=%s] [to=%s]", from, to);

  result = get_headers(from, meta);

  if(result != 0)
    return result;

  s3_realpath = get_realpath(from);
  meta["x-amz-copy-source"] = urlEncode("/" + bucket + s3_realpath);
  meta["Content-Type"] = lookupMimeType(to);
  meta["x-amz-metadata-directive"] = "REPLACE";

  result = put_headers(to, meta);
  if(result != 0)
    return result;

  result = s3fs_unlink(from);

  return result;
}

static int clone_directory_object(const char *from, const char *to) {
  int result;
  mode_t mode;
  headers_t meta;

  if(foreground)
    printf("clone_directory_object [from=%s] [to=%s]\n", from, to);

  if(debug)
    syslog(LOG_DEBUG, "clone_directory_object [from=%s] [to=%s]", from, to);

  // How to determine mode?
  mode = 493;

  // create the new directory object
  result = s3fs_mkdir(to, mode);
  if(result != 0)
    return result;

  // and transfer its attributes
  result = get_headers(from, meta);
  if(result != 0)
    return result;

  meta["x-amz-copy-source"] = urlEncode("/" + bucket + mount_prefix + from);
  meta["x-amz-metadata-directive"] = "REPLACE";

  result = put_headers(to, meta);
  if(result != 0)
    return result;

  return 0;
}

static int rename_directory( const char *from, const char *to) {
  int result;
  // mode_t mode;
  headers_t meta;
  int num_keys = 0;
  int max_keys = 50;
  string path;
  string new_path;
  string to_path;
  string from_path;
  MVNODE *head = NULL;
  MVNODE *tail = NULL;

  if(foreground) 
    cout << "rename_directory[from=" << from << "][to=" << to << "]" << endl;

  if(debug)
    syslog(LOG_DEBUG, "rename_directory [from=%s] [to=%s]", from, to);

  CURL *curl;
  struct BodyStruct body;
  string NextMarker;
  string IsTruncated("true");
  string object_type;
  string Key;
  bool is_dir;

  body.text = (char *)malloc(1);
  body.size = 0;

  // create the head/tail of the linked list
  from_path.assign(from);
  to_path.assign(to);
  is_dir = 1;

  // printf("calling create_mvnode\n");
  // head = create_mvnode((char *)from, (char *)to, is_dir);
  head = create_mvnode((char *)from_path.c_str(), (char *)to_path.c_str(), is_dir);
  tail = head;
  // printf("back from create_mvnode\n");

  while (IsTruncated == "true") {
    string query;
    string resource = urlEncode(service_path + bucket);

    if(mount_prefix.size() > 0)
      query = "prefix=" + mount_prefix .substr(1, mount_prefix.size() - 1) + "/";
    else
      query = "prefix=";

    if (strcmp(from, "/") != 0)
      query += urlEncode(string(from).substr(1) + "/");

    if (NextMarker.size() > 0)
      query += "&marker=" + urlEncode(NextMarker);

    query += "&max-keys=";
    query.append(IntToStr(max_keys));

    string url = host + resource + "?" + query;

    {
      curl = create_curl_handle();

      string my_url = prepare_url(url.c_str());

      if(body.text) {
        free(body.text);
        body.size = 0;
        body.text = (char *)malloc(1);
      }

      curl_easy_setopt(curl, CURLOPT_URL, my_url.c_str());
      curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, true);
      curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&body);
      curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);

      auto_curl_slist headers;
      string date = get_date();
      headers.append("Date: " + date);
      headers.append("ContentType: ");
      if (public_bucket.substr(0,1) != "1") {
        headers.append("Authorization: AWS " + AWSAccessKeyId + ":" +
          calc_signature("GET", "", date, headers.get(), resource + "/"));
      }

      curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers.get());
      
      result = my_curl_easy_perform(curl, &body);

      destroy_curl_handle(curl);

      if(result != 0) {
        if(body.text) {
          free(body.text);
        }
        free_mvnodes(head);
        return result;
      }
    }

    xmlDocPtr doc = xmlReadMemory(body.text, body.size, "", NULL, 0);
    if (doc != NULL && doc->children != NULL) {
      for (xmlNodePtr cur_node = doc->children->children;
           cur_node != NULL;
           cur_node = cur_node->next) {

        string cur_node_name(reinterpret_cast<const char *>(cur_node->name));
        if(cur_node_name == "IsTruncated")
          IsTruncated = reinterpret_cast<const char *>(cur_node->children->content);

        if (cur_node_name == "Contents") {
          if (cur_node->children != NULL) {
            string LastModified;
            string Size;
            for (xmlNodePtr sub_node = cur_node->children;
                 sub_node != NULL;
                 sub_node = sub_node->next) {

              if (sub_node->type == XML_ELEMENT_NODE) {
                string elementName = reinterpret_cast<const char*>(sub_node->name);
                if (sub_node->children != NULL) {
                  if (sub_node->children->type == XML_TEXT_NODE) {
                    if (elementName == "Key") {
                      Key = reinterpret_cast<const char *>(sub_node->children->content);
                    }
                    if (elementName == "LastModified") {
                      LastModified = reinterpret_cast<const char *>(sub_node->children->content);
                    }
                    if (elementName == "Size") {
                      Size = reinterpret_cast<const char *>(sub_node->children->content);
                    }
                  }
                }
              }
            }

            if (Key.size() > 0) {
               num_keys++;
               path = "/" + Key;
               new_path = path;
               if(mount_prefix.size() > 0)
                 new_path.replace(0, mount_prefix.substr(0, mount_prefix.size()).size() + from_path.size(), to_path);
               else
                 new_path.replace(0, from_path.size(), to_path);

               if(mount_prefix.size() > 0)
                 result = get_headers(path.replace(0, mount_prefix.size(), "").c_str(), meta);
               else
                 result = get_headers(path.c_str(), meta);
               
               if(result != 0) {
                 free_mvnodes(head);
                 free(body.text);
                 body.text = NULL;

                 return result;
               }

               // process the Key appropriately
               // if it is a directory move the directory object
               object_type = meta["Content-Type"];
               if(object_type.compare("application/x-directory") == 0)
                  is_dir = 1;
               else
                  is_dir = 0;

               // push this one onto the stack
               tail = add_mvnode(head, (char *)path.c_str(), (char *)new_path.c_str(), is_dir);
            }

          } // if (cur_node->children != NULL) {
        } // if (cur_node_name == "Contents") {
      } // for (xmlNodePtr cur_node = doc->children->children;
    } // if (doc != NULL && doc->children != NULL) {
    xmlFreeDoc(doc);

    if(IsTruncated == "true")
       NextMarker = Key;

  } // while (IsTruncated == "true") {

  free(body.text);
  body.text = NULL;

  // iterate over the list - clone directories first - top down
  if(head == NULL)
    return 0;

  MVNODE *my_head;
  MVNODE *my_tail;
  MVNODE *next;
  MVNODE *prev;
  my_head = head;
  my_tail = tail;
  next = NULL;
  prev = NULL;
 
  do {
    if(my_head->is_dir) {
      result = clone_directory_object( my_head->old_path, my_head->new_path);
      if(result != 0) {
         free_mvnodes(head);
         syslog(LOG_ERR, "clone_directory_object returned an error");
         return -EIO;
      }
    }
    next = my_head->next;
    my_head = next;
  } while(my_head != NULL);

  // iterate over the list - copy the files with rename_object
  // does a safe copy - copies first and then deletes old
  my_head = head;
  next = NULL;
 
  do {
    if(my_head->is_dir != 1) {
      result = rename_object( my_head->old_path, my_head->new_path);
      if(result != 0) {
         free_mvnodes(head);
         syslog(LOG_ERR, "rename_dir: rename_object returned an error");
         return -EIO;
      }
    }
    next = my_head->next;
    my_head = next;
  } while(my_head != NULL);

  // Iterate over old the directories, bottoms up and remove
  do {
    if(my_tail->is_dir) {
      result = s3fs_unlink( my_tail->old_path);
      if(result != 0) {
         free_mvnodes(head);
         syslog(LOG_ERR, "rename_dir: s3fs_unlink returned an error");
         return -EIO;
      }
    }
    prev = my_tail->prev;
    my_tail = prev;
  } while(my_tail != NULL);

  free_mvnodes(head);

  return 0;
}

static int s3fs_rename(const char *from, const char *to) {
  struct stat buf;
  int result;

  if(foreground) 
    cout << "rename[from=" << from << "][to=" << to << "]" << endl;

  if(debug)
    syslog(LOG_DEBUG, "rename [from=%s] [to=%s]", from, to);

  s3fs_getattr(from, &buf);
 
  // is a directory or a different type of file 
  if(S_ISDIR(buf.st_mode))
    result = rename_directory(from, to);
  else
    result = rename_object(from, to);

  return result;
}

static int s3fs_link(const char *from, const char *to) {
  if(foreground) 
    cout << "link[from=" << from << "][to=" << to << "]" << endl;
  return -EPERM;
}

static int s3fs_chmod(const char *path, mode_t mode) {
  int result;
  char *s3_realpath;
  headers_t meta;

  if(foreground) 
    printf("s3fs_chmod [path=%s] [mode=%d]\n", path, mode);

  result = get_headers(path, meta);
  if(result != 0)
    return result;

  s3_realpath = get_realpath(path);
  meta["x-amz-meta-mode"] = str(mode);
  meta["x-amz-copy-source"] = urlEncode("/" + bucket + s3_realpath);
  meta["x-amz-metadata-directive"] = "REPLACE";
  free(s3_realpath);

  delete_stat_cache_entry(path);

  return put_headers(path, meta);
}

static int s3fs_chown(const char *path, uid_t uid, gid_t gid) {
  int result;
  char *s3_realpath;

  if(foreground) 
    printf("s3fs_chown [path=%s] [uid=%d] [gid=%d]\n", path, uid, gid);

  headers_t meta;
  result = get_headers(path, meta);
  if(result != 0)
     return result;

  struct passwd *aaa = getpwuid(uid);
  if(aaa != 0)
    meta["x-amz-meta-uid"] = str((*aaa).pw_uid);

  struct group *bbb = getgrgid(gid);
  if(bbb != 0)
    meta["x-amz-meta-gid"] = str((*bbb).gr_gid);

  s3_realpath = get_realpath(path);
  meta["x-amz-copy-source"] = urlEncode("/" + bucket + s3_realpath);
  meta["x-amz-metadata-directive"] = "REPLACE";
  free(s3_realpath);

  delete_stat_cache_entry(path);

  return put_headers(path, meta);
}

static int s3fs_truncate(const char *path, off_t size) {
  int fd = -1;
  int result;
  headers_t meta;
  // TODO: honor size?!?

  if(foreground) 
    cout << "truncate[path=" << path << "][size=" << size << "]" << endl;

  // preserve headers across truncate
  result = get_headers(path, meta);
  if(result != 0)
     return result;

  fd = fileno(tmpfile());
  if(fd == -1) {
    syslog(LOG_ERR, "error: line %d: %d", __LINE__, -errno);
    return -errno;
  }
  
  result = put_local_fd(path, meta, fd);
  if(result != 0) {
     if(fd > 0)
       close(fd);

     return result;
  }

  if(fd > 0)
    close(fd);

  return 0;
}

static int s3fs_open(const char *path, struct fuse_file_info *fi) {
  int result;
  headers_t meta;

  if(foreground) 
    cout << "s3fs_open[path=" << path << "][flags=" << fi->flags << "]" <<  endl;

  // Go do the truncation if called for
  if((unsigned int)fi->flags & O_TRUNC) {
     result = s3fs_truncate(path, 0);
     if(result != 0)
        return result;
  }

  // TODO: check fi->fh here...
  fi->fh = get_local_fd(path);

  // remember flags and headers...
  pthread_mutex_lock( &s3fs_descriptors_lock );
  s3fs_descriptors[fi->fh] = fi->flags;
  pthread_mutex_unlock( &s3fs_descriptors_lock );

  return 0;
}

static int s3fs_read(
    const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
  int res;

  if(foreground) 
    cout << "s3fs_read[path=" << path << "]" << endl;

  res = pread(fi->fh, buf, size, offset);
  if(res == -1)
    YIKES(-errno);

  return res;
}

static int s3fs_write(
    const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
  int res = pwrite(fi->fh, buf, size, offset);

  if(foreground) 
    cout << "s3fs_write[path=" << path << "]" << endl;

  if(res == -1)
    YIKES(-errno);

  return res;
}

static int s3fs_statfs(const char *path, struct statvfs *stbuf) {
  // 256T
  stbuf->f_bsize  = 0X1000000;
  stbuf->f_blocks = 0X1000000;
  stbuf->f_bfree  = 0x1000000;
  stbuf->f_bavail = 0x1000000;
  return 0;
}

static int get_flags(int fd) {
  int flags;
  pthread_mutex_lock( &s3fs_descriptors_lock );
  flags = s3fs_descriptors[fd];
  pthread_mutex_unlock( &s3fs_descriptors_lock );
  return flags;
}

static int s3fs_flush(const char *path, struct fuse_file_info *fi) {
  int flags;
  int result;
  int fd = fi->fh;
  time_t mtime;

  if(foreground) 
    cout << "s3fs_flush[path=" << path << "][fd=" << fd << "]" << endl;

  // NOTE- fi->flags is not available here
  flags = get_flags(fd);
  if((flags & O_RDWR) || (flags & O_WRONLY)) {
    headers_t meta;
    result = get_headers(path, meta);

    if(result != 0)
      return result;

    // if the cached file matches the remote file skip uploading
    if(use_cache.size() > 0) {
      struct stat st;

      if((fstat(fd, &st)) == -1)
        YIKES(-errno);

      if(str(st.st_size) == meta["Content-Length"] && 
        (str(st.st_mtime) == meta["x-amz-meta-mtime"])) {
        return result;
      }
    }

    mtime = time(NULL);
    meta["x-amz-meta-mtime"] = str(mtime);

    // force the cached copy to have the same mtime as the remote copy
    if(use_cache.size() > 0) {
      struct stat st;
      struct utimbuf n_mtime;
      string cache_path(use_cache + "/" + bucket + path);

      if((stat(cache_path.c_str(), &st)) == 0) {
        n_mtime.modtime = mtime;
        if((utime(cache_path.c_str(), &n_mtime)) == -1) {
          YIKES(-errno);
        }
      }
    }

    return put_local_fd(path, meta, fd);
  }

  return 0;
}

static int s3fs_release(const char *path, struct fuse_file_info *fi) {
  int fd = fi->fh;

  if(foreground) 
    cout << "s3fs_release[path=" << path << "][fd=" << fd << "]" << endl;

  if(close(fd) == -1)
    YIKES(-errno);

  if((fi->flags & O_RDWR) || (fi->flags & O_WRONLY))
    delete_stat_cache_entry(path);

  return 0;
}

static int s3fs_readdir(
    const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi) {

  int result;
  char *s3_realpath;
  struct BodyStruct body;
  CURLMHLL *mhhead = NULL;
  CURLMHLL *mhcurrent = NULL;
  CURLM *current_multi_handle = NULL;
  CURLMcode curlm_code;
  CURL *curl;

  if(foreground) 
    cout << "readdir[path=" << path << "]" << endl;

  body.text = (char *) malloc(1);
  body.size = 0;

  s3_realpath = get_realpath(path);

  string NextMarker;
  string IsTruncated("true");

  while (IsTruncated == "true") {
    string resource = urlEncode(service_path + bucket); // this is what gets signed
    string query = "delimiter=/&prefix=";

    if(strcmp(path, "/") != 0)
      query += urlEncode(string(s3_realpath).substr(1) + "/");
    else
      query += urlEncode(string(s3_realpath).substr(1));

    if (NextMarker.size() > 0)
      query += "&marker=" + urlEncode(NextMarker);

    query += "&max-keys=500";

    string url = host + resource + "?" + query;

    {
      curl = create_curl_handle();

      string my_url = prepare_url(url.c_str());

      if(body.text) {
        free(body.text);
        body.size = 0;
        body.text = (char *)malloc(1);
      }

      curl_easy_setopt(curl, CURLOPT_URL, my_url.c_str());
      curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, true);
      curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&body);
      curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);

//    headers_t responseHeaders;
//      curl_easy_setopt(curl, CURLOPT_HEADERDATA, &responseHeaders);
//      curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_callback);

      auto_curl_slist headers;
      string date = get_date();
      headers.append("Date: " + date);
      headers.append("ContentType: ");
      if (public_bucket.substr(0,1) != "1") {
        headers.append("Authorization: AWS " + AWSAccessKeyId + ":" +
          calc_signature("GET", "", date, headers.get(), resource + "/"));
      }

      curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers.get());

      result = my_curl_easy_perform(curl, &body);

      destroy_curl_handle(curl);

      if(result != 0) {
        free(body.text);
        free(s3_realpath);

        return result;
      }
    }

    auto_stuff curlMap;
    current_multi_handle = curl_multi_init();

    if (mhhead == NULL) {
       mhhead = create_mh_element(current_multi_handle);
       mhcurrent = mhhead;
    } else {
       mhcurrent = add_mh_element(mhhead, current_multi_handle);
    }

//    long max_connects = 5;
//    curl_multi_setopt(multi_handle.get(), CURLMOPT_MAXCONNECTS, max_connects);

    {
      xmlDocPtr doc = xmlReadMemory(body.text, body.size, "", NULL, 0);
      if (doc != NULL && doc->children != NULL) {
        for (xmlNodePtr cur_node = doc->children->children;
             cur_node != NULL;
             cur_node = cur_node->next) {

          string cur_node_name(reinterpret_cast<const char *>(cur_node->name));
          if (cur_node_name == "IsTruncated")
            IsTruncated = reinterpret_cast<const char *>(cur_node->children->content);
          if (cur_node_name == "NextMarker")
            NextMarker = reinterpret_cast<const char *>(cur_node->children->content);
          if (cur_node_name == "Contents") {
            if (cur_node->children != NULL) {
              string Key;
              string LastModified;
              string Size;
              for (xmlNodePtr sub_node = cur_node->children;
                   sub_node != NULL;
                   sub_node = sub_node->next) {

                if (sub_node->type == XML_ELEMENT_NODE) {
                  string elementName = reinterpret_cast<const char*>(sub_node->name);
                  if (sub_node->children != NULL) {
                    if (sub_node->children->type == XML_TEXT_NODE) {
                      if (elementName == "Key")
                        Key = reinterpret_cast<const char *>(sub_node->children->content);
                      if (elementName == "LastModified")
                        LastModified = reinterpret_cast<const char *>(sub_node->children->content);
                      if (elementName == "Size")
                        Size = reinterpret_cast<const char *>(sub_node->children->content);
                    }
                  }
                }
              }

              bool in_stat_cache = false;
              string path = '/' + Key;
              if(get_stat_cache_entry(path.c_str(), NULL) == 0) {
                if(filler(buf, mybasename(Key).c_str(), 0, 0))
                  break;

                in_stat_cache = true;
              }

              if (Key.size() > 0 && !in_stat_cache) {
                if (filler(buf, mybasename(Key).c_str(), 0, 0)) {
                  break;
                }

                CURL* curl_handle = create_curl_handle();

                string resource = urlEncode(service_path + bucket + "/" + Key);
                string url = host + resource;

                stuff_t stuff;
                stuff.path = "/"+Key;

                // libcurl 7.17 does deep copy of url... e.g., fc7 has libcurl 7.16... therefore, must deep copy "stable" url...
                string my_url = prepare_url(url.c_str());
                stuff.url = new string(my_url.c_str());
                stuff.requestHeaders = 0;
                stuff.responseHeaders = new headers_t;

                curl_easy_setopt(curl_handle, CURLOPT_URL, stuff.url->c_str());
                // curl_easy_setopt(curl_handle, CURLOPT_FAILONERROR, true);
                curl_easy_setopt(curl_handle, CURLOPT_FOLLOWLOCATION, true);
                curl_easy_setopt(curl_handle, CURLOPT_NOBODY, true); // HEAD
                curl_easy_setopt(curl_handle, CURLOPT_FILETIME, true); // Last-Modified
                if (ssl_verify_hostname.substr(0,1) == "0") {
                  curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYHOST, 0);
                }
                if (curl_ca_bundle.size() != 0) {
                   curl_easy_setopt(curl_handle, CURLOPT_CAINFO, curl_ca_bundle.c_str());
                } 

                // requestHeaders
                string date = get_date();
                stuff.requestHeaders = curl_slist_append(
                    stuff.requestHeaders, string("Date: " + date).c_str());
                stuff.requestHeaders = curl_slist_append(
                    stuff.requestHeaders, string("Content-Type: ").c_str());
                if (public_bucket.substr(0,1) != "1") {
                  stuff.requestHeaders = curl_slist_append(
                    stuff.requestHeaders, string("Authorization: AWS " + AWSAccessKeyId + ":" +
                        calc_signature("HEAD", "", date, stuff.requestHeaders, resource)).c_str());
                }
                curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, stuff.requestHeaders);

                // responseHeaders
                curl_easy_setopt(curl_handle, CURLOPT_HEADERDATA, stuff.responseHeaders);
                curl_easy_setopt(curl_handle, CURLOPT_HEADERFUNCTION, header_callback);

                curlMap.get()[curl_handle] = stuff;

                curlm_code = curl_multi_add_handle(current_multi_handle, curl_handle);
                if(curlm_code != CURLM_OK) {
                  syslog(LOG_ERR, "readdir: curl_multi_add_handle code: %d msg: %s", 
                       curlm_code, curl_multi_strerror(curlm_code));
                  return -EIO;
                }
                add_h_to_mh(curl_handle, mhcurrent);
              }
            }
          }
        }
      }
      xmlFreeDoc(doc);
    }

    int running_handles;
    running_handles = 0;

    CURLMcode curlm_code = CURLM_CALL_MULTI_PERFORM;
    while(curlm_code == CURLM_CALL_MULTI_PERFORM) {
       curlm_code = curl_multi_perform(current_multi_handle, &running_handles);
    }
    // Error check
    if(curlm_code != CURLM_OK) {
       syslog(LOG_ERR, "readdir: curl_multi_perform code: %d msg: %s", 
                       curlm_code, curl_multi_strerror(curlm_code));
       return -EIO;
    }

    while (running_handles) {
      fd_set read_fd_set;
      fd_set write_fd_set;
      fd_set exc_fd_set;

      FD_ZERO(&read_fd_set);
      FD_ZERO(&write_fd_set);
      FD_ZERO(&exc_fd_set);

      long milliseconds;

      curlm_code = curl_multi_timeout(current_multi_handle, &milliseconds);
      if (curlm_code != CURLM_OK) {
        syslog(LOG_ERR, "readdir: curl_multi_timeout code: %d msg: %s", 
                       curlm_code, curl_multi_strerror(curlm_code));
        return -EIO;
      }

      if (milliseconds < 0)
        milliseconds = 50;
      if (milliseconds > 0) {
        struct timeval timeout;
        timeout.tv_sec = 1000 * milliseconds / 1000000;
        timeout.tv_usec = 1000 * milliseconds % 1000000;

        int max_fd;

        curlm_code = curl_multi_fdset(current_multi_handle, &read_fd_set, 
                                  &write_fd_set, &exc_fd_set, &max_fd);
        if (curlm_code != CURLM_OK) {
          syslog(LOG_ERR, "readdir: curl_multi_fdset code: %d msg: %s", 
                       curlm_code, curl_multi_strerror(curlm_code));
          return -EIO;
        }

        if (select(max_fd + 1, &read_fd_set, &write_fd_set, &exc_fd_set, &timeout) == -1) {
          YIKES(-errno);
        }
      }

      while (curl_multi_perform(current_multi_handle, &running_handles) == CURLM_CALL_MULTI_PERFORM);
    }

    int remaining_msgs = 1;
    while (remaining_msgs) {
      // this next line pegs cpu for directories w/lotsa files
      CURLMsg* msg = curl_multi_info_read(current_multi_handle, &remaining_msgs);
        if (msg != NULL) {
          CURLcode code =msg->data.result;
          if (code != 0) {
            syslog(LOG_DEBUG, "readdir: remaining_msgs: %i code: %d  msg: %s", 
                             remaining_msgs, code, curl_easy_strerror(code));
          }
          if (code == 0) {
            CURL* curl_handle = msg->easy_handle;
            stuff_t stuff = curlMap.get()[curl_handle];

            struct stat st;
            memset(&st, 0, sizeof(st));
            st.st_nlink = 1; // see fuse faq
            // mode
            st.st_mode = strtoul(
                (*stuff.responseHeaders)["x-amz-meta-mode"].c_str(), (char **)NULL, 10);
            char* ContentType = 0;
            if (curl_easy_getinfo(curl_handle, CURLINFO_CONTENT_TYPE, &ContentType) == 0) {
              if (ContentType) {
                st.st_mode |= strcmp(ContentType, "application/x-directory") == 0 ? S_IFDIR : S_IFREG;
              }
            }

            // mtime
            st.st_mtime = strtoul
                ((*stuff.responseHeaders)["x-amz-meta-mtime"].c_str(), (char **)NULL, 10);
            if (st.st_mtime == 0) {
              long LastModified;
              if (curl_easy_getinfo(curl_handle, CURLINFO_FILETIME, &LastModified) == 0) {
                st.st_mtime = LastModified;
              }
            }

            // size
            double ContentLength;
            if (curl_easy_getinfo(curl_handle, CURLINFO_CONTENT_LENGTH_DOWNLOAD, &ContentLength) == 0) {
              st.st_size = static_cast<off_t>(ContentLength);
            }

            // blocks
            if (S_ISREG(st.st_mode)) {
              st.st_blocks = st.st_size / 512 + 1;
            }

            st.st_uid = strtoul((*stuff.responseHeaders)["x-amz-meta-uid"].c_str(), (char **)NULL, 10);
            st.st_gid = strtoul((*stuff.responseHeaders)["x-amz-meta-gid"].c_str(), (char **)NULL, 10);

            add_stat_cache_entry(stuff.path.c_str(), &st);
        } // if (code == 0)
      } // if (msg != NULL) {
    } // while (remaining_msgs)
  } // while (IsTruncated == "true") {

  free(body.text);
  free(s3_realpath);
  cleanup_multi_stuff(mhhead);

  return 0;
}

static int remote_mountpath_exists(const char *path) {
  CURL *curl;
  int result;
  struct BodyStruct body;

  if(foreground) 
    printf("remote_mountpath_exists [path=%s]\n", path);

  body.text = (char *) malloc(1);
  body.size = 0;

  string resource = urlEncode(service_path + bucket + path);
  string url = host + resource;
  string my_url = prepare_url(url.c_str());
  headers_t responseHeaders;
  auto_curl_slist headers;
  string date = get_date();
  headers.append("Date: " + date);
  headers.append("Content-Type: ");
  if(public_bucket.substr(0,1) != "1")
    headers.append("Authorization: AWS " + AWSAccessKeyId + ":" +
      calc_signature("HEAD", "", date, headers.get(), resource));
  curl = create_curl_handle();
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&body);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, true);
  curl_easy_setopt(curl, CURLOPT_NOBODY, true); // HEAD
  curl_easy_setopt(curl, CURLOPT_FILETIME, true); // Last-Modified
  curl_easy_setopt(curl, CURLOPT_HEADERDATA, &responseHeaders);
  curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_callback);
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers.get());
  curl_easy_setopt(curl, CURLOPT_URL, my_url.c_str());

  result = my_curl_easy_perform(curl, &body);
  if(result != 0) {
    free(body.text);
    body.text = NULL;
    destroy_curl_handle(curl);

    return result;
  }

  struct stat stbuf;
  stbuf.st_mode = strtoul(responseHeaders["x-amz-meta-mode"].c_str(), (char **)NULL, 10);
  char* ContentType = 0;
  if(curl_easy_getinfo(curl, CURLINFO_CONTENT_TYPE, &ContentType) == 0)
    if(ContentType)
      stbuf.st_mode |= strcmp(ContentType, "application/x-directory") == 0 ? S_IFDIR : S_IFREG;

  free(body.text);
  body.text = NULL;
  destroy_curl_handle(curl);

  if(!S_ISDIR(stbuf.st_mode))
    return -1;

  return 0;
}

/**
 * OpenSSL locking function.
 *
 * @param    mode    lock mode
 * @param    n        lock number
 * @param    file    source file name
 * @param    line    source file line number
 * @return    none
 */
static void locking_function(int mode, int n, const char *file, int line) {
  if (mode & CRYPTO_LOCK) {
    pthread_mutex_lock(&mutex_buf[n]);
  } else {
    pthread_mutex_unlock(&mutex_buf[n]);
  }
}

/**
 * OpenSSL uniq id function.
 *
 * @return    thread id
 */
static unsigned long id_function(void) {
  return((unsigned long) pthread_self());
}

static void* s3fs_init(struct fuse_conn_info *conn) {
  syslog(LOG_INFO, "init $Rev$");
  // openssl
  mutex_buf = static_cast<pthread_mutex_t*>(malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t)));
  for (int i = 0; i < CRYPTO_num_locks(); i++)
    pthread_mutex_init(&mutex_buf[i], NULL);
  CRYPTO_set_locking_callback(locking_function);
  CRYPTO_set_id_callback(id_function);
  curl_global_init(CURL_GLOBAL_ALL);
  pthread_mutex_init(&curl_handles_lock, NULL);
  pthread_mutex_init(&s3fs_descriptors_lock, NULL);
  pthread_mutex_init(&stat_cache_lock, NULL);
  //
  string line;
  ifstream MT("/etc/mime.types");
  if (MT.good()) {
    while (getline(MT, line)) {
      if (line[0]=='#') {
        continue;
      }
      if (line.size() == 0) {
        continue;
      }
      stringstream tmp(line);
      string mimeType;
      tmp >> mimeType;
      while (tmp) {
        string ext;
        tmp >> ext;
        if (ext.size() == 0)
          continue;
        mimeTypes[ext] = mimeType;
      }
    }
  }

  // Investigate system capabilities
  if ( (unsigned int)conn->capable & FUSE_CAP_ATOMIC_O_TRUNC) {
     // so let's set the bit
     conn->want |= FUSE_CAP_ATOMIC_O_TRUNC;
  }

  return 0;
}

static void s3fs_destroy(void*) {
  if(debug)
    syslog(LOG_DEBUG, "destroy");

  // openssl
  CRYPTO_set_id_callback(NULL);
  CRYPTO_set_locking_callback(NULL);
  for (int i = 0; i < CRYPTO_num_locks(); i++)
    pthread_mutex_destroy(&mutex_buf[i]);
  free(mutex_buf);
  mutex_buf = NULL;
  curl_global_cleanup();
  pthread_mutex_destroy(&curl_handles_lock);
  pthread_mutex_destroy(&s3fs_descriptors_lock);
  pthread_mutex_destroy(&stat_cache_lock);
}

static int s3fs_access(const char *path, int mask) {
  if(foreground) 
    cout << "access[path=" << path << "]" <<  endl;
  return 0;
}

// aka touch
static int s3fs_utimens(const char *path, const struct timespec ts[2]) {
  int result;
  char *s3_realpath;
  headers_t meta;

  if(foreground) 
    cout << "s3fs_utimens[path=" << path << "][mtime=" << str(ts[1].tv_sec) << "]" << endl;

  result = get_headers(path, meta);
  if(result != 0)
    return result;

  s3_realpath = get_realpath(path);
  meta["x-amz-meta-mtime"] = str(ts[1].tv_sec);
  meta["x-amz-copy-source"] = urlEncode("/" + bucket + s3_realpath);
  meta["x-amz-metadata-directive"] = "REPLACE";
  free(s3_realpath);

  if(foreground) 
    cout << "  calling put_headers [path=" << path << "]" << endl;

  result = put_headers(path, meta);

  return result;
}

///////////////////////////////////////////////////////////
// List Multipart Uploads for bucket
///////////////////////////////////////////////////////////
static int list_multipart_uploads(void) {
  CURL *curl = NULL;
  string resource;
  string url;
  struct BodyStruct body;
  int result;
  string date;
  string raw_date;
  string auth;
  string my_url;
  struct curl_slist *slist=NULL;

  // Initialization of variables
  body.text = (char *)malloc(1);
  body.size = 0; 

  printf("List Multipart Uploads\n");

  //////////////////////////////////////////
  //  Syntax:
  //
  //    GET /?uploads HTTP/1.1
  //    Host: BucketName.s3.amazonaws.com
  //    Date: Date
  //    Authorization: Signature			
  //////////////////////////////////////////

  // printf("service_path: %s\n", service_path.c_str());

  // resource = urlEncode(service_path);
  resource = urlEncode(service_path + bucket + "/");
  // printf("resource: %s\n", resource.c_str());
  resource.append("?uploads");
  // printf("resource: %s\n", resource.c_str());

  url = host + resource;
  // printf("url: %s\n", url.c_str());

  my_url = prepare_url(url.c_str());
  // printf("my_url: %s\n", my_url.c_str());

  curl = create_curl_handle();

  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, true);
  // curl_easy_setopt(curl, CURLOPT_VERBOSE, true);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&body);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);

  date.assign("Date: ");
  raw_date = get_date();
  date.append(raw_date);
  slist = curl_slist_append(slist, date.c_str());

  slist = curl_slist_append(slist, "Accept:");

  if (public_bucket.substr(0,1) != "1") {
     auth.assign("Authorization: AWS ");
     auth.append(AWSAccessKeyId);
     auth.append(":");
     auth.append(calc_signature("GET", "", raw_date, slist, resource));
    slist = curl_slist_append(slist, auth.c_str());
  }
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);
  curl_easy_setopt(curl, CURLOPT_URL, my_url.c_str());

  result = my_curl_easy_perform(curl, &body);

  curl_slist_free_all(slist);
  destroy_curl_handle(curl);

  if(result != 0) {
    if(body.size > 0) {
      printf("body.text:\n%s\n", body.text);
    }
    if(body.text) free(body.text);
    return result;
  }

  if(body.size > 0) {
    printf("body.text:\n%s\n", body.text);
  }

  result = 0;
  return result;
}

/*
 * s3fs_check_service
 *
 * Preliminary check on credentials and bucket
 * If the network is up when s3fs is started and the bucket is not a public
 * bucket, then connect to S3 service with the bucket's credentials.
 * This will indicate if the credentials are valid or not.
 * If the connection is successful, then check the list of available buckets
 * against the bucket name that we are trying to mount.
 *
 * This function either just returns (in cases where the network is 
 * unavailable, a public bucket, etc...) of exits with an error message
 * (where the connection is successful, but returns an error code or if
 * the bucket isn't found in the service).
 */
static void s3fs_check_service(void) {
  CURL *curl = NULL;
  CURLcode curlCode = CURLE_OK;
  CURLcode ccode = CURLE_OK;

  if(foreground) 
    cout << "s3fs_check_service" << endl;

  struct BodyStruct body;
  body.text = (char *)malloc(1);
  body.size = 0;

  long responseCode;
  xmlDocPtr doc;
  xmlNodePtr cur_node;
  
  string resource = "/";
  string url = host + resource;

  auto_curl_slist headers;
  string date = get_date();
  headers.append("Date: " + date);
  if (public_bucket.substr(0,1) != "1") {
    headers.append("Authorization: AWS " + AWSAccessKeyId + ":" +
      calc_signature("GET", "", date, headers.get(), resource));
  } else {
     // This operation is only valid if done by an authenticated sender
     if(body.text) {
       free(body.text);
     }
     return;
  }

  curl = create_curl_handle();
  curl_easy_setopt(curl, CURLOPT_FAILONERROR, true);
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, true);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&body);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
  if(ssl_verify_hostname.substr(0,1) == "0")
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers.get());

  // Need to know if the curl response is just a timeout possibly indicating
  // the the network is down or if the connection was acutally made 
  // - my_curl_easy_perform doesn't differentiate between the two
  int t = retries + 1;
  while (t-- > 0) {
    curlCode = curl_easy_perform(curl);
    if(curlCode == 0)
      break;

    if (curlCode != CURLE_OPERATION_TIMEDOUT) {
      if (curlCode == CURLE_HTTP_RETURNED_ERROR) {
         break;
      } else {
        switch (curlCode) {
          case CURLE_SSL_CACERT:
            // try to locate cert, if successful, then set the
            // option and continue
            if (curl_ca_bundle.size() == 0) {
               locate_bundle();
               if (curl_ca_bundle.size() != 0) {
                  t++;
                  curl_easy_setopt(curl, CURLOPT_CAINFO, curl_ca_bundle.c_str());
                  continue;
               }
            }
            syslog(LOG_ERR, "curlCode: %i  msg: %s", curlCode,
               curl_easy_strerror(curlCode));;
            fprintf (stderr, "%s: curlCode: %i -- %s\n", 
               program_name.c_str(),
               curlCode,
               curl_easy_strerror(curlCode));
               exit(EXIT_FAILURE);
            break;

#ifdef CURLE_PEER_FAILED_VERIFICATION
          case CURLE_PEER_FAILED_VERIFICATION:
            fprintf (stderr, "%s: s3fs_check_service: curlCode: %i -- %s\n", 
               program_name.c_str(),
               curlCode,
               curl_easy_strerror(curlCode));
               exit(EXIT_FAILURE);
          break;
#endif

          default:
            // Unknown error - return
            syslog(LOG_ERR, "curlCode: %i  msg: %s", curlCode,
               curl_easy_strerror(curlCode));;
            if(body.text) {
              free(body.text);
            }
            return;
        }
      }
    }
  }
 
  // We get here under three conditions:
  //  - too many timeouts
  //  - connection, but a HTTP error
  //  - success

  if(debug) 
    syslog(LOG_DEBUG, "curlCode: %i   msg: %s\n", 
           curlCode, curl_easy_strerror(curlCode));

  // network is down
  if(curlCode == CURLE_OPERATION_TIMEDOUT) {
    free(body.text);
    body.text = NULL;

    return;
  }

  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &responseCode);

  if(debug)
    syslog(LOG_DEBUG, "responseCode: %i\n", (int)responseCode);

  // Connection was made, but there is a HTTP error
  if (curlCode == CURLE_HTTP_RETURNED_ERROR) {
     // Try again, but this time grab the data
     curl_easy_setopt(curl, CURLOPT_FAILONERROR, false);
     ccode = curl_easy_perform(curl);

     curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &responseCode);
    
     fprintf (stderr, "%s: CURLE_HTTP_RETURNED_ERROR\n", program_name.c_str());
     fprintf (stderr, "%s: HTTP Error Code: %i\n", program_name.c_str(), (int)responseCode);

     // Parse the return info
     doc = xmlReadMemory(body.text, body.size, "", NULL, 0);
     if(doc == NULL)
        exit(EXIT_FAILURE);

     if (doc->children == NULL) {
        xmlFreeDoc(doc);
        exit(EXIT_FAILURE);
     }

     for ( cur_node = doc->children->children; 
           cur_node != NULL; 
           cur_node = cur_node->next) {
   
       string cur_node_name(reinterpret_cast<const char *>(cur_node->name));

       if (cur_node_name == "Code") {
          string content = reinterpret_cast<const char *>(cur_node->children->content);
          fprintf (stderr, "%s: AWS Error Code: %s\n", program_name.c_str(), content.c_str());
       }
       if (cur_node_name == "Message") {
          string content = reinterpret_cast<const char *>(cur_node->children->content);
          fprintf (stderr, "%s: AWS Message: %s\n", program_name.c_str(), content.c_str());
       }
     }
     xmlFreeDoc(doc);
     exit(EXIT_FAILURE);
  }

  // Success
  if (responseCode != 200) {
    if(debug) syslog(LOG_DEBUG, "responseCode: %i\n", (int)responseCode);
    if(body.text) {
      free(body.text);
    }
    destroy_curl_handle(curl);
    return;
  }

  // Parse the return info and see if the bucket is available  
  doc = xmlReadMemory(body.text, body.size, "", NULL, 0);
  if(doc == NULL) {
    free(body.text);
    body.text = NULL;
    destroy_curl_handle(curl);

    return;
  } 

  if(doc->children == NULL) {
    xmlFreeDoc(doc);
    free(body.text);
    body.text = NULL;
    destroy_curl_handle(curl);

    return;
  }

  bool bucketFound = 0;
  bool matchFound = 0;

  // Parse the XML looking for the bucket names
  for ( cur_node = doc->children->children; 
        cur_node != NULL; 
        cur_node = cur_node->next) {

    string cur_node_name(reinterpret_cast<const char *>(cur_node->name));

    if (cur_node_name == "Buckets") {
      if (cur_node->children != NULL) {
        for (xmlNodePtr sub_node = cur_node->children;
                        sub_node != NULL;
                        sub_node = sub_node->next) {

          if (sub_node->type == XML_ELEMENT_NODE) {
            string elementName = reinterpret_cast<const char*>(sub_node->name);

            if (elementName == "Bucket") { 
               string Name;

              for (xmlNodePtr b_node = sub_node->children;
                              b_node != NULL;
                              b_node = b_node->next) {

                if (b_node->type == XML_ELEMENT_NODE) {
                  string elementName = reinterpret_cast<const char*>(b_node->name);
                  if (b_node->children != NULL) {
                    if (b_node->children->type == XML_TEXT_NODE) {
                      if (elementName == "Name") {
                        Name = reinterpret_cast<const char *>(b_node->children->content);
                        bucketFound = 1; 
                        if(Name == bucket) {
                           matchFound = 1;
                        }
                      }
                    }
                  }
                }
              } // for (xmlNodePtr b_node = sub_node->children;
            }
          }
        } // for (xmlNodePtr sub_node = cur_node->children;
      }
    }
  } // for (xmlNodePtr cur_node = doc->children->children; 

  xmlFreeDoc(doc);

  if (bucketFound == 0) {
    fprintf (stderr, "%s: the service specified by the credentials does not contain any buckets\n", 
        program_name.c_str());
    exit(EXIT_FAILURE);
  }

  if (matchFound == 0) {
    fprintf (stderr, "%s: bucket \"%s\" is not part of the service specified by the credentials\n", 
        program_name.c_str(), bucket.c_str());
    exit(EXIT_FAILURE);
  }

  // once we arrive here, that means that our preliminary connection
  // worked and the bucket matches the credentials provided
  // now check for bucket location using the virtual host name
  // this should expose the certificate mismatch that may occur
  // when using https:// (SSL) and a bucket name that contains periods
  resource = urlEncode(service_path + bucket);
  url = host + resource + "?location";

  string my_url = prepare_url(url.c_str());
  auto_curl_slist new_headers;
  date = get_date();
  new_headers.append("Date: " + date);
  new_headers.append("Authorization: AWS " + AWSAccessKeyId + ":" +
      calc_signature("GET", "", date, new_headers.get(), resource + "/?location"));

  curl_easy_setopt(curl, CURLOPT_URL, my_url.c_str());
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, new_headers.get());

  // Need to know if the curl response is just a timeout possibly
  // indicating the the network is down or if the connection was
  // acutally made - my_curl_easy_perform doesn't differentiate
  // between the two

  strcpy(body.text, "");
  body.size = 0;

  t = retries + 1;
  while (t-- > 0) {
    curlCode = curl_easy_perform(curl);
    if(curlCode == 0)
      break;

    if (curlCode != CURLE_OPERATION_TIMEDOUT) {
      if (curlCode == CURLE_HTTP_RETURNED_ERROR) {
         break;
      } else {
        switch (curlCode) {
          case CURLE_SSL_CACERT:
            // try to locate cert, if successful, then set the
            // option and continue
            if (curl_ca_bundle.size() == 0) {
               locate_bundle();
               if (curl_ca_bundle.size() != 0) {
                  t++;
                  curl_easy_setopt(curl, CURLOPT_CAINFO, curl_ca_bundle.c_str());
                  continue;
               }
            }
            syslog(LOG_ERR, "curlCode: %i  msg: %s", curlCode,
               curl_easy_strerror(curlCode));;
            fprintf (stderr, "%s: curlCode: %i -- %s\n", 
               program_name.c_str(),
               curlCode,
               curl_easy_strerror(curlCode));
               exit(EXIT_FAILURE);
            break;

#ifdef CURLE_PEER_FAILED_VERIFICATION
            case CURLE_PEER_FAILED_VERIFICATION:
              first_pos = bucket.find_first_of(".");
              if (first_pos != string::npos) {
                fprintf (stderr, "%s: curl returned a CURL_PEER_FAILED_VERIFICATION error\n", program_name.c_str());
                fprintf (stderr, "%s: security issue found: buckets with periods in their name are incompatible with https\n", program_name.c_str());
                fprintf (stderr, "%s: This check can be over-ridden by using the -o ssl_verify_hostname=0\n", program_name.c_str());
                fprintf (stderr, "%s: The certificate will still be checked but the hostname will not be verified.\n", program_name.c_str());
                fprintf (stderr, "%s: A more secure method would be to use a bucket name without periods.\n", program_name.c_str());
              } else {
                fprintf (stderr, "%s: my_curl_easy_perform: curlCode: %i -- %s\n", 
                   program_name.c_str(),
                   curlCode,
                   curl_easy_strerror(curlCode));
              }
              exit(EXIT_FAILURE);
            break;
#endif

          default:
            // Unknown error - return
            syslog(LOG_ERR, "curlCode: %i  msg: %s", curlCode,
               curl_easy_strerror(curlCode));;
            if(body.text) {
              free(body.text);
            }
            destroy_curl_handle(curl);
            return;
        }
      }
    }
  }

  // We get here under three conditions:
  //  - too many timeouts
  //  - connection, but a HTTP error
  //  - success

  if(debug)
    syslog(LOG_DEBUG, "curlCode: %i   msg: %s\n", 
           curlCode, curl_easy_strerror(curlCode));

  // network is down
  if(curlCode == CURLE_OPERATION_TIMEDOUT) {
    free(body.text);
    body.text = NULL;
    destroy_curl_handle(curl);

    return;
  }

  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &responseCode);
  if(debug)
    syslog(LOG_DEBUG, "responseCode: %i\n", (int)responseCode);

  // Connection was made, but there is a HTTP error
  if (curlCode == CURLE_HTTP_RETURNED_ERROR) {
     if (responseCode == 403) {
       fprintf (stderr, "%s: HTTP: 403 Forbidden - it is likely that your credentials are invalid\n", 
         program_name.c_str());
       exit(EXIT_FAILURE);
     }
     fprintf (stderr, "%s: HTTP: %i - report this to the s3fs developers\n", 
       program_name.c_str(), (int)responseCode);
     exit(EXIT_FAILURE);
  }

  // make sure remote mountpath exists and is a directory
  if(mount_prefix.size() > 0) {
    if(remote_mountpath_exists(mount_prefix.c_str()) != 0) {
      fprintf(stderr, "%s: remote mountpath %s not found.\n", 
          program_name.c_str(), mount_prefix.c_str());

      exit(EXIT_FAILURE);
    }
  }

  // Success
  service_validated = true;

  if(responseCode != 200) {
    if(debug)
      syslog(LOG_DEBUG, "responseCode: %i\n", (int)responseCode);

    free(body.text);
    body.text = NULL;
    destroy_curl_handle(curl);

    return;
  }

  free(body.text);
  body.text = NULL;
  destroy_curl_handle(curl);

  return;
}

static bool check_for_aws_format (void) {
  size_t first_pos = string::npos;
  string line;
  bool got_access_key_id_line = 0;
  bool got_secret_key_line = 0;
  string str1 ("AWSAccessKeyId=");
  string str2 ("AWSSecretKey=");
  size_t found;


  ifstream PF(passwd_file.c_str());
  if (PF.good()) {
    while (getline(PF, line)) {
      if (line[0]=='#') {
        continue;
      }
      if (line.size() == 0) {
        continue;
      }

      first_pos = line.find_first_of(" \t");
      if (first_pos != string::npos) {
        printf ("%s: invalid line in passwd file, found whitespace character\n", 
           program_name.c_str());
        exit(EXIT_FAILURE);
      }

      first_pos = line.find_first_of("[");
      if (first_pos != string::npos && first_pos == 0) {
        printf ("%s: invalid line in passwd file, found a bracket \"[\" character\n", 
           program_name.c_str());
        exit(EXIT_FAILURE);
      }

      found = line.find(str1);
      if (found != string::npos) {
         first_pos = line.find_first_of("=");
         AWSAccessKeyId = line.substr(first_pos + 1, string::npos);
         // cout << "AWSAccessKeyId: " << AWSAccessKeyId.c_str() << endl;
         got_access_key_id_line = 1;
         continue;
      }

      found = line.find(str2);
      if (found != string::npos) {
         first_pos = line.find_first_of("=");
         AWSSecretAccessKey = line.substr(first_pos + 1, string::npos);
         // cout << "AWSSecretAccessKey: " << AWSSecretAccessKey.c_str() << endl;
         got_secret_key_line = 1;
         continue;
      }
    }
  }

  if (got_access_key_id_line && got_secret_key_line) {
     return 1;
  } else {
     return 0;
  }

}

//////////////////////////////////////////////////////////////////
// check_passwd_file_perms
// 
// expect that global passwd_file variable contains
// a non-empty value and is readable by the current user
//
// Check for too permissive access to the file
// help save users from themselves via a security hole
//
// only two options: return or error out
//////////////////////////////////////////////////////////////////
static void check_passwd_file_perms (void) {
  struct stat info;

  // let's get the file info
  if (stat(passwd_file.c_str(), &info) != 0) {
    fprintf (stderr, "%s: unexpected error from stat(%s, ) \n", 
        program_name.c_str(), passwd_file.c_str());
    exit(EXIT_FAILURE);
  } 

  // return error if any file has others permissions 
  if ((info.st_mode & S_IROTH) ||
      (info.st_mode & S_IWOTH) || 
      (info.st_mode & S_IXOTH))  {
    fprintf (stderr, "%s: credentials file %s should not have others permissions\n", 
        program_name.c_str(), passwd_file.c_str());
    exit(EXIT_FAILURE);
  }

  // Any local file should not have any group permissions 
  // /etc/passwd-s3fs can have group permissions 
  if (passwd_file != "/etc/passwd-s3fs") {
    if ((info.st_mode & S_IRGRP) ||
        (info.st_mode & S_IWGRP) || 
        (info.st_mode & S_IXGRP))  {
      fprintf (stderr, "%s: credentials file %s should not have group permissions\n", 
        program_name.c_str(), passwd_file.c_str());
      exit(EXIT_FAILURE);
    }
  }

  // check for owner execute permissions?

  return;
}

//////////////////////////////////////////////////////////////////
// read_passwd_file
//
// Support for per bucket credentials
// 
// Format for the credentials file:
// [bucket:]AccessKeyId:SecretAccessKey
// 
// Lines beginning with # are considered comments
// and ignored, as are empty lines
//
// Uncommented lines without the ":" character are flagged as
// an error, so are lines with spaces or tabs
//
// only one default key pair is allowed, but not required
//////////////////////////////////////////////////////////////////
static void read_passwd_file (void) {
  string line;
  string field1, field2, field3;
  size_t first_pos = string::npos;
  size_t last_pos = string::npos;
  bool default_found = 0;
  bool aws_format;

  // if you got here, the password file
  // exists and is readable by the
  // current user, check for permissions
  check_passwd_file_perms();

  aws_format = check_for_aws_format();

  if (aws_format)
     return;

  ifstream PF(passwd_file.c_str());
  if (PF.good()) {
    while (getline(PF, line)) {
      if (line[0]=='#') {
        continue;
      }
      if (line.size() == 0) {
        continue;
      }

      first_pos = line.find_first_of(" \t");
      if (first_pos != string::npos) {
        printf ("%s: invalid line in passwd file, found whitespace character\n", 
           program_name.c_str());
        exit(EXIT_FAILURE);
      }

      first_pos = line.find_first_of("[");
      if (first_pos != string::npos && first_pos == 0) {
        printf ("%s: invalid line in passwd file, found a bracket \"[\" character\n", 
           program_name.c_str());
        exit(EXIT_FAILURE);
      }

      first_pos = line.find_first_of(":");
      if (first_pos == string::npos) {
        printf ("%s: invalid line in passwd file, no \":\" separator found\n", 
           program_name.c_str());
        exit(EXIT_FAILURE);
      }
      last_pos = line.find_last_of(":");

      if (first_pos != last_pos) {
        // bucket specified
        field1 = line.substr(0,first_pos);
        field2 = line.substr(first_pos + 1, last_pos - first_pos - 1);
        field3 = line.substr(last_pos + 1, string::npos);
      } else {
        // no bucket specified - original style - found default key
        if (default_found == 1) {
          printf ("%s: more than one default key pair found in passwd file\n", 
            program_name.c_str());
          exit(EXIT_FAILURE);
        }
        default_found = 1;
        field1.assign("");
        field2 = line.substr(0,first_pos);
        field3 = line.substr(first_pos + 1, string::npos);
        AWSAccessKeyId = field2;
        AWSSecretAccessKey = field3;
      }

      // does the bucket we are mounting match this passwd file entry?
      // if so, use that key pair, otherwise use the default key, if found,
      // will be used
      if (field1.size() != 0 && field1 == bucket) {
         AWSAccessKeyId = field2;
         AWSSecretAccessKey = field3;
         break;
      }
    }
  }
  return;
}

/////////////////////////////////////////////////////////////
// get_access_keys
//
// called only when were are not mounting a 
// public bucket
//
// Here is the order precedence for getting the
// keys:
//
// 1 - from the command line  (security risk)
// 2 - from a password file specified on the command line
// 3 - from environment variables
// 4 - from the users ~/.passwd-s3fs
// 5 - from /etc/passwd-s3fs
/////////////////////////////////////////////////////////////
static void get_access_keys (void) {

  // should be redundant
  if (public_bucket.substr(0,1) == "1") {
     return;
  }

  // 1 - keys specified on the command line
  if (AWSAccessKeyId.size() > 0 && AWSSecretAccessKey.size() > 0) {
     return;
  }

  // 2 - was specified on the command line
  if (passwd_file.size() > 0) {
    ifstream PF(passwd_file.c_str());
    if (PF.good()) {
       PF.close();
       read_passwd_file();
       return;
    } else {
      fprintf(stderr, "%s: specified passwd_file is not readable\n",
              program_name.c_str());
      exit(EXIT_FAILURE);
    }
  }

  // 3  - environment variables
  char * AWSACCESSKEYID;
  char * AWSSECRETACCESSKEY;

  AWSACCESSKEYID     = getenv("AWSACCESSKEYID");
  AWSSECRETACCESSKEY = getenv("AWSSECRETACCESSKEY");
  if (AWSACCESSKEYID != NULL || AWSSECRETACCESSKEY != NULL) {
    if ((AWSACCESSKEYID == NULL && AWSSECRETACCESSKEY != NULL) ||
        (AWSACCESSKEYID != NULL && AWSSECRETACCESSKEY == NULL) ){

      fprintf(stderr, "%s: if environment variable AWSACCESSKEYID is set then AWSSECRETACCESSKEY must be set too\n",
              program_name.c_str());
      exit(EXIT_FAILURE);
    }
    AWSAccessKeyId.assign(AWSACCESSKEYID);
    AWSSecretAccessKey.assign(AWSSECRETACCESSKEY);
    return;
  }

  // 3a - from the AWS_CREDENTIAL_FILE environment variable
  char * AWS_CREDENTIAL_FILE;
  AWS_CREDENTIAL_FILE = getenv("AWS_CREDENTIAL_FILE");
  if (AWS_CREDENTIAL_FILE != NULL) {
    passwd_file.assign(AWS_CREDENTIAL_FILE);
    if (passwd_file.size() > 0) {
      ifstream PF(passwd_file.c_str());
      if (PF.good()) {
         PF.close();
         read_passwd_file();
         return;
      } else {
        fprintf(stderr, "%s: AWS_CREDENTIAL_FILE: \"%s\" is not readable\n",
                program_name.c_str(), passwd_file.c_str());
        exit(EXIT_FAILURE);
      }
    }
  }

  // 4 - from the default location in the users home directory
  char * HOME;
  HOME = getenv ("HOME");
  if (HOME != NULL) {
     passwd_file.assign(HOME);
     passwd_file.append("/.passwd-s3fs");
     ifstream PF(passwd_file.c_str());
     if (PF.good()) {
       PF.close();
       read_passwd_file();
       // It is possible that the user's file was there but
       // contained no key pairs i.e. commented out
       // in that case, go look in the final location
       if (AWSAccessKeyId.size() > 0 && AWSSecretAccessKey.size() > 0) {
          return;
       }
     }
   }

  // 5 - from the system default location
  passwd_file.assign("/etc/passwd-s3fs"); 
  ifstream PF(passwd_file.c_str());
  if (PF.good()) {
    PF.close();
    read_passwd_file();
    return;
  }
  
  fprintf(stderr, "%s: could not determine how to establish security credentials\n",
           program_name.c_str());
  exit(EXIT_FAILURE);
}

static void show_usage (void) {
  printf("Usage: %s BUCKET:[PATH] MOUNTPOINT [OPTION]...\n",
    program_name.c_str());
}

static void show_help (void) {
  show_usage();
  printf( 
    "\n"
    "Mount an Amazon S3 bucket as a file system.\n"
    "\n"
    "   General forms for s3fs and FUSE/mount options:\n"
    "      -o opt[,opt...]\n"
    "      -o opt [-o opt] ...\n"
    "\n"
    "s3fs Options:\n"
    "\n"
    "   Most s3fs options are given in the form where \"opt\" is:\n"
    "\n"
    "             <option_name>=<option_value>\n"
    "\n"
    "   default_acl (default=\"private\")\n"
    "     - the default canned acl to apply to all written s3 objects\n"
    "          see http://aws.amazon.com/documentation/s3/ for the \n"
    "          full list of canned acls\n"
    "\n"
    "   retries (default=\"2\")\n"
    "      - number of times to retry a failed s3 transaction\n"
    "\n"
    "   use_cache (default=\"\" which means disabled)\n"
    "      - local folder to use for local file cache\n"
    "\n"
    "   use_rrs (default=\"\" which means diabled)\n"
    "      - use Amazon's Reduced Redundancy Storage when set to 1\n"
    "\n"
    "   public_bucket (default=\"\" which means disabled)\n"
    "      - anonymously mount a public bucket when set to 1\n"
    "\n"
    "   passwd_file (default=\"\")\n"
    "      - specify which s3fs password file to use\n"
    "\n"
    "   connect_timeout (default=\"10\" seconds)\n"
    "      - time to wait for connection before giving up\n"
    "\n"
    "   readwrite_timeout (default=\"30\" seconds)\n"
    "      - time to wait between read/write activity before giving up\n"
    "\n"
    "   max_stat_cache_size (default=\"10000\" entries (about 4MB))\n"
    "      - maximum number of entries in the stat cache\n"
    "\n"
    "   url (default=\"http://s3.amazonaws.com\")\n"
    "      - sets the url to use to access amazon s3\n"
    "\n"
    "   nomultipart - disable multipart uploads\n"
    "\n"
    "FUSE/mount Options:\n"
    "\n"
    "   Most of the generic mount options described in 'man mount' are\n"
    "   supported (ro, rw, suid, nosuid, dev, nodev, exec, noexec, atime,\n"
    "   noatime, sync async, dirsync).  Filesystems are mounted with\n"
    "   '-onodev,nosuid' by default, which can only be overridden by a\n"
    "   privileged user.\n"
    "   \n"
    "   There are many FUSE specific mount options that can be specified.\n"
    "   e.g. allow_other  See the FUSE's README for the full set.\n"
    "\n"
    "Miscellaneous Options:\n"
    "\n"
    " -h, --help        Output this help.\n"
    "     --version     Output version info.\n"
    " -d  --debug       Turn on DEBUG messages to syslog. Specifying -d\n"
    "                   twice turns on FUSE debug messages to STDOUT.\n"
    " -f                FUSE foreground option - do not run as daemon.\n"
    " -s                FUSE singlethread option\n"
    "                   disable multi-threaded operation\n"
    "\n"
    "\n"
    "Report bugs to <s3fs-devel@googlegroups.com>\n"
    "s3fs home page: <http://code.google.com/p/s3fs/>\n"
  );
  exit(EXIT_SUCCESS);
}

static void show_version(void) {
  printf(
  "Amazon Simple Storage Service File System %s\n"
  "Copyright (C) 2010 Randy Rizun <rrizun@gmail.com>\n"
  "License GPL2: GNU GPL version 2 <http://gnu.org/licenses/gpl.html>\n"
  "This is free software: you are free to change and redistribute it.\n"
  "There is NO WARRANTY, to the extent permitted by law.\n", VERSION );
  exit(EXIT_SUCCESS);
}

char *get_realpath(const char *path) {
  size_t size;
  char *realpath;

  size  = (strlen(path) + 1) + (mount_prefix.size() + 1);
  realpath = (char *) malloc(size);
  snprintf(realpath, size, "%s%s", mount_prefix.c_str(), path);

  return(realpath);
}

// This is repeatedly called by the fuse option parser
// if the key is equal to FUSE_OPT_KEY_OPT, it's an option passed in prefixed by 
// '-' or '--' e.g.: -f -d -ousecache=/tmp
//
// if the key is equal to FUSE_OPT_KEY_NONOPT, it's either the bucket name 
//  or the mountpoint. The bucket name will always come before the mountpoint
static int my_fuse_opt_proc(void *data, const char *arg, int key, struct fuse_args *outargs) {
  if(key == FUSE_OPT_KEY_NONOPT) {
    // the first NONOPT option is the bucket name
    if(bucket.size() == 0) {
      // extract remote mount path
      char *bucket_name = (char *) arg;
      if(strstr(arg, ":")) {
        bucket = strtok(bucket_name, ":");
        mount_prefix = strtok(NULL, ":");
        // remove trailing slash
        if(mount_prefix.at(mount_prefix.size() - 1) == '/')
          mount_prefix = mount_prefix.substr(0, mount_prefix.size() - 1);
      } else {
        bucket = arg;
      }

      return 0;
    }

    // save the mountpoint and do some basic error checking
    mountpoint = arg;
    struct stat stbuf;

    if(stat(arg, &stbuf) == -1) {
      fprintf(stderr, "%s: unable to access MOUNTPOINT %s: %s\n", 
          program_name.c_str(), mountpoint.c_str(), strerror(errno));
      exit(EXIT_FAILURE);
    }

    root_mode = stbuf.st_mode; // save mode for later usage
    
    if(!(S_ISDIR(stbuf.st_mode ))) {
      fprintf(stderr, "%s: MOUNTPOINT: %s is not a directory\n", 
              program_name.c_str(), mountpoint.c_str());
      exit(EXIT_FAILURE);
    } 

    struct dirent *ent;
    DIR *dp = opendir(mountpoint.c_str());
    if(dp == NULL) {
      fprintf(stderr, "%s: failed to open MOUNTPOINT: %s: %s\n", 
              program_name.c_str(), mountpoint.c_str(), strerror(errno));
      exit(EXIT_FAILURE); 
    }

    while((ent = readdir(dp)) != NULL) {
      if(strcmp(ent->d_name, ".") != 0 && strcmp(ent->d_name, "..") != 0) {
        closedir(dp);
        fprintf(stderr, "%s: MOUNTPOINT directory %s is not empty\n", 
                program_name.c_str(), mountpoint.c_str());
        exit(EXIT_FAILURE);
      }
    }
  }

  if (key == FUSE_OPT_KEY_OPT) {
    if (strstr(arg, "default_acl=") != 0) {
      default_acl = strchr(arg, '=') + 1;
      return 0;
    }
    if (strstr(arg, "retries=") != 0) {
      retries = atoi(strchr(arg, '=') + 1);
      return 0;
    }
    if (strstr(arg, "use_cache=") != 0) {
      use_cache = strchr(arg, '=') + 1;
      return 0;
    }

    if(strstr(arg, "nomultipart") != 0) {
      nomultipart = true;
      return 0;
    }
    
    if (strstr(arg, "use_rrs=") != 0) {
      use_rrs = strchr(arg, '=') + 1;
      if (strcmp(use_rrs.c_str(), "1") == 0 || 
          strcmp(use_rrs.c_str(), "")  == 0 ) {
        return 0;
      } else {
         fprintf(stderr, "%s: poorly formed argument to option: use_rrs\n", 
                 program_name.c_str());
         exit(EXIT_FAILURE);
      }
    }
    if (strstr(arg, "ssl_verify_hostname=") != 0) {
      ssl_verify_hostname = strchr(arg, '=') + 1;
      if (strcmp(ssl_verify_hostname.c_str(), "1") == 0 || 
          strcmp(ssl_verify_hostname.c_str(), "0") == 0 ) { 
        return 0;
      } else {
         fprintf(stderr, "%s: poorly formed argument to option: ssl_verify_hostname\n", 
                 program_name.c_str());
         exit(EXIT_FAILURE);
      }
    }
    if (strstr(arg, "passwd_file=") != 0) {
      passwd_file = strchr(arg, '=') + 1;
      return 0;
    }
    if (strstr(arg, "public_bucket=") != 0) {
      public_bucket = strchr(arg, '=') + 1;
      if (strcmp(public_bucket.c_str(), "1") == 0 || 
          strcmp(public_bucket.c_str(), "")  == 0 ) {
        return 0;
      } else {
         fprintf(stderr, "%s: poorly formed argument to option: public_bucket\n", 
                 program_name.c_str());
         exit(EXIT_FAILURE);
      }
    }
    if (strstr(arg, "host=") != 0) {
      host = strchr(arg, '=') + 1;
      return 0;
     }
    if (strstr(arg, "servicepath=") != 0) {
      service_path = strchr(arg, '=') + 1;
      return 0;
    }
    if (strstr(arg, "connect_timeout=") != 0) {
      connect_timeout = strtol(strchr(arg, '=') + 1, 0, 10);
      return 0;
    }
    if (strstr(arg, "readwrite_timeout=") != 0) {
      readwrite_timeout = strtoul(strchr(arg, '=') + 1, 0, 10);
      return 0;
    }
    if (strstr(arg, "max_stat_cache_size=") != 0) {
      max_stat_cache_size = strtoul(strchr(arg, '=') + 1, 0, 10);
      return 0;
    }
    if (strstr(arg, "url=") != 0) {
      host = strchr(arg, '=') + 1;
      // strip the trailing '/', if any, off the end of the host
      // string
      size_t found, length;
      found = host.find_last_of('/');
      length = host.length();
      while ( found == (length - 1) && length > 0 ) {
         host.erase(found);
         found = host.find_last_of('/');
         length = host.length();
      }
      return 0;
    }

    // debug option
    //
    // The first -d (or --debug) enables s3fs debug
    // the second -d option is passed to fuse to turn on its
    // debug output
    if ( (strcmp(arg, "-d") == 0) || (strcmp(arg, "--debug") == 0) ) {
      if (!debug) {
        debug = 1;
        return 0;
      } else {
         // fuse doesn't understand "--debug", but it 
         // understands -d, but we can't pass -d back
         // to fuse, in this case just ignore the
         // second --debug if is was provided.  If we
         // do not ignore this, fuse emits an error
         if(strcmp(arg, "--debug") == 0) {
            return 0;
         } 
      }
    }

    if (strstr(arg, "accessKeyId=") != 0) {
      fprintf(stderr, "%s: option accessKeyId is no longer supported\n", 
              program_name.c_str());
      exit(EXIT_FAILURE);
    }
    if (strstr(arg, "secretAccessKey=") != 0) {
      fprintf(stderr, "%s: option secretAccessKey is no longer supported\n", 
              program_name.c_str());
      exit(EXIT_FAILURE);
    }
  }

  return 1;
}

int main(int argc, char *argv[]) {
  int ch;
  int option_index = 0; 

  static const struct option long_opts[] = {
    {"help",    no_argument, NULL, 'h'},
    {"version", no_argument, 0,     0},
    {"debug",   no_argument, NULL, 'd'},
    {0, 0, 0, 0}};

   // get progam name - emulate basename 
   size_t found = string::npos;
   program_name.assign(argv[0]);
   found = program_name.find_last_of("/");
   if(found != string::npos) {
      program_name.replace(0, found+1, "");
   }

   while ((ch = getopt_long(argc, argv, "dho:fsu", long_opts, &option_index)) != -1) {
     switch (ch) {
     case 0:
       if(strcmp(long_opts[option_index].name, "version") == 0)
          show_version();
       break;
     case 'h':
       show_help();
       break;
     case 'o':
       break;
     case 'd':
       break;
     case 'f':
       foreground = 1;
       break;
     case 's':
       break;
     case 'u':
       utility_mode = 1;
       break;
     default:
       exit(EXIT_FAILURE);
     }
   }

  // clear this structure
  memset(&s3fs_oper, 0, sizeof(s3fs_oper));

  // This is the fuse-style parser for the arguments
  // after which the bucket name and mountpoint names
  // should have been set
  struct fuse_args custom_args = FUSE_ARGS_INIT(argc, argv);
  fuse_opt_parse(&custom_args, NULL, NULL, my_fuse_opt_proc);

  // The first plain argument is the bucket
  if (bucket.size() == 0) {
    fprintf(stderr, "%s: missing BUCKET argument\n", program_name.c_str());
    show_usage();
    exit(EXIT_FAILURE);
  }

  // bucket names cannot contain upper case characters
  if (lower(bucket) != bucket) {
    fprintf(stderr, "%s: BUCKET %s, upper case characters are not supported\n",
      program_name.c_str(), bucket.c_str());
    exit(EXIT_FAILURE);
  }

  // check bucket name for illegal characters
  found = bucket.find_first_of("/:\\;!@#$%^&*?|+=");
  if(found != string::npos) {
    fprintf(stderr, "%s: BUCKET %s -- bucket name contains an illegal character\n",
      program_name.c_str(), bucket.c_str());
    exit(EXIT_FAILURE);
  }

  // The second plain argument is the mountpoint
  // if the option was given, we all ready checked for a
  // readable, non-empty directory, this checks determines
  // if the mountpoint option was ever supplied
  if (utility_mode == 0) {
    if (mountpoint.size() == 0) {
      fprintf(stderr, "%s: missing MOUNTPOINT argument\n", program_name.c_str());
      show_usage();
      exit(EXIT_FAILURE);
    }
  }

  // error checking of command line arguments for compatability
  if ((AWSSecretAccessKey.size() > 0 && AWSAccessKeyId.size() == 0) ||
      (AWSSecretAccessKey.size() == 0 && AWSAccessKeyId.size() > 0)) {
    fprintf(stderr, "%s: if one access key is specified, both keys need to be specified\n",
      program_name.c_str());
    exit(EXIT_FAILURE);
  }

  if (public_bucket.substr(0,1) == "1" && 
       (AWSSecretAccessKey.size() > 0 || AWSAccessKeyId.size() > 0)) {
    fprintf(stderr, "%s: specifying both public_bucket and the access keys options is invalid\n",
      program_name.c_str());
    exit(EXIT_FAILURE);
  }

  if (passwd_file.size() > 0 && 
       (AWSSecretAccessKey.size() > 0 || AWSAccessKeyId.size() > 0)) {
    fprintf(stderr, "%s: specifying both passwd_file and the access keys options is invalid\n",
      program_name.c_str());
    exit(EXIT_FAILURE);
  }
  
  if (public_bucket.substr(0,1) != "1") {
     get_access_keys();
     if(AWSSecretAccessKey.size() == 0 || AWSAccessKeyId.size() == 0) {
        fprintf(stderr, "%s: could not establish security credentials, check documentation\n",
         program_name.c_str());
        exit(EXIT_FAILURE);
     }
     // More error checking on the access key pair can be done
     // like checking for appropriate lengths and characters  
  }

  // There's room for more command line error checking

  // Check to see if the bucket name contains periods and https (SSL) is
  // being used. This is a known limitation:
  // http://docs.amazonwebservices.com/AmazonS3/latest/dev/
  // The Developers Guide suggests that either use HTTP of for us to write
  // our own certificate verification logic.
  // For now, this will be unsupported unless we get a request for it to
  // be supported. In that case, we have a couple of options:
  // - implement a command line option that bypasses the verify host 
  //   but doesn't bypass verifying the certificate
  // - write our own host verification (this might be complex)
  // See issue #128strncasecmp
  
  /* 
  if (ssl_verify_hostname.substr(0,1) == "1") {
    found = bucket.find_first_of(".");
    if(found != string::npos) {
      found = host.find("https:");
      if(found != string::npos) {
        fprintf(stderr, "%s: Using https and a bucket name with periods is unsupported.\n",
          program_name.c_str());
        exit(1);
      }
    }
  }
  */

  // Does the bucket exist?
  // if the network is up, check for valid credentials and if the bucket
  // exists. skip check if mounting a public bucket
  if(public_bucket.substr(0,1) != "1")
     s3fs_check_service();

  if (utility_mode) {
     printf("Utility Mode\n");
     int result;
     result = list_multipart_uploads();
     exit(EXIT_SUCCESS);
  }

  s3fs_oper.getattr = s3fs_getattr;
  s3fs_oper.readlink = s3fs_readlink;
  s3fs_oper.mknod = s3fs_mknod;
  s3fs_oper.mkdir = s3fs_mkdir;
  s3fs_oper.unlink = s3fs_unlink;
  s3fs_oper.rmdir = s3fs_rmdir;
  s3fs_oper.symlink = s3fs_symlink;
  s3fs_oper.rename = s3fs_rename;
  s3fs_oper.link = s3fs_link;
  s3fs_oper.chmod = s3fs_chmod;
  s3fs_oper.chown = s3fs_chown;
  s3fs_oper.truncate = s3fs_truncate;
  s3fs_oper.open = s3fs_open;
  s3fs_oper.read = s3fs_read;
  s3fs_oper.write = s3fs_write;
  s3fs_oper.statfs = s3fs_statfs;
  s3fs_oper.flush = s3fs_flush;
  s3fs_oper.release = s3fs_release;
  s3fs_oper.readdir = s3fs_readdir;
  s3fs_oper.init = s3fs_init;
  s3fs_oper.destroy = s3fs_destroy;
  s3fs_oper.access = s3fs_access;
  s3fs_oper.utimens = s3fs_utimens;
  s3fs_oper.create = s3fs_create;

  // now passing things off to fuse, fuse will finish evaluating the command line args
  return fuse_main(custom_args.argc, custom_args.argv, &s3fs_oper, NULL);
}
