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

#include "s3fs.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#include <libgen.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <pwd.h>
#include <grp.h>
#include <syslog.h>
#include <getopt.h>

#include <fstream>
#include <iostream>
#include <vector>
#include <algorithm>
#include <strings.h>

#include "string_util.h"

using namespace std;

class auto_fd {
 public:
  auto_fd(int fd): fd(fd) { }
  ~auto_fd() {
    close(fd);
  }

  int get() {
    return fd;
  }

 private:
  int fd;
};

class auto_lock {
 public:
  auto_lock(pthread_mutex_t& lock) : lock(lock) {
    pthread_mutex_lock(&lock);
  }
  ~auto_lock() {
    pthread_mutex_unlock(&lock);
  }

 private:
  pthread_mutex_t& lock;
};

// homegrown timeout mechanism
static int my_curl_progress(
    void *clientp, double dltotal, double dlnow, double ultotal, double ulnow) {
  CURL* curl = static_cast<CURL*>(clientp);

  time_t now = time(0);
  progress_t p(dlnow, ulnow);

  //###cout << "/dlnow=" << dlnow << "/ulnow=" << ulnow << endl;

  auto_lock lock(curl_handles_lock);

  // any progress?
  if (p != curl_progress[curl]) {
    // yes!
    curl_times[curl] = now;
    curl_progress[curl] = p;
  } else {
    // timeout?
    if (now - curl_times[curl] > readwrite_timeout)
      return CURLE_ABORTED_BY_CALLBACK;
  }

  return 0;
}

static CURL* alloc_curl_handle() {
  CURL* curl;
  auto_lock lock(curl_handles_lock);
  if (curl_handles.size() == 0) {
    curl = curl_easy_init();
  } else {
    curl = curl_handles.top();
    curl_handles.pop();
  }
  curl_easy_reset(curl);
  long signal = 1;
  curl_easy_setopt(curl, CURLOPT_NOSIGNAL, signal);

//  long timeout = 3600;
//  curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout);

  //###long seconds = 10;
  curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, connect_timeout);

  curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0);
  curl_easy_setopt(curl, CURLOPT_PROGRESSFUNCTION, my_curl_progress);
  curl_easy_setopt(curl, CURLOPT_PROGRESSDATA, curl);
  time_t now = time(0);
  curl_times[curl] = now;
  curl_progress[curl] = progress_t(-1, -1);
  return curl;
}

static void return_curl_handle(CURL* curl_handle) {
  if (curl_handle != 0) {
    auto_lock lock(curl_handles_lock);
    curl_handles.push(curl_handle);
    curl_times.erase(curl_handle);
    curl_progress.erase(curl_handle);
  }
}

class auto_curl {
 public:
  auto_curl() : curl_handle(alloc_curl_handle()) { }

//  auto_curl(CURL* curl): curl(curl) {
////    auto_lock lock(curl_handles_lock);
////    if (curl_handles.size() == 0)
////      curl = curl_easy_init();
////    else {
////      curl = curl_handles.top();
////      curl_handles.pop();
////    }
////    curl_easy_reset(curl);
////    long seconds = 10;
////    //###curl_easy_setopt(curl, CURLOPT_TIMEOUT, seconds); // bad idea
////    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, seconds);
//  }
  ~auto_curl() {
    if (curl_handle != 0) {
      return_curl_handle(curl_handle);
//      auto_lock lock(curl_handles_lock);
//      curl_handles.push(curl);
    }
  }

  CURL* get() const { return curl_handle; }
//  CURL* release() {
//    CURL* tmp = curl;
//    curl = 0;
//    return tmp;
//  }
//  void reset(CURL* curl) {
//    if (curl != 0) {
//      auto_lock lock(curl_handles_lock);
//      curl_handles.push(curl);
//    }
//    this->curl = curl;
//  }
  operator CURL*() const { return curl_handle; }

 private:
  CURL* curl_handle;
};

struct curl_multi_remove_handle_functor {
  CURLM* multi_handle;
  curl_multi_remove_handle_functor(CURLM* multi_handle) : multi_handle(multi_handle) { }

  void operator()(CURL* curl_handle) {
    curl_multi_remove_handle(multi_handle, curl_handle);
    return_curl_handle(curl_handle);
  }
};

class auto_curl_multi {
 public:
  auto_curl_multi(): multi_handle(curl_multi_init()) { }
  ~auto_curl_multi() {
    curl_multi_cleanup(for_each(curl_handles.begin(), curl_handles.end(),
        curl_multi_remove_handle_functor(multi_handle)).multi_handle);
  }

  CURLM* get() const { return multi_handle; }

  void add_curl(CURL* curl_handle) {
    curl_handles.push_back(curl_handle);
    curl_multi_add_handle(multi_handle, curl_handle);
  }

 private:
  CURLM* multi_handle;
  vector<CURL*> curl_handles;
};

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

static string prepare_url(const char* url) {
  if(debug) syslog(LOG_DEBUG, "URL is %s", url);

  string url_str = str(url);
  string token =  str("/" + bucket);
  int bucket_pos = url_str.find(token);
  int bucket_size = token.size();

  int clipBy = 7;
  if(!strncasecmp(url_str.c_str(), "https://", 8)) {
    clipBy = 8;
  }
  url_str = url_str.substr(0, clipBy) + bucket + "." + url_str.substr(clipBy, bucket_pos - clipBy)
      + url_str.substr((bucket_pos + bucket_size));

  if(debug) syslog(LOG_DEBUG, "URL changed is %s", url_str.c_str());

  return str(url_str);
}

/**
 * @return fuse return code
 */
static int my_curl_easy_perform(CURL* curl, FILE* f = 0) {
  char* url = new char[128];
  curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL , &url);
  if(debug) syslog(LOG_DEBUG, "connecting to URL %s", url);

  // 1 attempt + retries...
  int t = retries + 1;
  while (t-- > 0) {
    if (f)
      rewind(f);
    CURLcode curlCode = curl_easy_perform(curl);
    if (curlCode == 0)
      return 0;
    if (curlCode == CURLE_OPERATION_TIMEDOUT) {
      syslog(LOG_ERR, "###timeout");
    } else if (curlCode == CURLE_HTTP_RETURNED_ERROR) {
      long responseCode;
      if (curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &responseCode) != 0)
        return -EIO;
      if (responseCode == 404)
        return -ENOENT;
        syslog(LOG_ERR, "###response=%ld", responseCode);

      if (responseCode < 500)
        return -EIO;
    } else {
      syslog(LOG_ERR, "###%s", curl_easy_strerror(curlCode));;
    }
    syslog(LOG_ERR, "###retrying...");
  }
  syslog(LOG_ERR, "###giving up");
  return -EIO;
}

/**
 * urlEncode a fuse path,
 * taking into special consideration "/",
 * otherwise regular urlEncode.
 */
string urlEncode(const string &s) {
  string result;
  for (unsigned i = 0; i < s.length(); ++i) {
    if (s[i] == '/') // Note- special case for fuse paths...
      result += s[i];
    else if (isalnum(s[i]))
      result += s[i];
    else if (s[i] == '.' || s[i] == '-' || s[i] == '*' || s[i] == '_')
      result += s[i];
    else if (s[i] == ' ')
      result += '+';
    else {
      result += "%";
      result += hexAlphabet[static_cast<unsigned char>(s[i]) / 16];
      result += hexAlphabet[static_cast<unsigned char>(s[i]) % 16];
    }
  }
  return result;
}

/**
 * Returns the current date
 * in a format suitable for a HTTP request header.
 */
string get_date() {
  char buf[100];
  time_t t = time(NULL);
  strftime(buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S GMT", gmtime(&t));
  return buf;
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
  BIO_write(b64, md, md_len);
  BIO_flush(b64);
  BUF_MEM *bptr;
  BIO_get_mem_ptr(b64, &bptr);

  Signature.resize(bptr->length - 1);
  memcpy(&Signature[0], bptr->data, bptr->length-1);

  BIO_free_all(b64);

  return Signature;
}

// libcurl callback
static size_t writeCallback(void* data, size_t blockSize, size_t numBlocks, void* userPtr) {
  string* userString = static_cast<string*>(userPtr);
  (*userString).append(reinterpret_cast<const char*>(data), blockSize*numBlocks);
  return blockSize * numBlocks;
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

  string resource(urlEncode(service_path + bucket + path));
  string url(host + resource);

  auto_curl curl;
  curl_easy_setopt(curl, CURLOPT_FAILONERROR, true);
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, true);
  curl_easy_setopt(curl, CURLOPT_NOBODY, true); // HEAD
  curl_easy_setopt(curl, CURLOPT_FILETIME, true); // Last-Modified

  headers_t responseHeaders;
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

  VERIFY(my_curl_easy_perform((curl.get())));

  // at this point we know the file exists in s3

  for (headers_t::iterator iter = responseHeaders.begin(); iter != responseHeaders.end(); ++iter) {
    string key = (*iter).first;
    string value = (*iter).second;
    if (key == "Content-Type")
      meta[key] = value;
    if (key == "ETag")
      meta[key] = value;
    if (key.substr(0, 5) == "x-amz")
      meta[key] = value;
  }

  return 0;
}

/**
 * get_local_fd
 */
int get_local_fd(const char* path) {
  string resource(urlEncode(service_path + bucket + path));
  string url(host + resource);

  string baseName = mybasename(path);
  string resolved_path(use_cache + "/" + bucket);

  int fd = -1;

  string cache_path(resolved_path + path);

  headers_t responseHeaders;

  if (use_cache.size() > 0) {
    VERIFY(get_headers(path, responseHeaders));

    fd = open(cache_path.c_str(), O_RDWR); // ### TODO should really somehow obey flags here

    if (fd != -1) {
      MD5_CTX c;
      if (MD5_Init(&c) != 1)
        Yikes(-EIO);
      int count;
      char buf[1024];
      while ((count = read(fd, buf, sizeof(buf))) > 0) {
        if (MD5_Update(&c, buf, count) != 1)
          Yikes(-EIO);
      }
      unsigned char md[MD5_DIGEST_LENGTH];
      if (MD5_Final(md, &c) != 1)
        Yikes(-EIO);

      char localMd5[2 * MD5_DIGEST_LENGTH+1];
      sprintf(localMd5, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
          md[0], md[1], md[2], md[3], md[4], md[5], md[6], md[7], md[8], md[9], md[10], md[11],
          md[12], md[13], md[14], md[15]);

      string remoteMd5(trim(responseHeaders["ETag"], "\""));

      // md5 match?
      if (string(localMd5) != remoteMd5) {
        // no! prepare to download
        if (close(fd) == -1)
          Yikes(-errno);
        fd = -1;
      }
    }
  }
  // need to download?
  if (fd == -1) {
    // yes!
    if (use_cache.size() > 0) {
      // only download files, not folders
      mode_t mode = strtoul(responseHeaders["x-amz-meta-mode"].c_str(), (char **)NULL, 10);
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

    if (fd == -1)
      Yikes(-errno);

    auto_curl curl;
    curl_easy_setopt(curl, CURLOPT_FAILONERROR, true);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, true);

    FILE* f = fdopen(fd, "w+");
    if (f == 0)
      Yikes(-errno);
    curl_easy_setopt(curl, CURLOPT_FILE, f);

    auto_curl_slist headers;
    string date = get_date();
    syslog(LOG_INFO, "LOCAL FD");
    headers.append("Date: " + date);
    headers.append("Content-Type: ");
    if (public_bucket.substr(0,1) != "1") {
      headers.append("Authorization: AWS " + AWSAccessKeyId + ":" +
        calc_signature("GET", "", date, headers.get(), resource));
    }
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers.get());

    cout << "downloading[path=" << path << "][fd=" << fd << "]" << endl;

    string my_url = prepare_url(url.c_str());
    curl_easy_setopt(curl, CURLOPT_URL, my_url.c_str());

    VERIFY(my_curl_easy_perform(curl.get(), f));

    //only one of these is needed...
    fflush(f);
    fsync(fd);

    if (fd == -1)
      Yikes(-errno);
  }

  return fd;
}

/**
 * create or update s3 meta
 * @return fuse return code
 */
static int put_headers(const char* path, headers_t meta) {
  string resource = urlEncode(service_path + bucket + path);
  string url = host + resource;

  auto_curl curl;
  curl_easy_setopt(curl, CURLOPT_FAILONERROR, true);
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, true);

  string responseText;
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseText);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);

  curl_easy_setopt(curl, CURLOPT_UPLOAD, true); // HTTP PUT
  curl_easy_setopt(curl, CURLOPT_INFILESIZE, 0); // Content-Length

  string ContentType = meta["Content-Type"];

  auto_curl_slist headers;
  string date = get_date();
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
    if (key == "x-amz-copy-source")
      headers.append(key + ":" + value);
  }

  if (use_rrs.substr(0,1) == "1") {
    headers.append("x-amz-storage-class:REDUCED_REDUNDANCY");
  }

  if (public_bucket.substr(0,1) != "1") {
    headers.append("Authorization: AWS " + AWSAccessKeyId + ":" +
      calc_signature("PUT", ContentType, date, headers.get(), resource));
  }
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers.get());

  //###rewind(f);

  syslog(LOG_INFO, "copy path=%s", path);
  cout << "copying[path=" << path << "]" << endl;

  string my_url = prepare_url(url.c_str());
  curl_easy_setopt(curl, CURLOPT_URL, my_url.c_str());

  VERIFY(my_curl_easy_perform(curl.get()));

  return 0;
}

/**
 * create or update s3 object
 * @return fuse return code
 */
static int put_local_fd(const char* path, headers_t meta, int fd) {
  string resource = urlEncode(service_path + bucket + path);
  string url = host + resource;

  struct stat st;
  if (fstat(fd, &st) == -1)
    Yikes(-errno);

  auto_curl curl;
  curl_easy_setopt(curl, CURLOPT_FAILONERROR, true);
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, true);

  string responseText;
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseText);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);

  curl_easy_setopt(curl, CURLOPT_UPLOAD, true); // HTTP PUT
  curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, static_cast<curl_off_t>(st.st_size)); // Content-Length

  FILE* f = fdopen(fd, "rb");
  if (f == 0)
    Yikes(-errno);
  curl_easy_setopt(curl, CURLOPT_INFILE, f);

  string ContentType = meta["Content-Type"];

  auto_curl_slist headers;
  string date = get_date();
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

  if (use_rrs.substr(0,1) == "1") {
    headers.append("x-amz-storage-class:REDUCED_REDUNDANCY");
  }
  
  if (public_bucket.substr(0,1) != "1") {
    headers.append("Authorization: AWS " + AWSAccessKeyId + ":" +
      calc_signature("PUT", ContentType, date, headers.get(), resource));
  }
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers.get());

  //###rewind(f);

  syslog(LOG_INFO, "upload path=%s size=%llu", path, st.st_size);
  cout << "uploading[path=" << path << "][fd=" << fd << "][size="<<st.st_size <<"]" << endl;

  string my_url = prepare_url(url.c_str());
  curl_easy_setopt(curl, CURLOPT_URL, my_url.c_str());

  VERIFY(my_curl_easy_perform(curl.get(), f));

  return 0;
}

static int s3fs_getattr(const char *path, struct stat *stbuf) {
  cout << "getattr[path=" << path << "]" << endl;
  memset(stbuf, 0, sizeof(struct stat));
  if (strcmp(path, "/") == 0) {
    stbuf->st_nlink = 1; // see fuse faq
    stbuf->st_mode = root_mode | S_IFDIR;
    return 0;
  }

  {
    auto_lock lock(stat_cache_lock);
    stat_cache_t::iterator iter = stat_cache.find(path);
    if (iter != stat_cache.end()) {
      *stbuf = (*iter).second;
      stat_cache.erase(path);
      return 0;
    }
  }

  string resource = urlEncode(service_path + bucket + path);
  string url = host + resource;

  auto_curl curl;
  curl_easy_setopt(curl, CURLOPT_FAILONERROR, true);
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, true);
  curl_easy_setopt(curl, CURLOPT_NOBODY, true); // HEAD
  curl_easy_setopt(curl, CURLOPT_FILETIME, true); // Last-Modified

  headers_t responseHeaders;
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

  VERIFY(my_curl_easy_perform(curl.get()));

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

  return 0;
}

static int s3fs_readlink(const char *path, char *buf, size_t size) {
  if (size > 0) {
    --size; // reserve nil terminator

    cout << "readlink[path=" << path << "]" << endl;

    auto_fd fd(get_local_fd(path));

    struct stat st;
    if (fstat(fd.get(), &st) == -1)
      Yikes(-errno);

    if (st.st_size < size)
      size = st.st_size;

    if (pread(fd.get(), buf, size, 0) == -1)
      Yikes(-errno);

    buf[size] = 0;
  }

  return 0;
}

struct case_insensitive_compare_func {
  bool operator ()(const string &a, const string &b) {
    return strcasecmp(a.c_str(), b.c_str()) < 0;
  }
};

typedef map<string, string, case_insensitive_compare_func> mimes_t;

static mimes_t mimeTypes;

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
  if (last_pos == string::npos) {
     return result;
  }

  // extract the last extension
  if (last_pos != string::npos) {
    ext = s.substr(1+last_pos, string::npos);
  }

   
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
  if (first_pos == last_pos) {
     return result;
  }

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

static int s3fs_mknod(const char *path, mode_t mode, dev_t rdev) {
  // see man 2 mknod
  // If pathname already exists, or is a symbolic link, this call fails with an EEXIST error.
  cout << "mknod[path=" << path << "][mode=" << mode << "]" << endl;

  string resource = urlEncode(service_path + bucket + path);
  string url = host + resource;

  auto_curl curl;
  curl_easy_setopt(curl, CURLOPT_FAILONERROR, true);
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, true);
  curl_easy_setopt(curl, CURLOPT_UPLOAD, true); // HTTP PUT
  curl_easy_setopt(curl, CURLOPT_INFILESIZE, 0); // Content-Length: 0

  auto_curl_slist headers;
  string date = get_date();
  headers.append("Date: " + date);
  string contentType(lookupMimeType(path));
  headers.append("Content-Type: " + contentType);
  // x-amz headers: (a) alphabetical order and (b) no spaces after colon
  headers.append("x-amz-acl:" + default_acl);
  headers.append("x-amz-meta-gid:" + str(getgid()));
  headers.append("x-amz-meta-mode:" + str(mode));
  headers.append("x-amz-meta-mtime:" + str(time(NULL)));
  headers.append("x-amz-meta-uid:" + str(getuid()));
  if (public_bucket.substr(0,1) != "1") {
    headers.append("Authorization: AWS " + AWSAccessKeyId + ":" +
      calc_signature("PUT", contentType, date, headers.get(), resource));
  }
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers.get());

  string my_url = prepare_url(url.c_str());
  curl_easy_setopt(curl, CURLOPT_URL, my_url.c_str());

  VERIFY(my_curl_easy_perform(curl.get()));

  return 0;
}

static int s3fs_mkdir(const char *path, mode_t mode) {
  cout << "mkdir[path=" << path << "][mode=" << mode << "]" << endl;

  string resource = urlEncode(service_path + bucket + path);
  string url = host + resource;

  auto_curl curl;
  curl_easy_setopt(curl, CURLOPT_FAILONERROR, true);
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, true);
  curl_easy_setopt(curl, CURLOPT_UPLOAD, true); // HTTP PUT
  curl_easy_setopt(curl, CURLOPT_INFILESIZE, 0); // Content-Length: 0

  auto_curl_slist headers;
  string date = get_date();
  headers.append("Date: " + date);
  headers.append("Content-Type: application/x-directory");
  // x-amz headers: (a) alphabetical order and (b) no spaces after colon
  headers.append("x-amz-acl:" + default_acl);
  headers.append("x-amz-meta-gid:" + str(getgid()));
  headers.append("x-amz-meta-mode:" + str(mode));
  headers.append("x-amz-meta-mtime:" + str(time(NULL)));
  headers.append("x-amz-meta-uid:" + str(getuid()));
  if (public_bucket.substr(0,1) != "1") {
    headers.append("Authorization: AWS " + AWSAccessKeyId + ":" +
      calc_signature("PUT", "application/x-directory", date, headers.get(), resource));
  }
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers.get());

  string my_url = prepare_url(url.c_str());
  curl_easy_setopt(curl, CURLOPT_URL, my_url.c_str());

  VERIFY(my_curl_easy_perform(curl.get()));

  return 0;
}

// aka rm
static int s3fs_unlink(const char *path) {
  cout << "unlink[path=" << path << "]" << endl;

  string resource = urlEncode(service_path + bucket + path);
  string url = host + resource;

  auto_curl curl;
  curl_easy_setopt(curl, CURLOPT_FAILONERROR, true);
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, true);
  curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");

  auto_curl_slist headers;
  string date = get_date();
  headers.append("Date: " + date);
  headers.append("Content-Type: ");
  if (public_bucket.substr(0,1) != "1") {
    headers.append("Authorization: AWS " + AWSAccessKeyId + ":" +
      calc_signature("DELETE", "", date, headers.get(), resource));
  }
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers.get());

  string my_url = prepare_url(url.c_str());
  curl_easy_setopt(curl, CURLOPT_URL, my_url.c_str());

  VERIFY(my_curl_easy_perform(curl.get()));

  return 0;
}

static int s3fs_rmdir(const char *path) {
   cout << "rmdir[path=" << path << "]" << endl;
 
   // need to check if the directory is empty
   {
      string responseText;
      string resource = urlEncode(service_path + bucket);
      string query = "delimiter=/&prefix=";

      if (strcmp(path, "/") != 0)
       query += urlEncode(string(path).substr(1) + "/");

      query += "&max-keys=50";

      string url = host + resource + "?"+ query;

      auto_curl curl;
      string my_url = prepare_url(url.c_str());
      curl_easy_setopt(curl, CURLOPT_URL, my_url.c_str());
      curl_easy_setopt(curl, CURLOPT_FAILONERROR, true);
      curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, true);
      curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseText);
      curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);

      auto_curl_slist headers;
      string date = get_date();
      headers.append("Date: " + date);
      headers.append("ContentType: ");
      if (public_bucket.substr(0,1) != "1") {
        headers.append("Authorization: AWS " + AWSAccessKeyId + ":" +
          calc_signature("GET", "", date, headers.get(), resource + "/"));
      }

      curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers.get());

      VERIFY(my_curl_easy_perform(curl.get()));

      cout << endl << responseText << endl;
      if (responseText.find ("<CommonPrefixes>") != std::string::npos ||
          responseText.find ("<ETag>") != std::string::npos ) {
        // directory is not empty
        cout << "[path=" << path << "] not empty" << endl;
        return -ENOTEMPTY;
      }
   }
   // delete the directory
  string resource = urlEncode(service_path + bucket + path);
  string url = host + resource;

  auto_curl curl;
  curl_easy_setopt(curl, CURLOPT_FAILONERROR, true);
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, true);
  curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");

  auto_curl_slist headers;
  string date = get_date();
  headers.append("Date: " + date);
  headers.append("Content-Type: ");
  if (public_bucket.substr(0,1) != "1") {
    headers.append("Authorization: AWS " + AWSAccessKeyId + ":" +
      calc_signature("DELETE", "", date, headers.get(), resource));
  }
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers.get());

  string my_url = prepare_url(url.c_str());
  curl_easy_setopt(curl, CURLOPT_URL, my_url.c_str());

  VERIFY(my_curl_easy_perform(curl.get()));

  return 0;
}

static int s3fs_symlink(const char *from, const char *to) {
  cout << "symlink[from=" << from << "][to=" << to << "]" << endl;

  headers_t headers;
  headers["x-amz-meta-mode"] = str(S_IFLNK);
  headers["x-amz-meta-mtime"] = str(time(NULL));

  auto_fd fd(fileno(tmpfile()));

  if (pwrite(fd.get(), from, strlen(from), 0) == -1)
    Yikes(-errno);

  VERIFY(put_local_fd(to, headers, fd.get()));

  return 0;
}

static int s3fs_rename(const char *from, const char *to) {
  cout << "rename[from=" << from << "][to=" << to << "]" << endl;

  // preserve meta headers across rename
  headers_t meta;
  VERIFY(get_headers(from, meta));

  meta["x-amz-copy-source"] = urlEncode("/" + bucket + from);

  meta["Content-Type"] = lookupMimeType(to);
  meta["x-amz-metadata-directive"] = "REPLACE";

  int result = put_headers(to, meta);
  if (result != 0)
    return result;

  return s3fs_unlink(from);
}

static int s3fs_link(const char *from, const char *to) {
  cout << "link[from=" << from << "][to=" << to << "]" << endl;
  return -EPERM;
}

static int s3fs_chmod(const char *path, mode_t mode) {
  cout << "chmod[path=" << path << "][mode=" << mode << "]" << endl;
  headers_t meta;
  VERIFY(get_headers(path, meta));
  meta["x-amz-meta-mode"] = str(mode);
  meta["x-amz-copy-source"] = urlEncode("/" + bucket + path);
  meta["x-amz-metadata-directive"] = "REPLACE";
  return put_headers(path, meta);
}


static int s3fs_chown(const char *path, uid_t uid, gid_t gid) {
  cout << "chown[path=" << path << "]" << endl;

  headers_t meta;
  VERIFY(get_headers(path, meta));

  struct passwd* aaa = getpwuid(uid);
  if (aaa != 0)
    meta["x-amz-meta-uid"] = str((*aaa).pw_uid);

  struct group* bbb = getgrgid(gid);
  if (bbb != 0)
    meta["x-amz-meta-gid"] = str((*bbb).gr_gid);

  meta["x-amz-copy-source"] = urlEncode("/" + bucket + path);
  meta["x-amz-metadata-directive"] = "REPLACE";
  return put_headers(path, meta);
}

static int s3fs_truncate(const char *path, off_t size) {
  //###TODO honor size?!?

  cout << "truncate[path=" << path << "][size=" << size << "]" << endl;

  // preserve headers across truncate
  headers_t meta;
  VERIFY(get_headers(path, meta));
  auto_fd fd(fileno(tmpfile()));
  //###verify fd here?!?
  VERIFY(put_local_fd(path, meta, fd.get()));

  return 0;
}

static int s3fs_open(const char *path, struct fuse_file_info *fi) {
    cout << "open[path=" << path << "][flags=" << fi->flags << "]" <<  endl;

  headers_t meta;
  //###TODO check fi->fh here...
  fi->fh = get_local_fd(path);

  // remember flags and headers...
  auto_lock lock(s3fs_descriptors_lock);

  s3fs_descriptors[fi->fh] = fi->flags;

  return 0;
}

static int s3fs_read(
    const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
  //###cout << "read: " << path << endl;
  int res = pread(fi->fh, buf, size, offset);
  if (res == -1)
    Yikes(-errno);
  return res;
}

static int s3fs_write(
    const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {

  //###cout << "write: " << path << endl;
  int res = pwrite(fi->fh, buf, size, offset);
  if (res == -1)
    Yikes(-errno);
  return res;
}

static int s3fs_statfs(const char *path, struct statvfs *stbuf) {
  // 256T
  stbuf->f_bsize = 0X1000000;
  stbuf->f_blocks = 0X1000000;
  stbuf->f_bfree = 0x1000000;
  stbuf->f_bavail = 0x1000000;
  return 0;
}

static int get_flags(int fd) {
  auto_lock lock(s3fs_descriptors_lock);
  return s3fs_descriptors[fd];
}

static int s3fs_flush(const char *path, struct fuse_file_info *fi) {
  int fd = fi->fh;
  cout << "flush[path=" << path << "][fd=" << fd << "]" << endl;
  // NOTE- fi->flags is not available here
  int flags = get_flags(fd);
  if ((flags & O_RDWR) || (flags &  O_WRONLY)) {
    headers_t meta;
    VERIFY(get_headers(path, meta));
    meta["x-amz-meta-mtime"] = str(time(NULL));
    return put_local_fd(path, meta, fd);
  }
  return 0;
}

static int s3fs_release(const char *path, struct fuse_file_info *fi) {
  int fd = fi->fh;
  cout << "release[path=" << path << "][fd=" << fd << "]" << endl;
  if (close(fd) == -1)
    Yikes(-errno);
  return 0;
}

time_t my_timegm (struct tm *tm) {
  time_t ret;
  char *tz;

  tz = getenv("TZ");
  setenv("TZ", "", 1);
  tzset();
  ret = mktime(tm);
  if (tz)
    setenv("TZ", tz, 1);
  else
    unsetenv("TZ");
  tzset();
  return ret;
}

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

static int s3fs_readdir(
    const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi) {
  //cout << "readdir:"<< " path="<< path << endl;

  string NextMarker;
  string IsTruncated("true");

  while (IsTruncated == "true") {
    string responseText;
    string resource = urlEncode(service_path + bucket); // this is what gets signed
    string query = "delimiter=/&prefix=";

    if (strcmp(path, "/") != 0)
      query += urlEncode(string(path).substr(1) + "/");

    if (NextMarker.size() > 0)
      query += "&marker=" + urlEncode(NextMarker);

    query += "&max-keys=50";

    string url = host + resource + "?" + query;

    {
      auto_curl curl;
      string my_url = prepare_url(url.c_str());

      curl_easy_setopt(curl, CURLOPT_URL, my_url.c_str());
      curl_easy_setopt(curl, CURLOPT_FAILONERROR, true);
      curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, true);
      curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseText);
      curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);

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


      VERIFY(my_curl_easy_perform(curl.get()));
    }

    auto_stuff curlMap;
    auto_curl_multi multi_handle;

//    long max_connects = 5;
//    curl_multi_setopt(multi_handle.get(), CURLMOPT_MAXCONNECTS, max_connects);

    {
      xmlDocPtr doc = xmlReadMemory(responseText.c_str(), responseText.size(), "", NULL, 0);
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

              if (Key.size() > 0) {
                if (filler(buf, mybasename(Key).c_str(), 0, 0))
                  break;

                CURL* curl_handle = alloc_curl_handle();

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
                curl_easy_setopt(curl_handle, CURLOPT_FAILONERROR, true);
                curl_easy_setopt(curl_handle, CURLOPT_FOLLOWLOCATION, true);
                curl_easy_setopt(curl_handle, CURLOPT_NOBODY, true); // HEAD
                curl_easy_setopt(curl_handle, CURLOPT_FILETIME, true); // Last-Modified

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
                multi_handle.add_curl(curl_handle);
              }
            }
          }
        }
      }
      xmlFreeDoc(doc);
    }

    int running_handles;

    while (curl_multi_perform(multi_handle.get(), &running_handles) == CURLM_CALL_MULTI_PERFORM);

    while (running_handles) {
      fd_set read_fd_set;
      fd_set write_fd_set;
      fd_set exc_fd_set;

      FD_ZERO(&read_fd_set);
      FD_ZERO(&write_fd_set);
      FD_ZERO(&exc_fd_set);

      long milliseconds;
      VERIFY(curl_multi_timeout(multi_handle.get(), &milliseconds));
      if (milliseconds < 0)
        milliseconds = 50;
      if (milliseconds > 0) {
        struct timeval timeout;
        timeout.tv_sec = 1000 * milliseconds / 1000000;
        timeout.tv_usec = 1000 * milliseconds % 1000000;

        int max_fd;
        VERIFY(curl_multi_fdset(
            multi_handle.get(), &read_fd_set, &write_fd_set, &exc_fd_set, &max_fd));

        if (select(max_fd + 1, &read_fd_set, &write_fd_set, &exc_fd_set, &timeout) == -1)
          Yikes(-errno);
      }

      while (curl_multi_perform(multi_handle.get(), &running_handles) == CURLM_CALL_MULTI_PERFORM);
    }

    int remaining_msgs = 1;
    while (remaining_msgs) {
      // this next line pegs cpu for directories w/lotsa files
      CURLMsg* msg = curl_multi_info_read(multi_handle.get(), &remaining_msgs);
        if (msg != NULL) {
          CURLcode code =msg->data.result;
          if (code != 0)
            syslog(LOG_ERR, "###%d %s", code, curl_easy_strerror(code));
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
              if (ContentType)
                st.st_mode |= strcmp(ContentType, "application/x-directory") == 0 ? S_IFDIR : S_IFREG;
            }
            // mtime
            st.st_mtime = strtoul
                ((*stuff.responseHeaders)["x-amz-meta-mtime"].c_str(), (char **)NULL, 10);
            if (st.st_mtime == 0) {
              long LastModified;
              if (curl_easy_getinfo(curl_handle, CURLINFO_FILETIME, &LastModified) == 0)
                st.st_mtime = LastModified;
            }
            // size
            double ContentLength;
            if (curl_easy_getinfo(curl_handle, CURLINFO_CONTENT_LENGTH_DOWNLOAD, &ContentLength) == 0)
              st.st_size = static_cast<off_t>(ContentLength);
            // blocks
            if (S_ISREG(st.st_mode))
              st.st_blocks = st.st_size / 512 + 1;

            st.st_uid = strtoul((*stuff.responseHeaders)["x-amz-meta-uid"].c_str(), (char **)NULL, 10);
            st.st_gid = strtoul((*stuff.responseHeaders)["x-amz-meta-gid"].c_str(), (char **)NULL, 10);

            auto_lock lock(stat_cache_lock);
            stat_cache[stuff.path] = st;
        }
      }
    }

  } // IsTruncated

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
static unsigned long id_function(void)
{
  return ((unsigned long) pthread_self());
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
  return 0;
}

static void s3fs_destroy(void*) {
  syslog(LOG_INFO, "destroy");
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
  //###cout << "###access[path=" << path << "]" <<  endl;
  return 0;
}

// aka touch
static int s3fs_utimens(const char *path, const struct timespec ts[2]) {
  cout << "utimens[path=" << path << "][mtime=" << str(ts[1].tv_sec) << "]" << endl;
  headers_t meta;
  VERIFY(get_headers(path, meta));
  meta["x-amz-meta-mtime"] = str(ts[1].tv_sec);
  meta["x-amz-copy-source"] = urlEncode("/" + bucket + path);
  meta["x-amz-metadata-directive"] = "REPLACE";
  return put_headers(path, meta);
}

///////////////////////////////////////////////////////////
// s3fs_check_service
//
// Preliminary check on credentials and bucket
// If the network is up when s3fs is started and the
// bucket is not a public bucket, then connect to S3 service
// with the bucket's credentials.  This will indicate if
// the credentials are valid or not.  If the connection
// is successful, then check the list of available buckets
// against the bucket name that we are trying to mount.
//
// This function either just returns (in cases where the
// network is unavailable, a public bucket, etc...) of
// exits with an error message (where the connection is
// successful, but returns an error code or if the bucket
// isn't found in the service).
////////////////////////////////////////////////////////////
static void s3fs_check_service(void) {
  // cout << "s3fs_check_service" << endl;

  string responseText;
  long responseCode;
  
  string resource = "/";
  string url = host + resource;

  auto_curl curl;
  // curl_easy_setopt(curl, CURLOPT_VERBOSE, true);
  curl_easy_setopt(curl, CURLOPT_FAILONERROR, true);
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, true);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseText);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
  curl_easy_setopt(curl, CURLOPT_URL, url.c_str());


  auto_curl_slist headers;
  string date = get_date();
  headers.append("Date: " + date);
  if (public_bucket.substr(0,1) != "1") {
    headers.append("Authorization: AWS " + AWSAccessKeyId + ":" +
      calc_signature("GET", "", date, headers.get(), resource));
  } else {
     // This operation is only valid if done by an authenticated sender
     return;
  }
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers.get());

  // Need to know if the curl response is just a timeout possibly
  // indicating the the network is down or if the connection was
  // acutally made - my_curl_easy_perform doesn't differentiate
  // between the two

  CURLcode curlCode;

  int t = retries + 1;
  while (t-- > 0) {
    curlCode = curl_easy_perform(curl.get());
    if (curlCode == 0) {
      break;
    }
    if (curlCode != CURLE_OPERATION_TIMEDOUT) {
      if (curlCode == CURLE_HTTP_RETURNED_ERROR) {
         break;
      } else {
         // Unknown error - log it and return
         syslog(LOG_ERR, "curlCode: %i  msg: %s", curlCode, curl_easy_strerror(curlCode));;
         return;
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
  if (curlCode == CURLE_OPERATION_TIMEDOUT) {
     return;
  }

  curl_easy_getinfo(curl.get(), CURLINFO_RESPONSE_CODE, &responseCode);
  if(debug) syslog(LOG_DEBUG, "responseCode: %i\n", (int)responseCode);

  // Connection was made, but there is a HTTP error
  if (curlCode == CURLE_HTTP_RETURNED_ERROR) {
     if (responseCode == 403) {
       fprintf (stderr, "%s: HTTP: 403 Forbidden - it is likely that your credentials are invalid\n", 
         program_name.c_str());
       exit(1);
     }
     fprintf (stderr, "%s: HTTP: %i - report this to the s3fs developers\n", 
       program_name.c_str(), (int)responseCode);
     exit(1);
  }

  // Success
  if (responseCode != 200) {
     if(debug) syslog(LOG_DEBUG, "responseCode: %i\n", (int)responseCode);
     return;
  }

  // Parse the return info and see if the bucket is available  

  xmlDocPtr doc = xmlReadMemory(responseText.c_str(), responseText.size(), "", NULL, 0);
  if (doc == NULL) {
     return;
  } 
  if (doc->children == NULL) {
     xmlFreeDoc(doc);
     return;
  }


  bool bucketFound = 0;
  bool matchFound = 0;

  // Parse the XML looking for the bucket names

  for (xmlNodePtr cur_node = doc->children->children; 
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
    exit(1);
  }

  if (matchFound == 0) {
    fprintf (stderr, "%s: bucket \"%s\" is not part of the service specified by the credentials\n", 
        program_name.c_str(), bucket.c_str());
    exit(1);
  }

  // cout << "responseText: " << responseText << endl;

  return;
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
    exit(1);
  } 

  // return error if any file has others permissions 
  if ((info.st_mode & S_IROTH) ||
      (info.st_mode & S_IWOTH) || 
      (info.st_mode & S_IXOTH))  {
    fprintf (stderr, "%s: credentials file %s should not have others permissions\n", 
        program_name.c_str(), passwd_file.c_str());
    exit(1);
  }

  // Any local file should not have any group permissions 
  if (passwd_file != "/etc/passwd-s3fs") {
    if ((info.st_mode & S_IRGRP) ||
        (info.st_mode & S_IWGRP) || 
        (info.st_mode & S_IXGRP))  {
      fprintf (stderr, "%s: credentials file %s should not have group permissions\n", 
        program_name.c_str(), passwd_file.c_str());
      exit(1);
    }
  }

  // check for owner execute permissions?

  // /etc/passwd-s3fs can have group permissions 

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

  // if you got here, the password file
  // exists and is readable by the
  // current user, check for permissions
  check_passwd_file_perms();

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
        exit(1);
      }

      first_pos = line.find_first_of(":");
      if (first_pos == string::npos) {
        printf ("%s: invalid line in passwd file, no \":\" separator found\n", 
           program_name.c_str());
        exit(1);
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
          exit(1);
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
      exit(1);
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
      exit(1);
    }
    AWSAccessKeyId.assign(AWSACCESSKEYID);
    AWSSecretAccessKey.assign(AWSSECRETACCESSKEY);
    return;
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
  exit(1);
}

static void show_usage (void) {
  printf("Usage: %s BUCKET MOUNTPOINT [OPTION]...\n",
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
    "   All s3fs options must given in the form where \"opt\" is:\n"
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
    "   connect_timeout (default=\"2\" seconds)\n"
    "      - time to wait for connection before giving up\n"
    "\n"
    "   readwrite_timeout (default=\"10\" seconds)\n"
    "      - time to wait between read/write activity before giving up\n"
    "\n"
    "   url (default=\"http://s3.amazonaws.com\")\n"
    "      - sets the url to use to access amazon s3\n"
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
    "\n"
    "\n"
    "Report bugs to <s3fs-devel@googlegroups.com>\n"
    "s3fs home page: <http://code.google.com/p/s3fs/>\n"
  );
  exit(0);
}

static void show_version(void) {
  printf(
  "Amazon Simple Storage Service File System %s\n"
  "Copyright (C) 2010 Randy Rizun <rrizun@gmail.com>\n"
  "License GPL2: GNU GPL version 2 <http://gnu.org/licenses/gpl.html>\n"
  "This is free software: you are free to change and redistribute it.\n"
  "There is NO WARRANTY, to the extent permitted by law.\n",
  VERSION );
  exit(0);
}

// This function gets called repeatedly by the
// fuse option parser
static int my_fuse_opt_proc(void *data, const char *arg, int key, struct fuse_args *outargs) {

  if (key == FUSE_OPT_KEY_NONOPT) {
    // tricky way to set the bucket name
    // the first plain option is assumed to be
    // the bucket
    if (bucket.size() == 0) {
      bucket = arg;
      return 0;
    } else {
      struct stat buf;
      if (mountpoint.size() != 0) {
         fprintf(stderr, "%s: argument MOUNTPOINT %s was all ready provided, %s is an invalid option\n",
                 program_name.c_str(), mountpoint.c_str(), arg);
         show_usage();
         exit(1);
      }
      // record the mountpoint
      mountpoint = arg;
      // it is the mountpoint...do some error checking, fuse will do more for us later
      if (stat(arg, &buf) != -1) {
        int isempty = 1;
        // record mode for later usage
        root_mode = buf.st_mode;
        
        if (!(S_ISDIR( buf.st_mode ))) {
          fprintf(stderr, "%s: MOUNTPOINT: %s is not a directory\n", 
                  program_name.c_str(), mountpoint.c_str());
          exit(1);
        } else {
          struct dirent *ent;
          DIR *dp = opendir(mountpoint.c_str());
          if (dp == NULL) {
            fprintf(stderr, "%s: failed to open MOUNTPOINT: %s for reading, error: %s\n", 
                    program_name.c_str(), mountpoint.c_str(), strerror(errno));
            exit(1); 
          }
          while ((ent = readdir(dp)) != NULL) {
            if (strcmp(ent->d_name, ".") != 0 && strcmp(ent->d_name, "..") != 0) {
              isempty = 0;
              break;
            }
          }
          closedir(dp);
          if (!isempty) {
            fprintf(stderr, "%s: MOUNTPOINT directory %s is not empty\n", 
                    program_name.c_str(), mountpoint.c_str());
            exit(1);
          }
        }
      } else {
         fprintf(stderr, "%s: accessing MOUNTPOINT %s had an error: %s\n", 
                 program_name.c_str(), mountpoint.c_str(), strerror(errno));
         exit(1);
      }
    }
  }

  if (key == FUSE_OPT_KEY_OPT) {
    if (strstr(arg, "accessKeyId=") != 0) {
      fprintf(stderr, "%s: option accessKeyId is no longer supported\n", 
              program_name.c_str());
      exit(1);
    }
    if (strstr(arg, "secretAccessKey=") != 0) {
      fprintf(stderr, "%s: option secretAccessKey is no longer supported\n", 
              program_name.c_str());
      exit(1);
    }
    if (strstr(arg, "default_acl=") != 0) {
      default_acl = strchr(arg, '=') + 1;
      return 0;
    }
    // ### TODO: prefix
    if (strstr(arg, "retries=") != 0) {
      retries = atoi(strchr(arg, '=') + 1);
      return 0;
    }
    if (strstr(arg, "use_cache=") != 0) {
      use_cache = strchr(arg, '=') + 1;
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
         exit(1);
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
         exit(1);
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
    if (strstr(arg, "url=") != 0) {
      host = strchr(arg, '=') + 1;
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
  }
  return 1;
}



int main(int argc, char *argv[]) {

  int ch;
  int option_index = 0; 

  static const struct option long_opts[] = {
    {"help",    no_argument, NULL, 'h'},
    {"version", no_argument, 0, 0},
    {"debug",   no_argument, NULL, 'd'},
    {0, 0, 0, 0}};

   // get progam name - emulate basename 
   size_t found;
   program_name.assign(argv[0]);
   found = program_name.find_last_of("/");
   if(found != string::npos) {
      program_name.replace(0, found+1, "");
   }

   while ((ch = getopt_long(argc, argv, "dho:f", long_opts, &option_index)) != -1) {
     switch (ch) {
     case 0:
       if (strcmp(long_opts[option_index].name, "version") == 0) {
          show_version();
       }
       break;

     case 'h':
       show_help();
       break;

     case 'o':
       break;

     case 'd':
       break;

     case 'f':
       break;

     default:
       exit(1);
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
    exit(1);
  }

  // bucket names cannot contain upper case characters
  if (lower(bucket) != bucket) {
    fprintf(stderr, "%s: BUCKET %s, upper case characters are not supported\n",
      program_name.c_str(), bucket.c_str());
    exit(1);
  }

  // The second plain argument is the mountpoint
  // if the option was given, we all ready checked for a
  // readable, non-empty directory, this checks determines
  // if the mountpoint option was ever supplied
  if (mountpoint.size() == 0) {
    fprintf(stderr, "%s: missing MOUNTPOINT argument\n", program_name.c_str());
    show_usage();
    exit(1);
  }

  // error checking of command line arguments for compatability
  if ((AWSSecretAccessKey.size() > 0 && AWSAccessKeyId.size() == 0) ||
      (AWSSecretAccessKey.size() == 0 && AWSAccessKeyId.size() > 0)) {
    fprintf(stderr, "%s: if one access key is specified, both keys need to be specified\n",
      program_name.c_str());
    exit(1);
  }

  if (public_bucket.substr(0,1) == "1" && 
       (AWSSecretAccessKey.size() > 0 || AWSAccessKeyId.size() > 0)) {
    fprintf(stderr, "%s: specifying both public_bucket and the access keys options is invalid\n",
      program_name.c_str());
    exit(1);
  }

  if (passwd_file.size() > 0 && 
       (AWSSecretAccessKey.size() > 0 || AWSAccessKeyId.size() > 0)) {
    fprintf(stderr, "%s: specifying both passwd_file and the access keys options is invalid\n",
      program_name.c_str());
    exit(1);
  }
  
  if (public_bucket.substr(0,1) != "1") {
     get_access_keys();
     if(AWSSecretAccessKey.size() == 0 || AWSAccessKeyId.size() == 0) {
        fprintf(stderr, "%s: could not establish security credentials, check documentation\n",
         program_name.c_str());
        exit(1);
     }
     // More error checking on the access key pair can be done
     // like checking for appropriate lengths and characters  
  }

  // There's room for more command line error checking



  // Does the bucket exist?
  // if the network is up, check for valid
  // credentials and if the bucket exixts
  // skip check if mounting a public bucket
  if (public_bucket.substr(0,1) != "1") {
     s3fs_check_service();
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

  // now passing things off to fuse, fuse will finish evaluating the command line args
  return fuse_main(custom_args.argc, custom_args.argv, &s3fs_oper, NULL);
}
