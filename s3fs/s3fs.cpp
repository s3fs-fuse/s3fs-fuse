/*
 * s3fs - FUSE filesystem backed by Amazon S3
 * 
 * Copyright 2007 Randy Rizun <rrizun@gmail.com>
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

#define FUSE_USE_VERSION 26

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#include <libgen.h>
#include <pthread.h>
#include <curl/curl.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <stack>
#include <string>
#include <vector>
using namespace std;

#define Oof(result) if (true) { \
	cout << __LINE__ << "###result=" << result << endl; \
	return result; \
}

class auto_lock {
	pthread_mutex_t& lock;
public:
	auto_lock(pthread_mutex_t& lock): lock(lock) {
		pthread_mutex_lock(&lock);
	}
	~auto_lock() {
		pthread_mutex_unlock(&lock);
	}
};

stack<CURL*> curl_handles;
static pthread_mutex_t curl_handles_lock;

class auto_curl {
	CURL* curl;
public:
	auto_curl() {
		auto_lock lock(curl_handles_lock);
		if (curl_handles.size() == 0)
			curl = curl_easy_init();
		else {
			curl = curl_handles.top();
			curl_handles.pop();
		}
		curl_easy_reset(curl);
		long seconds = 10;
		curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, seconds);
	}
	~auto_curl() {
		if (curl != 0) {
			auto_lock lock(curl_handles_lock);
			curl_handles.push(curl);
		}
	}
	CURL* get() const {
		return curl;
	}
//	CURL* release() {
//		CURL* tmp = curl;
//		curl = 0;
//		return tmp;
//	}
//	void reset(CURL* curl) {
//		if (curl != 0) {
//			auto_lock lock(curl_handles_lock);
//			curl_handles.push(curl);
//		}
//		this->curl = curl;
//	}
	operator CURL*() const {
		return curl;
	}
};

class auto_curl_slist {
	struct curl_slist* slist;
public:
	auto_curl_slist(): slist(0) {
	}
	~auto_curl_slist() {
		curl_slist_free_all(slist);
	}
	struct curl_slist* get() const {
		return slist;
	}
	void append(const string& s) {
		slist = curl_slist_append(slist, s.c_str());
	}
};

// ### TODO replace this with a plain 'ol function (or a method on auto_curl)
#define MY_CURL_EASY_PERFORM(curl) \
if (true) { \
	CURLcode curlCode = curl_easy_perform(curl.get()); \
	if (curlCode == CURLE_OPERATION_TIMEDOUT) \
		curlCode = curl_easy_perform(curl.get()); \
	if (curlCode != 0) { \
		long responseCode; \
		if (curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &responseCode) != 0) \
			Oof(-EIO); \
		if (responseCode == 500) { \
			cout << __LINE__ << "###curlCode=" << curlCode << "(" << curl_easy_strerror(curlCode) << ")" << "###responseCode=" << responseCode << endl; \
			cout << "retrying..." << endl; \
			curlCode = curl_easy_perform(curl.get()); \
			if (curlCode == CURLE_OPERATION_TIMEDOUT) \
				curlCode = curl_easy_perform(curl.get()); \
		} \
		if (curlCode != 0) { \
			if (curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &responseCode) != 0) \
				Oof(-EIO); \
			if (responseCode == 404) \
				return -ENOENT; \
			cout << __LINE__ << "###curlCode=" << curlCode << "(" << curl_easy_strerror(curlCode) << ")" << "###responseCode=" << responseCode << endl; \
			cout << "giving up..." << endl; \
			char *p = 0; *p = 0; \
			Oof(-EIO); \
		} \
	} \
}

static string bucket;
static string AWSAccessKeyId;
static string AWSSecretAccessKey;
static const string host = "http://s3.amazonaws.com";

// key=path
typedef map<string, struct stat> stat_cache_t;
static stat_cache_t stat_cache;
static pthread_mutex_t stat_cache_lock;

static const char hexAlphabet[] = "0123456789ABCDEF";

/**
 * urlEncode a fuse path,
 * taking into special consideration "/",
 * otherwise regular urlEncode.
 */
string
urlEncode(const string &s) {
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

// http headers
typedef map<string, string> headers_t;

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

static const EVP_MD* evp_md = EVP_sha1();

/**
 * Returns the current date
 * in a format suitable for a HTTP request header.
 */
string
get_date() {
	char buf[100];
	time_t t = time(NULL);
	strftime(buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S +0000", gmtime(&t));
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
string
calc_signature(string method, string content_type, string date, curl_slist* headers, string resource) {
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

string
calc_signature(string method, string content_type, string date, string resource) {
	return calc_signature(method, content_type, date, 0, resource);
}

// libcurl callback
static size_t
readCallback(void *data, size_t blockSize, size_t numBlocks, void *userPtr) {
  string *userString = static_cast<string *>(userPtr);
  size_t count = min((*userString).size(), blockSize*numBlocks);
  memcpy(data, (*userString).data(), count);
  (*userString).erase(0, count);
  return count;
}

// libcurl callback
static size_t
writeCallback(void* data, size_t blockSize, size_t numBlocks, void* userPtr) {
  string* userString = static_cast<string*>(userPtr);
  (*userString).append(reinterpret_cast<const char*>(data), blockSize*numBlocks);
  return blockSize*numBlocks;
}

// ### TODO replace this w/curl_easy_getopt
static size_t headerCallback(void *data,
                            size_t blockSize,
                            size_t numBlocks,
                            void *userPtr) {
  headers_t* headers = reinterpret_cast<headers_t*>(userPtr);
  string header(reinterpret_cast<char *>(data), blockSize*numBlocks);
  string key;
  stringstream ss(header);
  if (getline(ss, key, ' ')) {
	  string value;
	  getline(ss, value);
	  (*headers)[key] = value;
  }
//  ss >> key;
////  if (key == "Last-Modified:") {
////	  string LastModified;
////	  ss >> LastModified;
////	  
////	  cout << ">>>>>" << ss.str() << endl;
////	  //time_t t = curl_getdate(LastModified.c_str(), 0);
////	  stbuf->st_mtime = curl_getdate(LastModified.c_str(), 0);
////  }
//  if (key == "Content-Type:") {
//	  string ContentType;
//	  ss >> ContentType;
//	  stbuf->st_mode = S_IFREG | 0755;
//	  if (ContentType == "application/x-directory")
//		  stbuf->st_mode = S_IFDIR | 0755;
//  }
//  if (key == "Content-Length:")
//	  ss >> stbuf->st_size;
  return blockSize*numBlocks;
}

static int
s3fs_getattr(const char *path, struct stat *stbuf) {
	memset(stbuf, 0, sizeof(struct stat));
	if (strcmp(path, "/") == 0) {
		stbuf->st_nlink = 1; // see fuse faq
		stbuf->st_mode = S_IFDIR | 0755;
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
	
	string resource = urlEncode("/"+bucket + path);
	string url = host + resource;

	auto_curl curl;
	curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
	curl_easy_setopt(curl, CURLOPT_FAILONERROR, true);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, true);
	curl_easy_setopt(curl, CURLOPT_NOBODY, true); // HEAD
	curl_easy_setopt(curl, CURLOPT_FILETIME, true); // Last-Modified

	headers_t responseHeaders;
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &responseHeaders);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, headerCallback);

	auto_curl_slist headers;
	string date = get_date();
	headers.append("Date: "+date);
	headers.append("Authorization: AWS "+AWSAccessKeyId+":"+calc_signature("HEAD", "", date, resource));
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers.get());

	MY_CURL_EASY_PERFORM((curl));
    
	stbuf->st_nlink = 1; // see fuse faq
	
	long LastModified;
	if (curl_easy_getinfo(curl, CURLINFO_FILETIME, &LastModified) == 0)
		stbuf->st_mtime = LastModified;

	char* ContentType = 0;
	stbuf->st_mode = S_IFREG|0755;
	if (curl_easy_getinfo(curl, CURLINFO_CONTENT_TYPE, &ContentType) == 0 && ContentType)
		stbuf->st_mode = strcmp(ContentType, "application/x-directory")== 0 ? S_IFDIR | 0755 : S_IFREG | 0755;

	double ContentLength;
	if (curl_easy_getinfo(curl, CURLINFO_CONTENT_LENGTH_DOWNLOAD, &ContentLength) == 0)
		stbuf->st_size = static_cast<off_t>(ContentLength);
	
	if (S_ISREG(stbuf->st_mode))
		stbuf->st_blocks = stbuf->st_size / 512 + 1;

	return 0;
}

static int
s3fs_readlink(const char *path, char *buf, size_t size) {
    cout << "###readlink: path=" << path << endl;
    return -ENOENT;
}

static int
s3fs_mknod(const char *path, mode_t mode, dev_t rdev) {
	// see man 2 mknod
	// If pathname already exists, or is a symbolic link, this call fails with an EEXIST error.
	//###cout << "mknod: path="<< path << endl;

	string resource = urlEncode("/"+bucket + path);
	string url = host + resource;
	
	auto_curl curl;
	curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
	curl_easy_setopt(curl, CURLOPT_FAILONERROR, true);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, true);
	curl_easy_setopt(curl, CURLOPT_UPLOAD, true); // HTTP PUT
	curl_easy_setopt(curl, CURLOPT_INFILESIZE, 0); // Content-Length: 0

	auto_curl_slist headers;
	string date = get_date();
	headers.append("Date: "+date);
	headers.append("Authorization: AWS "+AWSAccessKeyId+":"+calc_signature("PUT", "application/octet-stream", date, headers.get(), resource));
	headers.append("Content-Type: application/octet-stream");
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers.get());

	MY_CURL_EASY_PERFORM((curl));

	return 0;
}

static int
s3fs_mkdir(const char *path, mode_t mode) {
	cout << "mkdir: path=" << path << endl;
	
	string resource = urlEncode("/"+bucket + path);
	string url = host + resource;
	
	auto_curl curl;
	curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
	curl_easy_setopt(curl, CURLOPT_FAILONERROR, true);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, true);
	curl_easy_setopt(curl, CURLOPT_UPLOAD, true); // HTTP PUT
	curl_easy_setopt(curl, CURLOPT_INFILESIZE, 0); // Content-Length: 0
	
	auto_curl_slist headers;
	string date = get_date();
	headers.append("Date: "+date);
	headers.append("Authorization: AWS "+AWSAccessKeyId+":"+calc_signature("PUT", "application/x-directory", date, resource));
	headers.append("Content-Type: application/x-directory");
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers.get());
	   
	MY_CURL_EASY_PERFORM((curl));

	return 0;
}

// aka rm
static int
s3fs_unlink(const char *path) {
	cout << "unlink: path=" << path << endl;
	
	string resource = urlEncode("/"+bucket + path);
	string url = host + resource;
	
	auto_curl curl;
	curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
	curl_easy_setopt(curl, CURLOPT_FAILONERROR, true);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, true);
	curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
	    
	auto_curl_slist headers;
	string date = get_date();
	headers.append("Date: "+date);
	headers.append("Authorization: AWS "+AWSAccessKeyId+":"+calc_signature("DELETE", "", date, resource));
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers.get());
	
	MY_CURL_EASY_PERFORM((curl));
	
	return 0;
}

static int
s3fs_rmdir(const char *path) {
	cout << "unlink: path=" << path << endl;
	
	string resource = urlEncode("/"+bucket + path);
	string url = host + resource;
	
	auto_curl curl;
	curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
	curl_easy_setopt(curl, CURLOPT_FAILONERROR, true);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, true);
	curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
	    
	auto_curl_slist headers;
	string date = get_date();
	headers.append("Date: "+date);
	headers.append("Authorization: AWS "+AWSAccessKeyId+":"+calc_signature("DELETE", "", date, resource));
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers.get());
	
	MY_CURL_EASY_PERFORM((curl));

	return 0;
}

static int
s3fs_symlink(const char *from, const char *to) {
    cout << "symlink:" << " from=" << from << " to=" << to << endl;
    return -EPERM;
}

static int
s3fs_rename(const char *from, const char *to) {
    cout << "rename:" << " from=" << from << " to=" << to << endl;
    // get local file handle
    // upload as new s3 object
    // delete old s3 object
    return -EXDEV;
}

static int
s3fs_link(const char *from, const char *to) {
    cout << "link:" << " from=" << from << " to=" << to << endl;
    return -EPERM;
}

static int
s3fs_chmod(const char *path, mode_t mode) {
    cout << "###chmod: path=" << path << endl;
    // get local file handle
    // re-upload as new s3 object w/updated mode
    return 0;
}

static int
s3fs_chown(const char *path, uid_t uid, gid_t gid) {
    cout << "###chown: path=" << path << endl;
    // hook this into s3's acl?!?
    return 0;
}

static int
s3fs_truncate(const char *path, off_t size) {
	//###TODO honor size?!?
	
    //###cout << "truncate:" << " path=" << path << " size=" << size << endl;
	
	string resource = urlEncode("/"+bucket + path);
	string url = host + resource;
	
	auto_curl curl;
	curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
	curl_easy_setopt(curl, CURLOPT_FAILONERROR, true);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, true);
	curl_easy_setopt(curl, CURLOPT_UPLOAD, true); // HTTP PUT
	curl_easy_setopt(curl, CURLOPT_INFILESIZE, 0); // Content-Length: 0
	
	auto_curl_slist headers;
	string date = get_date();
	headers.append("Date: "+date);
	headers.append("Authorization: AWS "+AWSAccessKeyId+":"+calc_signature("PUT", "application/octet-stream", date, resource));
	headers.append("Content-Type: application/octet-stream");
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers.get());
	   
	MY_CURL_EASY_PERFORM((curl));
	
	return 0;
}

// fd -> flags
typedef map<int, int> s3fs_descriptors_t;
static s3fs_descriptors_t s3fs_descriptors;
static pthread_mutex_t s3fs_descriptors_lock;

// mkdir --parents
static int
mkdirp(const string& path) {
	string base;
	string component;
	stringstream ss(path);
	while (getline(ss, component, '/')) {
		base += "/" + component;
		/*if (*/mkdir(base.c_str(), 0755)/* == -1);
			return -1*/;
	}
	return 0;
}

#include <pwd.h>

string
expand_path(const string& path) {
	if (path.length() == 0 || path[0] != '~')
		return path;
	const char *pfx= NULL;
	string::size_type pos = path.find_first_of('/');
	if (path.length() == 1 || pos == 1) {
		pfx = getenv("HOME");
		if (!pfx) {
			// Punt. We're trying to expand ~/, but HOME isn't set
			struct passwd *pw = getpwuid(getuid());
			if (pw)
				pfx = pw->pw_dir;
		}
	} else {
		string user(path, 1, (pos==string::npos) ? string::npos : pos-1);
		struct passwd *pw = getpwnam(user.c_str());
		if (pw)
			pfx = pw->pw_dir;
	}
	// if we failed to find an expansion, return the path unchanged.
	if (!pfx)
		return path;
	string result(pfx);
	if (pos == string::npos)
		return result;
	if (result.length() == 0 || result[result.length()-1] != '/')
		result += '/';
	result += path.substr(pos+1);
	return result;
}

#include <openssl/md5.h>

// safe variant of dirname
static string
mydirname(const string& path) {
	return dirname(&string(path)[0]);
}

// safe variant of basename
static string
mybasename(const string& path) {
	return basename(&string(path)[0]);
}

static int
s3fs_open(const char *path, struct fuse_file_info *fi) {
    //###cout << "open:" << " path="<< path << " flags=" << fi->flags << endl;
    
	string baseName(basename(&string(path)[0]));
	
	string resolved_path(expand_path("~/.s3fs/"+bucket));

	string resource = urlEncode("/"+bucket + path);
	string url = host + resource;

	auto_curl curl;
	curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
	curl_easy_setopt(curl, CURLOPT_FAILONERROR, true);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, true);
	curl_easy_setopt(curl, CURLOPT_NOBODY, true); // HEAD
	curl_easy_setopt(curl, CURLOPT_FILETIME, true); // Last-Modified

	headers_t responseHeaders;
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &responseHeaders);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, headerCallback);

	auto_curl_slist headers;
	string date = get_date();
	headers.append("Date: "+date);
	headers.append("Authorization: AWS "+AWSAccessKeyId+":"+calc_signature("HEAD", "", date, resource));
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers.get());

	MY_CURL_EASY_PERFORM((curl));
    
	// at this point we know the file exists

	mode_t mode = 0755;
	///###mode_t mode = atoi(row[0]);
	
	string cache_path(resolved_path + path);
	
	int fd = open(cache_path.c_str(), O_RDWR); // ### TODO should really somehow obey flags here
    if (fd != -1) {
		MD5_CTX c;
		if (MD5_Init(&c) != 1)
			Oof(-EIO);
		int count;
		char buf[1024];
		while ((count = read(fd, buf, sizeof(buf))) > 0) {
			if (MD5_Update(&c, buf, count) != 1)
				Oof(-EIO);
		}
		unsigned char md[MD5_DIGEST_LENGTH];
		if (MD5_Final(md, &c) != 1)
			Oof(-EIO);
		///###cout << md << endl;
		
		char localMd5[2*MD5_DIGEST_LENGTH+1];
		sprintf(localMd5, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
				md[0], md[1], md[2], md[3], md[4], md[5], md[6], md[7], md[8], md[9], md[10], md[11], md[12], md[13], md[14], md[15]);
		
		string remoteMd5(responseHeaders["ETag:"]);
		remoteMd5 = remoteMd5.substr(1, 32); // strip " " 
		
		// md5 match?		
		if (string(localMd5) != remoteMd5) {
			// no! prepare to download
			if (close(fd) == -1)
				Oof(-errno);
			fd = -1;
		} 

    }
    // need to download?
    if (fd == -1) {
    	// yes!
		/*if (*/mkdirp(resolved_path + mydirname(path))/* == -1)
			return -errno*/;
		fd = creat(cache_path.c_str(), mode);
		if (fd == -1)
			Oof(-errno);
		///////////////////string responseText;
		string resource = urlEncode("/"+bucket + path);
		string url = host + resource;

		auto_curl curl;
		curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
		curl_easy_setopt(curl, CURLOPT_FAILONERROR, true);
		curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, true);
		
		FILE* f = fdopen(fd, "wb");
		if (f == 0)
			Oof(-errno);
		curl_easy_setopt(curl, CURLOPT_FILE, f);

		auto_curl_slist headers;
		string date = get_date();
		headers.append("Date: "+date);
		headers.append("Authorization: AWS "+AWSAccessKeyId+":"+calc_signature("GET", "", date, resource));
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers.get());

		cout << "downloading: " << path << endl;
		MY_CURL_EASY_PERFORM((curl));
		
//		if (close(fd) == -1)
//			Oof(-errno);
		if (fclose(f) != 0)
			Oof(-errno);
	    fd = open(cache_path.c_str(), O_RDWR); // ### TODO should really somehow obey flags here
		if (fd == -1)
			Oof(-errno);
    }
    
    fi->fh = fd;
    
    // remember flags...
	auto_lock lock(s3fs_descriptors_lock);
	s3fs_descriptors[fi->fh] = fi->flags;
	
    return 0;
}

static int
s3fs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
	//###cout << "read: " << path << endl;
    int res = pread(fi->fh, buf, size, offset);
    if (res == -1)
		Oof(-errno);
    return res;
}

static int
s3fs_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
	//###cout << "write: " << path << endl;
    int res = pwrite(fi->fh, buf, size, offset);
    if (res == -1)
		Oof(-errno);
    return res;
}

static int
s3fs_statfs(const char *path, struct statvfs *stbuf) {
    // 256T
	stbuf->f_bsize = 0X1000000;
    stbuf->f_blocks = 0X1000000;
    stbuf->f_bfree = 0x1000000;
    stbuf->f_bavail = 0x1000000;
    return 0;
}

static bool
is_dirty(int fd) {
	auto_lock lock(s3fs_descriptors_lock);
	return (s3fs_descriptors[fd] & O_WRONLY) || (s3fs_descriptors[fd] & O_RDWR);
}

static int
s3fs_flush(const char *path, struct fuse_file_info *fi) {
	//###cout << "flush: path=" << path << endl;
	// NOTE- fi->flags unavailable here
	if (is_dirty(fi->fh)) {
		
		
		struct stat st;
		if (fstat(fi->fh, &st) == -1)
			Oof(-errno);
		
		///###string* requestText = reinterpret_cast<string*>(fi->fh);
		///###if ((*requestText).size() > 0)
		{
			string resource = urlEncode("/"+bucket + path);
			string url = host + resource;

			auto_curl curl;
			curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
			curl_easy_setopt(curl, CURLOPT_FAILONERROR, true);
			curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, true);

			string responseText;
			curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseText);
			curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);

			curl_easy_setopt(curl, CURLOPT_UPLOAD, true); // HTTP PUT
			curl_easy_setopt(curl, CURLOPT_INFILESIZE, st.st_size); // Content-Length
			FILE* f = fdopen(fi->fh, "rb");
			if (f == 0)
				Oof(-errno);
			//rewind(f);
			curl_easy_setopt(curl, CURLOPT_INFILE, f);
			///curl_easy_setopt(curl, CURLOPT_READFUNCTION, readCallback);
			    
			auto_curl_slist headers;
			string date = get_date();
			headers.append("Date: "+date);
			headers.append("Authorization: AWS "+AWSAccessKeyId+":"+calc_signature("PUT", "application/octet-stream", date, resource));
			headers.append("Content-Type: application/octet-stream"); //###not necessary... app/octets is s3 default
			curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers.get());
			
			rewind(f);
		
			cout << "uploading: " << path << "### fd=" << fi->fh << endl;
			MY_CURL_EASY_PERFORM((curl));
			
			return 0;
		}
	}
	return 0;
}

static int
s3fs_release(const char *path, struct fuse_file_info *fi) {
	//###cout << "release: " << path << endl;
	if (close(fi->fh) == -1)
		Oof(-errno);
	return 0;
}

time_t
my_timegm (struct tm *tm) {
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

static int
s3fs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi) {
	//cout << "readdir:"<< " path="<< path << endl;

	string NextMarker;
	string IsTruncated("true");
	
	while (IsTruncated == "true") {
		string responseText;
		string resource = urlEncode("/"+bucket); // this is what gets signed
		string query = "delimiter=/&prefix=";

		if (strcmp(path, "/") != 0)
			query += urlEncode(string(path).substr(1) + "/");
		
		if (NextMarker.size() > 0)
			query += "&marker=" + urlEncode(NextMarker);

		string url = host + resource + "?"+ query;

		auto_curl curl;
		curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
		curl_easy_setopt(curl, CURLOPT_FAILONERROR, true);
		curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, true);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseText);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);

		headers_t headersMap;
	    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &headersMap);
	    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, headerCallback);

		auto_curl_slist headers;
		string date = get_date();
		headers.append("Date: "+date);
		headers.append("Authorization: AWS "+AWSAccessKeyId+":"+calc_signature("GET", "", date, resource));
		
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers.get());

		MY_CURL_EASY_PERFORM((curl));

		{
			xmlDocPtr doc = xmlReadMemory(responseText.c_str(), responseText.size(), "", NULL, 0);
			if (doc != NULL&& doc->children != NULL) {
				for (xmlNodePtr cur_node = doc->children->children; cur_node != NULL; cur_node = cur_node->next) {
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
							for (xmlNodePtr sub_node = cur_node->children; sub_node != NULL; sub_node = sub_node->next) {
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
								struct stat st;
								memset(&st, 0, sizeof(st));
								st.st_nlink = 1; // see fuse faq
								// mode
								st.st_mode = S_IFREG | 0755;
								// size
								stringstream tmp(Size);
								tmp >> st.st_size;
								// modified... something like "2005-12-31T23:59:59Z"
								struct tm gmt;
								strptime(LastModified.c_str(), "%Y-%m-%dT%H:%M:%SZ", &gmt);
								st.st_mtime = my_timegm(&gmt);
								// blocks
								st.st_blocks = st.st_size / 512 + 1;
								// if size is 0 then we don't know whether its a file or a directory...
								// defer to getattr() to determine whether its a file or a directory from Content-Type
								if (st.st_size > 0) {
									auto_lock lock(stat_cache_lock);
									stat_cache["/"+Key] = st;
								}
								if (filler(buf, mybasename(Key).c_str(), 0, 0))
									break;
							}
						}
					}
				}
			}
			xmlFreeDoc(doc);
		}
	}
	
	return 0;
}

static void*
s3fs_init(struct fuse_conn_info *conn) {
	printf("init\n");
	pthread_mutex_init(&stat_cache_lock, NULL);
	pthread_mutex_init(&curl_handles_lock, NULL);
	pthread_mutex_init(&s3fs_descriptors_lock, NULL);
	return 0;
}

static void
s3fs_destroy(void*) {
	printf("destroy\n");
	pthread_mutex_destroy(&stat_cache_lock);
	pthread_mutex_destroy(&curl_handles_lock);
	pthread_mutex_destroy(&s3fs_descriptors_lock);
}

static int
s3fs_access(const char *path, int mask) {
    cout << "###access:" << " path=" << path << endl;
    return 0;
}

// aka touch
static int
s3fs_utimens(const char *path, const struct timespec ts[2]) {
    cout << "###utimens: path=" << path << endl;
    return -EPERM;
}

static int
my_fuse_opt_proc(void *data, const char *arg, int key, struct fuse_args *outargs) {
	if (key == FUSE_OPT_KEY_NONOPT) {
		if (bucket.size() == 0) {
			bucket = arg;
			return 0;
		}
	}
	if (key == FUSE_OPT_KEY_OPT) {
		if (strstr(arg, "accessKeyId=") != 0) {
			AWSAccessKeyId = strchr(arg, '=') + 1;
			return 0;
		}
		if (strstr(arg, "secretAccessKey=") != 0) {
			AWSSecretAccessKey = strchr(arg, '=') + 1;
			return 0;
		}
	}
	return 1;
}

static struct fuse_operations s3fs_oper;

int
main(int argc, char *argv[]) {
    memset(&s3fs_oper, sizeof(s3fs_oper), 0);
    
    struct fuse_args custom_args = FUSE_ARGS_INIT(argc, argv);
    fuse_opt_parse(&custom_args, NULL, NULL, my_fuse_opt_proc);
    
    if (bucket.size() == 0) {
    	cout << argv[0] << ": " << "missing bucket" << endl;
    	exit(1);
    }
    
    if (AWSSecretAccessKey.size() == 0) {
    	string line;
        ifstream passwd("/etc/passwd-s3fs");
    	while (getline(passwd, line)) {
    		if (line[0]=='#')
    			continue;
    		size_t pos = line.find(':');
    		if (pos != string::npos) {
    			// is accessKeyId missing?
    			if (AWSAccessKeyId.size() == 0)
    				AWSAccessKeyId = line.substr(0, pos);
    			// is secretAccessKey missing?
    			if (AWSSecretAccessKey.size() == 0) {
    				if (line.substr(0, pos) == AWSAccessKeyId)
    					AWSSecretAccessKey = line.substr(pos + 1, string::npos);
    			}
    		}
    	}
    }

    if (AWSAccessKeyId.size() == 0) {
    	cout << argv[0] << ": " << "missing accessKeyId.. see /etc/passwd-s3fs or use, e.g., -o accessKeyId=10QO29WI38EU47RY56T" << endl;
    	exit(1);
    }
    if (AWSSecretAccessKey.size() == 0) {
    	cout << argv[0] << ": " << "missing secretAccessKey... see /etc/passwd-s3fs" << endl;
    	exit(1);
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

    return fuse_main(custom_args.argc, custom_args.argv, &s3fs_oper, NULL);
}
