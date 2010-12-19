#ifndef S3FS_S3_H_
#define S3FS_S3_H_

#define FUSE_USE_VERSION 26

#include <map>
#include <string>

#include <curl/curl.h>
#include <fuse.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/md5.h>
#include <pthread.h>
#include <sys/time.h>


using namespace std;

#define YIKES(result) if (true) { \
  syslog(LOG_ERR, "%d###result=%d", __LINE__, result); \
  return result; \
}

typedef pair<double, double> progress_t;

static long connect_timeout = 3;
static time_t readwrite_timeout = 10;

// static stack<CURL*> curl_handles;
static pthread_mutex_t curl_handles_lock;
static map<CURL*, time_t> curl_times;
static map<CURL*, progress_t> curl_progress;

static int retries = 2;

static string bucket;
static string mountpoint;
static string program_name;
static string AWSAccessKeyId;
static string AWSSecretAccessKey;
static string host = "http://s3.amazonaws.com";
static string curl_ca_bundle;
static mode_t root_mode = 0;
static string service_path = "/";
static string passwd_file = "";
static bool debug = 0;
static bool foreground = 0;

// if .size()==0 then local file cache is disabled
static string use_cache;
static string use_rrs;
static string ssl_verify_hostname = "1";
static string public_bucket;

// TODO(apetresc): make this an enum
// private, public-read, public-read-write, authenticated-read
static string default_acl("private");

// key=path
typedef map<string, struct stat> stat_cache_t;
static stat_cache_t stat_cache;
static pthread_mutex_t stat_cache_lock;

static const char hexAlphabet[] = "0123456789ABCDEF";

// http headers
typedef map<string, string> headers_t;

static const EVP_MD* evp_md = EVP_sha1();

// fd -> flags
typedef map<int, int> s3fs_descriptors_t;
static s3fs_descriptors_t s3fs_descriptors;
static pthread_mutex_t s3fs_descriptors_lock;

static pthread_mutex_t *mutex_buf = NULL;

static struct fuse_operations s3fs_oper;

string urlEncode(const string &s);

static int s3fs_getattr(const char *path, struct stat *stbuf);
static int s3fs_readlink(const char *path, char *buf, size_t size);
static int s3fs_mknod(const char* path, mode_t mode, dev_t rdev);
static int s3fs_mkdir(const char *path, mode_t mode);
static int s3fs_unlink(const char *path);
static int s3fs_rmdir(const char *path);
static int s3fs_symlink(const char *from, const char *to);
static int s3fs_rename(const char *from, const char *to);
static int s3fs_link(const char *from, const char *to);
static int s3fs_chmod(const char *path, mode_t mode);
static int s3fs_chown(const char *path, uid_t uid, gid_t gid);
static int s3fs_truncate(const char *path, off_t size);
static int s3fs_open(const char *path, struct fuse_file_info *fi);
static int s3fs_read(
    const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi);
static int s3fs_write(
    const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi);
static int s3fs_statfs(const char *path, struct statvfs *stbuf);
static int s3fs_flush(const char *path, struct fuse_file_info *fi);
static int s3fs_release(const char *path, struct fuse_file_info *fi);
static int s3fs_readdir(
    const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi);
static int s3fs_access(const char *path, int mask);
static int s3fs_utimens(const char *path, const struct timespec ts[2]);
static void* s3fs_init(struct fuse_conn_info *conn);
static void s3fs_destroy(void*);

#endif // S3FS_S3_H_
