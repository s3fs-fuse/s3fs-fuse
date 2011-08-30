#ifndef S3FS_S3_H_
#define S3FS_S3_H_

#define FUSE_USE_VERSION 26
#define MULTIPART_SIZE 10485760 // 10MB
#define MAX_REQUESTS 100        // max number of concurrent HTTP requests
#define MAX_COPY_SOURCE_SIZE  524288000 // 500MB
#define FIVE_GB 5368709120LL

#include <map>
#include <string>
#include <vector>

#include <curl/curl.h>
#include <fuse.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/md5.h>
#include <pthread.h>
#include <sys/time.h>

#define YIKES(result) if (true) { \
  syslog(LOG_ERR, "%d###result=%d", __LINE__, result); \
  return result; \
}

long connect_timeout = 10;
time_t readwrite_timeout = 30;

int retries = 2;

bool debug = 0;
bool foreground = 0;
bool nomultipart = false;
bool service_validated = false;
static std::string host = "http://s3.amazonaws.com";
static std::string service_path = "/";
std::string bucket = "";
std::string mount_prefix = "";
static std::string mountpoint;
std::string program_name;
static std::string AWSAccessKeyId;
static std::string AWSSecretAccessKey;
static mode_t root_mode = 0;
static std::string passwd_file = "";
static bool utility_mode = 0;
unsigned long max_stat_cache_size = 10000;

// if .size()==0 then local file cache is disabled
static std::string use_cache;
static std::string use_rrs;
std::string ssl_verify_hostname = "1";
static std::string public_bucket;

extern pthread_mutex_t stat_cache_lock;
extern pthread_mutex_t curl_handles_lock;
extern std::string curl_ca_bundle;

// TODO(apetresc): make this an enum
// private, public-read, public-read-write, authenticated-read
static std::string default_acl("private");

struct file_part {
  char path[17];
  std::string etag;
  bool uploaded;

  file_part() : uploaded(false) {}
};

static const char hexAlphabet[] = "0123456789ABCDEF";

// http headers
typedef std::map<std::string, std::string> headers_t;

static const EVP_MD* evp_md = EVP_sha1();

// fd -> flags
typedef std::map<int, int> s3fs_descriptors_t;
static s3fs_descriptors_t s3fs_descriptors;
static pthread_mutex_t s3fs_descriptors_lock;

static pthread_mutex_t *mutex_buf = NULL;

static struct fuse_operations s3fs_oper;

std::string lookupMimeType(std::string);
std::string initiate_multipart_upload(const char *path, off_t size, headers_t meta);
std::string upload_part(const char *path, const char *source, int part_number, std::string upload_id);
std::string copy_part(const char *from, const char *to, int part_number, std::string upload_id, headers_t meta);
static int complete_multipart_upload(const char *path, std::string upload_id, std::vector <file_part> parts);
std::string md5sum(int fd);
char *get_realpath(const char *path);

static int insert_object(char *name, struct s3_object **head);
static unsigned int count_object_list(struct s3_object *list);
static int free_object(struct s3_object *object);
static int free_object_list(struct s3_object *head);

static CURL *create_head_handle(struct head_data *request);
static int list_bucket(const char *path, struct s3_object **head);
static bool is_truncated(const char *xml);
static int append_objects_from_xml(const char *xml, struct s3_object **head);
static const char *get_next_marker(const char *xml);
static char *get_object_name(xmlDocPtr doc, xmlNodePtr node);

static int put_headers(const char *path, headers_t meta);
static int put_multipart_headers(const char *path, headers_t meta);

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
static int remote_mountpath_exists(const char *path);
static void* s3fs_init(struct fuse_conn_info *conn);
static void s3fs_destroy(void*);

#endif // S3FS_S3_H_
