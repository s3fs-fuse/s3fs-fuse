#ifndef S3FS_AUTH_H_
#define S3FS_AUTH_H_

//-------------------------------------------------------------------
// Utility functions for Authentication
//-------------------------------------------------------------------
//
// in common_auth.cpp
//
char* s3fs_base64(unsigned char* input, size_t length);
std::string s3fs_get_content_md5(int fd);
std::string s3fs_md5sum(int fd, off_t start, ssize_t size);
std::string s3fs_sha256sum(int fd, off_t start, ssize_t size);

//
// in xxxxxx_auth.cpp
//
const char* s3fs_crypt_lib_name(void);
bool s3fs_init_global_ssl(void);
bool s3fs_destroy_global_ssl(void);
bool s3fs_init_crypt_mutex(void);
bool s3fs_destroy_crypt_mutex(void);
bool s3fs_HMAC(const void* key, size_t keylen, const unsigned char* data, size_t datalen, unsigned char** digest, unsigned int* digestlen);
size_t get_md5_digest_length(void);
unsigned char* s3fs_md5hexsum(int fd, off_t start, ssize_t size);
bool s3fs_sha256(const unsigned char* data, unsigned int datalen, unsigned char** digest, unsigned int* digestlen);
size_t get_sha256_digest_length(void);
unsigned char* s3fs_sha256hexsum(int fd, off_t start, ssize_t size);

#endif // S3FS_AUTH_H_
