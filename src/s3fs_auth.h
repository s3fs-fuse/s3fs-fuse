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

#ifndef S3FS_AUTH_H_
#define S3FS_AUTH_H_

#include <string>
#include <sys/types.h>

//-------------------------------------------------------------------
// Utility functions for Authentication
//-------------------------------------------------------------------
//
// in common_auth.cpp
//
std::string s3fs_get_content_md5(int fd);
std::string s3fs_sha256_hex_fd(int fd, off_t start, off_t size);

//
// in xxxxxx_auth.cpp
//
const char* s3fs_crypt_lib_name();
bool s3fs_init_global_ssl();
bool s3fs_destroy_global_ssl();
bool s3fs_init_crypt_mutex();
bool s3fs_destroy_crypt_mutex();
bool s3fs_HMAC(const void* key, size_t keylen, const unsigned char* data, size_t datalen, unsigned char** digest, unsigned int* digestlen);
bool s3fs_HMAC256(const void* key, size_t keylen, const unsigned char* data, size_t datalen, unsigned char** digest, unsigned int* digestlen);
size_t get_md5_digest_length();
unsigned char* s3fs_md5_fd(int fd, off_t start, off_t size);
bool s3fs_sha256(const unsigned char* data, size_t datalen, unsigned char** digest, unsigned int* digestlen);
size_t get_sha256_digest_length();
unsigned char* s3fs_sha256_fd(int fd, off_t start, off_t size);

#endif // S3FS_AUTH_H_

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
