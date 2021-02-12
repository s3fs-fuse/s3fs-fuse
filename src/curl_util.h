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

#ifndef S3FS_CURL_UTIL_H_
#define S3FS_CURL_UTIL_H_

#include <curl/curl.h>

class sse_type_t;

//----------------------------------------------
// Functions
//----------------------------------------------
std::string GetContentMD5(int fd);
struct curl_slist* curl_slist_sort_insert(struct curl_slist* list, const char* data);
struct curl_slist* curl_slist_sort_insert(struct curl_slist* list, const char* key, const char* value);
struct curl_slist* curl_slist_remove(struct curl_slist* list, const char* key);
std::string get_sorted_header_keys(const struct curl_slist* list);
std::string get_canonical_headers(const struct curl_slist* list, bool only_amz = false);
std::string get_header_value(const struct curl_slist* list, const std::string &key);
bool MakeUrlResource(const char* realpath, std::string& resourcepath, std::string& url);
std::string prepare_url(const char* url);
bool get_object_sse_type(const char* path, sse_type_t& ssetype, std::string& ssevalue);   // implement in s3fs.cpp

bool make_md5_from_binary(const char* pstr, size_t length, std::string& md5);
std::string url_to_host(const std::string &url);
std::string get_bucket_host();
const char* getCurlDebugHead(curl_infotype type);

bool etag_equals(std::string s1, std::string s2);

#endif // S3FS_CURL_UTIL_H_

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
