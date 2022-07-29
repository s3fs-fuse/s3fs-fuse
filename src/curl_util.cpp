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

#include <cstdio>
#include <cstdlib>
#include <curl/curl.h>

#include "common.h"
#include "s3fs_logger.h"
#include "curl_util.h"
#include "string_util.h"
#include "s3fs_auth.h"
#include "s3fs_cred.h"

//-------------------------------------------------------------------
// Utility Functions
//-------------------------------------------------------------------
//
// curl_slist_sort_insert
// This function is like curl_slist_append function, but this adds data by a-sorting.
// Because AWS signature needs sorted header.
//
struct curl_slist* curl_slist_sort_insert(struct curl_slist* list, const char* data)
{
    if(!data){
        return list;
    }
    std::string strkey = data;
    std::string strval;

    std::string::size_type pos = strkey.find(':', 0);
    if(std::string::npos != pos){
        strval = strkey.substr(pos + 1);
        strkey.erase(pos);
    }

    return curl_slist_sort_insert(list, strkey.c_str(), strval.c_str());
}

struct curl_slist* curl_slist_sort_insert(struct curl_slist* list, const char* key, const char* value)
{
    if(!key){
        return list;
    }

    // key & value are trimmed and lower (only key)
    std::string strkey = trim(std::string(key));
    std::string strval = value ? trim(std::string(value)) : "";
    std::string strnew = key + std::string(": ") + strval;
    char* data;
    if(NULL == (data = strdup(strnew.c_str()))){
        return list;
    }

    struct curl_slist **p = &list;
    for(;*p; p = &(*p)->next){
        std::string strcur = (*p)->data;
        size_t pos;
        if(std::string::npos != (pos = strcur.find(':', 0))){
            strcur.erase(pos);
        }

        int result = strcasecmp(strkey.c_str(), strcur.c_str());
        if(0 == result){
            free((*p)->data);
            (*p)->data = data;
            return list;
        }else if(result < 0){
            break;
        }
    }

    struct curl_slist* new_item;
    if(NULL == (new_item = static_cast<struct curl_slist*>(malloc(sizeof(*new_item))))){
        free(data);
        return list;
    }

    struct curl_slist* before = *p;
    *p = new_item;
    new_item->data = data;
    new_item->next = before;

    return list;
}

struct curl_slist* curl_slist_remove(struct curl_slist* list, const char* key)
{
    if(!key){
        return list;
    }

    std::string strkey = trim(std::string(key));
    struct curl_slist **p = &list;
    while(*p){
        std::string strcur = (*p)->data;
        size_t pos;
        if(std::string::npos != (pos = strcur.find(':', 0))){
            strcur.erase(pos);
        }

        int result = strcasecmp(strkey.c_str(), strcur.c_str());
        if(0 == result){
            free((*p)->data);
            struct curl_slist *tmp = *p;
            *p = (*p)->next;
            free(tmp);
        }else{
            p = &(*p)->next;
        }
    }

    return list;
}

std::string get_sorted_header_keys(const struct curl_slist* list)
{
    std::string sorted_headers;

    if(!list){
        return sorted_headers;
    }

    for( ; list; list = list->next){
        std::string strkey = list->data;
        size_t pos;
        if(std::string::npos != (pos = strkey.find(':', 0))){
            if (trim(strkey.substr(pos + 1)).empty()) {
                // skip empty-value headers (as they are discarded by libcurl)
                continue;
            }
            strkey.erase(pos);
        }
        if(!sorted_headers.empty()){
            sorted_headers += ";";
        }
        sorted_headers += lower(strkey);
    }

    return sorted_headers;
}

std::string get_header_value(const struct curl_slist* list, const std::string &key)
{
    if(!list){
        return "";
    }

    for( ; list; list = list->next){
        std::string strkey = list->data;
        size_t pos;
        if(std::string::npos != (pos = strkey.find(':', 0))){
            if(0 == strcasecmp(trim(strkey.substr(0, pos)).c_str(), key.c_str())){
                return trim(strkey.substr(pos+1));
            }
        }
    }

    return "";
}

std::string get_canonical_headers(const struct curl_slist* list)
{
    std::string canonical_headers;

    if(!list){
        canonical_headers = "\n";
        return canonical_headers;
    }

    for( ; list; list = list->next){
        std::string strhead = list->data;
        size_t pos;
        if(std::string::npos != (pos = strhead.find(':', 0))){
            std::string strkey = trim(lower(strhead.substr(0, pos)));
            std::string strval = trim(strhead.substr(pos + 1));
            if (strval.empty()) {
                // skip empty-value headers (as they are discarded by libcurl)
                continue;
            }
            strhead = strkey;
            strhead += ":";
            strhead += strval;
        }else{
            strhead = trim(lower(strhead));
        }
        canonical_headers += strhead;
        canonical_headers += "\n";
    }
    return canonical_headers;
}

std::string get_canonical_headers(const struct curl_slist* list, bool only_amz)
{
    std::string canonical_headers;

    if(!list){
        canonical_headers = "\n";
        return canonical_headers;
    }

    for( ; list; list = list->next){
        std::string strhead = list->data;
        size_t pos;
        if(std::string::npos != (pos = strhead.find(':', 0))){
            std::string strkey = trim(lower(strhead.substr(0, pos)));
            std::string strval = trim(strhead.substr(pos + 1));
            if (strval.empty()) {
                // skip empty-value headers (as they are discarded by libcurl)
                continue;
            }
            strhead = strkey;
            strhead += ":";
            strhead += strval;
        }else{
            strhead = trim(lower(strhead));
        }
        if(only_amz && strhead.substr(0, 5) != "x-amz"){
            continue;
        }
        canonical_headers += strhead;
        canonical_headers += "\n";
    }
    return canonical_headers;
}

// function for using global values
bool MakeUrlResource(const char* realpath, std::string& resourcepath, std::string& url)
{
    if(!realpath){
        return false;
    }
    resourcepath = urlEncode(service_path + S3fsCred::GetBucket() + realpath);
    url          = s3host + resourcepath;
    return true;
}

std::string prepare_url(const char* url)
{
    S3FS_PRN_INFO3("URL is %s", url);

    std::string uri;
    std::string hostname;
    std::string path;
    std::string url_str = std::string(url);
    std::string token = std::string("/") + S3fsCred::GetBucket();
    size_t bucket_pos;
    size_t bucket_length = token.size();
    size_t uri_length = 0;

    if(!strncasecmp(url_str.c_str(), "https://", 8)){
        uri_length = 8;
    } else if(!strncasecmp(url_str.c_str(), "http://", 7)) {
        uri_length = 7;
    }
    uri  = url_str.substr(0, uri_length);
    bucket_pos = url_str.find(token, uri_length);

    if(!pathrequeststyle){
        hostname = S3fsCred::GetBucket() + "." + url_str.substr(uri_length, bucket_pos - uri_length);
        path = url_str.substr((bucket_pos + bucket_length));
    }else{
        hostname = url_str.substr(uri_length, bucket_pos - uri_length);
        std::string part = url_str.substr((bucket_pos + bucket_length));
        if('/' != part[0]){
            part = "/" + part;
        }
        path = "/" + S3fsCred::GetBucket() + part;
    }

    url_str = uri + hostname + path;

    S3FS_PRN_INFO3("URL changed is %s", url_str.c_str());

    return url_str;
}

// [TODO]
// This function uses temporary file, but should not use it.
// For not using it, we implement function in each auth file(openssl, nss. gnutls).
//
bool make_md5_from_binary(const char* pstr, size_t length, std::string& md5)
{
    if(!pstr || '\0' == pstr[0]){
        S3FS_PRN_ERR("Parameter is wrong.");
        return false;
    }
    FILE* fp;
    if(NULL == (fp = tmpfile())){
        S3FS_PRN_ERR("Could not make tmpfile.");
        return false;
    }
    if(length != fwrite(pstr, sizeof(char), length, fp)){
        S3FS_PRN_ERR("Failed to write tmpfile.");
        fclose(fp);
        return false;
    }
    int fd;
    if(0 != fflush(fp) || 0 != fseek(fp, 0L, SEEK_SET) || -1 == (fd = fileno(fp))){
        S3FS_PRN_ERR("Failed to make MD5.");
        fclose(fp);
        return false;
    }
    // base64 md5
    md5 = s3fs_get_content_md5(fd);
    if(md5.empty()){
        S3FS_PRN_ERR("Failed to make MD5.");
        fclose(fp);
        return false;
    }
    fclose(fp);
    return true;
}

std::string url_to_host(const std::string &url)
{
    S3FS_PRN_INFO3("url is %s", url.c_str());

    static const char HTTP[] = "http://";
    static const char HTTPS[] = "https://";
    std::string hostname;

    if (is_prefix(url.c_str(), HTTP)) {
        hostname = url.substr(sizeof(HTTP) - 1);
    } else if (is_prefix(url.c_str(), HTTPS)) {
        hostname = url.substr(sizeof(HTTPS) - 1);
    } else {
        S3FS_PRN_EXIT("url does not begin with http:// or https://");
        abort();
    }

    size_t idx;
    if ((idx = hostname.find('/')) != std::string::npos) {
        return hostname.substr(0, idx);
    } else {
        return hostname;
    }
}

std::string get_bucket_host()
{
    if(!pathrequeststyle){
        return S3fsCred::GetBucket() + "." + url_to_host(s3host);
    }
    return url_to_host(s3host);
}

const char* getCurlDebugHead(curl_infotype type)
{
    const char* unknown = "";
    const char* dataIn  = "BODY <";
    const char* dataOut = "BODY >";
    const char* headIn  = "<";
    const char* headOut = ">";

    switch(type){
        case CURLINFO_DATA_IN:
            return dataIn;
        case CURLINFO_DATA_OUT:
            return dataOut;
        case CURLINFO_HEADER_IN:
            return headIn;
        case CURLINFO_HEADER_OUT:
            return headOut;
        default:
            break;
    }
    return unknown;
}

//
// compare ETag ignoring quotes and case
//
bool etag_equals(std::string s1, std::string s2)
{
    if(s1.length() > 1 && s1[0] == '\"' && *s1.rbegin() == '\"'){
        s1.erase(s1.size() - 1);
        s1.erase(0, 1);
    }
    if(s2.length() > 1 && s2[0] == '\"' && *s2.rbegin() == '\"'){
        s2.erase(s2.size() - 1);
        s2.erase(0, 1);
    }
    return 0 == strcasecmp(s1.c_str(), s2.c_str());
}

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
