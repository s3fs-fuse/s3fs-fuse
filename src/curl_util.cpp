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
#include "s3fs.h"
#include "curl_util.h"
#include "string_util.h"
#include "s3fs_auth.h"

using namespace std;

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
    string strkey = data;
    string strval;

    string::size_type pos = strkey.find(':', 0);
    if(string::npos != pos){
        strval = strkey.substr(pos + 1);
        strkey = strkey.substr(0, pos);
    }

    return curl_slist_sort_insert(list, strkey.c_str(), strval.c_str());
}

struct curl_slist* curl_slist_sort_insert(struct curl_slist* list, const char* key, const char* value)
{
    struct curl_slist* curpos;
    struct curl_slist* lastpos;
    struct curl_slist* new_item;

    if(!key){
        return list;
    }
    if(NULL == (new_item = reinterpret_cast<struct curl_slist*>(malloc(sizeof(struct curl_slist))))){
        return list;
    }

    // key & value are trimmed and lower (only key)
    string strkey = trim(string(key));
    string strval = trim(string(value ? value : ""));
    string strnew = key + string(": ") + strval;
    if(NULL == (new_item->data = strdup(strnew.c_str()))){
        free(new_item);
        return list;
    }
    new_item->next = NULL;

    for(lastpos = NULL, curpos = list; curpos; lastpos = curpos, curpos = curpos->next){
        string strcur = curpos->data;
        size_t pos;
        if(string::npos != (pos = strcur.find(':', 0))){
            strcur = strcur.substr(0, pos);
        }

        int result = strcasecmp(strkey.c_str(), strcur.c_str());
        if(0 == result){
            // same data, so replace it.
            if(lastpos){
                lastpos->next = new_item;
            }else{
                list = new_item;
            }
            new_item->next = curpos->next;
            free(curpos->data);
            free(curpos);
            break;

        }else if(0 > result){
          // add data before curpos.
          if(lastpos){
              lastpos->next = new_item;
          }else{
              list = new_item;
          }
          new_item->next = curpos;
          break;
        }
    }

    if(!curpos){
        // append to last pos
        if(lastpos){
            lastpos->next = new_item;
        }else{
            // a case of list is null
            list = new_item;
        }
    }
    return list;
}

string get_sorted_header_keys(const struct curl_slist* list)
{
    string sorted_headers;

    if(!list){
        return sorted_headers;
    }

    for( ; list; list = list->next){
        string strkey = list->data;
        size_t pos;
        if(string::npos != (pos = strkey.find(':', 0))){
            if (trim(strkey.substr(pos + 1)).empty()) {
                // skip empty-value headers (as they are discarded by libcurl)
                continue;
            }
            strkey = strkey.substr(0, pos);
        }
        if(0 < sorted_headers.length()){
            sorted_headers += ";";
        }
        sorted_headers += lower(strkey);
    }

    return sorted_headers;
}

string get_header_value(const struct curl_slist* list, const string &key)
{
    if(!list){
        return "";
    }

    for( ; list; list = list->next){
        string strkey = list->data;
        size_t pos;
        if(string::npos != (pos = strkey.find(':', 0))){
            if(0 == strcasecmp(trim(strkey.substr(0, pos)).c_str(), key.c_str())){
                return trim(strkey.substr(pos+1));
            }
        }
    }

    return "";
}

string get_canonical_headers(const struct curl_slist* list)
{
    string canonical_headers;

    if(!list){
        canonical_headers = "\n";
        return canonical_headers;
    }

    for( ; list; list = list->next){
        string strhead = list->data;
        size_t pos;
        if(string::npos != (pos = strhead.find(':', 0))){
            string strkey = trim(lower(strhead.substr(0, pos)));
            string strval = trim(strhead.substr(pos + 1));
            if (strval.empty()) {
                // skip empty-value headers (as they are discarded by libcurl)
                continue;
            }
            strhead       = strkey.append(":").append(strval);
        }else{
            strhead       = trim(lower(strhead));
        }
        canonical_headers += strhead;
        canonical_headers += "\n";
    }
    return canonical_headers;
}

string get_canonical_headers(const struct curl_slist* list, bool only_amz)
{
    string canonical_headers;

    if(!list){
        canonical_headers = "\n";
        return canonical_headers;
    }

    for( ; list; list = list->next){
        string strhead = list->data;
        size_t pos;
        if(string::npos != (pos = strhead.find(':', 0))){
            string strkey = trim(lower(strhead.substr(0, pos)));
            string strval = trim(strhead.substr(pos + 1));
            if (strval.empty()) {
                // skip empty-value headers (as they are discarded by libcurl)
                continue;
            }
            strhead       = strkey.append(":").append(strval);
        }else{
            strhead       = trim(lower(strhead));
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
bool MakeUrlResource(const char* realpath, string& resourcepath, string& url)
{
    if(!realpath){
        return false;
    }
    resourcepath = urlEncode(service_path + bucket + realpath);
    url          = s3host + resourcepath;
    return true;
}

string prepare_url(const char* url)
{
    S3FS_PRN_INFO3("URL is %s", url);

    string uri;
    string hostname;
    string path;
    string url_str = string(url);
    string token = string("/") + bucket;
    int bucket_pos;
    int bucket_length = token.size();
    int uri_length = 0;

    if(!strncasecmp(url_str.c_str(), "https://", 8)){
        uri_length = 8;
    } else if(!strncasecmp(url_str.c_str(), "http://", 7)) {
        uri_length = 7;
    }
    uri  = url_str.substr(0, uri_length);
    bucket_pos = url_str.find(token, uri_length);

    if(!pathrequeststyle){
        hostname = bucket + "." + url_str.substr(uri_length, bucket_pos - uri_length);
        path = url_str.substr((bucket_pos + bucket_length));
    }else{
        hostname = url_str.substr(uri_length, bucket_pos - uri_length);
        string part = url_str.substr((bucket_pos + bucket_length));
        if('/' != part[0]){
            part = "/" + part;
        }
        path = "/" + bucket + part;
    }

    url_str = uri + hostname + path;

    S3FS_PRN_INFO3("URL changed is %s", url_str.c_str());

    return url_str;
}

// [TODO]
// This function uses temporary file, but should not use it.
// For not using it, we implement function in each auth file(openssl, nss. gnutls).
//
bool make_md5_from_binary(const char* pstr, size_t length, string& md5)
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
    if(0 == md5.length()){
        S3FS_PRN_ERR("Failed to make MD5.");
        fclose(fp);
        return false;
    }
    fclose(fp);
    return true;
}

string url_to_host(const string &url)
{
    S3FS_PRN_INFO3("url is %s", url.c_str());

    static const string http = "http://";
    static const string https = "https://";
    std::string hostname;

    if (url.compare(0, http.size(), http) == 0) {
        hostname = url.substr(http.size());
    } else if (url.compare(0, https.size(), https) == 0) {
        hostname = url.substr(https.size());
    } else {
        S3FS_PRN_EXIT("url does not begin with http:// or https://");
        abort();
    }

    size_t idx;
    if ((idx = hostname.find('/')) != string::npos) {
        return hostname.substr(0, idx);
    } else {
        return hostname;
    }
}

string get_bucket_host()
{
    if(!pathrequeststyle){
        return bucket + "." + url_to_host(s3host);
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
bool etag_equals(string s1, string s2)
{
    if(s1.length() > 1 && s1[0] == '\"' && s1[s1.length() - 1] == '\"'){
        s1 = s1.substr(1, s1.size() - 2);
    }
    if(s2.length() > 1 && s2[0] == '\"' && s2[s2.length() - 1] == '\"'){
        s2 = s2.substr(1, s2.size() - 2);
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
