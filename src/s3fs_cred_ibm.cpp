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

#include <cstring>
#include <sstream>
#include <string>

#include "common.h"
#include "s3fs_cred_ibm.h"
#include "s3fs_logger.h"
#include "curl_util.h"
#include "string_util.h"

using namespace std::string_literals;

//-------------------------------------------------------------------
// Methods : Options
//-------------------------------------------------------------------
int IbmIamCred::DetectParam(const char* arg)
{
    if(!arg){
        return 1;
    }

    if(0 == strcmp(arg, "ibm_iam_auth")){
        enabled = true;
        return 0;
    }

    if(is_prefix(arg, "ibm_iam_endpoint=")){
        const char* iam_endpoint = strchr(arg, '=') + sizeof(char);

        // Check url for http / https protocol std::string
        if(!is_prefix(iam_endpoint, "https://") && !is_prefix(iam_endpoint, "http://")){
            S3FS_PRN_EXIT("option ibm_iam_endpoint has invalid format, missing http / https protocol");
            return -1;
        }
        endpoint = iam_endpoint;
        return 0;
    }

    return 1;
}

bool IbmIamCred::CheckAcl(acl_t acl) const
{
    if(!enabled){
        return true;
    }

    // check that default ACL is either public-read or private
    if(acl != acl_t::PRIVATE && acl != acl_t::PUBLIC_READ){
        S3FS_PRN_EXIT("can only use 'public-read' or 'private' ACL while using ibm_iam_auth");
        return false;
    }
    return true;
}

//-------------------------------------------------------------------
// Methods : Credential request
//-------------------------------------------------------------------
// [NOTE]
// The endpoint is kept separately from the derived URL so that
// "ibm_iam_endpoint" and "ibm_iam_auth" may be given in either order.
//
std::string IbmIamCred::GetCredentialsURL() const
{
    std::string url = endpoint.empty() ? std::string(IbmIamCred::DEFAULT_ENDPOINT) : endpoint;
    url += IbmIamCred::TOKEN_PATH;
    return url;
}

std::string IbmIamCred::MakePostBody(const std::string& apikey)
{
    return "grant_type=urn:ibm:params:oauth:grant-type:apikey&response_type=cloud_iam&apikey="s + apikey;
}

const char* IbmIamCred::GetAuthorization()
{
    // [NOTE]
    // "Yng6Yng=" is base64("bx:bx"), the well known public client credentials
    // which the IBM IAM token endpoint expects for this grant type.
    //
    return "Basic Yng6Yng=";
}

//-------------------------------------------------------------------
// Methods : Credential response
//-------------------------------------------------------------------
// The response is a JSON object whose access token is a quoted string and
// whose expiration is a bare integer(seconds since the epoch), ex:
//
//   {"access_token":"eyJ...","token_type":"Bearer","expiration":1600000000}
//
bool IbmIamCred::ParseCredentialResponse(const char* response, std::string& token, time_t& expire)
{
    if(!response){
        return false;
    }

    std::string strtoken;
    off_t       tmpexpire   = 0;
    bool        found_token = false;
    bool        found_expire= false;

    std::istringstream sscred(response);
    std::string        oneline;
    while(getline(sscred, oneline, ',')){
        std::string::size_type pos;
        bool                   is_token;

        if(std::string::npos != (pos = oneline.find(IbmIamCred::TOKEN_FIELD))){
            is_token = true;
            pos     += sizeof(IbmIamCred::TOKEN_FIELD) - 1;
        }else if(std::string::npos != (pos = oneline.find(IbmIamCred::EXPIRY_FIELD))){
            is_token = false;
            pos     += sizeof(IbmIamCred::EXPIRY_FIELD) - 1;
        }else{
            continue;
        }
        if(std::string::npos == (pos = oneline.find(':', pos))){
            continue;
        }

        if(is_token){
            // parse std::string value (starts and ends with quotes)
            if(std::string::npos == (pos = oneline.find('\"', pos))){
                continue;
            }
            oneline.erase(0, pos + 1);
            if(std::string::npos == (pos = oneline.find('\"'))){
                continue;
            }
            strtoken    = oneline.substr(0, pos);
            found_token = true;
        }else{
            // parse integer value
            if(std::string::npos == (pos = oneline.find_first_of("0123456789", pos))){
                continue;
            }
            oneline.erase(0, pos);
            if(std::string::npos == (pos = oneline.find_last_of("0123456789"))){
                continue;
            }
            if(!s3fs_strtoofft(&tmpexpire, oneline.substr(0, pos + 1).c_str(), /*base=*/ 10)){
                continue;
            }
            found_expire = true;
        }
    }

    if(!found_token || !found_expire){
        return false;
    }
    token  = strtoken;
    expire = static_cast<time_t>(tmpexpire);

    return true;
}

//-------------------------------------------------------------------
// Methods : Request signing
//-------------------------------------------------------------------
void IbmIamCred::InsertAuthHeaders(struct curl_slist*& headers, const std::string& op, const std::string& path, const std::string& access_key_id, const std::string& access_token)
{
    headers = curl_slist_sort_insert(headers, "Authorization", ("Bearer " + access_token).c_str());

    if(op == "PUT" && path == mount_prefix + "/"){
        // ibm-service-instance-id header is required for bucket creation requests
        headers = curl_slist_sort_insert(headers, "ibm-service-instance-id", access_key_id.c_str());
    }
}

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
