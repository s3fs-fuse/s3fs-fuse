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

#ifndef S3FS_CRED_IBM_H_
#define S3FS_CRED_IBM_H_

#include <ctime>
#include <curl/curl.h>
#include <string>

#include "types.h"

//------------------------------------------------
// class IbmIamCred
//------------------------------------------------
// IBM Cloud Object Storage authenticates with a bearer token fetched from an
// IAM token endpoint instead of signing every request with an AWS signature.
// Everything s3fs does differently for IBM is collected in this class:
//
//   - the "ibm_iam_auth" and "ibm_iam_endpoint" options
//   - building the token request(URL, POST body and Authorization header)
//   - parsing the token response, whose expiration is a bare integer
//   - the request headers, which carry a bearer token, not a signature
//
// The class holds no S3fs-wide state and calls into no other s3fs class, so
// it can be exercised on its own(see test_cred_ibm.cpp).
//
class IbmIamCred
{
    private:
        static constexpr char DEFAULT_ENDPOINT[] = "https://iam.cloud.ibm.com";
        static constexpr char TOKEN_PATH[]       = "/identity/token";

        // [NOTE]
        // The response fields are matched together with their surrounding
        // quotes so that only the JSON key itself can match, and not a value
        // which happens to contain the same text.
        //
        static constexpr char TOKEN_FIELD[]      = "\"access_token\"";
        static constexpr char EXPIRY_FIELD[]     = "\"expiration\"";

        bool        enabled = false;
        std::string endpoint;

    public:
        bool IsEnabled() const { return enabled; }

        //
        // Options
        //
        // return value:  1 = not an option for this class
        //                0 = the option was detected and processed
        //               -1 = a fatal error was detected
        //
        int DetectParam(const char* arg);
        bool CheckAcl(acl_t acl) const;

        //
        // Credential request
        //
        std::string GetCredentialsURL() const;
        static std::string MakePostBody(const std::string& apikey);
        static const char* GetAuthorization();

        //
        // Credential response
        //
        static bool ParseCredentialResponse(const char* response, std::string& token, time_t& expire);

        //
        // Request signing
        //
        static void InsertAuthHeaders(struct curl_slist*& headers, const std::string& op, const std::string& path, const std::string& access_key_id, const std::string& access_token);
};

#endif // S3FS_CRED_IBM_H_

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
