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

#include <ctime>
#include <string>

#include "curl_util.h"
#include "s3fs_cred_ibm.h"
#include "test_util.h"

//---------------------------------------------------------
// Stubs
//
// [NOTE]
// mount_prefix is defined in s3fs_util.cpp and S3fsCred::GetBucket is
// called from curl_util.cpp; neither of those files can be linked here
// without pulling in most of s3fs.  IbmIamCred itself needs no more than
// this, which is the point of it being a separate class.
//
std::string mount_prefix;

class S3fsCred
{
    private:
        static std::string  bucket_name;
    public:
        static const std::string& GetBucket();
};

std::string  S3fsCred::bucket_name;

const std::string& S3fsCred::GetBucket()
{
    return S3fsCred::bucket_name;
}
//---------------------------------------------------------

//---------------------------------------------------------
// Options
//---------------------------------------------------------
void test_detect_param()
{
    // not an IBM option
    {
        IbmIamCred ibm;
        ASSERT_EQUALS(1, ibm.DetectParam("ecs"));
        ASSERT_EQUALS(1, ibm.DetectParam(nullptr));
        ASSERT_FALSE(ibm.IsEnabled());
    }

    // ibm_iam_auth alone uses the default endpoint
    {
        IbmIamCred ibm;
        ASSERT_EQUALS(0, ibm.DetectParam("ibm_iam_auth"));
        ASSERT_TRUE(ibm.IsEnabled());
        ASSERT_EQUALS(std::string("https://iam.cloud.ibm.com/identity/token"), ibm.GetCredentialsURL());
    }

    // ibm_iam_endpoint does not by itself enable IBM IAM authentication
    {
        IbmIamCred ibm;
        ASSERT_EQUALS(0, ibm.DetectParam("ibm_iam_endpoint=https://private.iam.example.com"));
        ASSERT_FALSE(ibm.IsEnabled());
    }

    // the endpoint must carry a protocol
    {
        IbmIamCred ibm;
        ASSERT_EQUALS(-1, ibm.DetectParam("ibm_iam_endpoint=private.iam.example.com"));
        ASSERT_EQUALS(std::string("https://iam.cloud.ibm.com/identity/token"), ibm.GetCredentialsURL());
    }

    // both orders of the two options give the same endpoint
    {
        IbmIamCred ibm;
        ASSERT_EQUALS(0, ibm.DetectParam("ibm_iam_auth"));
        ASSERT_EQUALS(0, ibm.DetectParam("ibm_iam_endpoint=https://private.iam.example.com"));
        ASSERT_TRUE(ibm.IsEnabled());
        ASSERT_EQUALS(std::string("https://private.iam.example.com/identity/token"), ibm.GetCredentialsURL());
    }
    {
        IbmIamCred ibm;
        ASSERT_EQUALS(0, ibm.DetectParam("ibm_iam_endpoint=http://private.iam.example.com"));
        ASSERT_EQUALS(0, ibm.DetectParam("ibm_iam_auth"));
        ASSERT_TRUE(ibm.IsEnabled());
        ASSERT_EQUALS(std::string("http://private.iam.example.com/identity/token"), ibm.GetCredentialsURL());
    }
}

void test_check_acl()
{
    // no restriction while IBM IAM authentication is off
    {
        IbmIamCred ibm;
        ASSERT_TRUE(ibm.CheckAcl(acl_t::PUBLIC_READ_WRITE));
    }

    {
        IbmIamCred ibm;
        ASSERT_EQUALS(0, ibm.DetectParam("ibm_iam_auth"));
        ASSERT_TRUE(ibm.CheckAcl(acl_t::PRIVATE));
        ASSERT_TRUE(ibm.CheckAcl(acl_t::PUBLIC_READ));
        ASSERT_FALSE(ibm.CheckAcl(acl_t::PUBLIC_READ_WRITE));
        ASSERT_FALSE(ibm.CheckAcl(acl_t::AUTHENTICATED_READ));
    }
}

//---------------------------------------------------------
// Credential request
//---------------------------------------------------------
void test_make_post_body()
{
    ASSERT_EQUALS(std::string("grant_type=urn:ibm:params:oauth:grant-type:apikey&response_type=cloud_iam&apikey=SECRET"), IbmIamCred::MakePostBody("SECRET"));
    ASSERT_STREQUALS("Basic Yng6Yng=", IbmIamCred::GetAuthorization());
}

//---------------------------------------------------------
// Credential response
//---------------------------------------------------------
void test_parse_credential_response()
{
    std::string token;
    time_t      expire;

    // a representative token endpoint response
    {
        constexpr char response[] = "{\"access_token\":\"eyJraWQiOiIyMDI1MDgxMiJ9.payload.sig\",\"refresh_token\":\"not_supported\",\"token_type\":\"Bearer\",\"expires_in\":3600,\"expiration\":1600003600,\"scope\":\"ibm openid\"}";
        token.clear();
        expire = 0;
        ASSERT_TRUE(IbmIamCred::ParseCredentialResponse(response, token, expire));
        ASSERT_EQUALS(std::string("eyJraWQiOiIyMDI1MDgxMiJ9.payload.sig"), token);
        ASSERT_EQUALS(static_cast<time_t>(1600003600), expire);
    }

    // the fields are matched with their quotes, so a value cannot pose as a key
    {
        constexpr char response[] = "{\"scope\":\"ibm openid expiration access_token\",\"access_token\":\"tok\",\"expiration\":1600003600}";
        token.clear();
        expire = 0;
        ASSERT_TRUE(IbmIamCred::ParseCredentialResponse(response, token, expire));
        ASSERT_EQUALS(std::string("tok"), token);
        ASSERT_EQUALS(static_cast<time_t>(1600003600), expire);
    }

    // both fields are required
    {
        token.clear();
        expire = 0;
        ASSERT_FALSE(IbmIamCred::ParseCredentialResponse("{\"access_token\":\"tok\"}", token, expire));
        ASSERT_FALSE(IbmIamCred::ParseCredentialResponse("{\"expiration\":1600003600}", token, expire));
    }

    // a non-numeric expiration is rejected
    {
        token.clear();
        expire = 0;
        ASSERT_FALSE(IbmIamCred::ParseCredentialResponse("{\"access_token\":\"tok\",\"expiration\":\"soon\"}", token, expire));
    }

    // malformed and empty input
    {
        token.clear();
        expire = 0;
        ASSERT_FALSE(IbmIamCred::ParseCredentialResponse(nullptr, token, expire));
        ASSERT_FALSE(IbmIamCred::ParseCredentialResponse("", token, expire));
        ASSERT_FALSE(IbmIamCred::ParseCredentialResponse("not json", token, expire));
        ASSERT_FALSE(IbmIamCred::ParseCredentialResponse("{\"access_token\":\"unterminated,\"expiration\":1}", token, expire));
    }
}

//---------------------------------------------------------
// Request signing
//---------------------------------------------------------
void test_insert_auth_headers()
{
    mount_prefix.clear();

    // an ordinary request carries only the bearer token
    {
        struct curl_slist* headers = nullptr;
        IbmIamCred::InsertAuthHeaders(headers, "GET", "/dir/file", "instance-id", "TOKEN");
        ASSERT_EQUALS(std::string("Bearer TOKEN"), get_header_value(headers, "authorization"));
        ASSERT_EQUALS(std::string(""), get_header_value(headers, "ibm-service-instance-id"));
        curl_slist_free_all(headers);
    }

    // a bucket creation request also carries the service instance id
    {
        struct curl_slist* headers = nullptr;
        IbmIamCred::InsertAuthHeaders(headers, "PUT", "/", "instance-id", "TOKEN");
        ASSERT_EQUALS(std::string("Bearer TOKEN"), get_header_value(headers, "authorization"));
        ASSERT_EQUALS(std::string("instance-id"), get_header_value(headers, "ibm-service-instance-id"));
        curl_slist_free_all(headers);
    }

    // a PUT of an object is not a bucket creation
    {
        struct curl_slist* headers = nullptr;
        IbmIamCred::InsertAuthHeaders(headers, "PUT", "/dir/file", "instance-id", "TOKEN");
        ASSERT_EQUALS(std::string(""), get_header_value(headers, "ibm-service-instance-id"));
        curl_slist_free_all(headers);
    }

    // the bucket root moves with the mount prefix
    {
        mount_prefix = "/prefix";

        struct curl_slist* headers = nullptr;
        IbmIamCred::InsertAuthHeaders(headers, "PUT", "/prefix/", "instance-id", "TOKEN");
        ASSERT_EQUALS(std::string("instance-id"), get_header_value(headers, "ibm-service-instance-id"));
        curl_slist_free_all(headers);

        headers = nullptr;
        IbmIamCred::InsertAuthHeaders(headers, "PUT", "/", "instance-id", "TOKEN");
        ASSERT_EQUALS(std::string(""), get_header_value(headers, "ibm-service-instance-id"));
        curl_slist_free_all(headers);

        mount_prefix.clear();
    }
}

int main(int argc, const char *argv[])
{
    test_detect_param();
    test_check_acl();
    test_make_post_body();
    test_parse_credential_response();
    test_insert_auth_headers();
    return 0;
}

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
