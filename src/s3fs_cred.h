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

#ifndef S3FS_CRED_H_
#define S3FS_CRED_H_

//----------------------------------------------
// Typedefs
//----------------------------------------------
typedef std::map<std::string, std::string> iamcredmap_t;

//------------------------------------------------
// class S3fsCred
//------------------------------------------------
// This is a class for operating and managing Credentials(accesskey,
// secret key, tokens, etc.) used by S3fs.
// Operations related to Credentials are aggregated in this class.
//
// cppcheck-suppress ctuOneDefinitionRuleViolation       ; for stub in test_curl_util.cpp
class S3fsCred
{
    private:
        static const char*  ALLBUCKET_FIELDS_TYPE;      // special key for mapping(This name is absolutely not used as a bucket name)
        static const char*  KEYVAL_FIELDS_TYPE;         // special key for mapping(This name is absolutely not used as a bucket name)
        static const char*  AWS_ACCESSKEYID;
        static const char*  AWS_SECRETKEY;

        static const int    IAM_EXPIRE_MERGIN;
        static const char*  IAMCRED_ACCESSKEYID;
        static const char*  IAMCRED_SECRETACCESSKEY;
        static const char*  IAMCRED_ROLEARN;

        static std::string  bucket_name;

        std::string         passwd_file;
        std::string         aws_profile;

        bool                load_iamrole;

        std::string         AWSAccessKeyId;
        std::string         AWSSecretAccessKey;
        std::string         AWSAccessToken;
        time_t              AWSAccessTokenExpire;

        bool                is_ecs;
        bool                is_use_session_token;
        bool                is_ibm_iam_auth;

        std::string         IAM_cred_url;
        int                 IAM_api_version;
        std::string         IAMv2_api_token;
        size_t              IAM_field_count;
        std::string         IAM_token_field;
        std::string         IAM_expiry_field;
        std::string         IAM_role;

    public:
        static const char*  ECS_IAM_ENV_VAR;

        static const char*  IAMv2_token_url;
        static int          IAMv2_token_ttl;
        static const char*  IAMv2_token_ttl_hdr;
        static const char*  IAMv2_token_hdr;

    private:
        static bool ParseIAMRoleFromMetaDataResponse(const char* response, std::string& rolename);

        bool SetS3fsPasswdFile(const char* file);
        bool IsSetPasswdFile();
        bool SetAwsProfileName(const char* profile_name);
        bool SetIAMRoleMetadataType(bool flag);

        bool SetAccessKey(const char* AccessKeyId, const char* SecretAccessKey);
        bool SetAccessKeyWithSessionToken(const char* AccessKeyId, const char* SecretAccessKey, const char * SessionToken);
        bool IsSetAccessKeys() const;

        bool SetIsECS(bool flag);
        bool SetIsUseSessionToken(bool flag);

        bool SetIsIBMIAMAuth(bool flag);

        std::string SetIAMRole(const char* role);
        size_t SetIAMFieldCount(size_t field_count);
        std::string SetIAMCredentialsURL(const char* url);
        std::string SetIAMTokenField(const char* token_field);
        std::string SetIAMExpiryField(const char* expiry_field);

        bool IsReadableS3fsPasswdFile();
        bool CheckS3fsPasswdFilePerms();
        bool ParseS3fsPasswdFile(bucketkvmap_t& resmap);
        bool ReadS3fsPasswdFile();

        int CheckS3fsCredentialAwsFormat(const kvmap_t& kvmap);
        bool ReadAwsCredentialFile(const std::string &filename);

        bool InitialS3fsCredentials();
        bool ParseIAMCredentialResponse(const char* response, iamcredmap_t& keyval);

        bool CheckForbiddenBucketParams();

    public:
        static bool SetBucket(const char* bucket);
        static const std::string& GetBucket();

        S3fsCred();
        ~S3fsCred();

        bool IsIAMRoleMetadataType() const { return load_iamrole; }
        const std::string& GetAccessKeyID() const { return AWSAccessKeyId; }
        const std::string& GetSecretAccessKey() const { return AWSSecretAccessKey; }
        const std::string& GetAccessToken() const { return AWSAccessToken; }

        bool IsECS() const { return is_ecs; }
        bool IsUseSessionToken() const { return is_use_session_token; }

        bool IsIBMIAMAuth() const { return is_ibm_iam_auth; }

        const std::string& GetIAMRole() const { return IAM_role; }
        const std::string& GetIAMCredentialsURL() const { return IAM_cred_url; }
        int SetIMDSVersion(int version);
        int GetIMDSVersion() const { return IAM_api_version; }

        bool SetIAMv2APIToken(const char* response);
        const std::string& GetIAMv2APIToken() const { return IAMv2_api_token; }
        bool SetIAMCredentials(const char* response);
        bool SetIAMRoleFromMetaData(const char* response);

        bool CheckIAMCredentialUpdate();

        int DetectParam(const char* arg);
        bool CheckAllParams();
};

#endif // S3FS_CRED_H_

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
