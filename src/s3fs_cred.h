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

#include "autolock.h"

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
        static const char*  ECS_IAM_ENV_VAR;
        static const char*  IAMCRED_ACCESSKEYID;
        static const char*  IAMCRED_SECRETACCESSKEY;
        static const char*  IAMCRED_ROLEARN;

        static std::string  bucket_name;

        pthread_mutex_t     token_lock;
        bool                is_lock_init;

        std::string         passwd_file;
        std::string         aws_profile;

        bool                load_iamrole;

        std::string         AWSAccessKeyId;         // Protect exclusively
        std::string         AWSSecretAccessKey;     // Protect exclusively
        std::string         AWSAccessToken;         // Protect exclusively
        time_t              AWSAccessTokenExpire;   // Protect exclusively

        bool                is_ecs;
        bool                is_use_session_token;
        bool                is_ibm_iam_auth;

        std::string         IAM_cred_url;
        int                 IAM_api_version;        // Protect exclusively
        std::string         IAMv2_api_token;        // Protect exclusively
        size_t              IAM_field_count;
        std::string         IAM_token_field;
        std::string         IAM_expiry_field;
        std::string         IAM_role;               // Protect exclusively

    public:
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

        bool SetAccessKey(const char* AccessKeyId, const char* SecretAccessKey, AutoLock::Type type);
        bool SetAccessKeyWithSessionToken(const char* AccessKeyId, const char* SecretAccessKey, const char * SessionToken, AutoLock::Type type);
        bool IsSetAccessKeys(AutoLock::Type type);

        bool SetIsECS(bool flag);
        bool SetIsUseSessionToken(bool flag);

        bool SetIsIBMIAMAuth(bool flag);

        int SetIMDSVersion(int version, AutoLock::Type type);
        int GetIMDSVersion(AutoLock::Type type);

        bool SetIAMv2APIToken(const std::string& token, AutoLock::Type type);
        std::string GetIAMv2APIToken(AutoLock::Type type);

        bool SetIAMRole(const char* role, AutoLock::Type type);
        std::string GetIAMRole(AutoLock::Type type);
        bool IsSetIAMRole(AutoLock::Type type);
        size_t SetIAMFieldCount(size_t field_count);
        std::string SetIAMCredentialsURL(const char* url);
        std::string SetIAMTokenField(const char* token_field);
        std::string SetIAMExpiryField(const char* expiry_field);

        bool IsReadableS3fsPasswdFile();
        bool CheckS3fsPasswdFilePerms();
        bool ParseS3fsPasswdFile(bucketkvmap_t& resmap);
        bool ReadS3fsPasswdFile(AutoLock::Type type);

        static int CheckS3fsCredentialAwsFormat(const kvmap_t& kvmap, std::string& access_key_id, std::string& secret_access_key);
        bool ReadAwsCredentialFile(const std::string &filename, AutoLock::Type type);

        bool InitialS3fsCredentials();
        bool ParseIAMCredentialResponse(const char* response, iamcredmap_t& keyval);

        bool GetIAMCredentialsURL(std::string& url, bool check_iam_role, AutoLock::Type type);
        bool LoadIAMCredentials(AutoLock::Type type);
        bool SetIAMCredentials(const char* response, AutoLock::Type type);
        bool SetIAMRoleFromMetaData(const char* response, AutoLock::Type type);

        static bool CheckForbiddenBucketParams();

    public:
        static bool SetBucket(const char* bucket);
        static const std::string& GetBucket();

        S3fsCred();
        ~S3fsCred();

        bool IsIBMIAMAuth() const { return is_ibm_iam_auth; }

        bool LoadIAMRoleFromMetaData();

        bool CheckIAMCredentialUpdate(std::string* access_key_id = NULL, std::string* secret_access_key = NULL, std::string* access_token = NULL);

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
