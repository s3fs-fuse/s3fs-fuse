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

#include <map>
#include <mutex>
#include <string>

#include "common.h"
#include "s3fs_extcred.h"
#include "types.h"

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
        static constexpr char ALLBUCKET_FIELDS_TYPE[] = "";  // special key for mapping(This name is absolutely not used as a bucket name)
        static constexpr char KEYVAL_FIELDS_TYPE[] = "\t";  // special key for mapping(This name is absolutely not used as a bucket name)
        static constexpr char AWS_ACCESSKEYID[] = "AWSAccessKeyId";
        static constexpr char AWS_SECRETKEY[] = "AWSSecretKey";

        static constexpr int IAM_EXPIRE_MERGING = 20 * 60;  // update timing
        static constexpr char ECS_IAM_ENV_VAR[] = "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI";
        static constexpr char IAMCRED_ACCESSKEYID[] = "AccessKeyId";
        static constexpr char IAMCRED_SECRETACCESSKEY[] = "SecretAccessKey";
        static constexpr char IAMCRED_ROLEARN[] = "RoleArn";

        static std::string  bucket_name;

        mutable std::mutex token_lock;

        std::string         passwd_file;
        std::string         aws_profile;

        bool                load_iamrole;

        std::string         AWSAccessKeyId GUARDED_BY(token_lock);
        std::string         AWSSecretAccessKey GUARDED_BY(token_lock);
        std::string         AWSAccessToken GUARDED_BY(token_lock);
        time_t              AWSAccessTokenExpire GUARDED_BY(token_lock);

        bool                is_ecs;
        bool                is_use_session_token;
        bool                is_ibm_iam_auth;

        std::string         IAM_cred_url;
        int                 IAM_api_version GUARDED_BY(token_lock);
        std::string         IAMv2_api_token GUARDED_BY(token_lock);
        size_t              IAM_field_count;
        std::string         IAM_token_field;
        std::string         IAM_expiry_field;
        std::string         IAM_role GUARDED_BY(token_lock);

        bool                set_builtin_cred_opts;  // true if options other than "credlib" is set
        std::string         credlib;                // credlib(name or path)
        std::string         credlib_opts;           // options for credlib

        void*                    hExtCredLib;
        fp_VersionS3fsCredential pFuncCredVersion;
        fp_InitS3fsCredential    pFuncCredInit;
        fp_FreeS3fsCredential    pFuncCredFree;
        fp_UpdateS3fsCredential  pFuncCredUpdate;

    public:
        static constexpr char IAMv2_token_url[] = "http://169.254.169.254/latest/api/token";
        static constexpr int IAMv2_token_ttl = 21600;
        static constexpr char IAMv2_token_ttl_hdr[] = "X-aws-ec2-metadata-token-ttl-seconds";
        static constexpr char IAMv2_token_hdr[] = "X-aws-ec2-metadata-token";

    private:
        static bool ParseIAMRoleFromMetaDataResponse(const char* response, std::string& rolename);

        bool SetS3fsPasswdFile(const char* file);
        bool IsSetPasswdFile() const;
        bool SetAwsProfileName(const char* profile_name);
        bool SetIAMRoleMetadataType(bool flag);

        bool SetAccessKey(const char* AccessKeyId, const char* SecretAccessKey) REQUIRES(S3fsCred::token_lock);
        bool SetAccessKeyWithSessionToken(const char* AccessKeyId, const char* SecretAccessKey, const char * SessionToken) REQUIRES(S3fsCred::token_lock);
        bool IsSetAccessKeys() const REQUIRES(S3fsCred::token_lock);

        bool SetIsECS(bool flag);
        bool SetIsUseSessionToken(bool flag);

        bool SetIsIBMIAMAuth(bool flag);

        int SetIMDSVersionHasLock(int version) REQUIRES(S3fsCred::token_lock);
        int SetIMDSVersion(int version)
        {
            const std::lock_guard<std::mutex> lock(token_lock);
            return SetIMDSVersionHasLock(version);
        }
        int GetIMDSVersion() const REQUIRES(S3fsCred::token_lock);

        bool SetIAMv2APITokenHasLock(const std::string& token) REQUIRES(S3fsCred::token_lock);
        const std::string& GetIAMv2APIToken() const REQUIRES(S3fsCred::token_lock);

        bool SetIAMRole(const char* role) REQUIRES(S3fsCred::token_lock);
        const std::string& GetIAMRoleHasLock() const REQUIRES(S3fsCred::token_lock);
        const std::string& GetIAMRole() const
        {
            const std::lock_guard<std::mutex> lock(token_lock);
            return GetIAMRoleHasLock();
        }
        bool IsSetIAMRole() const REQUIRES(S3fsCred::token_lock);
        size_t SetIAMFieldCount(size_t field_count);
        std::string SetIAMCredentialsURL(const char* url);
        std::string SetIAMTokenField(const char* token_field);
        std::string SetIAMExpiryField(const char* expiry_field);

        bool IsReadableS3fsPasswdFile() const;
        bool CheckS3fsPasswdFilePerms();
        bool ParseS3fsPasswdFile(bucketkvmap_t& resmap);
        bool ReadS3fsPasswdFile() REQUIRES(S3fsCred::token_lock);

        static int CheckS3fsCredentialAwsFormat(const kvmap_t& kvmap, std::string& access_key_id, std::string& secret_access_key);
        bool ReadAwsCredentialFile(const std::string &filename) REQUIRES(S3fsCred::token_lock);

        bool InitialS3fsCredentials() REQUIRES(S3fsCred::token_lock);
        bool ParseIAMCredentialResponse(const char* response, iamcredmap_t& keyval);

        bool GetIAMCredentialsURL(std::string& url, bool check_iam_role) REQUIRES(S3fsCred::token_lock);
        bool LoadIAMCredentials() REQUIRES(S3fsCred::token_lock);
        bool SetIAMCredentials(const char* response);
        bool SetIAMRoleFromMetaData(const char* response);

        bool SetExtCredLib(const char* arg);
        bool IsSetExtCredLib() const;
        bool SetExtCredLibOpts(const char* args);
        bool IsSetExtCredLibOpts() const;

        bool InitExtCredLib();
        bool LoadExtCredLib();
        bool UnloadExtCredLib();
        bool UpdateExtCredentials() REQUIRES(S3fsCred::token_lock);

        static bool CheckForbiddenBucketParams();

    public:
        static bool SetBucket(const std::string& bucket);
        static const std::string& GetBucket();

        S3fsCred();
        ~S3fsCred();
        S3fsCred(const S3fsCred&) = delete;
        S3fsCred(S3fsCred&&) = delete;
        S3fsCred& operator=(const S3fsCred&) = delete;
        S3fsCred& operator=(S3fsCred&&) = delete;

        bool IsIBMIAMAuth() const { return is_ibm_iam_auth; }

        bool LoadIAMRoleFromMetaData();

        bool CheckIAMCredentialUpdate(std::string* access_key_id = nullptr, std::string* secret_access_key = nullptr, std::string* access_token = nullptr);
        const char* GetCredFuncVersion(bool detail) const;

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
