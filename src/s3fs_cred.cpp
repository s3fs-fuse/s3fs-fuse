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

#include <unistd.h>
#include <pwd.h>
#include <sys/types.h>
#include <fstream>
#include <sstream>

#include "common.h"
#include "s3fs.h"
#include "s3fs_cred.h"
#include "curl.h"
#include "string_util.h"
#include "metaheader.h"

//-------------------------------------------------------------------
// Symbols
//-------------------------------------------------------------------
#define	DEFAULT_AWS_PROFILE_NAME	"default"

//-------------------------------------------------------------------
// Class Variables
//-------------------------------------------------------------------
const char* S3fsCred::ALLBUCKET_FIELDS_TYPE     = "";
const char*	S3fsCred::KEYVAL_FIELDS_TYPE        = "\t";
const char* S3fsCred::AWS_ACCESSKEYID           = "AWSAccessKeyId";
const char* S3fsCred::AWS_SECRETKEY             = "AWSSecretKey";

const int   S3fsCred::IAM_EXPIRE_MERGIN         = 20 * 60;              // update timing
const char* S3fsCred::ECS_IAM_ENV_VAR           = "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI";
const char* S3fsCred::IAMCRED_ACCESSKEYID       = "AccessKeyId";
const char* S3fsCred::IAMCRED_SECRETACCESSKEY   = "SecretAccessKey";
const char* S3fsCred::IAMCRED_ROLEARN           = "RoleArn";

const char* S3fsCred::IAMv2_token_url           = "http://169.254.169.254/latest/api/token";
int         S3fsCred::IAMv2_token_ttl           = 21600;
const char* S3fsCred::IAMv2_token_ttl_hdr       = "X-aws-ec2-metadata-token-ttl-seconds";
const char* S3fsCred::IAMv2_token_hdr           = "X-aws-ec2-metadata-token";

std::string S3fsCred::bucket_name;

//-------------------------------------------------------------------
// Class Methods 
//-------------------------------------------------------------------
bool S3fsCred::SetBucket(const char* bucket)
{
    if(!bucket || strlen(bucket) == 0){
        return false;
    }
    S3fsCred::bucket_name = bucket;
    return true;
}

const std::string& S3fsCred::GetBucket()
{
	return S3fsCred::bucket_name;
}

bool S3fsCred::ParseIAMRoleFromMetaDataResponse(const char* response, std::string& rolename)
{
    if(!response){
        return false;
    }
    // [NOTE]
    // expected following strings.
    // 
    // myrolename
    //
    std::istringstream ssrole(response);
    std::string        oneline;
    if (getline(ssrole, oneline, '\n')){
        rolename = oneline;
        return !rolename.empty();
    }
    return false;
}

//-------------------------------------------------------------------
// Methods : Constructor / Destructor
//-------------------------------------------------------------------
S3fsCred::S3fsCred() :
    passwd_file(""),
    aws_profile(DEFAULT_AWS_PROFILE_NAME),
    load_iamrole(false),
    AWSAccessKeyId(""),
    AWSSecretAccessKey(""),
    AWSAccessToken(""),
    AWSAccessTokenExpire(0),
    is_ecs(false),
    is_use_session_token(false),
    is_ibm_iam_auth(false),
    IAM_cred_url("http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
    IAM_api_version(2),
    IAMv2_api_token(""),
    IAM_field_count(4),
    IAM_token_field("Token"),
    IAM_expiry_field("Expiration"),
    IAM_role("")
{
}

S3fsCred::~S3fsCred()
{
}

//-------------------------------------------------------------------
// Methods : Access member variables
//-------------------------------------------------------------------
bool S3fsCred::SetS3fsPasswdFile(const char* file)
{
    if(!file || strlen(file) == 0){
        return false;
    }
    passwd_file = file;

    return true;
}

bool S3fsCred::IsSetPasswdFile()
{
    return !passwd_file.empty();
}

bool S3fsCred::SetAwsProfileName(const char* name)
{
    if(!name || strlen(name) == 0){
        return false;
    }
    aws_profile = name;

    return true;
}

bool S3fsCred::SetIAMRoleMetadataType(bool flag)
{
    bool old = load_iamrole;
    load_iamrole = flag;
    return old;
}

bool S3fsCred::SetAccessKey(const char* AccessKeyId, const char* SecretAccessKey)
{
    if((!is_ibm_iam_auth && (!AccessKeyId || '\0' == AccessKeyId[0])) || !SecretAccessKey || '\0' == SecretAccessKey[0]){
        return false;
    }
    AWSAccessKeyId     = AccessKeyId;
    AWSSecretAccessKey = SecretAccessKey;

    return true;
}

bool S3fsCred::SetAccessKeyWithSessionToken(const char* AccessKeyId, const char* SecretAccessKey, const char * SessionToken)
{
    bool access_key_is_empty        = !AccessKeyId     || '\0' == AccessKeyId[0];
    bool secret_access_key_is_empty = !SecretAccessKey || '\0' == SecretAccessKey[0];
    bool session_token_is_empty     = !SessionToken    || '\0' == SessionToken[0];

    if((!is_ibm_iam_auth && access_key_is_empty) || secret_access_key_is_empty || session_token_is_empty){
        return false;
    }
    AWSAccessKeyId      = AccessKeyId;
    AWSSecretAccessKey  = SecretAccessKey;
    AWSAccessToken      = SessionToken;
    is_use_session_token= true;

    return true;
}

bool S3fsCred::IsSetAccessKeyID() const
{
    return !AWSAccessKeyId.empty();
}

bool S3fsCred::IsSetAccessKeys() const
{
    return !IAM_role.empty() || ((!AWSAccessKeyId.empty() || is_ibm_iam_auth) && !AWSSecretAccessKey.empty());
}

bool S3fsCred::SetIsECS(bool flag)
{
    bool old = is_ecs;
    is_ecs = flag;
    return old;
}

bool S3fsCred::SetIsUseSessionToken(bool flag)
{
    bool old = is_use_session_token;
    is_use_session_token = flag;
    return old;
}

bool S3fsCred::SetIsIBMIAMAuth(bool flag)
{
    bool old = is_ibm_iam_auth;
    is_ibm_iam_auth = flag;
    return old;
}

std::string S3fsCred::SetIAMRole(const char* role)
{
    std::string old = IAM_role;
    IAM_role = role ? role : "";
    return old;
}

size_t S3fsCred::SetIAMFieldCount(size_t field_count)
{
    size_t old = IAM_field_count;
    IAM_field_count = field_count;
    return old;
}

std::string S3fsCred::SetIAMCredentialsURL(const char* url)
{
    std::string old = IAM_cred_url;
    IAM_cred_url = url ? url : "";
    return old;
}

std::string S3fsCred::SetIAMTokenField(const char* token_field)
{
    std::string old = IAM_token_field;
    IAM_token_field = token_field ? token_field : "";
    return old;
}

std::string S3fsCred::SetIAMExpiryField(const char* expiry_field)
{
    std::string old = IAM_expiry_field;
    IAM_expiry_field = expiry_field ? expiry_field : "";
    return old;
}

int S3fsCred::SetIMDSVersion(int version)
{
    int old = IAM_api_version;
    IAM_api_version = version;
    return old;
}

bool S3fsCred::SetIAMv2APIToken(const char* response)
{
    S3FS_PRN_INFO3("Setting AWS IMDSv2 API token to %s", response ? response : "(null)");
    if(!response){
        return false;
    }
    IAMv2_api_token = std::string(response);
    return true;
}

bool S3fsCred::SetIAMCredentials(const char* response)
{
    S3FS_PRN_INFO3("IAM credential response = \"%s\"", response);

    iamcredmap_t keyval;

    if(!ParseIAMCredentialResponse(response, keyval)){
        return false;
    }

    if(IAM_field_count != keyval.size()){
        return false;
    }

    AWSAccessToken = keyval[IAM_token_field];

    if(is_ibm_iam_auth){
        off_t tmp_expire = 0;
        if(!s3fs_strtoofft(&tmp_expire, keyval[IAM_expiry_field].c_str(), /*base=*/ 10)){
            return false;
        }
        AWSAccessTokenExpire = static_cast<time_t>(tmp_expire);
    }else{
        AWSAccessKeyId       = keyval[std::string(S3fsCred::IAMCRED_ACCESSKEYID)];
        AWSSecretAccessKey   = keyval[std::string(S3fsCred::IAMCRED_SECRETACCESSKEY)];
        AWSAccessTokenExpire = cvtIAMExpireStringToTime(keyval[IAM_expiry_field].c_str());
    }
    return true;
}

bool S3fsCred::SetIAMRoleFromMetaData(const char* response)
{
    S3FS_PRN_INFO3("IAM role name response = \"%s\"", response ? response : "(null)");

    std::string rolename;
    if(!S3fsCred::ParseIAMRoleFromMetaDataResponse(response, rolename)){
        return false;
    }

    SetIAMRole(rolename.c_str());
    return true;
}


//-------------------------------------------------------------------
// Methods : for Credentials
//-------------------------------------------------------------------
//
// Check passwd file readable
//
bool S3fsCred::IsReadableS3fsPasswdFile()
{
    if(passwd_file.empty()){
        return false;
    }

    std::ifstream PF(passwd_file.c_str());
    if(!PF.good()){
        return false;
    }
    PF.close();

    return true;
}

//
// S3fsCred::CheckS3fsPasswdFilePerms
//
// expect that global passwd_file variable contains
// a non-empty value and is readable by the current user
//
// Check for too permissive access to the file
// help save users from themselves via a security hole
//
// only two options: return or error out
//
bool S3fsCred::CheckS3fsPasswdFilePerms()
{
    struct stat info;

    // let's get the file info
    if(stat(passwd_file.c_str(), &info) != 0){
        S3FS_PRN_EXIT("unexpected error from stat(%s).", passwd_file.c_str());
        return false;
    }

	// Check readable
    if(!IsReadableS3fsPasswdFile()){
        S3FS_PRN_EXIT("S3fs passwd file \"%s\" is not readable.", passwd_file.c_str());
        return false;
    }

    // return error if any file has others permissions
    if( (info.st_mode & S_IROTH) ||
        (info.st_mode & S_IWOTH) ||
        (info.st_mode & S_IXOTH)) {
        S3FS_PRN_EXIT("credentials file %s should not have others permissions.", passwd_file.c_str());
        return false;
    }

    // Any local file should not have any group permissions
    // /etc/passwd-s3fs can have group permissions
    if(passwd_file != "/etc/passwd-s3fs"){
        if( (info.st_mode & S_IRGRP) ||
            (info.st_mode & S_IWGRP) ||
            (info.st_mode & S_IXGRP)) {
            S3FS_PRN_EXIT("credentials file %s should not have group permissions.", passwd_file.c_str());
            return false;
        }
    }else{
        // "/etc/passwd-s3fs" does not allow group write.
        if((info.st_mode & S_IWGRP)){
            S3FS_PRN_EXIT("credentials file %s should not have group writable permissions.", passwd_file.c_str());
            return false;
        }
    }
    if((info.st_mode & S_IXUSR) || (info.st_mode & S_IXGRP)){
        S3FS_PRN_EXIT("credentials file %s should not have executable permissions.", passwd_file.c_str());
        return false;
    }
    return true;
}

//
// Read and Parse passwd file
//
// The line of the password file is one of the following formats:
//   (1) "accesskey:secretkey"         : AWS format for default(all) access key/secret key
//   (2) "bucket:accesskey:secretkey"  : AWS format for bucket's access key/secret key
//   (3) "key=value"                   : Content-dependent KeyValue contents
//
// This function sets result into bucketkvmap_t, it bucket name and key&value mapping.
// If bucket name is empty(1 or 3 format), bucket name for mapping is set "\t" or "".
//
// Return: true  - Succeed parsing
//         false - Should shutdown immediately
//
bool S3fsCred::ParseS3fsPasswdFile(bucketkvmap_t& resmap)
{
    std::string          line;
    size_t               first_pos;
    readline_t           linelist;
    readline_t::iterator iter;

    // open passwd file
    std::ifstream PF(passwd_file.c_str());
    if(!PF.good()){
        S3FS_PRN_EXIT("could not open passwd file : %s", passwd_file.c_str());
        return false;;
    }

    // read each line
    while(getline(PF, line)){
        line = trim(line);
        if(line.empty()){
            continue;
        }
        if('#' == line[0]){
            continue;
        }
        if(std::string::npos != line.find_first_of(" \t")){
            S3FS_PRN_EXIT("invalid line in passwd file, found whitespace character.");
            return false;;
        }
        if('[' == line[0]){
            S3FS_PRN_EXIT("invalid line in passwd file, found a bracket \"[\" character.");
            return false;;
        }
        linelist.push_back(line);
    }

    // read '=' type
    kvmap_t kv;
    for(iter = linelist.begin(); iter != linelist.end(); ++iter){
        first_pos = iter->find_first_of('=');
        if(first_pos == std::string::npos){
            continue;
        }
        // formatted by "key=val"
        std::string key = trim(iter->substr(0, first_pos));
        std::string val = trim(iter->substr(first_pos + 1, std::string::npos));
        if(key.empty()){
            continue;
        }
        if(kv.end() != kv.find(key)){
            S3FS_PRN_WARN("same key name(%s) found in passwd file, skip this.", key.c_str());
            continue;
        }
        kv[key] = val;
    }
    // set special key name
    resmap[S3fsCred::KEYVAL_FIELDS_TYPE] = kv;

    // read ':' type
    for(iter = linelist.begin(); iter != linelist.end(); ++iter){
        first_pos       = iter->find_first_of(':');
        size_t last_pos = iter->find_last_of(':');
        if(first_pos == std::string::npos){
            continue;
        }
        std::string bucketname;
        std::string accesskey;
        std::string secret;
        if(first_pos != last_pos){
            // formatted by "bucket:accesskey:secretkey"
            bucketname= trim(iter->substr(0, first_pos));
            accesskey = trim(iter->substr(first_pos + 1, last_pos - first_pos - 1));
            secret    = trim(iter->substr(last_pos + 1, std::string::npos));
        }else{
            // formatted by "accesskey:secretkey"
            bucketname= S3fsCred::ALLBUCKET_FIELDS_TYPE;
            accesskey = trim(iter->substr(0, first_pos));
            secret    = trim(iter->substr(first_pos + 1, std::string::npos));
        }
        if(resmap.end() != resmap.find(bucketname)){
            S3FS_PRN_EXIT("there are multiple entries for the same bucket(%s) in the passwd file.", (bucketname.empty() ? "default" : bucketname.c_str()));
            return false;;
        }
        kv.clear();
        kv[S3fsCred::AWS_ACCESSKEYID] = accesskey;
        kv[S3fsCred::AWS_SECRETKEY]   = secret;
        resmap[bucketname] = kv;
    }
    return true;
}

//
// ReadS3fsPasswdFile
//
// Support for per bucket credentials
//
// Format for the credentials file:
// [bucket:]AccessKeyId:SecretAccessKey
//
// Lines beginning with # are considered comments
// and ignored, as are empty lines
//
// Uncommented lines without the ":" character are flagged as
// an error, so are lines with spaces or tabs
//
// only one default key pair is allowed, but not required
//
bool S3fsCred::ReadS3fsPasswdFile()
{
    bucketkvmap_t bucketmap;
    kvmap_t       keyval;

    // if you got here, the password file
    // exists and is readable by the
    // current user, check for permissions
    if(!CheckS3fsPasswdFilePerms()){
        return false;
    }

    //
    // parse passwd file
    //
    if(!ParseS3fsPasswdFile(bucketmap)){
        return false;
    }

    //
    // check key=value type format.
    //
    bucketkvmap_t::iterator it = bucketmap.find(S3fsCred::KEYVAL_FIELDS_TYPE);
    if(bucketmap.end() != it){
        // aws format
        int result = CheckS3fsCredentialAwsFormat(it->second);
        if(-1 == result){
            return false;
        }else if(1 == result){
            // success to set
            return true;
        }
    }

    std::string bucket_key = S3fsCred::ALLBUCKET_FIELDS_TYPE;
    if(!S3fsCred::bucket_name.empty() && bucketmap.end() != bucketmap.find(S3fsCred::bucket_name)){
        bucket_key = S3fsCred::bucket_name;
    }

    it = bucketmap.find(bucket_key);
    if(bucketmap.end() == it){
        S3FS_PRN_EXIT("Not found access key/secret key in passwd file.");
        return false;
    }
    keyval = it->second;
    kvmap_t::iterator aws_accesskeyid_it = keyval.find(S3fsCred::AWS_ACCESSKEYID);
    kvmap_t::iterator aws_secretkey_it   = keyval.find(S3fsCred::AWS_SECRETKEY);
    if(keyval.end() == aws_accesskeyid_it || keyval.end() == aws_secretkey_it){
        S3FS_PRN_EXIT("Not found access key/secret key in passwd file.");
        return false;
    }

    if(!SetAccessKey(aws_accesskeyid_it->second.c_str(), aws_secretkey_it->second.c_str())){
        S3FS_PRN_EXIT("failed to set internal data for access key/secret key from passwd file.");
        return false;
    }
    return true;
}

//
// Return:  1 - OK(could read and set accesskey etc.)
//          0 - NG(could not read)
//         -1 - Should shutdown immediately
//
int S3fsCred::CheckS3fsCredentialAwsFormat(const kvmap_t& kvmap)
{
    std::string str1(S3fsCred::AWS_ACCESSKEYID);
    std::string str2(S3fsCred::AWS_SECRETKEY);

    if(kvmap.empty()){
        return 0;
    }
    kvmap_t::const_iterator str1_it = kvmap.find(str1);
    kvmap_t::const_iterator str2_it = kvmap.find(str2);
    if(kvmap.end() == str1_it && kvmap.end() == str2_it){
        return 0;
    }
    if(kvmap.end() == str1_it || kvmap.end() == str2_it){
        S3FS_PRN_EXIT("AWSAccesskey or AWSSecretkey is not specified.");
        return -1;
    }
    if(!SetAccessKey(str1_it->second.c_str(), str2_it->second.c_str())){
        S3FS_PRN_EXIT("failed to set access key/secret key.");
        return -1;
    }
    return 1;
}

//
// Read Aws Credential File
//
bool S3fsCred::ReadAwsCredentialFile(const std::string &filename)
{
    // open passwd file
    std::ifstream PF(filename.c_str());
    if(!PF.good()){
        return false;
    }

    std::string profile;
    std::string accesskey;
    std::string secret;
    std::string session_token;

    // read each line
    std::string line;
    while(getline(PF, line)){
        line = trim(line);
        if(line.empty()){
            continue;
        }
        if('#' == line[0]){
            continue;
        }

        if(line.size() > 2 && line[0] == '[' && line[line.size() - 1] == ']') {
            if(profile == aws_profile){
                break;
            }
            profile = line.substr(1, line.size() - 2);
            accesskey.clear();
            secret.clear();
            session_token.clear();
        }

        size_t pos = line.find_first_of('=');
        if(pos == std::string::npos){
            continue;
        }
        std::string key   = trim(line.substr(0, pos));
        std::string value = trim(line.substr(pos + 1, std::string::npos));
        if(key == "aws_access_key_id"){
            accesskey = value;
        }else if(key == "aws_secret_access_key"){
            secret = value;
        }else if(key == "aws_session_token"){
            session_token = value;
        }
    }

    if(profile != aws_profile){
        return false;
    }
    if(session_token.empty()){
        if(is_use_session_token){
            S3FS_PRN_EXIT("AWS session token was expected but wasn't provided in aws/credentials file for profile: %s.", aws_profile.c_str());
            return false;
        }
        if(!SetAccessKey(accesskey.c_str(), secret.c_str())){
            S3FS_PRN_EXIT("failed to set internal data for access key/secret key from aws credential file.");
            return false;
        }
    }else{
        if(!SetAccessKeyWithSessionToken(accesskey.c_str(), secret.c_str(), session_token.c_str())){
            S3FS_PRN_EXIT("session token is invalid.");
            return false;
        }
    }
    return true;
}

//
// InitialS3fsCredentials
//
// called only when were are not mounting a
// public bucket
//
// Here is the order precedence for getting the
// keys:
//
// 1 - from the command line  (security risk)
// 2 - from a password file specified on the command line
// 3 - from environment variables
// 3a - from the AWS_CREDENTIAL_FILE environment variable
// 3b - from ${HOME}/.aws/credentials
// 4 - from the users ~/.passwd-s3fs
// 5 - from /etc/passwd-s3fs
//
bool S3fsCred::InitialS3fsCredentials()
{
    // should be redundant
    if(S3fsCurl::IsPublicBucket()){
        return true;
    }

    // access key loading is deferred
    if(load_iamrole || is_ecs){
        return true;
    }

    // 1 - keys specified on the command line
    if(IsSetAccessKeys()){
        return true;
    }

    // 2 - was specified on the command line
    if(IsSetPasswdFile()){
        if(!ReadS3fsPasswdFile()){
            return false;;
        }
        return true;
    }

    // 3  - environment variables
    char* AWSACCESSKEYID     = getenv("AWS_ACCESS_KEY_ID") ?     getenv("AWS_ACCESS_KEY_ID") :     getenv("AWSACCESSKEYID");
    char* AWSSECRETACCESSKEY = getenv("AWS_SECRET_ACCESS_KEY") ? getenv("AWS_SECRET_ACCESS_KEY") : getenv("AWSSECRETACCESSKEY");
    char* AWSSESSIONTOKEN    = getenv("AWS_SESSION_TOKEN") ?     getenv("AWS_SESSION_TOKEN") :     getenv("AWSSESSIONTOKEN");

    if(AWSACCESSKEYID != NULL || AWSSECRETACCESSKEY != NULL){
        if( (AWSACCESSKEYID == NULL && AWSSECRETACCESSKEY != NULL) ||
            (AWSACCESSKEYID != NULL && AWSSECRETACCESSKEY == NULL) ){
            S3FS_PRN_EXIT("both environment variables AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY must be set together.");
            return false;;
        }
        S3FS_PRN_INFO2("access key from env variables");
        if(AWSSESSIONTOKEN != NULL){
            S3FS_PRN_INFO2("session token is available");
            if(!SetAccessKeyWithSessionToken(AWSACCESSKEYID, AWSSECRETACCESSKEY, AWSSESSIONTOKEN)){
                 S3FS_PRN_EXIT("session token is invalid.");
                 return false;;
            }
        }else{
            S3FS_PRN_INFO2("session token is not available");
            if(is_use_session_token){
                S3FS_PRN_EXIT("environment variable AWS_SESSION_TOKEN is expected to be set.");
                return false;;
            }
        }
        if(!SetAccessKey(AWSACCESSKEYID, AWSSECRETACCESSKEY)){
            S3FS_PRN_EXIT("if one access key is specified, both keys need to be specified.");
            return false;;
        }
        return true;
    }

    // 3a - from the AWS_CREDENTIAL_FILE environment variable
    char* AWS_CREDENTIAL_FILE = getenv("AWS_CREDENTIAL_FILE");
    if(AWS_CREDENTIAL_FILE != NULL){
        passwd_file = AWS_CREDENTIAL_FILE;
        if(!passwd_file.empty()){
            if(!ReadS3fsPasswdFile()){
                return false;;
            }
            return true;
        }
    }

    // 3b - check ${HOME}/.aws/credentials
    std::string aws_credentials = std::string(getpwuid(getuid())->pw_dir) + "/.aws/credentials";
    if(ReadAwsCredentialFile(aws_credentials)){
        return true;
    }else if(aws_profile != DEFAULT_AWS_PROFILE_NAME){
        S3FS_PRN_EXIT("Could not find profile: %s in file: %s", aws_profile.c_str(), aws_credentials.c_str());
        return false;;
    }

    // 4 - from the default location in the users home directory
    char* HOME = getenv("HOME");
    if(HOME != NULL){
        passwd_file = HOME;
        passwd_file += "/.passwd-s3fs";
        if(IsReadableS3fsPasswdFile()){
            if(!ReadS3fsPasswdFile()){
                return false;;
            }

            // It is possible that the user's file was there but
            // contained no key pairs i.e. commented out
            // in that case, go look in the final location
            if(IsSetAccessKeys()){
                return true;
            }
        }
    }

    // 5 - from the system default location
    passwd_file = "/etc/passwd-s3fs";
    if(IsReadableS3fsPasswdFile()){
        if(!ReadS3fsPasswdFile()){
            return false;;
        }
        return true;
    }

    S3FS_PRN_EXIT("could not determine how to establish security credentials.");
    return false;;
}

//-------------------------------------------------------------------
// Methods : for IAM
//-------------------------------------------------------------------
bool S3fsCred::ParseIAMCredentialResponse(const char* response, iamcredmap_t& keyval)
{
    if(!response){
      return false;
    }
    std::istringstream sscred(response);
    std::string        oneline;
    keyval.clear();
    while(getline(sscred, oneline, ',')){
        std::string::size_type pos;
        std::string            key;
        std::string            val;
        if(std::string::npos != (pos = oneline.find(S3fsCred::IAMCRED_ACCESSKEYID))){
            key = S3fsCred::IAMCRED_ACCESSKEYID;
        }else if(std::string::npos != (pos = oneline.find(S3fsCred::IAMCRED_SECRETACCESSKEY))){
            key = S3fsCred::IAMCRED_SECRETACCESSKEY;
        }else if(std::string::npos != (pos = oneline.find(IAM_token_field))){
            key = IAM_token_field;
        }else if(std::string::npos != (pos = oneline.find(IAM_expiry_field))){
            key = IAM_expiry_field;
        }else if(std::string::npos != (pos = oneline.find(S3fsCred::IAMCRED_ROLEARN))){
            key = S3fsCred::IAMCRED_ROLEARN;
        }else{
            continue;
        }
        if(std::string::npos == (pos = oneline.find(':', pos + key.length()))){
            continue;
        }

        if(is_ibm_iam_auth && key == IAM_expiry_field){
            // parse integer value
            if(std::string::npos == (pos = oneline.find_first_of("0123456789", pos))){
                continue;
            }
            oneline.erase(0, pos);
            if(std::string::npos == (pos = oneline.find_last_of("0123456789"))){
                continue;
            }
            val = oneline.substr(0, pos+1);
        }else{
            // parse std::string value (starts and ends with quotes)
            if(std::string::npos == (pos = oneline.find('\"', pos))){
                continue;
            }
            oneline.erase(0, pos+1);
            if(std::string::npos == (pos = oneline.find('\"'))){
                continue;
            }
            val = oneline.substr(0, pos);
        }
        keyval[key] = val;
    }
    return true;
}

bool S3fsCred::CheckIAMCredentialUpdate()
{
    if(IAM_role.empty() && !is_ecs && !is_ibm_iam_auth){
        return true;
    }
    if(time(NULL) + S3fsCred::IAM_EXPIRE_MERGIN <= AWSAccessTokenExpire){
        return true;
    }
    S3FS_PRN_INFO("IAM Access Token refreshing...");

    // update
    S3fsCurl s3fscurl;
    if(0 != s3fscurl.GetIAMCredentials()){
        S3FS_PRN_ERR("IAM Access Token refresh failed");
        return false;
    }
    S3FS_PRN_INFO("IAM Access Token refreshed");

    return true;
}

//-------------------------------------------------------------------
// Methods : Checking forbidden parameters
//-------------------------------------------------------------------
//
// Checking forbidden parameters for bucket
//
bool S3fsCred::CheckForbiddenBucketParams()
{
    // The first plain argument is the bucket
    if(bucket_name.empty()){
        S3FS_PRN_EXIT("missing BUCKET argument.");
        return false;
    }

    // bucket names cannot contain upper case characters in virtual-hosted style
    if(!pathrequeststyle && (lower(bucket_name) != bucket_name)){
        S3FS_PRN_EXIT("BUCKET %s, name not compatible with virtual-hosted style.", bucket_name.c_str());
        return false;
    }

    // check bucket name for illegal characters
    size_t found = bucket_name.find_first_of("/:\\;!@#$%^&*?|+=");
    if(found != std::string::npos){
        S3FS_PRN_EXIT("BUCKET %s -- bucket name contains an illegal character.", bucket_name.c_str());
        return false;
    }

    if(!pathrequeststyle && is_prefix(s3host.c_str(), "https://") && bucket_name.find_first_of('.') != std::string::npos) {
        S3FS_PRN_EXIT("BUCKET %s -- cannot mount bucket with . while using HTTPS without use_path_request_style", bucket_name.c_str());
        return false;
    }
    return true;
}

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
