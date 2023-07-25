/*
 * s3fs - FUSE-based file system backed by Amazon S3
 *
 * Copyright(C) 2007 Takeshi Nakatani <ggtakec@gmail.com>
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

#ifndef S3FS_EXTCRED_H_
#define S3FS_EXTCRED_H_

//-------------------------------------------------------------------
// Attributes(weak) : use only in s3fs-fuse internally
//-------------------------------------------------------------------
// [NOTE]
// This macro is only used inside s3fs-fuse.
// External projects that utilize this header file substitute empty
//values as follows:
//
#ifndef	S3FS_FUNCATTR_WEAK
#define	S3FS_FUNCATTR_WEAK
#endif

extern "C" {
//-------------------------------------------------------------------
// Prototype for External Credential 4 functions
//-------------------------------------------------------------------
//
// [Required] VersionS3fsCredential
//
// Returns the library name and version as a string.
//
extern const char* VersionS3fsCredential(bool detail) S3FS_FUNCATTR_WEAK;

//
// [Optional] InitS3fsCredential
//
// A function that does the necessary initialization after the library is
// loaded. This function is called only once immediately after loading the
// library.
// If there is a required initialization inside the library, implement it.
// Implementation of this function is optional and not required. If not
// implemented, it will not be called.
//
// const char* popts : String passed with the credlib_opts option. If the
//                     credlib_opts option is not specified, nullptr will be
//                     passed.
// char** pperrstr   : pperrstr is used to pass the error message to the
//                     caller when an error occurs.
//                     If this pointer is not nullptr, you can allocate memory
//                     and set an error message to it. The allocated memory
//                     area is freed by the caller.
//
extern bool InitS3fsCredential(const char* popts, char** pperrstr) S3FS_FUNCATTR_WEAK;

//
// [Optional] FreeS3fsCredential
//
// A function that is called only once just before the library is unloaded.
// If there is a required discard process in the library, implement it.
// Implementation of this feature is optional and not required.
// If not implemented, it will not be called.
//
// char** pperrstr : pperrstr is used to pass the error message to the
//                   caller when an error occurs.
//                   If this pointer is not nullptr, you can allocate memory
//                   and set an error message to it. The allocated memory
//                   area is freed by the caller.
//
extern bool FreeS3fsCredential(char** pperrstr) S3FS_FUNCATTR_WEAK;

//
// [Required] UpdateS3fsCredential
//
// A function that updates the token.
//
// char** ppaccess_key_id     : Allocate and set "Access Key ID" string
//                              area to *ppaccess_key_id.
// char** ppserect_access_key : Allocate and set "Access Secret Key ID"
//                              string area to *ppserect_access_key.
// char** ppaccess_token      : Allocate and set "Token" string area to
//                              *ppaccess_token.
// long long* ptoken_expire   : Set token expire time(time_t) value to
//                              *ptoken_expire.
//                              This is essentially a time_t* variable.
//                              To avoid system differences about time_t
//                              size, long long* is used.
//                              When setting the value, cast from time_t
//                              to long long to set the value.
// char** pperrstr            : pperrstr is used to pass the error message to the
//                              caller when an error occurs.
//
// For all argument of the character string pointer(char **) set the
// allocated string area. The allocated area is freed by the caller.
//
extern bool UpdateS3fsCredential(char** ppaccess_key_id, char** ppserect_access_key, char** ppaccess_token, long long* ptoken_expire, char** pperrstr) S3FS_FUNCATTR_WEAK;

//---------------------------------------------------------
// Typedef Prototype function
//---------------------------------------------------------
//
// const char* VersionS3fsCredential()
//
typedef const char* (*fp_VersionS3fsCredential)(bool detail);

//
// bool InitS3fsCredential(char** pperrstr)
//
typedef bool (*fp_InitS3fsCredential)(const char* popts, char** pperrstr);

//
// bool FreeS3fsCredential(char** pperrstr)
//
typedef bool (*fp_FreeS3fsCredential)(char** pperrstr);

//
// bool UpdateS3fsCredential(char** ppaccess_key_id, char** ppserect_access_key, char** ppaccess_token, long long* ptoken_expire, char** pperrstr)
//
typedef bool (*fp_UpdateS3fsCredential)(char** ppaccess_key_id, char** ppserect_access_key, char** ppaccess_token, long long* ptoken_expire, char** pperrstr);

}   // extern "C"

#endif // S3FS_EXTCRED_H_

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
