/*
 * s3fs - FUSE-based file system backed by Amazon S3
 *
 * Copyright 2007-2008 Randy Rizun <rrizun@gmail.com>
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

#ifndef S3FS_COMMON_H_
#define S3FS_COMMON_H_

#include "../config.h"

//
// Macro
//
#define SAFESTRPTR(strptr) (strptr ? strptr : "")

//
// Debug level
//
enum s3fs_log_level{
 S3FS_LOG_CRIT = 0,          // LOG_CRIT
 S3FS_LOG_ERR  = 1,          // LOG_ERR
 S3FS_LOG_WARN = 3,          // LOG_WARNING
 S3FS_LOG_INFO = 7,          // LOG_INFO
 S3FS_LOG_DBG  = 15          // LOG_DEBUG
};

//
// Debug macros
//
#define IS_S3FS_LOG_CRIT()   (S3FS_LOG_CRIT == debug_level)
#define IS_S3FS_LOG_ERR()    (S3FS_LOG_ERR  == (debug_level & S3FS_LOG_DBG))
#define IS_S3FS_LOG_WARN()   (S3FS_LOG_WARN == (debug_level & S3FS_LOG_DBG))
#define IS_S3FS_LOG_INFO()   (S3FS_LOG_INFO == (debug_level & S3FS_LOG_DBG))
#define IS_S3FS_LOG_DBG()    (S3FS_LOG_DBG  == (debug_level & S3FS_LOG_DBG))

#define S3FS_LOG_LEVEL_TO_SYSLOG(level) \
        ( S3FS_LOG_DBG  == (level & S3FS_LOG_DBG) ? LOG_DEBUG   : \
          S3FS_LOG_INFO == (level & S3FS_LOG_DBG) ? LOG_INFO    : \
          S3FS_LOG_WARN == (level & S3FS_LOG_DBG) ? LOG_WARNING : \
          S3FS_LOG_ERR  == (level & S3FS_LOG_DBG) ? LOG_ERR     : LOG_CRIT )

#define S3FS_LOG_LEVEL_STRING(level) \
        ( S3FS_LOG_DBG  == (level & S3FS_LOG_DBG) ? "[DBG] " : \
          S3FS_LOG_INFO == (level & S3FS_LOG_DBG) ? "[INF] " : \
          S3FS_LOG_WARN == (level & S3FS_LOG_DBG) ? "[WAN] " : \
          S3FS_LOG_ERR  == (level & S3FS_LOG_DBG) ? "[ERR] " : "[CRT] " )

#define S3FS_LOG_NEST_MAX    4
#define S3FS_LOG_NEST(nest)  (nest < S3FS_LOG_NEST_MAX ? s3fs_log_nest[nest] : s3fs_log_nest[S3FS_LOG_NEST_MAX - 1])

#define S3FS_LOW_LOGPRN(level, fmt, ...) \
       if(S3FS_LOG_CRIT == level || (S3FS_LOG_CRIT != debug_level && level == (debug_level & level))){ \
         if(foreground){ \
           fprintf(stdout, "%s%s:%s(%d): " fmt "%s\n", S3FS_LOG_LEVEL_STRING(level), __FILE__, __func__, __LINE__, __VA_ARGS__); \
         }else{ \
           syslog(S3FS_LOG_LEVEL_TO_SYSLOG(level), "%s:%s(%d): " fmt "%s", __FILE__, __func__, __LINE__, __VA_ARGS__); \
         } \
       }

#define S3FS_LOW_LOGPRN2(level, nest, fmt, ...) \
       if(S3FS_LOG_CRIT == level || (S3FS_LOG_CRIT != debug_level && level == (debug_level & level))){ \
         if(foreground){ \
           fprintf(stdout, "%s%s%s:%s(%d): " fmt "%s\n", S3FS_LOG_LEVEL_STRING(level), S3FS_LOG_NEST(nest), __FILE__, __func__, __LINE__, __VA_ARGS__); \
         }else{ \
           syslog(S3FS_LOG_LEVEL_TO_SYSLOG(level), "%s" fmt "%s", S3FS_LOG_NEST(nest), __VA_ARGS__); \
         } \
       }

#define S3FS_LOW_LOGPRN_EXIT(fmt, ...) \
       if(foreground){ \
         fprintf(stderr, "s3fs: " fmt "%s\n", __VA_ARGS__); \
       }else{ \
         fprintf(stderr, "s3fs: " fmt "%s\n", __VA_ARGS__); \
         syslog(S3FS_LOG_LEVEL_TO_SYSLOG(S3FS_LOG_CRIT), "s3fs: " fmt "%s", __VA_ARGS__); \
       }

// [NOTE]
// small trick for VA_ARGS
//
#define S3FS_PRN_EXIT(fmt, ...)   S3FS_LOW_LOGPRN_EXIT(fmt, ##__VA_ARGS__, "")
#define S3FS_PRN_CRIT(fmt, ...)   S3FS_LOW_LOGPRN(S3FS_LOG_CRIT, fmt, ##__VA_ARGS__, "")
#define S3FS_PRN_ERR(fmt, ...)    S3FS_LOW_LOGPRN(S3FS_LOG_ERR,  fmt, ##__VA_ARGS__, "")
#define S3FS_PRN_WARN(fmt, ...)   S3FS_LOW_LOGPRN(S3FS_LOG_WARN, fmt, ##__VA_ARGS__, "")
#define S3FS_PRN_DBG(fmt, ...)    S3FS_LOW_LOGPRN(S3FS_LOG_DBG,  fmt, ##__VA_ARGS__, "")
#define S3FS_PRN_INFO(fmt, ...)   S3FS_LOW_LOGPRN2(S3FS_LOG_INFO, 0, fmt, ##__VA_ARGS__, "")
#define S3FS_PRN_INFO0(fmt, ...)  S3FS_LOG_INFO(fmt, __VA_ARGS__)
#define S3FS_PRN_INFO1(fmt, ...)  S3FS_LOW_LOGPRN2(S3FS_LOG_INFO, 1, fmt, ##__VA_ARGS__, "")
#define S3FS_PRN_INFO2(fmt, ...)  S3FS_LOW_LOGPRN2(S3FS_LOG_INFO, 2, fmt, ##__VA_ARGS__, "")
#define S3FS_PRN_INFO3(fmt, ...)  S3FS_LOW_LOGPRN2(S3FS_LOG_INFO, 3, fmt, ##__VA_ARGS__, "")
#define S3FS_PRN_CURL(fmt, ...)   S3FS_LOW_LOGPRN2(S3FS_LOG_CRIT, 0, fmt, ##__VA_ARGS__, "")

//
// Typedef
//
typedef std::map<std::string, std::string> headers_t;

//
// Header "x-amz-meta-xattr" is for extended attributes.
// This header is url encoded string which is json formated.
//   x-amz-meta-xattr:urlencod({"xattr-1":"base64(value-1)","xattr-2":"base64(value-2)","xattr-3":"base64(value-3)"})
//
typedef struct xattr_value{
  unsigned char* pvalue;
  size_t         length;

  explicit xattr_value(unsigned char* pval = NULL, size_t len = 0) : pvalue(pval), length(len) {}
  ~xattr_value()
  {
    if(pvalue){
      free(pvalue);
    }
  }
}XATTRVAL, *PXATTRVAL;

typedef std::map<std::string, PXATTRVAL> xattrs_t;

//
// Global valiables
//
extern bool           foreground;
extern bool           nomultipart;
extern bool           pathrequeststyle;
extern std::string    program_name;
extern std::string    service_path;
extern std::string    host;
extern std::string    bucket;
extern std::string    mount_prefix;
extern std::string    endpoint;
extern s3fs_log_level debug_level;
extern const char*    s3fs_log_nest[S3FS_LOG_NEST_MAX];

#endif // S3FS_COMMON_H_

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: noet sw=4 ts=4 fdm=marker
* vim<600: noet sw=4 ts=4
*/
