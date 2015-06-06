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

//
// Macro
//
#define SAFESTRPTR(strptr) (strptr ? strptr : "")

// for debug
#define	FPRINT_NEST_SPACE_0  ""
#define	FPRINT_NEST_SPACE_1  "  "
#define	FPRINT_NEST_SPACE_2  "    "
#define	FPRINT_NEST_CHECK(NEST) \
        (0 == NEST ? FPRINT_NEST_SPACE_0 : 1 == NEST ? FPRINT_NEST_SPACE_1 : FPRINT_NEST_SPACE_2)

#define LOWFPRINT(NEST, ...) \
        printf("%s%s(%d): ", FPRINT_NEST_CHECK(NEST), __func__, __LINE__); \
        printf(__VA_ARGS__); \
        printf("\n"); \

#define FPRINT(NEST, ...) \
        if(foreground){ \
          LOWFPRINT(NEST, __VA_ARGS__); \
        }

#define FPRINT2(NEST, ...) \
        if(foreground2){ \
          LOWFPRINT(NEST, __VA_ARGS__); \
        }

#define LOWSYSLOGPRINT(LEVEL, ...) \
        syslog(LEVEL, __VA_ARGS__);

#define SYSLOGPRINT(LEVEL, ...) \
        if(LEVEL <= LOG_CRIT || debug){ \
          LOWSYSLOGPRINT(LEVEL, __VA_ARGS__); \
        }

#define DPRINT(LEVEL, NEST, ...) \
        FPRINT(NEST, __VA_ARGS__); \
        SYSLOGPRINT(LEVEL, __VA_ARGS__);

#define DPRINT2(LEVEL, ...) \
        FPRINT2(2, __VA_ARGS__); \
        SYSLOGPRINT(LEVEL, __VA_ARGS__);

// print debug message
#define FPRN(...)      FPRINT(0, __VA_ARGS__)
#define FPRNN(...)     FPRINT(1, __VA_ARGS__)
#define FPRNNN(...)    FPRINT(2, __VA_ARGS__)
#define FPRNINFO(...)  FPRINT2(2, __VA_ARGS__)

// print debug message with putting syslog
#define DPRNCRIT(...)  DPRINT(LOG_CRIT, 0, __VA_ARGS__)
#define DPRN(...)      DPRINT(LOG_ERR, 0, __VA_ARGS__)
#define DPRNN(...)     DPRINT(LOG_DEBUG, 1, __VA_ARGS__)
#define DPRNNN(...)    DPRINT(LOG_DEBUG, 2, __VA_ARGS__)
#define DPRNINFO(...)  DPRINT2(LOG_INFO, __VA_ARGS__)

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

  xattr_value(unsigned char* pval = NULL, size_t len = 0) : pvalue(pval), length(len) {}
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
extern bool debug;
extern bool foreground;
extern bool foreground2;
extern bool nomultipart;
extern bool pathrequeststyle;
extern std::string program_name;
extern std::string service_path;
extern std::string host;
extern std::string bucket;
extern std::string mount_prefix;
extern std::string endpoint;

#endif // S3FS_COMMON_H_

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: noet sw=4 ts=4 fdm=marker
* vim<600: noet sw=4 ts=4
*/
