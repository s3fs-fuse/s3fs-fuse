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

#ifndef S3FS_STRING_UTIL_H_
#define S3FS_STRING_UTIL_H_

#include <cstring>

//
// A collection of string utilities for manipulating URLs and HTTP responses.
//
//-------------------------------------------------------------------
// Global variables
//-------------------------------------------------------------------
extern const char SPACES[];

//-------------------------------------------------------------------
// Inline functions
//-------------------------------------------------------------------
static inline int is_prefix(const char *str, const char *prefix) { return strncmp(str, prefix, strlen(prefix)) == 0; }
static inline const char* SAFESTRPTR(const char *strptr) { return strptr ? strptr : ""; }

//-------------------------------------------------------------------
// Templates
//-------------------------------------------------------------------
template <class T> std::string str(T value);

//-------------------------------------------------------------------
// Macros(WTF8)
//-------------------------------------------------------------------
#define WTF8_ENCODE(ARG)  \
        std::string ARG##_buf; \
        const char * ARG = _##ARG; \
        if (use_wtf8 && s3fs_wtf8_encode( _##ARG, 0 )) { \
            s3fs_wtf8_encode( _##ARG, &ARG##_buf); \
            ARG = ARG##_buf.c_str(); \
        }

//-------------------------------------------------------------------
// Utilities
//-------------------------------------------------------------------
#ifdef __MSYS__
//
// Polyfill for strptime function.
//
char* strptime(const char* s, const char* f, struct tm* tm);
#endif
//
// Convert string to off_t.  Returns false on bad input.
// Replacement for C++11 std::stoll.
//
bool s3fs_strtoofft(off_t* value, const char* str, int base = 0);
//
// This function returns 0 if a value that cannot be converted is specified.
// Only call if 0 is considered an error and the operation can continue.
//
off_t cvt_strtoofft(const char* str, int base);

//
// String Manipulation
//
std::string trim_left(const std::string &s, const char *t = SPACES);
std::string trim_right(const std::string &s, const char *t = SPACES);
std::string trim(const std::string &s, const char *t = SPACES);
std::string lower(std::string s);

//
// Date string
//
std::string get_date_rfc850();
void get_date_sigv3(std::string& date, std::string& date8601);
std::string get_date_string(time_t tm);
std::string get_date_iso8601(time_t tm);
bool get_unixtime_from_iso8601(const char* pdate, time_t& unixtime);
bool convert_unixtime_from_option_arg(const char* argv, time_t& unixtime);

//
// For encoding
//
std::string urlEncode(const std::string &s);
std::string urlEncode2(const std::string &s);
std::string urlDecode(const std::string& s);

bool takeout_str_dquart(std::string& str);
bool get_keyword_value(const std::string& target, const char* keyword, std::string& value);

//
// For binary string
//
std::string s3fs_hex_lower(const unsigned char* input, size_t length);
std::string s3fs_hex_upper(const unsigned char* input, size_t length);
char* s3fs_base64(const unsigned char* input, size_t length);
unsigned char* s3fs_decode64(const char* input, size_t input_len, size_t* plength);

//
// WTF8
//
bool s3fs_wtf8_encode(const char *s, std::string *result);
std::string s3fs_wtf8_encode(const std::string &s);
bool s3fs_wtf8_decode(const char *s, std::string *result);
std::string s3fs_wtf8_decode(const std::string &s);

#endif // S3FS_STRING_UTIL_H_

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
