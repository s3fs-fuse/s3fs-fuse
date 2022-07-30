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

#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <climits>
#include <iomanip>

#include <sstream>

#include "s3fs_logger.h"
#include "string_util.h"

//-------------------------------------------------------------------
// Global variables
//-------------------------------------------------------------------
const char SPACES[] = " \t\r\n";

//-------------------------------------------------------------------
// Templates
//-------------------------------------------------------------------
template <class T> std::string str(T value)
{
    std::ostringstream s;
    s << value;
    return s.str();
}

template std::string str(short value);
template std::string str(unsigned short value);
template std::string str(int value);
template std::string str(unsigned int value);
template std::string str(long value);
template std::string str(unsigned long value);
template std::string str(long long value);
template std::string str(unsigned long long value);

template<> std::string str(const struct timespec value)
{
    std::ostringstream s;
    s << value.tv_sec;
    if(value.tv_nsec != 0){
        s << "." << std::setfill('0') << std::setw(9) << value.tv_nsec;
    }
    return s.str();
}

//-------------------------------------------------------------------
// Functions
//-------------------------------------------------------------------

#ifdef __MSYS__
/*
 * Polyfill for strptime function
 *
 * This source code is from https://gist.github.com/jeremyfromearth/5694aa3a66714254752179ecf3c95582 .
 */
char* strptime(const char* s, const char* f, struct tm* tm)
{
    std::istringstream input(s);
    input.imbue(std::locale(setlocale(LC_ALL, nullptr)));
    input >> std::get_time(tm, f);
    if (input.fail()) {
        return nullptr;
    }
    return (char*)(s + input.tellg());
}
#endif

bool s3fs_strtoofft(off_t* value, const char* str, int base)
{
    if(value == NULL || str == NULL){
        return false;
    }
    errno = 0;
    char *temp;
    long long result = strtoll(str, &temp, base);

    if(temp == str || *temp != '\0'){
        return false;
    }
    if((result == LLONG_MIN || result == LLONG_MAX) && errno == ERANGE){
        return false;
    }

    *value = result;
    return true;
}

off_t cvt_strtoofft(const char* str, int base)
{
    off_t result = 0;
    if(!s3fs_strtoofft(&result, str, base)){
        S3FS_PRN_WARN("something error is occurred in convert std::string(%s) to off_t, thus return 0 as default.", (str ? str : "null"));
        return 0;
    }
    return result;
}

std::string lower(std::string s)
{
    // change each character of the std::string to lower case
    for(size_t i = 0; i < s.length(); i++){
        s[i] = tolower(s[i]);
    }
    return s;
}

std::string trim_left(const std::string &s, const char *t /* = SPACES */)
{
    std::string d(s);
    return d.erase(0, s.find_first_not_of(t));
}

std::string trim_right(const std::string &s, const char *t /* = SPACES */)
{
    std::string d(s);
    std::string::size_type i(d.find_last_not_of(t));
    if(i == std::string::npos){
        return "";
    }else{
        return d.erase(d.find_last_not_of(t) + 1);
    }
}

std::string trim(const std::string &s, const char *t /* = SPACES */)
{
    return trim_left(trim_right(s, t), t);
}

//
// urlEncode a fuse path,
// taking into special consideration "/",
// otherwise regular urlEncode.
//
std::string urlEncode(const std::string &s)
{
    std::string result;
    for (size_t i = 0; i < s.length(); ++i) {
        unsigned char c = s[i];
        if (c == '/' // Note- special case for fuse paths...
            || c == '.'
            || c == '-'
            || c == '_'
            || c == '~'
            || (c >= 'a' && c <= 'z')
            || (c >= 'A' && c <= 'Z')
            || (c >= '0' && c <= '9'))
        {
            result += c;
        }else{
            result += "%";
            result += s3fs_hex_upper(&c, 1);
        }
    }
    return result;
}

//
// urlEncode a fuse path,
// taking into special consideration "/",
// otherwise regular urlEncode.
//
std::string urlEncode2(const std::string &s)
{
    std::string result;
    for (size_t i = 0; i < s.length(); ++i) {
        unsigned char c = s[i];
        if (c == '=' // Note- special case for fuse paths...
          || c == '&' // Note- special case for s3...
          || c == '%'
          || c == '.'
          || c == '-'
          || c == '_'
          || c == '~'
          || (c >= 'a' && c <= 'z')
          || (c >= 'A' && c <= 'Z')
          || (c >= '0' && c <= '9'))
        {
            result += c;
        }else{
            result += "%";
            result += s3fs_hex_upper(&c, 1);
        }
    }
    return result;
}

std::string urlDecode(const std::string& s)
{
    std::string result;
    for(size_t i = 0; i < s.length(); ++i){
        if(s[i] != '%'){
            result += s[i];
        }else{
            int ch = 0;
            if(s.length() <= ++i){
                break;       // wrong format.
            }
            ch += ('0' <= s[i] && s[i] <= '9') ? (s[i] - '0') : ('A' <= s[i] && s[i] <= 'F') ? (s[i] - 'A' + 0x0a) : ('a' <= s[i] && s[i] <= 'f') ? (s[i] - 'a' + 0x0a) : 0x00;
            if(s.length() <= ++i){
                break;       // wrong format.
            }
            ch *= 16;
            ch += ('0' <= s[i] && s[i] <= '9') ? (s[i] - '0') : ('A' <= s[i] && s[i] <= 'F') ? (s[i] - 'A' + 0x0a) : ('a' <= s[i] && s[i] <= 'f') ? (s[i] - 'a' + 0x0a) : 0x00;
            result += static_cast<char>(ch);
        }
    }
    return result;
}

bool takeout_str_dquart(std::string& str)
{
    size_t pos;

    // '"' for start
    if(std::string::npos != (pos = str.find_first_of('\"'))){
        str.erase(0, pos + 1);

        // '"' for end
        if(std::string::npos == (pos = str.find_last_of('\"'))){
            return false;
        }
        str.erase(pos);
        if(std::string::npos != str.find_first_of('\"')){
            return false;
        }
    }
    return true;
}

//
// ex. target="http://......?keyword=value&..."
//
bool get_keyword_value(const std::string& target, const char* keyword, std::string& value)
{
    if(!keyword){
        return false;
    }
    size_t spos;
    size_t epos;
    if(std::string::npos == (spos = target.find(keyword))){
        return false;
    }
    spos += strlen(keyword);
    if('=' != target[spos]){
        return false;
    }
    spos++;
    if(std::string::npos == (epos = target.find('&', spos))){
        value = target.substr(spos);
    }else{
        value = target.substr(spos, (epos - spos));
    }
    return true;
}

//
// Returns the current date
// in a format suitable for a HTTP request header.
//
std::string get_date_rfc850()
{
    char buf[100];
    time_t t = time(NULL);
    struct tm res;
    strftime(buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S GMT", gmtime_r(&t, &res));
    return buf;
}

void get_date_sigv3(std::string& date, std::string& date8601)
{
    time_t tm = time(NULL);
    date     = get_date_string(tm);
    date8601 = get_date_iso8601(tm);
}

std::string get_date_string(time_t tm)
{
    char buf[100];
    struct tm res;
    strftime(buf, sizeof(buf), "%Y%m%d", gmtime_r(&tm, &res));
    return buf;
}

std::string get_date_iso8601(time_t tm)
{
    char buf[100];
    struct tm res;
    strftime(buf, sizeof(buf), "%Y%m%dT%H%M%SZ", gmtime_r(&tm, &res));
    return buf;
}

bool get_unixtime_from_iso8601(const char* pdate, time_t& unixtime)
{
    if(!pdate){
        return false;
    }

    struct tm tm;
    char*     prest = strptime(pdate, "%Y-%m-%dT%T", &tm);
    if(prest == pdate){
        // wrong format
        return false;
    }
    unixtime = mktime(&tm);
    return true;
}

//
// Convert to unixtime from std::string which formatted by following:
//   "12Y12M12D12h12m12s", "86400s", "9h30m", etc
//
bool convert_unixtime_from_option_arg(const char* argv, time_t& unixtime)
{
    if(!argv){
      return false;
    }
    unixtime = 0;
    const char* ptmp;
    int         last_unit_type = 0;       // unit flag.
    bool        is_last_number;
    time_t      tmptime;
    for(ptmp = argv, is_last_number = true, tmptime = 0; ptmp && *ptmp; ++ptmp){
        if('0' <= *ptmp && *ptmp <= '9'){
            tmptime        *= 10;
            tmptime        += static_cast<time_t>(*ptmp - '0');
            is_last_number  = true;
        }else if(is_last_number){
            if('Y' == *ptmp && 1 > last_unit_type){
                unixtime      += (tmptime * (60 * 60 * 24 * 365));   // average 365 day / year
                last_unit_type = 1;
            }else if('M' == *ptmp && 2 > last_unit_type){
                unixtime      += (tmptime * (60 * 60 * 24 * 30));    // average 30 day / month
                last_unit_type = 2;
            }else if('D' == *ptmp && 3 > last_unit_type){
                unixtime      += (tmptime * (60 * 60 * 24));
                last_unit_type = 3;
            }else if('h' == *ptmp && 4 > last_unit_type){
                unixtime      += (tmptime * (60 * 60));
                last_unit_type = 4;
            }else if('m' == *ptmp && 5 > last_unit_type){
                unixtime      += (tmptime * 60);
                last_unit_type = 5;
            }else if('s' == *ptmp && 6 > last_unit_type){
                unixtime      += tmptime;
                last_unit_type = 6;
            }else{
                return false;
            }
            tmptime        = 0;
            is_last_number = false;
        }else{
            return false;
        }
    }
    if(is_last_number){
        return false;
    }
    return true;
}

static std::string s3fs_hex(const unsigned char* input, size_t length, const char *hexAlphabet)
{
    std::string hex;
    for(size_t pos = 0; pos < length; ++pos){
        hex += hexAlphabet[input[pos] / 16];
        hex += hexAlphabet[input[pos] % 16];
    }
    return hex;
}

std::string s3fs_hex_lower(const unsigned char* input, size_t length)
{
    return s3fs_hex(input, length, "0123456789abcdef");
}

std::string s3fs_hex_upper(const unsigned char* input, size_t length)
{
    return s3fs_hex(input, length, "0123456789ABCDEF");
}

char* s3fs_base64(const unsigned char* input, size_t length)
{
    static const char base[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
    char* result;

    if(!input || 0 == length){
        return NULL;
    }
    result = new char[((length + 3 - 1) / 3) * 4 + 1];

    unsigned char parts[4];
    size_t rpos;
    size_t wpos;
    for(rpos = 0, wpos = 0; rpos < length; rpos += 3){
        parts[0] = (input[rpos] & 0xfc) >> 2;
        parts[1] = ((input[rpos] & 0x03) << 4) | ((((rpos + 1) < length ? input[rpos + 1] : 0x00) & 0xf0) >> 4);
        parts[2] = (rpos + 1) < length ? (((input[rpos + 1] & 0x0f) << 2) | ((((rpos + 2) < length ? input[rpos + 2] : 0x00) & 0xc0) >> 6)) : 0x40;
        parts[3] = (rpos + 2) < length ? (input[rpos + 2] & 0x3f) : 0x40;

        result[wpos++] = base[parts[0]];
        result[wpos++] = base[parts[1]];
        result[wpos++] = base[parts[2]];
        result[wpos++] = base[parts[3]];
    }
    result[wpos] = '\0';

    return result;
}

inline unsigned char char_decode64(const char ch)
{
    unsigned char by;
    if('A' <= ch && ch <= 'Z'){                   // A - Z
        by = static_cast<unsigned char>(ch - 'A');
    }else if('a' <= ch && ch <= 'z'){             // a - z
        by = static_cast<unsigned char>(ch - 'a' + 26);
    }else if('0' <= ch && ch <= '9'){             // 0 - 9
        by = static_cast<unsigned char>(ch - '0' + 52);
    }else if('+' == ch){                         // +
        by = 62;
    }else if('/' == ch){                         // /
        by = 63;
    }else if('=' == ch){                         // =
        by = 64;
    }else{                                       // something wrong
        by = UCHAR_MAX;
    }
    return by;
}

unsigned char* s3fs_decode64(const char* input, size_t input_len, size_t* plength)
{
    unsigned char* result;
    if(!input || 0 == input_len || !plength){
        return NULL;
    }
    result = new unsigned char[input_len / 4 * 3];

    unsigned char parts[4];
    size_t rpos;
    size_t wpos;
    for(rpos = 0, wpos = 0; rpos < input_len; rpos += 4){
        parts[0] = char_decode64(input[rpos]);
        parts[1] = (rpos + 1) < input_len ? char_decode64(input[rpos + 1]) : 64;
        parts[2] = (rpos + 2) < input_len ? char_decode64(input[rpos + 2]) : 64;
        parts[3] = (rpos + 3) < input_len ? char_decode64(input[rpos + 3]) : 64;

        result[wpos++] = ((parts[0] << 2) & 0xfc) | ((parts[1] >> 4) & 0x03);
        if(64 == parts[2]){
            break;
        }
        result[wpos++] = ((parts[1] << 4) & 0xf0) | ((parts[2] >> 2) & 0x0f);
        if(64 == parts[3]){
            break;
        }
        result[wpos++] = ((parts[2] << 6) & 0xc0) | (parts[3] & 0x3f);
    }
    *plength = wpos;
    return result;
}

//
// detect and rewrite invalid utf8.  We take invalid bytes
// and encode them into a private region of the unicode
// space.  This is sometimes known as wtf8, wobbly transformation format.
// it is necessary because S3 validates the utf8 used for identifiers for
// correctness, while some clients may provide invalid utf, notably
// windows using cp1252.
//

// Base location for transform.  The range 0xE000 - 0xF8ff
// is a private range, se use the start of this range.
static const unsigned int escape_base = 0xe000;

// encode bytes into wobbly utf8.  
// 'result' can be null. returns true if transform was needed.
bool s3fs_wtf8_encode(const char *s, std::string *result)
{
    bool invalid = false;

    // Pass valid utf8 code through
    for (; *s; s++) {
        const unsigned char c = *s;

        // single byte encoding
        if (c <= 0x7f) {
            if (result) {
                *result += c;
            }
            continue;
        }

        // otherwise, it must be one of the valid start bytes
        if ( c >= 0xc2 && c <= 0xf5 ) {
            // two byte encoding
            // don't need bounds check, std::string is zero terminated
            if ((c & 0xe0) == 0xc0 && (s[1] & 0xc0) == 0x80) {
                // all two byte encodings starting higher than c1 are valid
                if (result) {
                    *result += c;
                    *result += *(++s);
                }
                continue;
            } 
            // three byte encoding
            if ((c & 0xf0) == 0xe0 && (s[1] & 0xc0) == 0x80 && (s[2] & 0xc0) == 0x80) {
                const unsigned code = ((c & 0x0f) << 12) | ((s[1] & 0x3f) << 6) | (s[2] & 0x3f);
                if (code >= 0x800 && ! (code >= 0xd800 && code <= 0xd8ff)) {
                    // not overlong and not a surrogate pair 
                    if (result) {
                        *result += c;
                        *result += *(++s);
                        *result += *(++s);
                    }
                    continue;
                }
            }
            // four byte encoding
            if ((c & 0xf8) == 0xf0 && (s[1] & 0xc0) == 0x80 && (s[2] & 0xc0) == 0x80 && (s[3] & 0xc0) == 0x80) {
                const unsigned code = ((c & 0x07) << 18) | ((s[1] & 0x3f) << 12) | ((s[2] & 0x3f) << 6) | (s[3] & 0x3f);
                if (code >= 0x10000 && code <= 0x10ffff) {
                  // not overlong and in defined unicode space
                  if (result) {
                      *result += c;
                      *result += *(++s);
                      *result += *(++s);
                      *result += *(++s);
                  }
                  continue;
                }
            }
        }
        // printf("invalid %02x at %d\n", c, i);
        // Invalid utf8 code.  Convert it to a private two byte area of unicode
        // e.g. the e000 - f8ff area.  This will be a three byte encoding
        invalid = true;
        if (result) {
            unsigned escape = escape_base + c;
            *result += static_cast<char>(0xe0 | ((escape >> 12) & 0x0f));
            *result += static_cast<char>(0x80 | ((escape >> 06) & 0x3f));
            *result += static_cast<char>(0x80 | ((escape >> 00) & 0x3f));
        }
    }
    return invalid;
}

std::string s3fs_wtf8_encode(const std::string &s)
{
    std::string result;
    s3fs_wtf8_encode(s.c_str(), &result);
    return result;
}

// The reverse operation, turn encoded bytes back into their original values
// The code assumes that we map to a three-byte code point.
bool s3fs_wtf8_decode(const char *s, std::string *result)
{
    bool encoded = false;
    for (; *s; s++) {
        unsigned char c = *s;
        // look for a three byte tuple matching our encoding code
        if ((c & 0xf0) == 0xe0 && (s[1] & 0xc0) == 0x80 && (s[2] & 0xc0) == 0x80) {
            unsigned code = (c & 0x0f) << 12;
            code |= (s[1] & 0x3f) << 6;
            code |= (s[2] & 0x3f) << 0;
            if (code >= escape_base && code <= escape_base + 0xff) {
                // convert back
                encoded = true;
                if(result){
                    *result += static_cast<char>(code - escape_base);
                }
                s+=2;
                continue;
            }
        }
        if (result) {
            *result += c;
        }
    }
    return encoded;
}
 
std::string s3fs_wtf8_decode(const std::string &s)
{
    std::string result;
    s3fs_wtf8_decode(s.c_str(), &result);
    return result;
}

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
