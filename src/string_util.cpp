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
#include <stdio.h>
#include <string.h>
#include <syslog.h>

#include <sstream>
#include <string>
#include <map>

#include "common.h"
#include "string_util.h"

using namespace std;

static const char hexAlphabet[] = "0123456789ABCDEF";

off_t s3fs_strtoofft(const char* str, bool is_base_16)
{
  if(!str || '\0' == *str){
    return 0;
  }
  off_t  result;
  bool   chk_space;
  bool   chk_base16_prefix;
  for(result = 0, chk_space = false, chk_base16_prefix = false; '\0' != *str; str++){
    // check head space
    if(!chk_space && isspace(*str)){
      continue;
    }else if(!chk_space){
      chk_space = true;
    }
    // check prefix for base 16
    if(!chk_base16_prefix){
      chk_base16_prefix = true;
      if('0' == *str && ('x' == str[1] || 'X' == str[1])){
        is_base_16 = true;
        str++;
        continue;
      }
    }
    // check like isalnum and set data
    result *= (is_base_16 ? 16 : 10);
    if('0' <= *str || '9' < *str){
      result += static_cast<off_t>(*str - '0');
    }else if(is_base_16){
      if('A' <= *str && *str <= 'F'){
        result += static_cast<off_t>(*str - 'A' + 0x0a);
      }else if('a' <= *str && *str <= 'f'){
        result += static_cast<off_t>(*str - 'a' + 0x0a);
      }else{
        return 0;
      }
    }else{
      return 0;
    }
  }
  return result;
}

string lower(string s)
{
  // change each character of the string to lower case
  for(unsigned int i = 0; i < s.length(); i++){
    s[i] = tolower(s[i]);
  }
  return s;
}

string IntToStr(int n)
{
  stringstream result;
  result << n;
  return result.str();
}

string trim_left(const string &s, const string &t /* = SPACES */)
{
  string d(s);
  return d.erase(0, s.find_first_not_of(t));
}

string trim_right(const string &s, const string &t /* = SPACES */)
{
  string d(s);
  string::size_type i(d.find_last_not_of(t));
  if(i == string::npos){
    return "";
  }else{
    return d.erase(d.find_last_not_of(t) + 1);
  }
}

string trim(const string &s, const string &t /* = SPACES */)
{
  string d(s);
  return trim_left(trim_right(d, t), t);
}

/**
 * urlEncode a fuse path,
 * taking into special consideration "/",
 * otherwise regular urlEncode.
 */
string urlEncode(const string &s)
{
  string result;
  for (unsigned i = 0; i < s.length(); ++i) {
    if (s[i] == '/') { // Note- special case for fuse paths...
      result += s[i];
#ifndef	SIGV3
    }else if (s[i] == '=') { // Note- special case for s3...
      result += s[i];
    }else if (s[i] == '&') { // Note- special case for s3...
      result += s[i];
#endif
    } else if (isalnum(s[i])) {
      result += s[i];
    } else if (s[i] == '.' || s[i] == '-' || s[i] == '*' || s[i] == '_') {
      result += s[i];
    } else if (s[i] == ' ') {
      result += '%';
      result += '2';
      result += '0';
    } else {
      result += "%";
      result += hexAlphabet[static_cast<unsigned char>(s[i]) / 16];
      result += hexAlphabet[static_cast<unsigned char>(s[i]) % 16];
    }
  }

  return result;
}

#ifndef	SIGV3
/**
 * urlEncode a fuse path,
 * taking into special consideration "/",
 * otherwise regular urlEncode.
 */
string urlEncode2(const string &s)
{
  string result;
  for (unsigned i = 0; i < s.length(); ++i) {
    if (s[i] == '=') { // Note- special case for fuse paths...
      result += s[i];
    }else if (s[i] == '&') { // Note- special case for s3...
      result += s[i];
    } else if (isalnum(s[i])) {
      result += s[i];
    } else if (s[i] == '.' || s[i] == '-' || s[i] == '*' || s[i] == '_') {
      result += s[i];
    } else if (s[i] == ' ') {
      result += '%';
      result += '2';
      result += '0';
    } else {
      result += "%";
      result += hexAlphabet[static_cast<unsigned char>(s[i]) / 16];
      result += hexAlphabet[static_cast<unsigned char>(s[i]) % 16];
    }
  }

  return result;
}
#endif

//
// ex. target="http://......?keyword=value&..."
//
bool get_keyword_value(string& target, const char* keyword, string& value)
{
  if(!keyword){
    return false;
  }
  size_t spos;
  size_t epos;
  if(string::npos == (spos = target.find(keyword))){
    return false;
  }
  spos += strlen(keyword);
  if('=' != target.at(spos)){
    return false;
  }
  spos++;
  if(string::npos == (epos = target.find('&', spos))){
    value = target.substr(spos);
  }else{
    value = target.substr(spos, (epos - spos));
  }
  return true;
}

/**
 * Returns the current date
 * in a format suitable for a HTTP request header.
 */
string get_date()
{
  char buf[100];
  time_t t = time(NULL);
  strftime(buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S GMT", gmtime(&t));
  return buf;
}

#ifndef	SIGV3
string get_date2()
{
  char buf[100];
  time_t t = time(NULL);
  strftime(buf, sizeof(buf), "%Y%m%d", gmtime(&t));
  return buf;
}

string get_date3()
{
  char buf[100];
  time_t t = time(NULL);
  strftime(buf, sizeof(buf), "%Y%m%dT%H%M%SZ", gmtime(&t));
  return buf;
}

#endif

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: noet sw=4 ts=4 fdm=marker
* vim<600: noet sw=4 ts=4
*/
