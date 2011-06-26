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
#include <string.h>
#include <syslog.h>

#include <sstream>
#include <string>

#include "string_util.h"

using namespace std;

static const char hexAlphabet[] = "0123456789ABCDEF";

string lower(string s) {
  // change each character of the string to lower case
  for(unsigned int i = 0; i < s.length(); i++)
    s[i] = tolower(s[i]);

  return s;
}

string IntToStr(int n) {
  stringstream result;
  result << n;
  return result.str();
}

string trim_left(const string &s, const string &t /* = SPACES */) {
  string d(s);
  return d.erase(0, s.find_first_not_of(t));
}

string trim_right(const string &s, const string &t /* = SPACES */) {
  string d(s);
  string::size_type i(d.find_last_not_of(t));
  if (i == string::npos)
    return "";
  else
    return d.erase(d.find_last_not_of(t) + 1);
}

string trim(const string &s, const string &t /* = SPACES */) {
  string d(s);
  return trim_left(trim_right(d, t), t);
}

/**
 * urlEncode a fuse path,
 * taking into special consideration "/",
 * otherwise regular urlEncode.
 */
string urlEncode(const string &s) {
  string result;
  for (unsigned i = 0; i < s.length(); ++i) {
    if (s[i] == '/') // Note- special case for fuse paths...
      result += s[i];
    else if (isalnum(s[i]))
      result += s[i];
    else if (s[i] == '.' || s[i] == '-' || s[i] == '*' || s[i] == '_')
      result += s[i];
    else if (s[i] == ' ')
      result += '+';
    else {
      result += "%";
      result += hexAlphabet[static_cast<unsigned char>(s[i]) / 16];
      result += hexAlphabet[static_cast<unsigned char>(s[i]) % 16];
    }
  }

  return result;
}

string prepare_url(const char* url) {
  if(debug)
    syslog(LOG_DEBUG, "URL is %s", url);

  string uri;
  string host;
  string path;
  string url_str = str(url);
  string token =  str("/" + bucket);
  int bucket_pos = url_str.find(token);
  int bucket_length = token.size();
  int uri_length = 7;

  if(!strncasecmp(url_str.c_str(), "https://", 8))
    uri_length = 8;

  uri  = url_str.substr(0, uri_length);
  host = bucket + "." + url_str.substr(uri_length, bucket_pos - uri_length).c_str();
  path = url_str.substr((bucket_pos + bucket_length));

  url_str = uri + host + path;

  if(debug)
    syslog(LOG_DEBUG, "URL changed is %s", url_str.c_str());

  return str(url_str);
}

/**
 * Returns the current date
 * in a format suitable for a HTTP request header.
 */
string get_date() {
  char buf[100];
  time_t t = time(NULL);
  strftime(buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S GMT", gmtime(&t));
  return buf;
}
