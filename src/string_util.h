#ifndef S3FS_STRING_UTIL_H_
#define S3FS_STRING_UTIL_H_

/*
 * A collection of string utilities for manipulating URLs and HTTP responses.
 */
#include <string.h>
#include <syslog.h>

#include <string>
#include <sstream>

#define SPACES                " \t\r\n"
#define STR2NCMP(str1, str2)  strncmp(str1, str2, strlen(str2))

template<typename T> std::string str(T value) {
  std::stringstream s;
  s << value;
  return s.str();
}

off_t s3fs_strtoofft(const char* str, bool is_base_16 = false);

std::string trim_left(const std::string &s, const std::string &t = SPACES);
std::string trim_right(const std::string &s, const std::string &t = SPACES);
std::string trim(const std::string &s, const std::string &t = SPACES);
std::string lower(std::string s);
std::string IntToStr(int);
std::string get_date();
std::string urlEncode(const std::string &s);
std::string prepare_url(const char* url);
bool get_keyword_value(std::string& target, const char* keyword, std::string& value);

#endif // S3FS_STRING_UTIL_H_
