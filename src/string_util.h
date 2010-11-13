#ifndef S3FS_STRING_UTIL_H_
#define S3FS_STRING_UTIL_H_

/*
 * A collection of string utilities for manipulating URLs and HTTP responses.
 */
#include <sstream>
#include <string>

#define SPACES " \t\r\n"

using namespace std;

template<typename T> string str(T value) {
  stringstream tmp;
  tmp << value;
  return tmp.str();
}

inline string trim_left(const string &s, const string &t = SPACES) {
  string d(s);
  return d.erase(0, s.find_first_not_of(t));
}

inline string trim_right(const string &s, const string &t = SPACES) {
  string d(s);
  string::size_type i(d.find_last_not_of(t));
  if (i == string::npos)
    return "";
  else
    return d.erase(d.find_last_not_of(t) + 1);
}

inline string trim(const string &s, const string &t = SPACES) {
  string d(s);
  return trim_left(trim_right(d, t), t);
}

string lower(string s);

#endif // S3FS_STRING_UTIL_H_
