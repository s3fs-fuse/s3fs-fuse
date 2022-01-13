/*
 * Polyfill for strptime function
 *
 * This source code is from https://gist.github.com/jeremyfromearth/5694aa3a66714254752179ecf3c95582 .
 */

#include <iostream>
#include <time.h>
#include <iomanip>
#include <sstream>

#include "strptime.h"

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
