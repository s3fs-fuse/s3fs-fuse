/*
 * s3fs - FUSE-based file system backed by Amazon S3
 *
 * Copyright(C) 2020 Andrew Gaul <andrew@gaul.org>
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

#include <string>
#include <cstring>

#include "curl_util.h"
#include "test_util.h"

#define ASSERT_IS_SORTED(x) assert_is_sorted((x), __FILE__, __LINE__)

void assert_is_sorted(struct curl_slist* list, const char *file, int line)
{
    for(; list != NULL; list = list->next){
        std::string key1 = list->data;
        key1.erase(key1.find(':'));
        std::string key2 = list->data;
        key2.erase(key2.find(':'));
        std::cerr << "key1: " << key1 << " key2: " << key2 << std::endl;

        if(strcasecmp(key1.c_str(), key2.c_str()) > 0){
            std::cerr << "not sorted: " << key1 << " " << key2 << " at " << file << ":" << line << std::endl;
            std::exit(1);
        }
    }
    std::cerr << std::endl;
}

size_t curl_slist_length(const struct curl_slist* list)
{
    size_t len = 0;
    for(; list != NULL; list = list->next){
        ++len;
    }
    return len;
}

void test_sort_insert()
{
    struct curl_slist* list = NULL;
    ASSERT_IS_SORTED(list);
    // add to head
    list = curl_slist_sort_insert(list, "2", "val");
    ASSERT_IS_SORTED(list);
    // add to tail
    list = curl_slist_sort_insert(list, "4", "val");
    ASSERT_IS_SORTED(list);
    // add in between
    list = curl_slist_sort_insert(list, "3", "val");
    ASSERT_IS_SORTED(list);
    // add to head
    list = curl_slist_sort_insert(list, "1", "val");
    ASSERT_IS_SORTED(list);
    ASSERT_STREQUALS("1: val", list->data);
    // replace head
    list = curl_slist_sort_insert(list, "1", "val2");
    ASSERT_IS_SORTED(list);
    ASSERT_EQUALS(static_cast<size_t>(4), curl_slist_length(list));
    ASSERT_STREQUALS("1: val2", list->data);
    curl_slist_free_all(list);
}

int main(int argc, char *argv[])
{
    test_sort_insert();
    return 0;
}

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
