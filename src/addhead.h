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

#ifndef S3FS_ADDHEAD_H_
#define S3FS_ADDHEAD_H_

#include <regex.h>

//----------------------------------------------
// class AdditionalHeader
//----------------------------------------------
typedef struct add_header{
  regex_t*      pregex;         // not NULL means using regex, NULL means comparing suffix directly.
  std::string   basestring;
  std::string   headkey;
  std::string   headvalue;
}ADDHEAD, *PADDHEAD;

typedef std::vector<PADDHEAD>  addheadlist_t;

class AdditionalHeader
{
  private:
    static AdditionalHeader singleton;
    bool                    is_enable;
    addheadlist_t           addheadlist;

  protected:
    AdditionalHeader();
    ~AdditionalHeader();

  public:
    // Reference singleton
    static AdditionalHeader* get(void) { return &singleton; }

    bool Load(const char* file);
    void Unload(void);

    bool AddHeader(headers_t& meta, const char* path) const;
    struct curl_slist* AddHeader(struct curl_slist* list, const char* path) const;
    bool Dump(void) const;
};

#endif // S3FS_ADDHEAD_H_

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: noet sw=4 ts=4 fdm=marker
* vim<600: noet sw=4 ts=4
*/
