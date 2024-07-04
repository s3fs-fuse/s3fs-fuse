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

#ifndef S3FS_S3OBJLIST_H_
#define S3FS_S3OBJLIST_H_

#include <map>
#include <string>
#include <utility>
#include <vector>
#include <sstream>

#include "types.h"

//-------------------------------------------------------------------
// Structure / Typedef
//-------------------------------------------------------------------
struct s3obj_entry{
    std::string normalname;                 // normalized name: if empty, object is normalized name.
    std::string orgname;                    // original name: if empty, object is original name.
    std::string etag;
    objtype_t   type = objtype_t::UNKNOWN;  // only set for directories, UNKNOWN for non-directories.
};

typedef std::map<std::string, struct s3obj_entry, std::less<>> s3obj_t;
typedef std::vector<std::string> s3obj_list_t;
typedef std::map<std::string, objtype_t> s3obj_type_map_t;

//-------------------------------------------------------------------
// Class S3ObjList
//-------------------------------------------------------------------
class S3ObjList
{
    private:
        s3obj_t objects;
        std::vector<std::string> common_prefixes;

        bool insert_normalized(const char* name, const char* normalized, objtype_t type);
        const s3obj_entry* GetS3Obj(const char* name) const;
        bool RawGetNames(s3obj_list_t* plist, s3obj_type_map_t* pobjmap, bool OnlyNormalized, bool CutSlash) const;

        s3obj_t::const_iterator cbegin() const { return objects.cbegin(); }
        s3obj_t::const_iterator cend() const { return objects.cend(); }

    public:
        bool IsEmpty() const { return objects.empty(); }
        bool insert(const char* name, const char* etag = nullptr, bool is_dir = false);
        std::string GetOrgName(const char* name) const;
        std::string GetNormalizedName(const char* name) const;
        std::string GetETag(const char* name) const;
        const std::vector<std::string>& GetCommonPrefixes() const { return common_prefixes; }
        void AddCommonPrefix(std::string prefix) { common_prefixes.push_back(std::move(prefix)); }
        bool IsDir(const char* name) const;
        bool GetNameList(s3obj_list_t& list, bool OnlyNormalized = true, bool CutSlash = true) const;
        bool GetNameMap(s3obj_type_map_t& objmap, bool OnlyNormalized = true, bool CutSlash = true) const;
        bool GetLastName(std::string& lastname) const;
        bool HasName(const std::string& strName);
        bool Remove(const std::string& strName);
        void Dump(const std::string& indent, std::ostringstream& oss) const;

        static bool MakeHierarchizedList(s3obj_list_t& list, bool haveSlash);
};

#endif // S3FS_S3OBJLIST_H_

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
