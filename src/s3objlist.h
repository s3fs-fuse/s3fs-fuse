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

#include <list>
#include <map>
#include <string>

//-------------------------------------------------------------------
// Structure / Typedef
//-------------------------------------------------------------------
struct s3obj_entry{
    std::string normalname; // normalized name: if empty, object is normalized name.
    std::string orgname;    // original name: if empty, object is original name.
    std::string etag;
    bool        is_dir;

    s3obj_entry() : is_dir(false) {}
};

typedef std::map<std::string, struct s3obj_entry> s3obj_t;
typedef std::list<std::string> s3obj_list_t;

//-------------------------------------------------------------------
// Class S3ObjList
//-------------------------------------------------------------------
class S3ObjList
{
    private:
        s3obj_t objects;

    private:
        bool insert_normalized(const char* name, const char* normalized, bool is_dir);
        const s3obj_entry* GetS3Obj(const char* name) const;

        s3obj_t::const_iterator begin() const { return objects.begin(); }
        s3obj_t::const_iterator end() const { return objects.end(); }

    public:
        S3ObjList() {}
        ~S3ObjList() {}

        bool IsEmpty() const { return objects.empty(); }
        bool insert(const char* name, const char* etag = NULL, bool is_dir = false);
        std::string GetOrgName(const char* name) const;
        std::string GetNormalizedName(const char* name) const;
        std::string GetETag(const char* name) const;
        bool IsDir(const char* name) const;
        bool GetNameList(s3obj_list_t& list, bool OnlyNormalized = true, bool CutSlash = true) const;
        bool GetLastName(std::string& lastname) const;

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
