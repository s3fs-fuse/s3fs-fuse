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

#ifndef S3FS_FDCACHE_STAT_H_
#define S3FS_FDCACHE_STAT_H_

#include <string>

//------------------------------------------------
// CacheFileStat
//------------------------------------------------
class CacheFileStat
{
    private:
        std::string path;
        int         fd;

    private:
        static bool MakeCacheFileStatPath(const char* path, std::string& sfile_path, bool is_create_dir = true);

        bool RawOpen(bool readonly);

    public:
        static std::string GetCacheFileStatTopDir();
        static bool DeleteCacheFileStat(const char* path);
        static bool CheckCacheFileStatTopDir();
        static bool DeleteCacheFileStatDirectory();
        static bool RenameCacheFileStat(const char* oldpath, const char* newpath);

        explicit CacheFileStat(const char* tpath = NULL);
        ~CacheFileStat();

        bool Open();
        bool ReadOnlyOpen();
        bool Release();
        bool SetPath(const char* tpath, bool is_open = true);
        int GetFd() const { return fd; }
};

#endif // S3FS_FDCACHE_STAT_H_

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
