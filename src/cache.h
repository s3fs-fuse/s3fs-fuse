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

#ifndef S3FS_CACHE_H_
#define S3FS_CACHE_H_

#include <cstring>
#include <map>
#include <mutex>
#include <string>
#include <sys/stat.h>
#include <vector>

#include "common.h"
#include "metaheader.h"
#include "s3objlist.h"
#include "cache_node.h"

//-------------------------------------------------------------------
// Class StatCache
//-------------------------------------------------------------------
// [NOTE] About Symbolic link cache
// The Stats cache class now also has a symbolic link cache.
// It is possible to take out the Symbolic link cache in another class,
// but the cache out etc. should be synchronized with the Stats cache
// and implemented in this class.
// Symbolic link cache size and timeout use the same settings as Stats
// cache. This simplifies user configuration, and from a user perspective,
// the symbolic link cache appears to be included in the Stats cache.
//
class StatCache
{
    private:
        static StatCache       singleton;
        static std::mutex      stat_cache_lock;

        std::shared_ptr<DirStatCache> pMountPointDir GUARDED_BY(stat_cache_lock);   // Top directory = Mount point
        unsigned long                 CacheSize;

    private:
        StatCache();
        ~StatCache();

        bool AddStatHasLock(const std::string& key, const struct stat* pstbuf, const headers_t* pmeta, objtype_t type, bool notruncate) REQUIRES(StatCache::stat_cache_lock);
        bool TruncateCacheHasLock(bool check_only_oversize_case = true) REQUIRES(StatCache::stat_cache_lock);
        bool DelStatHasLock(const std::string& key) REQUIRES(StatCache::stat_cache_lock);
        bool RawGetChildStats(const std::string& dir, s3obj_list_t* plist, s3obj_type_map_t* pobjmap);

    public:
        StatCache(const StatCache&) = delete;
        StatCache(StatCache&&) = delete;
        StatCache& operator=(const StatCache&) = delete;
        StatCache& operator=(StatCache&&) = delete;

        // Reference singleton
        static StatCache* getStatCacheData()
        {
            return &singleton;
        }

        // Attribute
        unsigned long GetCacheSize() const;
        unsigned long SetCacheSize(unsigned long size);

        // Get stat cache
        bool GetStat(const std::string& key, struct stat* pstbuf, headers_t* pmeta, objtype_t* ptype, const char* petag = nullptr);
        bool GetStat(const std::string& key, struct stat* pstbuf, headers_t* pmeta)
        {
            return GetStat(key, pstbuf, pmeta, nullptr, nullptr);
        }
        bool GetStat(const std::string& key, struct stat* pstbuf, const char* petag)
        {
            return GetStat(key, pstbuf, nullptr, nullptr, petag);
        }
        bool GetStat(const std::string& key, struct stat* pstbuf)
        {
            return GetStat(key, pstbuf, nullptr, nullptr, nullptr);
        }
        bool GetStat(const std::string& key, headers_t* pmeta)
        {
            return GetStat(key, nullptr, pmeta, nullptr, nullptr);
        }
        bool HasStat(const std::string& key, const char* petag = nullptr)
        {
            return GetStat(key, nullptr, nullptr, nullptr, petag);
        }
        bool GetS3ObjList(const std::string& key, S3ObjList& list);

        // Add stat cache
        bool AddStat(const std::string& key, const struct stat& stbuf, const headers_t& meta, objtype_t type, bool notruncate = false);
        bool AddStat(const std::string& key, const struct stat& stbuf, objtype_t type, bool notruncate = false);
        bool AddNegativeStat(const std::string& key);
        bool AddS3ObjList(const std::string& key, const S3ObjList& list);

        // Update meta stats
        bool UpdateStat(const std::string& key, const struct stat& stbuf, const headers_t& meta);

        // Change no truncate flag
        void ClearNoTruncateFlag(const std::string& key);

        // Delete stat cache
        bool DelStat(const std::string& key);

        // Cache for symbolic link
        bool GetSymlink(const std::string& key, std::string& value);
        bool AddSymlink(const std::string& key, const struct stat& stbuf, const headers_t& meta, const std::string& value);

        // Get List/Map
        bool GetChildStatList(const std::string& dir, s3obj_list_t& list);
        bool GetChildStatMap(const std::string& dir, s3obj_type_map_t& objmap);

        // For debugging
        void Dump(bool detail);
};

#endif // S3FS_CACHE_H_

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
