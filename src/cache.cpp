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

#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <mutex>
#include <string>
#include <sys/stat.h>
#include <utility>
#include <vector>

#include "s3fs.h"
#include "s3fs_logger.h"
#include "s3fs_util.h"
#include "cache.h"
#include "string_util.h"

//-------------------------------------------------------------------
// Static
//-------------------------------------------------------------------
StatCache       StatCache::singleton;
std::mutex      StatCache::stat_cache_lock;

//-------------------------------------------------------------------
// Constructor/Destructor
//-------------------------------------------------------------------
StatCache::StatCache() : pMountPointDir(nullptr), CacheSize(100'000)
{
    if(this == StatCache::getStatCacheData()){
        pMountPointDir = std::make_shared<DirStatCache>("/");
    }else{
        abort();
    }
}

StatCache::~StatCache()
{
    if(this != StatCache::getStatCacheData()){
        abort();
    }
}

//-------------------------------------------------------------------
// Methods
//-------------------------------------------------------------------
unsigned long StatCache::GetCacheSize() const
{
    return CacheSize;
}

unsigned long StatCache::SetCacheSize(unsigned long size)
{
    unsigned long old = CacheSize;
    CacheSize = size;
    return old;
}

bool StatCache::GetStat(const std::string& key, struct stat* pstbuf, headers_t* pmeta, objtype_t* ptype, const char* petag)
{
    const std::lock_guard<std::mutex> lock(StatCache::stat_cache_lock);

    // find key(path) in cache
    auto pStatCache = pMountPointDir->Find(key, petag);
    if(!pStatCache){
        return false;
    }

    // [NOTE]
    // The object type will always be set.
    // This is useful for determining cache types(such as Negative type)
    // where the caller receives false.
    //
    if(ptype){
        *ptype = pStatCache->GetType();
    }

    // check negative cache
    if(pStatCache->isNegative()){
        pStatCache->IncrementHitCount();
        S3FS_PRN_DBG("Hit negative stat cache [path=%s][hit count=%lu]", key.c_str(), pStatCache->GetHitCount());
        return false;
    }

    // set data
    if(!pStatCache->Get(pmeta, pstbuf)){
        return false;
    }

    // hit cache
    S3FS_PRN_DBG("Hit stat cache [path=%s][hit count=%lu]", key.c_str(), pStatCache->GetHitCount());

    // for debug
    //pMountPointDir->Dump(true);

    return true;
}

bool StatCache::AddStatHasLock(const std::string& key, const struct stat* pstbuf, const headers_t* pmeta, objtype_t type, bool notruncate)
{
    // Add(overwrite) new cache
    if(!pMountPointDir->Add(key, pstbuf, pmeta, type, notruncate)){
        S3FS_PRN_DBG("failed to add stat cache entry[path=%s]", key.c_str());
        return false;
    }

    // Truncate cache(if over cache size)
    if(TruncateCacheHasLock(true)){
        S3FS_PRN_DBG("Some expired caches have been truncated.");
    }
    S3FS_PRN_INFO3("add stat cache entry[path=%s]", key.c_str());

    // for debug
    //pMountPointDir->Dump(true);

    return true;
}

bool StatCache::AddStat(const std::string& key, const struct stat& stbuf, const headers_t& meta, objtype_t type, bool notruncate)
{
    // [NOTE]
    // If notruncate=true, force caching
    //
    if(GetCacheSize() < 1 && !notruncate){
        return true;
    }
    const std::lock_guard<std::mutex> lock(StatCache::stat_cache_lock);

    return AddStatHasLock(key, &stbuf, &meta, type, notruncate);
}

bool StatCache::AddStat(const std::string& key, const struct stat& stbuf, objtype_t type, bool notruncate)
{
    // [NOTE]
    // If notruncate=true, force caching
    //
    if(GetCacheSize() < 1 && !notruncate){
        return true;
    }
    const std::lock_guard<std::mutex> lock(StatCache::stat_cache_lock);

    return AddStatHasLock(key, &stbuf, nullptr, type, notruncate);
}

// [NOTE]
// Updates only meta data if cached data exists.
// And when these are updated, it also updates the cache time.
//
// Since the file mode may change while the file is open, it is
// updated as well.
//
bool StatCache::UpdateStat(const std::string& key, const struct stat& stbuf, const headers_t& meta)
{
    const std::lock_guard<std::mutex> lock(StatCache::stat_cache_lock);

    // search key cache
    auto pCache = pMountPointDir->Find(key);
    if(!pCache){
        // Not found cache
        return false;
    }
    if(!pCache->Update(stbuf, meta)){
        S3FS_PRN_DBG("failed to update stat cache entry[path=%s]", key.c_str());
        return false;
    }
    S3FS_PRN_INFO3("update stat cache entry[path=%s]", key.c_str());

    // for debug
    //pMountPointDir->Dump(true);

    return true;
}

bool StatCache::AddNegativeStat(const std::string& key)
{
    const std::lock_guard<std::mutex> lock(StatCache::stat_cache_lock);

    // [NOTE]
    // Since Negative Cache exists regardless of cache size, first delete
    // the cache if it exists.
    //
    auto pCache = pMountPointDir->Find(key);
    if(pCache){
        pMountPointDir->RemoveChild(key);
    }

    if(GetCacheSize() < 1){
        S3FS_PRN_INFO3("failed to add negative cache entry[path=%s], but returns true.", key.c_str());
        return true;
    }

    // Add cache
    if(!pMountPointDir->Add(key, nullptr, nullptr, objtype_t::NEGATIVE)){
        S3FS_PRN_INFO3("failed to add negative cache entry[path=%s]", key.c_str());
        return false;
    }

    // Truncate cache(if over cache size)
    if(TruncateCacheHasLock(true)){
        S3FS_PRN_DBG("Some expired caches have been truncated.");
    }
    S3FS_PRN_INFO3("add negative cache entry[path=%s]", key.c_str());

    // for debug
    //pMountPointDir->Dump(true);

    return true;
}

void StatCache::ClearNoTruncateFlag(const std::string& key)
{
    const std::lock_guard<std::mutex> lock(StatCache::stat_cache_lock);

    // search key cache
    auto pCache = pMountPointDir->Find(key);
    if(pCache){
        // Clear NoTruncate Flag
        pCache->ClearNoTruncate();
    }
}

//
// Cache truncation will be performed if check_only_oversize_case=true
// or the cache size overflows.
//
// [NOTE]
// If there are no expired caches, no cache truncation will occur.
// Also, caches marked as NoTruncate and caches in non-empty directories
// will never be deleted.
// This behavior means that no truncation will occur and caches will
// accumulate until one of the caches expires.
//
bool StatCache::TruncateCacheHasLock(bool check_only_oversize_case)
{
    if(check_only_oversize_case && StatCacheNode::GetCacheCount() <= GetCacheSize()){
        return false;
    }
    if(!pMountPointDir->TruncateCache()){
        S3FS_PRN_DBG("could not truncate any cache[current size=%lu, maximum size=%lu]", StatCacheNode::GetCacheCount(), GetCacheSize());
        return false;
    }

    // for debug
    //pMountPointDir->Dump(true);

    return true;
}

bool StatCache::DelStatHasLock(const std::string& key)
{
    // remove cache(can not remove mount point)
    if(key == pMountPointDir->Get()){
        if(!pMountPointDir->ClearData()){
            S3FS_PRN_DBG("Failed to clear cache data for mount point.");
            return false;
        }
    }else if(!pMountPointDir->RemoveChild(key)){
        // not found key in cache(already removed)
        S3FS_PRN_DBG("not found stat cache entry[path=%s]", key.c_str());
    }else{
        S3FS_PRN_INFO3("delete stat cache entry[path=%s]", key.c_str());

        // for debug
        //pMountPointDir->Dump(true);
    }
    return true;
}

bool StatCache::DelStat(const std::string& key)
{
    const std::lock_guard<std::mutex> lock(StatCache::stat_cache_lock);
    return DelStatHasLock(key);
}

bool StatCache::GetSymlink(const std::string& key, std::string& value)
{
    if(GetCacheSize() < 1){
        return true;
    }
    const std::lock_guard<std::mutex> lock(StatCache::stat_cache_lock);

    // search key cache
    auto pCache = pMountPointDir->Find(key);
    if(!pCache){
        // Not found cache
        return false;
    }

    if(!pCache->isSymlink()){
        // Cache object is not symlink.
        //
        // [NOTE]
        // If updating this cache(key) as a Symlink, the caller must
        // delete or overwrite it.
        //
        return false;
    }

    if(!pCache->GetExtra(value)){
        return false;
    }
    S3FS_PRN_INFO3("get symbolic link cache entry[path=%s]", key.c_str());

    // for debug
    //pMountPointDir->Dump(true);

    return true;
}

bool StatCache::AddSymlink(const std::string& key, const struct stat& stbuf, const headers_t& meta, const std::string& value)
{
    const std::lock_guard<std::mutex> lock(StatCache::stat_cache_lock);

    // find in cache
    auto pCache = pMountPointDir->Find(key);
    if(pCache && !pCache->isSymlink()){
        // found stat cache is not symlink type, remove it.
        pMountPointDir->RemoveChild(key);
        pCache = pMountPointDir->Find(key);     // = nullptr
    }

    // add new cache if not found in cache
    if(!pCache){
        // add symlink stat cache
        if(!pMountPointDir->Add(key, &stbuf, &meta, objtype_t::SYMLINK, false)){
            S3FS_PRN_DBG("failed to add symbolic link cache entry[path=%s, value=%s]", key.c_str(), value.c_str());
            return false;
        }

        // re-get symlink stat cache
        if(nullptr == (pCache = pMountPointDir->Find(key))){
            S3FS_PRN_ERR("Symlink stat cache not found even though it was added[path=%s]", key.c_str());
            return false;
        }
    }

    // add(update) symlink path
    if(!pCache->Update(value)){
        S3FS_PRN_ERR("failed to add symbolic link cache entry[path=%s, value=%s]", key.c_str(), value.c_str());
        return false;
    }

    // Truncate cache(if over cache size)
    if(TruncateCacheHasLock(true)){
        S3FS_PRN_DBG("Some expired caches have been truncated.");
    }
    S3FS_PRN_INFO3("add symbolic link cache entry[path=%s, value=%s]", key.c_str(), value.c_str());

    // for debug
    //pMountPointDir->Dump(true);

    return true;
}

// [Background]
// When s3fs creates a new file, the file does not exist until the file contents
// are uploaded.(because it doesn't create a 0 byte file)
// From the time this file is created(opened) until it is uploaded(flush), it
// will have a Stat cache with the No truncate flag added.
// This avoids file not existing errors in operations such as chmod and utimens
// that occur in the short period before file upload.
// Besides this, we also need to support readdir(list_bucket), this method is
// called to maintain the cache for readdir and return its value.
//
// [NOTE]
// Add the file names under "dir" to the list.
// However, if the same file name exists in the list, it will not be added.
// "dir" must be terminated with a '/'.
//
bool StatCache::RawGetChildStats(const std::string& dir, s3obj_list_t* plist, s3obj_type_map_t* pobjmap)
{
    if(dir.empty()){
        return false;
    }
    if(!plist && !pobjmap){
        return false;
    }

    S3FS_PRN_INFO3("get child stat cache list[path=%s]", dir.c_str());

    const std::lock_guard<std::mutex> lock(StatCache::stat_cache_lock);

    // [NOTE]
    // Since Negative Cache exists regardless of cache size, first delete
    // the cache if it exists.
    //
    auto pCache = pMountPointDir->Find(dir);
    if(!pCache){
        // not found directory stat cache
        return true;
    }

    // get child leaf path list
    s3obj_type_map_t childmap;
    if(0 == pCache->GetChildMap(childmap)){
        return true;
    }

    // merge list
    for(auto iter = childmap.cbegin(); iter != childmap.cend(); ++iter){
        if(plist){
            if(plist->cend() == std::find(plist->cbegin(), plist->cend(), iter->first)){
               plist->push_back(iter->first);
            }
        }
        if(pobjmap){
            if(pobjmap->cend() == pobjmap->find(iter->first)){
                (*pobjmap)[iter->first] = iter->second;
            }
        }
    }
    return true;
}

bool StatCache::GetChildStatList(const std::string& dir, s3obj_list_t& list)
{
    return RawGetChildStats(dir, &list, nullptr);
}

bool StatCache::GetChildStatMap(const std::string& dir, s3obj_type_map_t& objmap)
{
    return RawGetChildStats(dir, nullptr, &objmap);
}

void StatCache::Dump(bool detail)
{
    const std::lock_guard<std::mutex> lock(StatCache::stat_cache_lock);
    pMountPointDir->Dump(detail);
}

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
