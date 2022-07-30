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
#include <vector>

#include "s3fs.h"
#include "s3fs_logger.h"
#include "s3fs_util.h"
#include "cache.h"
#include "autolock.h"
#include "string_util.h"

//-------------------------------------------------------------------
// Utility
//-------------------------------------------------------------------
inline void SetStatCacheTime(struct timespec& ts)
{
    if(-1 == clock_gettime(static_cast<clockid_t>(CLOCK_MONOTONIC_COARSE), &ts)){
        S3FS_PRN_CRIT("clock_gettime failed: %d", errno);
        abort();
    }
}

inline void InitStatCacheTime(struct timespec& ts)
{
    ts.tv_sec  = 0;
    ts.tv_nsec = 0;
}

inline int CompareStatCacheTime(const struct timespec& ts1, const struct timespec& ts2)
{
    // return -1:  ts1 < ts2
    //         0:  ts1 == ts2
    //         1:  ts1 > ts2
    if(ts1.tv_sec < ts2.tv_sec){
        return -1;
    }else if(ts1.tv_sec > ts2.tv_sec){
        return 1;
    }else{
        if(ts1.tv_nsec < ts2.tv_nsec){
            return -1;
        }else if(ts1.tv_nsec > ts2.tv_nsec){
            return 1;
        }
    }
    return 0;
}

inline bool IsExpireStatCacheTime(const struct timespec& ts, const time_t& expire)
{
    struct timespec nowts;
    SetStatCacheTime(nowts);
    nowts.tv_sec -= expire;

    return (0 < CompareStatCacheTime(nowts, ts));
}

//
// For stats cache out 
//
typedef std::vector<stat_cache_t::iterator>   statiterlist_t;

struct sort_statiterlist{
    // ascending order
    bool operator()(const stat_cache_t::iterator& src1, const stat_cache_t::iterator& src2) const
    {
        int result = CompareStatCacheTime(src1->second->cache_date, src2->second->cache_date);
        if(0 == result){
            if(src1->second->hit_count < src2->second->hit_count){
                result = -1;
            }
        }
        return (result < 0);
    }
};

//
// For symbolic link cache out 
//
typedef std::vector<symlink_cache_t::iterator>   symlinkiterlist_t;

struct sort_symlinkiterlist{
    // ascending order
    bool operator()(const symlink_cache_t::iterator& src1, const symlink_cache_t::iterator& src2) const
    {
        int result = CompareStatCacheTime(src1->second->cache_date, src2->second->cache_date);  // use the same as Stats
        if(0 == result){
            if(src1->second->hit_count < src2->second->hit_count){
                result = -1;
            }
        }
        return (result < 0);
    }
};

//-------------------------------------------------------------------
// Static
//-------------------------------------------------------------------
StatCache       StatCache::singleton;
pthread_mutex_t StatCache::stat_cache_lock;

//-------------------------------------------------------------------
// Constructor/Destructor
//-------------------------------------------------------------------
StatCache::StatCache() : IsExpireTime(true), IsExpireIntervalType(false), ExpireTime(15 * 60), CacheSize(100000), IsCacheNoObject(true)
{
    if(this == StatCache::getStatCacheData()){
        stat_cache.clear();
        pthread_mutexattr_t attr;
        pthread_mutexattr_init(&attr);
#if S3FS_PTHREAD_ERRORCHECK
        pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK);
#endif
        int result;
        if(0 != (result = pthread_mutex_init(&StatCache::stat_cache_lock, &attr))){
            S3FS_PRN_CRIT("failed to init stat_cache_lock: %d", result);
            abort();
        }
    }else{
        abort();
    }
}

StatCache::~StatCache()
{
    if(this == StatCache::getStatCacheData()){
        Clear();
        int result = pthread_mutex_destroy(&StatCache::stat_cache_lock);
        if(result != 0){
            S3FS_PRN_CRIT("failed to destroy stat_cache_lock: %d", result);
            abort();
        }
    }else{
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

time_t StatCache::GetExpireTime() const
{
    return (IsExpireTime ? ExpireTime : (-1));
}

time_t StatCache::SetExpireTime(time_t expire, bool is_interval)
{
    time_t old           = ExpireTime;
    ExpireTime           = expire;
    IsExpireTime         = true;
    IsExpireIntervalType = is_interval;
    return old;
}

time_t StatCache::UnsetExpireTime()
{
    time_t old           = IsExpireTime ? ExpireTime : (-1);
    ExpireTime           = 0;
    IsExpireTime         = false;
    IsExpireIntervalType = false;
    return old;
}

bool StatCache::SetCacheNoObject(bool flag)
{
    bool old = IsCacheNoObject;
    IsCacheNoObject = flag;
    return old;
}

void StatCache::Clear()
{
    AutoLock lock(&StatCache::stat_cache_lock);

    for(stat_cache_t::iterator iter = stat_cache.begin(); iter != stat_cache.end(); ++iter){
        delete (*iter).second;
    }
    stat_cache.clear();
    S3FS_MALLOCTRIM(0);
}

bool StatCache::GetStat(const std::string& key, struct stat* pst, headers_t* meta, bool overcheck, const char* petag, bool* pisforce)
{
    bool is_delete_cache = false;
    std::string strpath = key;

    AutoLock lock(&StatCache::stat_cache_lock);

    stat_cache_t::iterator iter = stat_cache.end();
    if(overcheck && '/' != *strpath.rbegin()){
        strpath += "/";
        iter = stat_cache.find(strpath);
    }
    if(iter == stat_cache.end()){
        strpath = key;
        iter = stat_cache.find(strpath);
    }

    if(iter != stat_cache.end() && (*iter).second){
        stat_cache_entry* ent = (*iter).second;
        if(0 < ent->notruncate || !IsExpireTime || !IsExpireStatCacheTime(ent->cache_date, ExpireTime)){
            if(ent->noobjcache){
                if(!IsCacheNoObject){
                    // need to delete this cache.
                    DelStat(strpath, AutoLock::ALREADY_LOCKED);
                }else{
                    // noobjcache = true means no object.
                }
                return false;
            }
            // hit without checking etag
            std::string stretag;
            if(petag){
                // find & check ETag
                for(headers_t::iterator hiter = ent->meta.begin(); hiter != ent->meta.end(); ++hiter){
                    std::string tag = lower(hiter->first);
                    if(tag == "etag"){
                        stretag = hiter->second;
                        if('\0' != petag[0] && 0 != strcmp(petag, stretag.c_str())){
                            is_delete_cache = true;
                        }
                        break;
                    }
                }
            }
            if(is_delete_cache){
                // not hit by different ETag
                S3FS_PRN_DBG("stat cache not hit by ETag[path=%s][time=%lld.%09ld][hit count=%lu][ETag(%s)!=(%s)]",
                    strpath.c_str(), static_cast<long long>(ent->cache_date.tv_sec), ent->cache_date.tv_nsec, ent->hit_count, petag ? petag : "null", stretag.c_str());
            }else{
                // hit 
                S3FS_PRN_DBG("stat cache hit [path=%s][time=%lld.%09ld][hit count=%lu]",
                    strpath.c_str(), static_cast<long long>(ent->cache_date.tv_sec), ent->cache_date.tv_nsec, ent->hit_count);

                if(pst!= NULL){
                    *pst= ent->stbuf;
                }
                if(meta != NULL){
                    *meta = ent->meta;
                }
                if(pisforce != NULL){
                    (*pisforce) = ent->isforce;
                }
                ent->hit_count++;
  
                if(IsExpireIntervalType){
                    SetStatCacheTime(ent->cache_date);
                }
                return true;
            }

        }else{
            // timeout
            is_delete_cache = true;
        }
    }

    if(is_delete_cache){
        DelStat(strpath, AutoLock::ALREADY_LOCKED);
    }
    return false;
}

bool StatCache::IsNoObjectCache(const std::string& key, bool overcheck)
{
    bool is_delete_cache = false;
    std::string strpath = key;

    if(!IsCacheNoObject){
        return false;
    }

    AutoLock lock(&StatCache::stat_cache_lock);

    stat_cache_t::iterator iter = stat_cache.end();
    if(overcheck && '/' != *strpath.rbegin()){
        strpath += "/";
        iter     = stat_cache.find(strpath);
    }
    if(iter == stat_cache.end()){
        strpath = key;
        iter    = stat_cache.find(strpath);
    }

    if(iter != stat_cache.end() && (*iter).second) {
        stat_cache_entry* ent = (*iter).second;
        if(0 < ent->notruncate || !IsExpireTime || !IsExpireStatCacheTime((*iter).second->cache_date, ExpireTime)){
            if((*iter).second->noobjcache){
                // noobjcache = true means no object.
                SetStatCacheTime((*iter).second->cache_date);
                return true;
            }
        }else{
            // timeout
            is_delete_cache = true;
        }
    }

    if(is_delete_cache){
        DelStat(strpath, AutoLock::ALREADY_LOCKED);
    }
    return false;
}

bool StatCache::AddStat(const std::string& key, headers_t& meta, bool forcedir, bool no_truncate)
{
    if(!no_truncate && CacheSize< 1){
        return true;
    }
    S3FS_PRN_INFO3("add stat cache entry[path=%s]", key.c_str());

    bool found;
    bool do_truncate;
    {
        AutoLock lock(&StatCache::stat_cache_lock);
        found       = stat_cache.end() != stat_cache.find(key);
        do_truncate = stat_cache.size() > CacheSize;
    }

    if(found){
        DelStat(key.c_str());
    }else{
        if(do_truncate){
            if(!TruncateCache()){
                return false;
            }
        }
    }

    // make new
    stat_cache_entry* ent = new stat_cache_entry();
    if(!convert_header_to_stat(key.c_str(), meta, &(ent->stbuf), forcedir)){
        delete ent;
        return false;
    }
    ent->hit_count  = 0;
    ent->isforce    = forcedir;
    ent->noobjcache = false;
    ent->notruncate = (no_truncate ? 1L : 0L);
    ent->meta.clear();
    SetStatCacheTime(ent->cache_date);    // Set time.
    //copy only some keys
    for(headers_t::iterator iter = meta.begin(); iter != meta.end(); ++iter){
        std::string tag   = lower(iter->first);
        std::string value = iter->second;
        if(tag == "content-type"){
            ent->meta[iter->first] = value;
        }else if(tag == "content-length"){
            ent->meta[iter->first] = value;
        }else if(tag == "etag"){
            ent->meta[iter->first] = value;
        }else if(tag == "last-modified"){
            ent->meta[iter->first] = value;
        }else if(is_prefix(tag.c_str(), "x-amz")){
            ent->meta[tag] = value;      // key is lower case for "x-amz"
        }
    }

    // add
    AutoLock lock(&StatCache::stat_cache_lock);

    std::pair<stat_cache_t::iterator, bool> pair = stat_cache.insert(std::make_pair(key, ent));
    if(!pair.second){
        delete pair.first->second;
        pair.first->second = ent;
    }

    // check symbolic link cache
    if(!S_ISLNK(ent->stbuf.st_mode)){
        if(symlink_cache.end() != symlink_cache.find(key)){
            // if symbolic link cache has key, thus remove it.
            DelSymlink(key.c_str(), AutoLock::ALREADY_LOCKED);
        }
    }
    return true;
}

// [NOTE]
// Updates only meta data if cached data exists.
// And when these are updated, it also updates the cache time.
//
// Since the file mode may change while the file is open, it is
// updated as well.
//
bool StatCache::UpdateMetaStats(const std::string& key, headers_t& meta)
{
    if(CacheSize < 1){
        return true;
    }
    S3FS_PRN_INFO3("update stat cache entry[path=%s]", key.c_str());

    AutoLock lock(&StatCache::stat_cache_lock);
    stat_cache_t::iterator iter = stat_cache.find(key);
    if(stat_cache.end() == iter || !(iter->second)){
        return true;
    }
    stat_cache_entry* ent = iter->second;

    // update only meta keys
    for(headers_t::iterator metaiter = meta.begin(); metaiter != meta.end(); ++metaiter){
        std::string tag   = lower(metaiter->first);
        std::string value = metaiter->second;
        if(tag == "content-type"){
            ent->meta[metaiter->first] = value;
        }else if(tag == "content-length"){
            ent->meta[metaiter->first] = value;
        }else if(tag == "etag"){
            ent->meta[metaiter->first] = value;
        }else if(tag == "last-modified"){
            ent->meta[metaiter->first] = value;
        }else if(is_prefix(tag.c_str(), "x-amz")){
            ent->meta[tag] = value;      // key is lower case for "x-amz"
        }
    }

    // Update time.
    SetStatCacheTime(ent->cache_date);

    // Update only mode
    ent->stbuf.st_mode = get_mode(meta);

    return true;
}

bool StatCache::AddNoObjectCache(const std::string& key)
{
    if(!IsCacheNoObject){
        return true;    // pretend successful
    }
    if(CacheSize < 1){
        return true;
    }
    S3FS_PRN_INFO3("add no object cache entry[path=%s]", key.c_str());

    bool found;
    bool do_truncate;
    {
        AutoLock lock(&StatCache::stat_cache_lock);
        found       = stat_cache.end() != stat_cache.find(key);
        do_truncate = stat_cache.size() > CacheSize;
    }

    if(found){
        DelStat(key.c_str());
    }else{
        if(do_truncate){
            if(!TruncateCache()){
                return false;
            }
        }
    }

    // make new
    stat_cache_entry* ent = new stat_cache_entry();
    memset(&(ent->stbuf), 0, sizeof(struct stat));
    ent->hit_count  = 0;
    ent->isforce    = false;
    ent->noobjcache = true;
    ent->notruncate = 0L;
    ent->meta.clear();
    SetStatCacheTime(ent->cache_date);    // Set time.

    // add
    AutoLock lock(&StatCache::stat_cache_lock);

    std::pair<stat_cache_t::iterator, bool> pair = stat_cache.insert(std::make_pair(key, ent));
    if(!pair.second){
        delete pair.first->second;
        pair.first->second = ent;
    }

    // check symbolic link cache
    if(symlink_cache.end() != symlink_cache.find(key)){
        // if symbolic link cache has key, thus remove it.
        DelSymlink(key.c_str(), AutoLock::ALREADY_LOCKED);
    }
    return true;
}

void StatCache::ChangeNoTruncateFlag(const std::string& key, bool no_truncate)
{
    AutoLock lock(&StatCache::stat_cache_lock);
    stat_cache_t::iterator iter = stat_cache.find(key);

    if(stat_cache.end() != iter){
        stat_cache_entry* ent = iter->second;
        if(ent){
            if(no_truncate){
                ++(ent->notruncate);
            }else{
                if(0L < ent->notruncate){
                    --(ent->notruncate);
                }
            }
        }
    }
}

bool StatCache::TruncateCache()
{
    AutoLock lock(&StatCache::stat_cache_lock);

    if(stat_cache.empty()){
        return true;
    }

    // 1) erase over expire time
    if(IsExpireTime){
        for(stat_cache_t::iterator iter = stat_cache.begin(); iter != stat_cache.end(); ){
            stat_cache_entry* entry = iter->second;
            if(!entry || (0L == entry->notruncate && IsExpireStatCacheTime(entry->cache_date, ExpireTime))){
                delete entry;
                stat_cache.erase(iter++);
            }else{
                ++iter;
            }
        }
    }

    // 2) check stat cache count
    if(stat_cache.size() < CacheSize){
        return true;
    }

    // 3) erase from the old cache in order
    size_t            erase_count= stat_cache.size() - CacheSize + 1;
    statiterlist_t    erase_iters;
    for(stat_cache_t::iterator iter = stat_cache.begin(); iter != stat_cache.end() && 0 < erase_count; ++iter){
        // check no truncate
        stat_cache_entry* ent = iter->second;
        if(ent && 0L < ent->notruncate){
            // skip for no truncate entry and keep extra counts for this entity.
            if(0 < erase_count){
                --erase_count;     // decrement
            }
        }else{
            // iter is not have notruncate flag
            erase_iters.push_back(iter);
        }
        if(erase_count < erase_iters.size()){
            std::sort(erase_iters.begin(), erase_iters.end(), sort_statiterlist());
            while(erase_count < erase_iters.size()){
                erase_iters.pop_back();
            }
        }
    }
    for(statiterlist_t::iterator iiter = erase_iters.begin(); iiter != erase_iters.end(); ++iiter){
        stat_cache_t::iterator siter = *iiter;

        S3FS_PRN_DBG("truncate stat cache[path=%s]", siter->first.c_str());
        delete siter->second;
        stat_cache.erase(siter);
    }
    S3FS_MALLOCTRIM(0);

    return true;
}

bool StatCache::DelStat(const char* key, AutoLock::Type locktype)
{
    if(!key){
        return false;
    }
    S3FS_PRN_INFO3("delete stat cache entry[path=%s]", key);

    AutoLock lock(&StatCache::stat_cache_lock, locktype);

    stat_cache_t::iterator iter;
    if(stat_cache.end() != (iter = stat_cache.find(std::string(key)))){
        delete (*iter).second;
        stat_cache.erase(iter);
    }
    if(0 < strlen(key) && 0 != strcmp(key, "/")){
        std::string strpath = key;
        if('/' == *strpath.rbegin()){
            // If there is "path" cache, delete it.
            strpath.erase(strpath.length() - 1);
        }else{
            // If there is "path/" cache, delete it.
            strpath += "/";
        }
        if(stat_cache.end() != (iter = stat_cache.find(strpath))){
            delete (*iter).second;
            stat_cache.erase(iter);
        }
    }
    S3FS_MALLOCTRIM(0);

    return true;
}

bool StatCache::GetSymlink(const std::string& key, std::string& value)
{
    bool is_delete_cache = false;
    const std::string& strpath = key;

    AutoLock lock(&StatCache::stat_cache_lock);

    symlink_cache_t::iterator iter = symlink_cache.find(strpath);
    if(iter != symlink_cache.end() && iter->second){
        symlink_cache_entry* ent = iter->second;
        if(!IsExpireTime || !IsExpireStatCacheTime(ent->cache_date, ExpireTime)){   // use the same as Stats
            // found
            S3FS_PRN_DBG("symbolic link cache hit [path=%s][time=%lld.%09ld][hit count=%lu]",
                strpath.c_str(), static_cast<long long>(ent->cache_date.tv_sec), ent->cache_date.tv_nsec, ent->hit_count);

            value = ent->link;

            ent->hit_count++;
            if(IsExpireIntervalType){
                SetStatCacheTime(ent->cache_date);
            }
            return true;
        }else{
            // timeout
            is_delete_cache = true;
        }
    }

    if(is_delete_cache){
        DelSymlink(strpath.c_str(), AutoLock::ALREADY_LOCKED);
    }
    return false;
}

bool StatCache::AddSymlink(const std::string& key, const std::string& value)
{
    if(CacheSize< 1){
        return true;
    }
    S3FS_PRN_INFO3("add symbolic link cache entry[path=%s, value=%s]", key.c_str(), value.c_str());

    bool found;
    bool do_truncate;
    {
        AutoLock lock(&StatCache::stat_cache_lock);
        found       = symlink_cache.end() != symlink_cache.find(key);
        do_truncate = symlink_cache.size() > CacheSize;
    }

    if(found){
        DelSymlink(key.c_str());
    }else{
        if(do_truncate){
            if(!TruncateSymlink()){
                return false;
            }
        }
    }

    // make new
    symlink_cache_entry* ent = new symlink_cache_entry();
    ent->link       = value;
    ent->hit_count  = 0;
    SetStatCacheTime(ent->cache_date);    // Set time(use the same as Stats).

    // add
    AutoLock lock(&StatCache::stat_cache_lock);

    std::pair<symlink_cache_t::iterator, bool> pair = symlink_cache.insert(std::make_pair(key, ent));
    if(!pair.second){
        delete pair.first->second;
        pair.first->second = ent;
    }

    return true;
}

bool StatCache::TruncateSymlink()
{
    AutoLock lock(&StatCache::stat_cache_lock);

    if(symlink_cache.empty()){
        return true;
    }

    // 1) erase over expire time
    if(IsExpireTime){
        for(symlink_cache_t::iterator iter = symlink_cache.begin(); iter != symlink_cache.end(); ){
            symlink_cache_entry* entry = iter->second;
            if(!entry || IsExpireStatCacheTime(entry->cache_date, ExpireTime)){  // use the same as Stats
                delete entry;
                symlink_cache.erase(iter++);
            }else{
                ++iter;
            }
        }
    }

    // 2) check stat cache count
    if(symlink_cache.size() < CacheSize){
        return true;
    }

    // 3) erase from the old cache in order
    size_t            erase_count= symlink_cache.size() - CacheSize + 1;
    symlinkiterlist_t erase_iters;
    for(symlink_cache_t::iterator iter = symlink_cache.begin(); iter != symlink_cache.end(); ++iter){
        erase_iters.push_back(iter);
        sort(erase_iters.begin(), erase_iters.end(), sort_symlinkiterlist());
        if(erase_count < erase_iters.size()){
            erase_iters.pop_back();
        }
    }
    for(symlinkiterlist_t::iterator iiter = erase_iters.begin(); iiter != erase_iters.end(); ++iiter){
        symlink_cache_t::iterator siter = *iiter;

        S3FS_PRN_DBG("truncate symbolic link  cache[path=%s]", siter->first.c_str());
        delete siter->second;
        symlink_cache.erase(siter);
    }
    S3FS_MALLOCTRIM(0);

    return true;
}

bool StatCache::DelSymlink(const char* key, AutoLock::Type locktype)
{
    if(!key){
        return false;
    }
    S3FS_PRN_INFO3("delete symbolic link cache entry[path=%s]", key);

    AutoLock lock(&StatCache::stat_cache_lock, locktype);

    symlink_cache_t::iterator iter;
    if(symlink_cache.end() != (iter = symlink_cache.find(std::string(key)))){
        delete iter->second;
        symlink_cache.erase(iter);
    }
    S3FS_MALLOCTRIM(0);

    return true;
}

//-------------------------------------------------------------------
// Functions
//-------------------------------------------------------------------
bool convert_header_to_stat(const char* path, const headers_t& meta, struct stat* pst, bool forcedir)
{
    if(!path || !pst){
        return false;
    }
    memset(pst, 0, sizeof(struct stat));

    pst->st_nlink = 1; // see fuse FAQ

    // mode
    pst->st_mode = get_mode(meta, path, true, forcedir);

    // blocks
    if(S_ISREG(pst->st_mode)){
        pst->st_blocks = get_blocks(pst->st_size);
    }
    pst->st_blksize = 4096;

    // mtime
    struct timespec mtime = get_mtime(meta);
    if(pst->st_mtime < 0){
        pst->st_mtime = 0L;
    }else{
        if(mtime.tv_sec < 0){
            mtime.tv_sec  = 0;
            mtime.tv_nsec = 0;
        }
        set_timespec_to_stat(*pst, ST_TYPE_MTIME, mtime);
    }

    // ctime
    struct timespec ctime = get_ctime(meta);
    if(pst->st_ctime < 0){
        pst->st_ctime = 0L;
    }else{
        if(ctime.tv_sec < 0){
            ctime.tv_sec  = 0;
            ctime.tv_nsec = 0;
        }
        set_timespec_to_stat(*pst, ST_TYPE_CTIME, ctime);
    }

    // atime
    struct timespec atime = get_atime(meta);
    if(pst->st_atime < 0){
        pst->st_atime = 0L;
    }else{
        if(atime.tv_sec < 0){
            atime.tv_sec  = 0;
            atime.tv_nsec = 0;
        }
        set_timespec_to_stat(*pst, ST_TYPE_ATIME, atime);
    }

    // size
    pst->st_size = get_size(meta);

    // uid/gid
    pst->st_uid = get_uid(meta);
    pst->st_gid = get_gid(meta);

    return true;
}

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
