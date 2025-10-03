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

#include <iomanip>
#include <sstream>

#include "s3fs.h"
#include "s3fs_logger.h"
#include "cache_node.h"
#include "string_util.h"

//===================================================================
// Utilities
//===================================================================
static void SetCurrentTime(struct timespec& ts)
{
    if(-1 == clock_gettime(static_cast<clockid_t>(S3FS_CLOCK_MONOTONIC), &ts)){
        S3FS_PRN_CRIT("clock_gettime failed: %d", errno);
        abort();
    }
}

static constexpr int CompareStatCacheTime(const struct timespec& ts1, const struct timespec& ts2)
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

static bool IsExpireStatCacheTime(const struct timespec& ts, time_t expire)
{
    struct timespec nowts;
    SetCurrentTime(nowts);
    nowts.tv_sec -= expire;

    return (0 < CompareStatCacheTime(nowts, ts));
}

//
// Usage: isStatCacheObjectType<DirStatCache>(pcache)
//
template <typename T>
bool isStatCacheObjectType(std::shared_ptr<StatCacheNode>& pstatcache)
{
    return (nullptr != std::dynamic_pointer_cast<T>(pstatcache));
}

//
// Usage: std::shared_ptr<DirStatCache> pDirStat ConvertStatCacheObject<DirStatCache>(pcache)
//
template <typename T>
std::shared_ptr<T> ConvertStatCacheObject(std::shared_ptr<StatCacheNode>& pstatcache)
{
    if(!isStatCacheObjectType<T>(pstatcache)){
        return std::shared_ptr<T>();
    }
    return std::dynamic_pointer_cast<T>(pstatcache);
}

//===================================================================
// Base Class : StatCacheNode
//===================================================================
//
// Class Variables
//
std::mutex      StatCacheNode::counter_lock;
unsigned long   StatCacheNode::counter[MAX_STAT_CACHE_COUNTER] = {0, 0, 0, 0, 0, 0};
bool            StatCacheNode::EnableExpireTime                = true;
bool            StatCacheNode::IsExpireIntervalType            = false;
time_t          StatCacheNode::ExpireTime                      = 15 * 60;
bool            StatCacheNode::UseNegativeCache                = true;
std::mutex      StatCacheNode::cache_lock;
unsigned long   StatCacheNode::DisableCheckingExpire           = 0L;
struct timespec StatCacheNode::DisableExpireDate               = {0, 0};

//
// Class Methods
//
unsigned long StatCacheNode::GetCacheCount(objtype_t type)
{
    // [NOTE]
    // To get counter of directories, specify one of the following:
    // DIR_NORMAL, DIR_NOT_TERMINATE_SLASH, DIR_FOLDER_SUFFIX, DIR_NOT_EXIST_OBJECT
    //
    std::lock_guard<std::mutex> cntlock(StatCacheNode::counter_lock);
    return counter[stat_counter_pos(type)];
}

void StatCacheNode::IncrementCacheCount(objtype_t type)
{
    std::lock_guard<std::mutex> cntlock(StatCacheNode::counter_lock);
    ++counter[stat_counter_pos(type)];
}

void StatCacheNode::DecrementCacheCount(objtype_t type)
{
    std::lock_guard<std::mutex> cntlock(StatCacheNode::counter_lock);
    if(0 < counter[stat_counter_pos(type)]){
        --counter[stat_counter_pos(type)];
    }
}

time_t StatCacheNode::GetExpireTime()
{
    return StatCacheNode::ExpireTime;
}

time_t StatCacheNode::SetExpireTime(time_t expire, bool is_interval)
{
    time_t old                          = StatCacheNode::ExpireTime;
    StatCacheNode::ExpireTime           = expire;
    StatCacheNode::EnableExpireTime     = true;
    StatCacheNode::IsExpireIntervalType = is_interval;
    return old;
}

time_t StatCacheNode::UnsetExpireTime()
{
    time_t old                          = StatCacheNode::ExpireTime;
    StatCacheNode::ExpireTime           = 0;
    StatCacheNode::EnableExpireTime     = false;
    StatCacheNode::IsExpireIntervalType = false;
    return old;
}

bool StatCacheNode::IsEnableExpireTime()
{
    return StatCacheNode::EnableExpireTime;
}

bool StatCacheNode::SetNegativeCache(bool flag)
{
    bool old = UseNegativeCache;
    UseNegativeCache = flag;
    return old;
}

bool StatCacheNode::NeedExpireCheckHasLock(const struct timespec& ts)
{
    if(!StatCacheNode::IsEnableExpireTime()){
        return false;
    }

    // [NOTE]
    // If the expiration date check is disabled(0 < DisableCheckingExpire)
    // and the date is later than DisableExpireDate, it is determined that
    // checking is not necessary.
    //
    if(0L < StatCacheNode::DisableCheckingExpire){
        if(0 >= CompareStatCacheTime(StatCacheNode::DisableExpireDate, ts)){
            return false;
        }
    }
    return true;
}

bool StatCacheNode::PreventExpireCheck()
{
    if(!StatCacheNode::IsEnableExpireTime()){
        return false;
    }
    std::lock_guard<std::mutex> lock(StatCacheNode::cache_lock);

    ++StatCacheNode::DisableCheckingExpire;

    if(0 == StatCacheNode::DisableExpireDate.tv_sec){
        SetCurrentTime(StatCacheNode::DisableExpireDate);
        StatCacheNode::DisableExpireDate.tv_sec -= StatCacheNode::GetExpireTime();
    }
    return true;
}

bool StatCacheNode::ResumeExpireCheck()
{
    if(!StatCacheNode::IsEnableExpireTime()){
        return false;
    }
    std::lock_guard<std::mutex> lock(StatCacheNode::cache_lock);

    if(0 < StatCacheNode::DisableCheckingExpire){
        --StatCacheNode::DisableCheckingExpire;
    }
    if(0 == StatCacheNode::DisableCheckingExpire){
        StatCacheNode::DisableExpireDate = {0, 0};
    }
    return true;
}

//-------------------------------------------------------------------
// Methods
//-------------------------------------------------------------------
StatCacheNode::StatCacheNode(const char* path, objtype_t type) : cache_type(type), fullpath(path ? path: "")
{
    if(IS_DIR_OBJ(cache_type)){
        // directory type must end with '/'.
        if(fullpath.empty() || '/' != *fullpath.rbegin()){
            fullpath += '/';
        }
    }else{
        // other than directory type must cut the end of '/'.
        if(!fullpath.empty() && '/' == *fullpath.rbegin()){
            fullpath.erase(fullpath.size() - 1);
        }
    }

    // Set now time.
    SetCurrentTime(cache_date);

    StatCacheNode::IncrementCacheCount(objtype_t::UNKNOWN);
}

StatCacheNode::~StatCacheNode()
{
    StatCacheNode::DecrementCacheCount(objtype_t::UNKNOWN);
}

bool StatCacheNode::isSameObjectTypeHasLock(objtype_t type) const
{
    return IS_SAME_OBJ(cache_type, type);
}

bool StatCacheNode::isDirectoryHasLock() const
{
    return IS_DIR_OBJ(cache_type);
}

bool StatCacheNode::isFileHasLock() const
{
    return IS_FILE_OBJ(cache_type);
}

bool StatCacheNode::isSymlinkHasLock() const
{
    return IS_SYMLINK_OBJ(cache_type);
}

bool StatCacheNode::isNegativeHasLock() const
{
    return IS_NEGATIVE_OBJ(cache_type);
}

bool StatCacheNode::isSameObjectType(objtype_t type)
{
    std::lock_guard<std::mutex> lock(StatCacheNode::cache_lock);
    return isSameObjectTypeHasLock(type);
}

bool StatCacheNode::isDirectory()
{
    std::lock_guard<std::mutex> lock(StatCacheNode::cache_lock);
    return isDirectoryHasLock();
}

bool StatCacheNode::isFile()
{
    std::lock_guard<std::mutex> lock(StatCacheNode::cache_lock);
    return isFileHasLock();
}

bool StatCacheNode::isSymlink()
{
    std::lock_guard<std::mutex> lock(StatCacheNode::cache_lock);
    return isSymlinkHasLock();
}

bool StatCacheNode::isNegative()
{
    std::lock_guard<std::mutex> lock(StatCacheNode::cache_lock);
    return isNegativeHasLock();
}

bool StatCacheNode::ClearDataHasLock()
{
    if(!UpdateHasLock(nullptr, nullptr, true) || !UpdateHasLock(false)  || !UpdateHasLock(nullptr) || !UpdateHasLock()){
        return false;
    }
    return true;
}

bool StatCacheNode::ClearHasLock()
{
    fullpath.clear();
    return ClearDataHasLock();
}

bool StatCacheNode::ClearData()
{
    std::lock_guard<std::mutex> lock(StatCacheNode::cache_lock);

    if(!IS_DIR_OBJ(cache_type)){
        S3FS_PRN_ERR("Called from outside the directory type cache.");
        return false;
    }
    return ClearDataHasLock();
}

bool StatCacheNode::Clear()
{
    std::lock_guard<std::mutex> lock(StatCacheNode::cache_lock);
    return ClearHasLock();
}

bool StatCacheNode::RemoveChildHasLock(const std::string& strpath)
{
    return false;
}

bool StatCacheNode::RemoveChild(const std::string& strpath)
{
    std::lock_guard<std::mutex> lock(StatCacheNode::cache_lock);
    return RemoveChildHasLock(strpath);
}

bool StatCacheNode::isRemovableHasLock()
{
    return true;
}

bool StatCacheNode::AddHasLock(const std::string& strpath, const struct stat* pstat, const headers_t* pmeta, objtype_t type, bool is_notruncate)
{
    return false;
}

bool StatCacheNode::Add(const std::string& strpath, const struct stat* pstat, const headers_t* pmeta, objtype_t type, bool is_notruncate)
{
    std::lock_guard<std::mutex> lock(StatCacheNode::cache_lock);
    return AddHasLock(strpath, pstat, pmeta, type, is_notruncate);
}

bool StatCacheNode::UpdateHasLock(objtype_t type)
{
    // [NOTE]
    // Setting anything other than the directory type will fail.
    // Only the directory type may change while the object exists,
    // nothing else can not change.
    //
    if(!isDirectoryHasLock() || !IS_DIR_OBJ(type)){
        return false;
    }

    // inc/decrement count value
    StatCacheNode::DecrementCacheCount(GetTypeHasLock());
    StatCacheNode::IncrementCacheCount(type);

    // set type
    cache_type = type;

    return true;
}

bool StatCacheNode::UpdateHasLock(const struct stat* pstat, const headers_t* pmeta, bool clear_meta)
{
    if(pstat){
        has_stat = true;
        stbuf    = *pstat;
    }else{
        has_stat = false;
        stbuf    = {};
    }

    if(pmeta){
        has_meta = true;

        // copy only some keys
        meta.clear();
        for(auto iter = pmeta->cbegin(); iter != pmeta->cend(); ++iter){
            if(!iter->second.empty()){
                auto tag = CaseInsensitiveStringView(iter->first);
                if(tag == "content-type"   ||
                   tag == "content-length" ||
                   tag == "etag"           ||
                   tag == "last-modified"  ||
                   tag.is_prefix("x-amz")  )
                {
                    meta[iter->first] = iter->second;
                }
            }
        }
    }else if(clear_meta){
        has_meta = false;
        meta.clear();
    }
    return true;
}

bool StatCacheNode::UpdateHasLock(const struct stat* pstat, bool clear_meta)
{
    return UpdateHasLock(pstat, nullptr, clear_meta);
}

bool StatCacheNode::UpdateHasLock(bool is_notruncate)
{
    notruncate = is_notruncate;
    return true;
}

bool StatCacheNode::UpdateHasLock(const std::string* pextvalue)
{
    // [NOTE]
    // This can only be set for Symlink.
    //
    if(isSymlinkHasLock()){
        if(pextvalue){
            has_extval = true;
            extvalue   = *pextvalue;
        }else{
            has_extval = false;
            extvalue.clear();
        }
    }
    return true;
}

bool StatCacheNode::UpdateHasLock()
{
    hit_count = 0;              // Reset hit count
    SetCurrentTime(cache_date); // Set now time.
    return true;
}

bool StatCacheNode::Update(const struct stat& stbuf, const headers_t& meta)
{
    std::lock_guard<std::mutex> lock(StatCacheNode::cache_lock);

    if(fullpath.empty()){
        return false;
    }
    if(!UpdateHasLock(&stbuf, &meta, false) || !UpdateHasLock()){
        return false;
    }
    return true;
}

bool StatCacheNode::Update(const struct stat& stbuf, bool clear_meta)
{
    std::lock_guard<std::mutex> lock(StatCacheNode::cache_lock);

    if(fullpath.empty()){
        return false;
    }
    if(!UpdateHasLock(&stbuf, clear_meta) || !UpdateHasLock()){
        return false;
    }
    return true;
}

bool StatCacheNode::Update(bool is_notruncate)
{
    std::lock_guard<std::mutex> lock(StatCacheNode::cache_lock);

    if(fullpath.empty()){
        return false;
    }
    if(!UpdateHasLock(is_notruncate) || !UpdateHasLock()){
        return false;
    }
    return true;
}

bool StatCacheNode::Update(const std::string& extvalue)
{
    std::lock_guard<std::mutex> lock(StatCacheNode::cache_lock);

    if(fullpath.empty()){
        return false;
    }
    return UpdateHasLock(&extvalue);
}

bool StatCacheNode::SetHasLock(const struct stat& stbuf, const headers_t& meta, bool is_notruncate)
{
    if(!UpdateHasLock(&stbuf, &meta, false) || !UpdateHasLock(is_notruncate) || !UpdateHasLock()){
        return false;
    }
    return true;
}

bool StatCacheNode::Set(const struct stat& stbuf, const headers_t& meta, bool is_notruncate)
{
    std::lock_guard<std::mutex> lock(StatCacheNode::cache_lock);

    if(fullpath.empty()){
        return false;
    }
    return SetHasLock(stbuf, meta, is_notruncate);
}

bool StatCacheNode::CheckETagValueHasLock(const char* petagval) const
{
    if(!petagval || 0 == strlen(petagval)){
        return true;    // No checking ETag
    }
    if(!has_meta){
        // not have meta headers
        return false;
    }
    auto iter = meta.find("etag");
    if(iter == meta.end()){
        // not have "ETag" header
        return false;
    }

    // compare ETag value
    std::string strval = iter->second;
    if(strval != petagval){
        // different ETag
        return false;
    }

    // same ETag
    return true;
}

std::shared_ptr<StatCacheNode> StatCacheNode::FindHasLock(const std::string& strpath, const char* petagval, bool& needTruncate)
{
    needTruncate = false;

    if(fullpath != strpath){
        // not same self leaf
        return std::shared_ptr<StatCacheNode>();
    }
    if(IsExpiredHasLock()){
        // this cache is expired
        needTruncate = true;
        return std::shared_ptr<StatCacheNode>();
    }
    if(petagval && !CheckETagValueHasLock(petagval)){
        needTruncate = true;
        return std::shared_ptr<StatCacheNode>();
    }
    return shared_from_this();
}

std::shared_ptr<StatCacheNode> StatCacheNode::Find(const std::string& strpath, const char* petagval)
{
    std::lock_guard<std::mutex> lock(StatCacheNode::cache_lock);
    bool needTruncate = false;      // Not use in this method

    return FindHasLock(strpath, petagval, needTruncate);
}

bool StatCacheNode::GetHasLock(headers_t* pmeta, struct stat* pst)
{
    if(fullpath.empty()){
        return false;
    }
    if(pmeta){
        if(!has_meta){
            return false;
        }
        *pmeta = meta;
    }
    if(pst){
        if(!has_stat){
            return false;
        }
        *pst = stbuf;
    }
    if(StatCacheNode::IsExpireIntervalType){
        SetCurrentTime(cache_date);
    }
    ++hit_count;

    return true;
}

std::string StatCacheNode::Get()
{
    std::lock_guard<std::mutex> lock(StatCacheNode::cache_lock);
    return fullpath;
}

bool StatCacheNode::Get(headers_t* pmeta, struct stat* pstbuf)
{
    std::lock_guard<std::mutex> lock(StatCacheNode::cache_lock);
    return GetHasLock(pmeta, pstbuf);
}

bool StatCacheNode::Get(headers_t& get_meta, struct stat& st)
{
    std::lock_guard<std::mutex> lock(StatCacheNode::cache_lock);
    return GetHasLock(&get_meta, &st);
}

bool StatCacheNode::Get(headers_t& get_meta)
{
    std::lock_guard<std::mutex> lock(StatCacheNode::cache_lock);
    return GetHasLock(&get_meta, nullptr);
}

bool StatCacheNode::Get(struct stat& st)
{
    std::lock_guard<std::mutex> lock(StatCacheNode::cache_lock);
    return GetHasLock(nullptr, &st);
}

unsigned long StatCacheNode::GetHitCount() const
{
    std::lock_guard<std::mutex> lock(StatCacheNode::cache_lock);
    return hit_count;
}

struct timespec StatCacheNode::GetDate() const
{
    std::lock_guard<std::mutex> lock(StatCacheNode::cache_lock);
    return cache_date;
}

objtype_t StatCacheNode::GetTypeHasLock() const
{
    return cache_type;
}

objtype_t StatCacheNode::GetType() const
{
    std::lock_guard<std::mutex> lock(StatCacheNode::cache_lock);
    return GetTypeHasLock();
}

const std::string& StatCacheNode::GetPathHasLock() const
{
    return fullpath;
}

bool StatCacheNode::HasStatHasLock() const
{
    return has_stat;
}

bool StatCacheNode::HasMetaHasLock() const
{
    return has_meta;
}

bool StatCacheNode::GetNoTruncateHasLock() const
{
    return notruncate;
}

unsigned long StatCacheNode::IncrementHitCount()
{
    std::lock_guard<std::mutex> lock(StatCacheNode::cache_lock);
    return ++hit_count;
}

bool StatCacheNode::GetExtraHasLock(std::string& value)
{
    if(!has_extval){
        return false;
    }
    value = extvalue;

    if(StatCacheNode::IsExpireIntervalType){
        SetCurrentTime(cache_date);
    }
    ++hit_count;

    return true;
}

bool StatCacheNode::GetExtra(std::string& value)
{
    std::lock_guard<std::mutex> lock(StatCacheNode::cache_lock);
    return GetExtraHasLock(value);
}

s3obj_type_map_t::size_type StatCacheNode::GetChildMapHasLock(s3obj_type_map_t& childmap)
{
    childmap.clear();
    return childmap.size();
}

s3obj_type_map_t::size_type StatCacheNode::GetChildMap(s3obj_type_map_t& childmap)
{
    std::lock_guard<std::mutex> lock(StatCacheNode::cache_lock);
    return GetChildMapHasLock(childmap);
}

bool StatCacheNode::IsExpireStatCacheTimeHasLock() const
{
    if(NeedExpireCheckHasLock(cache_date)){
        if(IsExpireStatCacheTime(cache_date, StatCacheNode::GetExpireTime())){
            // this cache is expired
            return true;
        }
    }
    return false;
}

bool StatCacheNode::IsExpiredHasLock()
{
    if(notruncate){
        // not truncate
        return false;
    }
    if(IsExpireStatCacheTimeHasLock()){
        return true;
    }
    if(!has_meta && !has_stat && !has_extval){
        // this cache is empty
        return true;
    }
    return false;
}

bool StatCacheNode::IsExpired()
{
    std::lock_guard<std::mutex> lock(StatCacheNode::cache_lock);
    return IsExpiredHasLock();
}

void StatCacheNode::ClearNoTruncate()
{
    std::lock_guard<std::mutex> lock(StatCacheNode::cache_lock);
    notruncate = false;
}

bool StatCacheNode::TruncateCacheHasLock()
{
    // [NOTE]
    // This base class (and any other type besides Directory) does not
    // have child objects, so the Truncate operation will always fail.
    //
    return false;
}

bool StatCacheNode::TruncateCache()
{
    std::lock_guard<std::mutex> lock(StatCacheNode::cache_lock);
    return TruncateCacheHasLock();
}

void StatCacheNode::DumpElementHasLock(const std::string& indent, std::ostringstream& oss) const
{
    oss << indent << "fullpath   = " << fullpath                          << std::endl;
    oss << indent << "cache_type = " << STR_OBJTYPE(cache_type)           << std::endl;
    oss << indent << "hit_count  = " << hit_count                         << std::endl;
    oss << indent << "cache_date = " << str(cache_date)                   << std::endl;
    oss << indent << "notruncate = " << (notruncate ? "true" : "false")   << std::endl;

    oss << indent << "has_extval = " << (has_extval ? "true" : "false")   << std::endl;
    oss << indent << "extvalue   = " << extvalue                          << std::endl;

    oss << indent << "has_stat   = " << (has_stat ? "true" : "false")     << std::endl;
    oss << indent << "stbuf      = {"                                     << std::endl;
    oss << indent << "  st_size  = " << std::dec << static_cast<unsigned long long>(stbuf.st_size)      << std::endl;
    oss << indent << "  st_mode  = " << std::setw(4) << std::setfill('0') << std::oct  << stbuf.st_mode << std::endl;
    oss << indent << "  st_uid   = " << std::dec<< static_cast<unsigned int>(stbuf.st_uid)              << std::endl;
    oss << indent << "  st_gid   = " << std::dec<< static_cast<unsigned int>(stbuf.st_gid)              << std::endl;
    oss << indent << "  st_atime = " << std::dec<< static_cast<unsigned long>(stbuf.st_atime)           << std::endl;
    oss << indent << "  st_mtime = " << std::dec<< static_cast<unsigned long>(stbuf.st_mtime)           << std::endl;
    oss << indent << "  st_ctime = " << std::dec<< static_cast<unsigned long>(stbuf.st_ctime)           << std::endl;
    oss << indent << "}"                                                  << std::endl;

    oss << indent << "has_meta   = " << (has_meta ? "true" : "false")     << std::endl;
    oss << indent << "meta       = {"                                     << std::endl;
    for(auto iter = meta.cbegin(); iter != meta.cend(); ++iter){
        if(lower(iter->first) == "x-amz-meta-mode"){
            // ex. "x-amz-meta-mode = 0666(438)"
            oss << indent << "  " << std::left << std::setw(20) << std::setfill(' ') << iter->first << "= " << std::setw(4) << std::setfill('0') << std::oct << static_cast<unsigned int>(cvt_strtoofft(iter->second.c_str(), 10)) << "(" << iter->second << ")" << std::endl;
        }else{
            oss << indent << "  " << std::left << std::setw(20) << std::setfill(' ') << iter->first << "= " << iter->second << std::endl;
        }
    }
    oss << indent << "}" << std::endl;
}

void StatCacheNode::DumpHasLock(const std::string& indent, bool detail, std::ostringstream& oss)
{
    if(!detail){
        oss << indent << fullpath << std::endl;
    }else{
        std::string child_indent = indent + "  ";

        oss << indent << fullpath << " = {" << std::endl;
        DumpElementHasLock(child_indent, oss);
        oss << indent << "}" << std::endl;
    }
}

void StatCacheNode::Dump(bool detail)
{
    std::lock_guard<std::mutex> lock(StatCacheNode::cache_lock);
    std::string        indent;
    std::ostringstream oss;

    oss << "STAT CACHE DUMP(" << (detail ? "full tree detail)" : "simple tree only)") << std::endl;
    DumpHasLock(indent, detail, oss);
    S3FS_PRN_DBG("%s", oss.str().c_str());
}

//===================================================================
// Derived Class : FileStatCache
//===================================================================
//
// Methods
//
FileStatCache::FileStatCache(const char* path) : StatCacheNode(path, objtype_t::FILE)
{
    StatCacheNode::IncrementCacheCount(objtype_t::FILE);
}

FileStatCache::~FileStatCache()
{
    StatCacheNode::DecrementCacheCount(objtype_t::FILE);
}

//===================================================================
// Derived Class : DirStatCache
//===================================================================
//
// Methods
//
DirStatCache::DirStatCache(const char* path, objtype_t type) : StatCacheNode(path, type), dir_cache_type(type)
{
    std::lock_guard<std::mutex> dircachelock(dir_cache_lock);
    SetCurrentTime(last_check_date);

    StatCacheNode::IncrementCacheCount(type);
}

DirStatCache::~DirStatCache()
{
    std::lock_guard<std::mutex> dircachelock(dir_cache_lock);
    children.clear();

    StatCacheNode::DecrementCacheCount(dir_cache_type);
}

bool DirStatCache::ClearHasLock()
{
    {
        std::lock_guard<std::mutex> dircachelock(dir_cache_lock);
        children.clear();
    }
    return StatCacheNode::ClearHasLock();
}

bool DirStatCache::RemoveChildHasLock(const std::string& strpath)
{
    if(strpath.empty()){
        return false;
    }

    // Check the path contains fullpath
    if(strpath == GetPathHasLock() || strpath.size() < GetPathHasLock().size() || GetPathHasLock() != strpath.substr(0, GetPathHasLock().size())){
        return false;
    }

    // make key(leaf name without slash) for children map
    std::string strLeafName;
    bool        hasNestedChildren = false;
    if(!GetChildLeafNameHasLock(strpath, strLeafName, hasNestedChildren)){
        return false;
    }

    // Search in children
    std::lock_guard<std::mutex> dircachelock(dir_cache_lock);
    auto iter = children.find(strLeafName);
    if(iter == children.cend()){
        // not found
        return false;
    }

    // found
    if(hasNestedChildren){
        // type must be directory
        if(!iter->second->isDirectoryHasLock()){
            return false;
        }
        if(!iter->second->RemoveChildHasLock(strpath)){
            return false;
        }
        if(iter->second->isRemovableHasLock()){
            children.erase(iter);
        }
    }else{
        if(iter->second->isDirectoryHasLock()){
            // if it is a directory type, first clear the data.
            if(!iter->second->UpdateHasLock(nullptr, nullptr, true) || !iter->second->UpdateHasLock(false) || !iter->second->UpdateHasLock()){
                return false;
            }
        }
        if(iter->second->isRemovableHasLock()){
            children.erase(iter);
        }
    }
    return true;
}

bool DirStatCache::isRemovableHasLock()
{
    if(HasStatHasLock() || HasMetaHasLock()){
        return false;
    }

    std::lock_guard<std::mutex> dircachelock(dir_cache_lock);
    if(HasExistedChildHasLock()){
        return false;
    }
    return true;
}

bool DirStatCache::HasExistedChildHasLock()
{
    // [FIXME]
    // This for statement will result in an error saying that it can be
    // replaced with std::any_of using clang-tidy.
    // However, if we replace this loop with std::any_of as shown below,
    // an error will occur in thread_safety.
    //
    //    std::any_of(children.begin(), children.end(), [](const auto& pair){ return !pair.second->isNegativeHasLock(); });
    //
    // This is because that when using as std::any_of algorithms with
    // lambda expressions, static analysis assumes that "the lambda may
    // be called outside the scope of the caller."
    // As a result, it concludes that there is no guarantee that the
    // mutex is held within the lambda (a limitation of the analysis).
    //
    // Therefore, until this false positive is resolved, we use
    // NOLINTNEXTLINE(readability-use-anyofallof) to avoid clang-tidy
    // errors.
    //

    // NOLINTNEXTLINE(readability-use-anyofallof)
    for(const auto& pair: children){
        if(!pair.second->isNegativeHasLock()){
            return true;
        }
    }
    return false;
}

bool DirStatCache::AddHasLock(const std::string& strpath, const struct stat* pstat, const headers_t* pmeta, objtype_t type, bool is_notruncate)
{
    // Check size
    if(strpath.size() < GetPathHasLock().size()){          // fullpath includes the terminating slash, but strpath may not.
        return false;
    }

    //
    // Check path (itself or contains itself)
    //
    // [NOTE]
    // Directory paths must end with a slash, but strpath does not.
    //
    if(GetPathHasLock() == strpath || GetPathHasLock().substr(0, GetPathHasLock().size() - 1) == strpath){
        if(!IS_DIR_OBJ(type)){
            // The path matched but the object type is not a directory
            return false;
        }

        // Update directory type / stat / meta / no truncate flag / hit count / time
        if(!UpdateHasLock(type)){
            return false;
        }else{
            std::lock_guard<std::mutex> dircachelock(dir_cache_lock);
            dir_cache_type = GetTypeHasLock();
        }
        if(!UpdateHasLock(pstat, pmeta, true) || !UpdateHasLock(is_notruncate) || !UpdateHasLock()){
            return false;
        }
        return true;

    }else if(strpath.substr(0, GetPathHasLock().size()) != GetPathHasLock()){
        // The path does not include the path of this object.
        return false;
    }

    // make key(leaf name without slash) for children map
    std::string strLeafName;
    bool        hasNestedChildren = false;
    if(!GetChildLeafNameHasLock(strpath, strLeafName, hasNestedChildren)){
        return false;
    }

    // Search in children
    std::lock_guard<std::mutex> dircachelock(dir_cache_lock);
    auto iter = children.find(strLeafName);
    if(iter != children.end()){
        if(iter->second->isNegativeHasLock()){
            // found negative type
            if(hasNestedChildren){
                // strpath is an under child.

                // [NOTE]
                // The strpath is an under child, so the found child must be a directory.
                // However, it is currently a negative type, so it shuold be deleted.
                //
                children.erase(iter);
                iter = children.end();
            }else{
                // strpath is a direct child
                if(!IS_NEGATIVE_OBJ(type)){
                    // [NOTE]
                    // If the object found is Negative type and the adding object
                    // is not Negative type, delete the found Negative type object.
                    //
                    children.erase(iter);
                    iter = children.end();
                }
            }
        }else{
            // found not negative type
            if(!hasNestedChildren && (IS_NEGATIVE_OBJ(type) || !iter->second->isSameObjectTypeHasLock(type))){
                // strpath is a direct child as negative cache
                children.erase(iter);
                iter = children.end();
            }
        }
    }

    if(iter != children.end()){
        // found
        if(hasNestedChildren){
            // Add an under child
            if(!iter->second->AddHasLock(strpath, pstat, pmeta, type, is_notruncate)){
                return false;
            }
        }else{
            // Add as a child
            if(!iter->second->isSameObjectTypeHasLock(type)){
                // The type(other than negative type) of object found is different
                return false;
            }
            // Already has strpath child, so set stat and meta.
            if(!iter->second->UpdateHasLock(pstat, pmeta, true) || !iter->second->UpdateHasLock(is_notruncate) || !iter->second->UpdateHasLock()){
                return false;
            }
        }
    }else{
        // not found, add as a new object
        if(hasNestedChildren){
            // First add directory child, and add an under child
            std::string subdir     = GetPathHasLock() + strLeafName + "/";  // terminate with "/". (if not terminated, it will added automatically.)
            auto        pstatcache = std::make_shared<DirStatCache>(subdir.c_str());

            if(!pstatcache->AddHasLock(strpath, pstat, pmeta, type, is_notruncate)){
                return false;
            }

            // add as a child
            children[strLeafName] = std::move(pstatcache);

        }else{
            // create and add as a direct child
            std::shared_ptr<StatCacheNode> pstatcache;
            if(IS_DIR_OBJ(type)){
                pstatcache = std::make_shared<DirStatCache>(strpath.c_str(), type);
            }else if(objtype_t::FILE == type){
                pstatcache = std::make_shared<FileStatCache>(strpath.c_str());
            }else if(objtype_t::SYMLINK == type){
                pstatcache = std::make_shared<SymlinkStatCache>(strpath.c_str());
            }else if(objtype_t::NEGATIVE == type){
                if(!StatCacheNode::IsEnabledNegativeCache()){
                    // Negative cache is invalid.
                    // This method does not add it and returns true.
                    //
                    return true;
                }
                pstatcache = std::make_shared<NegativeStatCache>(strpath.c_str());
            }else{  // objtype_t::UNKNOWN
                // [NOTE]
                // If the type of object is UNKNOWN,  it has not been determined
                // up to this point(by path name etc).
                // Therefore, it is determined from the st_mode in stat structure
                // or meta header.
                //
                if(pstat){
                    if(S_ISREG(pstat->st_mode)){
                        pstatcache = std::make_shared<FileStatCache>(strpath.c_str());
                    }else if(S_ISLNK(pstat->st_mode)){
                        pstatcache = std::make_shared<SymlinkStatCache>(strpath.c_str());
                    }else if(S_ISDIR(pstat->st_mode)){
                        pstatcache = std::make_shared<DirStatCache>(strpath.c_str(), objtype_t::DIR_NOT_TERMINATE_SLASH);   // objtype_t::DIR_NOT_TERMINATE_SLASH
                    }else{
                        S3FS_PRN_ERR("The object type of path(%s) is unspecified(objtype_t::UNKNOWN) and cannot be determined.", strpath.c_str());
                        return false;
                    }
                }else if(pmeta){
                    if(is_reg_fmt(*pmeta)){
                        pstatcache = std::make_shared<FileStatCache>(strpath.c_str());
                    }else if(is_symlink_fmt(*pmeta)){
                        pstatcache = std::make_shared<SymlinkStatCache>(strpath.c_str());
                    }else if(is_dir_fmt(*pmeta)){
                        pstatcache = std::make_shared<DirStatCache>(strpath.c_str(), objtype_t::DIR_NOT_TERMINATE_SLASH);   // objtype_t::DIR_NOT_TERMINATE_SLASH
                    }else{
                        S3FS_PRN_ERR("The object type of path(%s) is unspecified(objtype_t::UNKNOWN) and cannot be determined.", strpath.c_str());
                        return false;
                    }
                }else{
                    S3FS_PRN_ERR("The object type of path(%s) is unspecified(objtype_t::UNKNOWN) and cannot be determined.", strpath.c_str());
                    return false;
                }
            }

            // set stat and meta
            if(objtype_t::NEGATIVE != type){
                if(!pstatcache->UpdateHasLock(pstat, pmeta, true) || !pstatcache->UpdateHasLock(is_notruncate) || !pstatcache->UpdateHasLock()){
                    return false;
                }
            }

            // add as a child
            children[strLeafName] = std::move(pstatcache);
        }
    }

    if(!UpdateHasLock()){
        return false;
    }
    return true;
}

s3obj_type_map_t::size_type DirStatCache::GetChildMapHasLock(s3obj_type_map_t& childmap)
{
    childmap.clear();

    std::lock_guard<std::mutex> dircachelock(dir_cache_lock);
    for(const auto& pair: children){
        if(!pair.second->isNegativeHasLock()){
            childmap[pair.first] = pair.second->GetTypeHasLock();
        }
    }
    return childmap.size();
}

std::shared_ptr<StatCacheNode> DirStatCache::FindHasLock(const std::string& strpath, const char* petagval, bool& needTruncate)
{
    needTruncate = false;

    // Check size
    if(strpath.size() < GetPathHasLock().size()){          // fullpath includes the terminating slash, but strpath may not.
        return std::shared_ptr<StatCacheNode>();
    }

    // Check self path
    //
    // [NOTE]
    // Directory paths must end with a slash, but strpath does not.
    //
    if(GetPathHasLock() == strpath || GetPathHasLock().substr(0, GetPathHasLock().size() - 1) == strpath){
        if(IsExpiredHasLock()){
            // this cache is expired
            needTruncate = true;
            return std::shared_ptr<StatCacheNode>();
        }
        if(petagval && !CheckETagValueHasLock(petagval)){
            needTruncate = true;
            return std::shared_ptr<StatCacheNode>();
        }
        return shared_from_this();
    }

    // Checks whether the path of this object is included
    if(strpath.substr(0, GetPathHasLock().size()) != GetPathHasLock()){
        return std::shared_ptr<StatCacheNode>();
    }

    // make key(leaf name without slash) for children map
    std::string strLeafName;
    bool        hasNestedChildren = false;
    if(!GetChildLeafNameHasLock(strpath, strLeafName, hasNestedChildren)){
        return std::shared_ptr<StatCacheNode>();
    }

    std::shared_ptr<StatCacheNode> pstatcache;
    bool isRemovePath = false;
    {
        std::lock_guard<std::mutex> dircachelock(dir_cache_lock);
        auto iter = children.find(strLeafName);
        if(iter == children.cend()){
            // not found in children
            return std::shared_ptr<StatCacheNode>();
        }

        // found in children
        if(hasNestedChildren){
            // search in found child
            bool childTruncate = false;     // Not use in this method
            return iter->second->FindHasLock(strpath, petagval, childTruncate);
        }

        // check child's expired and ETag
        if(iter->second->IsExpiredHasLock()){
            // this cache is expired
            isRemovePath = true;
        }else if(petagval && !iter->second->CheckETagValueHasLock(petagval)){
            // different ETag
            isRemovePath = true;
        }else{
            pstatcache = iter->second;
        }
    }
    if(isRemovePath){
        // expired or different etag
        if(!RemoveChildHasLock(strpath)){
            S3FS_PRN_ERR("Failed to remove stat which is expired or different ETag[path=%s]", strpath.c_str());
        }
        return std::shared_ptr<StatCacheNode>();
    }

    // found child
    return pstatcache;
}

bool DirStatCache::NeedTruncateProcessing()
{
    std::lock_guard<std::mutex> lock(StatCacheNode::cache_lock);
    if(!NeedExpireCheckHasLock(cache_date)){
        return false;
    }

    std::lock_guard<std::mutex> dircachelock(dir_cache_lock);
    return IsExpireStatCacheTime(last_check_date, StatCacheNode::GetExpireTime());
}

//
// Override to add the condition when children is empty.
//
bool DirStatCache::IsExpiredHasLock()
{
    if(GetNoTruncateHasLock()){
        // not truncate
        return false;
    }
    if(IsExpireStatCacheTimeHasLock()){
        return true;
    }

    std::lock_guard<std::mutex> dircachelock(dir_cache_lock);
    if(!HasStatHasLock() && !HasMetaHasLock() && !HasExistedChildHasLock()){
        // this cache is empty
        return true;
    }
    return false;
}

bool DirStatCache::TruncateCacheHasLock()
{
    bool isTruncated = false;

    // check self
    if(StatCacheNode::IsExpiredHasLock()){
        // [NOTE]
        // If this directory is Expired, only the cached data will be cleared first.
        // It is up to the caller to decide whether to delete this directory.
        //
        if(!ClearDataHasLock()){
            return false;
        }
    }

    // Check all children
    std::lock_guard<std::mutex> dircachelock(dir_cache_lock);
    for(auto iter = children.begin(); iter != children.end(); ){
        if(iter->second->isDirectoryHasLock()){
            // [NOTE]
            // It is checked only if the expire time has passed since the last check.
            //
            if(iter->second->IsExpireStatCacheTimeHasLock()){
                if(iter->second->TruncateCacheHasLock()){
                    // Some files and directories under the directory have been deleted.
                    isTruncated = true;

                    if(iter->second->IsExpiredHasLock()){
                        // This child directory is now empty and can be deleted.
                        S3FS_PRN_DBG("Remove stat cache [directory path=%s]", iter->first.c_str());

                        iter = children.erase(iter);
                        continue;
                    }
                }
            }
        }else{
            // not a directory
            if(iter->second->IsExpiredHasLock()){
                // This object has expired and can be deleted.
                S3FS_PRN_DBG("Remove stat cache [path=%s]", iter->first.c_str());

                isTruncated = true;
                iter = children.erase(iter);
                continue;
            }
        }
        ++iter;
    }

    if(isTruncated){
        // Update last check time for this object
        SetCurrentTime(last_check_date);
    }

    return isTruncated;
}

bool DirStatCache::GetChildLeafNameHasLock(const std::string& strpath, std::string& strLeafName, bool& hasNestedChildren)
{
    if(strpath.size() < GetPathHasLock().size()){
        return false;
    }

    strLeafName = strpath.substr(GetPathHasLock().size());
    if(strLeafName.empty()){
        return false;
    }

    std::string::size_type slash_pos = strLeafName.find_first_of('/');
    if(slash_pos == (strLeafName.size() - 1)){
        // strpath is my sub-directory leaf
        strLeafName.resize(slash_pos);
        hasNestedChildren = false;
    }else if(slash_pos != std::string::npos){
        // strpath is at least two levels deep within this directory.
        strLeafName.resize(slash_pos);
        hasNestedChildren = true;
    }else{
        // strpath is my child file leaf
        hasNestedChildren = false;
    }
    return true;
}

void DirStatCache::DumpHasLock(const std::string& indent, bool detail, std::ostringstream& oss)
{
    std::string child_indent    = indent + "  ";
    std::string in_child_indent = child_indent + "  ";

    oss << indent << GetPathHasLock() << " = {" << std::endl;

    DumpElementHasLock(child_indent, oss);

    std::vector<std::string> children_paths;
    {
        std::lock_guard<std::mutex> dircachelock(dir_cache_lock);

        oss << child_indent << "children(" << children.size() << ") = [" << std::endl;

        for(const auto& pair: children){
            std::string child_path = GetPathHasLock() + pair.first;
            children_paths.push_back(child_path);
        }
    }
    for(const std::string& child_fullpath: children_paths){
        bool childTruncate = false;
        auto pstatcache    = FindHasLock(child_fullpath, nullptr, childTruncate);
        if(pstatcache){
            pstatcache->DumpHasLock(in_child_indent, detail, oss);
        }else{
            oss << in_child_indent << child_fullpath << "(NO STAT OBJECT)" << std::endl;
        }
    }
    oss << child_indent << "]" << std::endl;

    oss << indent << "}" << std::endl;
}

//===================================================================
// Derived Class : SymlinkStatCache
//===================================================================
//
// Methods
//
SymlinkStatCache::SymlinkStatCache(const char* path) : StatCacheNode(path, objtype_t::SYMLINK)
{
    StatCacheNode::IncrementCacheCount(objtype_t::SYMLINK);
}

SymlinkStatCache::~SymlinkStatCache()
{
    StatCacheNode::DecrementCacheCount(objtype_t::SYMLINK);
}

bool SymlinkStatCache::ClearHasLock()
{
    link_path.clear();
    return StatCacheNode::ClearHasLock();
}

//===================================================================
// Derived Class : NegativeStatCache
//===================================================================
//
// Methods
//
NegativeStatCache::NegativeStatCache(const char* path) : StatCacheNode(path, objtype_t::NEGATIVE)
{
    StatCacheNode::IncrementCacheCount(objtype_t::NEGATIVE);
}

NegativeStatCache::~NegativeStatCache()
{
    StatCacheNode::DecrementCacheCount(objtype_t::NEGATIVE);
}

bool NegativeStatCache::CheckETagValueHasLock(const char* petagval) const
{
    // Negative cache doe not have meta header(ETag), so it always returns true.
    //
    return true;
}

//
// Override to exclude when has_stat and has_meta are false (both in this object always are false).
//
bool NegativeStatCache::IsExpiredHasLock()
{
    if(GetNoTruncateHasLock()){
        // not truncate
        return false;
    }
    if(IsExpireStatCacheTimeHasLock()){
        return true;
    }
    return false;
}

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
