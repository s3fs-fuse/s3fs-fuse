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

#ifndef S3FS_CACHE_NODE_H_
#define S3FS_CACHE_NODE_H_

#include <iosfwd>
#include <memory>
#include <mutex>

#include "common.h"
#include "metaheader.h"
#include "s3objlist.h"
#include "types.h"

//-------------------------------------------------------------------
// Utilities
//-------------------------------------------------------------------
#define MAX_STAT_CACHE_COUNTER  6

constexpr int stat_counter_pos(objtype_t type)
{
    if(IS_FILE_OBJ(type)){
        return 1;
    }else if(IS_SYMLINK_OBJ(type)){
        return 2;
    }else if(IS_DIR_OBJ(type)){
        return 3;
    }else if(IS_NEGATIVE_OBJ(type)){
        return 4;
    }else{  // objtype_t::UNKNOWN and other
        return 0;
    }
}

//-------------------------------------------------------------------
// Base Class : StatCacheNode
//-------------------------------------------------------------------
class DirStatCache;

class StatCacheNode : public std::enable_shared_from_this<StatCacheNode>
{
    // [NOTE]
    // As an exception, declare friends to call some protected methods from
    // DirStatCache::RemoveChildHasLock and AddHasLock methods.
    //
    friend class DirStatCache;

    protected:
        // Stat cache counter(see. stat_counter_pos())
        //     <position>
        //     0 = total node count
        //     1 = file node count
        //     2 = symlink node count
        //     3 = directory node count
        //     4 = negative cache node count
        //
        static std::mutex       counter_lock;
        static unsigned long    counter[MAX_STAT_CACHE_COUNTER] GUARDED_BY(counter_lock);
        static bool             EnableExpireTime;
        static bool             IsExpireIntervalType;                                      // if this flag is true, cache data is updated at last access time.
        static time_t           ExpireTime;
        static bool             UseNegativeCache;
        static std::mutex       cache_lock;                                                // for internal data
        static unsigned long    DisableCheckingExpire GUARDED_BY(cache_lock);              // If greater than 0, it disables the expiration check, which allows disabling checks during processing.
        static struct timespec  DisableExpireDate GUARDED_BY(cache_lock);                  // Data registered after this time will not be truncated(if 0 < DisableCheckingExpire)

    private:
        objtype_t               cache_type GUARDED_BY(StatCacheNode::cache_lock) = objtype_t::UNKNOWN;  // object type is set in the constructor(except dir).
        std::string             fullpath   GUARDED_BY(StatCacheNode::cache_lock);          // full path(This value is set only when the object is created)
        unsigned long           hit_count  GUARDED_BY(StatCacheNode::cache_lock) = 0L;     // hit count
        struct timespec         cache_date GUARDED_BY(StatCacheNode::cache_lock) = {0, 0}; // registration/renewal time
        bool                    notruncate GUARDED_BY(StatCacheNode::cache_lock) = false;  // If true, not remove automatically at checking truncate.
        bool                    has_stat   GUARDED_BY(StatCacheNode::cache_lock) = false;  // valid stat information flag (for case only path registration and no stat information)
        struct stat             stbuf      GUARDED_BY(StatCacheNode::cache_lock) = {};     // stat data
        bool                    has_meta   GUARDED_BY(StatCacheNode::cache_lock) = false;  // valid meta headers information flag (for case only path registration and no meta headers)
        headers_t               meta       GUARDED_BY(StatCacheNode::cache_lock);          // meta list
        bool                    has_extval GUARDED_BY(StatCacheNode::cache_lock) = false;  // valid extra value flag
        std::string             extvalue   GUARDED_BY(StatCacheNode::cache_lock);          // extra value for key(ex. used for symlink)

    protected:
        static void IncrementCacheCount(objtype_t type);
        static void DecrementCacheCount(objtype_t type);
        static bool SetNegativeCache(bool flag);
        static bool NeedExpireCheckHasLock(const struct timespec& ts) REQUIRES(StatCacheNode::cache_lock);

        // Cache Type
        bool isSameObjectTypeHasLock(objtype_t type) const REQUIRES(StatCacheNode::cache_lock);
        bool isDirectoryHasLock() const REQUIRES(StatCacheNode::cache_lock);
        bool isFileHasLock() const REQUIRES(StatCacheNode::cache_lock);
        bool isSymlinkHasLock() const REQUIRES(StatCacheNode::cache_lock);
        bool isNegativeHasLock() const REQUIRES(StatCacheNode::cache_lock);

        // Clear
        virtual bool ClearDataHasLock() REQUIRES(StatCacheNode::cache_lock);
        virtual bool ClearHasLock() REQUIRES(StatCacheNode::cache_lock);
        virtual bool RemoveChildHasLock(const std::string& strpath) REQUIRES(StatCacheNode::cache_lock);
        virtual bool isRemovableHasLock() REQUIRES(StatCacheNode::cache_lock);

        // Add
        virtual bool AddHasLock(const std::string& strpath, const struct stat* pstat, const headers_t* pmeta, objtype_t type, bool is_notruncate) REQUIRES(StatCacheNode::cache_lock);
        virtual bool AddS3ObjListHasLock(const std::string& strpath, const S3ObjList& list) REQUIRES(StatCacheNode::cache_lock);

        // Update(Set)
        bool UpdateHasLock(objtype_t type) REQUIRES(StatCacheNode::cache_lock);
        virtual bool UpdateHasLock(const struct stat* pstat, const headers_t* pmeta, bool clear_meta) REQUIRES(StatCacheNode::cache_lock);
        virtual bool UpdateHasLock(const struct stat* pstat, bool clear_meta) REQUIRES(StatCacheNode::cache_lock);
        virtual bool UpdateHasLock(bool is_notruncate) REQUIRES(StatCacheNode::cache_lock);
        virtual bool UpdateHasLock(const std::string* pextvalue) REQUIRES(StatCacheNode::cache_lock);
        virtual bool UpdateHasLock() REQUIRES(StatCacheNode::cache_lock);
        virtual bool SetHasLock(const struct stat& stbuf, const headers_t& meta, bool is_notruncate) REQUIRES(StatCacheNode::cache_lock);

        // Get
        objtype_t GetTypeHasLock() const REQUIRES(StatCacheNode::cache_lock);
        const std::string& GetPathHasLock() const REQUIRES(StatCacheNode::cache_lock);
        bool HasStatHasLock() const REQUIRES(StatCacheNode::cache_lock);
        bool HasMetaHasLock() const REQUIRES(StatCacheNode::cache_lock);
        bool GetNoTruncateHasLock() const REQUIRES(StatCacheNode::cache_lock);
        virtual bool GetHasLock(headers_t* pmeta, struct stat* pst) REQUIRES(StatCacheNode::cache_lock);
        virtual bool GetExtraHasLock(std::string& value) REQUIRES(StatCacheNode::cache_lock);
        virtual s3obj_type_map_t::size_type GetChildMapHasLock(s3obj_type_map_t& childmap) REQUIRES(StatCacheNode::cache_lock);
        virtual bool GetS3ObjListHasLock(S3ObjList& list) REQUIRES(StatCacheNode::cache_lock);

        // Find
        virtual bool CheckETagValueHasLock(const char* petagval) const REQUIRES(StatCacheNode::cache_lock);
        virtual std::shared_ptr<StatCacheNode> FindHasLock(const std::string& strpath, const char* petagval, bool& needTruncate) REQUIRES(StatCacheNode::cache_lock);

        // Cache out
        bool IsExpireStatCacheTimeHasLock() const REQUIRES(StatCacheNode::cache_lock);
        virtual bool IsExpiredHasLock() REQUIRES(StatCacheNode::cache_lock);
        virtual bool TruncateCacheHasLock() REQUIRES(StatCacheNode::cache_lock);

        // For debug
        void DumpElementHasLock(const std::string& indent, std::ostringstream& oss) const REQUIRES(StatCacheNode::cache_lock);
        virtual void DumpHasLock(const std::string& indent, bool detail, std::ostringstream& oss) REQUIRES(StatCacheNode::cache_lock);

    public:
        // Properties
        static unsigned long GetCacheCount(objtype_t type = objtype_t::UNKNOWN);
        static time_t GetExpireTime();
        static time_t SetExpireTime(time_t expire, bool is_interval = false);
        static time_t UnsetExpireTime();
        static bool IsEnableExpireTime();
        static bool EnableNegativeCache() { return SetNegativeCache(true); }
        static bool DisableNegativeCache() { return SetNegativeCache(false); }
        static bool IsEnabledNegativeCache() { return UseNegativeCache; }
        static bool PreventExpireCheck();
        static bool ResumeExpireCheck();

        // Constructor/Destructor
        explicit StatCacheNode(const char* path = nullptr, objtype_t type = objtype_t::UNKNOWN);
        virtual ~StatCacheNode();

        StatCacheNode(const StatCacheNode&) = delete;
        StatCacheNode(StatCacheNode&&) = delete;
        StatCacheNode& operator=(const StatCacheNode&) = delete;
        StatCacheNode& operator=(StatCacheNode&&) = delete;

        // Cache Type
        bool isSameObjectType(objtype_t type);
        bool isDirectory();
        bool isFile();
        bool isSymlink();
        bool isNegative();

        // Clear
        bool Clear();
        bool ClearData();
        bool RemoveChild(const std::string& strpath);

        // Add
        bool Add(const std::string& strpath, const struct stat* pstat, const headers_t* pmeta, objtype_t type, bool is_notruncate = false);
        bool AddExtra(const std::string& value);
        bool AddS3ObjList(const std::string& strpath, const S3ObjList& list);

        // Update(Set)
        bool Update(const struct stat& stbuf, const headers_t& meta);
        bool Update(const struct stat& stbuf, bool clear_meta);
        bool Update(bool is_notruncate);
        bool Update(const std::string& extvalue);
        bool Set(const struct stat& stbuf, const headers_t& meta, bool is_notruncate);

        // Get
        std::string Get();
        bool Get(headers_t* pmeta, struct stat* pstbuf);
        bool Get(headers_t& get_meta, struct stat& st);
        bool Get(headers_t& get_meta);
        bool Get(struct stat& st);
        objtype_t GetType() const;
        struct timespec GetDate() const;
        unsigned long GetHitCount() const;
        unsigned long IncrementHitCount();
        bool GetExtra(std::string& value);
        s3obj_type_map_t::size_type GetChildMap(s3obj_type_map_t& childmap);
        bool GetS3ObjList(S3ObjList& list);

        // Find
        std::shared_ptr<StatCacheNode> Find(const std::string& strpath, const char* petagval = nullptr);

        // Cache out
        bool IsExpired();
        void ClearNoTruncate();
        bool TruncateCache();

        // For debug
        void Dump(bool detail);
};

typedef std::map<std::string, std::shared_ptr<StatCacheNode>> statcache_map_t;

//-------------------------------------------------------------------
// Derived Class : FileStatCache
//-------------------------------------------------------------------
class FileStatCache : public StatCacheNode
{
    public:
        explicit FileStatCache(const char* path = nullptr);
        ~FileStatCache() override;

        FileStatCache(const FileStatCache&) = delete;
        FileStatCache(FileStatCache&&) = delete;
        FileStatCache& operator=(const FileStatCache&) = delete;
        FileStatCache& operator=(FileStatCache&&) = delete;
};

//-------------------------------------------------------------------
// Derived Class : DirStatCache
//-------------------------------------------------------------------
// [NOTE]
// The fullpath of a DirStatCache always ends with a slash ('/').
// The keys of the 'children' map managed by this object are the partial
// path names of the child objects(files, directories, etc).
// For sub-directory objects, the partial path names do not include a
// slash.
//
class DirStatCache : public StatCacheNode
{
    private:
        std::mutex      dir_cache_lock;                                                     // for local variables
        struct timespec last_check_date GUARDED_BY(dir_cache_lock) = {0, 0};
        objtype_t       dir_cache_type  GUARDED_BY(dir_cache_lock) = objtype_t::UNKNOWN;    // [NOTE] backup for use in destructors only
        statcache_map_t children        GUARDED_BY(dir_cache_lock);
        bool            has_s3obj       GUARDED_BY(dir_cache_lock) = false;
        S3ObjList       s3obj           GUARDED_BY(dir_cache_lock);

    protected:
        bool ClearHasLock() override REQUIRES(StatCacheNode::cache_lock);
        bool ClearS3ObjListHasLock() REQUIRES(dir_cache_lock);
        bool RemoveChildHasLock(const std::string& strpath) override REQUIRES(StatCacheNode::cache_lock);
        bool RemoveChildInS3ObjListHasLock(const std::string& strChildLeaf) REQUIRES(StatCacheNode::cache_lock, dir_cache_lock);
        bool isRemovableHasLock() override REQUIRES(StatCacheNode::cache_lock);
        bool HasExistedChildHasLock() REQUIRES(StatCacheNode::cache_lock, dir_cache_lock);

        bool AddHasLock(const std::string& strpath, const struct stat* pstat, const headers_t* pmeta, objtype_t type, bool is_notruncate) override REQUIRES(StatCacheNode::cache_lock);
        bool AddS3ObjListHasLock(const std::string& strpath, const S3ObjList& list) override REQUIRES(StatCacheNode::cache_lock);

        s3obj_type_map_t::size_type GetChildMapHasLock(s3obj_type_map_t& childmap) override REQUIRES(StatCacheNode::cache_lock);
        bool GetS3ObjListHasLock(S3ObjList& list) override REQUIRES(StatCacheNode::cache_lock);

        std::shared_ptr<StatCacheNode> FindHasLock(const std::string& strpath, const char* petagval, bool& needTruncate) override REQUIRES(StatCacheNode::cache_lock);

        bool NeedTruncateProcessing();
        bool IsExpiredHasLock() override REQUIRES(StatCacheNode::cache_lock);

        bool TruncateCacheHasLock() override REQUIRES(StatCacheNode::cache_lock);

        bool GetChildLeafNameHasLock(const std::string& strpath, std::string& strLeafName, bool& hasNestedChildren) REQUIRES(StatCacheNode::cache_lock);

        void DumpHasLock(const std::string& indent, bool detail, std::ostringstream& oss) override REQUIRES(StatCacheNode::cache_lock);

    public:
        explicit DirStatCache(const char* path = nullptr, objtype_t type = objtype_t::DIR_NORMAL);
        ~DirStatCache() override;

        DirStatCache(const DirStatCache&) = delete;
        DirStatCache(DirStatCache&&) = delete;
        DirStatCache& operator=(const DirStatCache&) = delete;
        DirStatCache& operator=(DirStatCache&&) = delete;
};

//-------------------------------------------------------------------
// Derived Class : SymlinkStatCache
//-------------------------------------------------------------------
class SymlinkStatCache : public StatCacheNode
{
    private:
        std::string       link_path;

    protected:
        bool ClearHasLock() override REQUIRES(StatCacheNode::cache_lock);

    public:
        explicit SymlinkStatCache(const char* path = nullptr);
        ~SymlinkStatCache() override;

        SymlinkStatCache(const SymlinkStatCache&) = delete;
        SymlinkStatCache(SymlinkStatCache&&) = delete;
        SymlinkStatCache& operator=(const SymlinkStatCache&) = delete;
        SymlinkStatCache& operator=(SymlinkStatCache&&) = delete;
};

//-------------------------------------------------------------------
// Derived Class : NegativeStatCache
//-------------------------------------------------------------------
class NegativeStatCache : public StatCacheNode
{
    protected:
        bool CheckETagValueHasLock(const char* petagval) const override REQUIRES(StatCacheNode::cache_lock);

        bool IsExpiredHasLock() override REQUIRES(StatCacheNode::cache_lock);

    public:
        explicit NegativeStatCache(const char* path = nullptr);
        ~NegativeStatCache() override;

        NegativeStatCache(const NegativeStatCache&) = delete;
        NegativeStatCache(NegativeStatCache&&) = delete;
        NegativeStatCache& operator=(const NegativeStatCache&) = delete;
        NegativeStatCache& operator=(NegativeStatCache&&) = delete;
};

//-------------------------------------------------------------------
// Utility Class : PreventStatCacheExpire
//-------------------------------------------------------------------
class PreventStatCacheExpire
{
    public:
        explicit PreventStatCacheExpire()
        {
            StatCacheNode::PreventExpireCheck();
        }

        ~PreventStatCacheExpire()
        {
            StatCacheNode::ResumeExpireCheck();
        }

        PreventStatCacheExpire(const PreventStatCacheExpire&) = delete;
        PreventStatCacheExpire(PreventStatCacheExpire&&) = delete;
        PreventStatCacheExpire& operator=(const PreventStatCacheExpire&) = delete;
        PreventStatCacheExpire& operator=(PreventStatCacheExpire&&) = delete;
};

#endif // S3FS_CACHE_NODE_H_

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
