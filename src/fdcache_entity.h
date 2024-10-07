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

#ifndef S3FS_FDCACHE_ENTITY_H_
#define S3FS_FDCACHE_ENTITY_H_

#include <cstdint>
#include <fcntl.h>
#include <memory>
#include <mutex>

#include "common.h"
#include "fdcache_page.h"
#include "fdcache_fdinfo.h"
#include "fdcache_untreated.h"
#include "metaheader.h"

//------------------------------------------------
// class FdEntity
//------------------------------------------------
class FdEntity
{
    private:
        // [NOTE]
        // Distinguish between meta pending and new file creation pending,
        // because the processing(request) at these updates is different.
        // Therefore, the pending state is expressed by this enum type.
        //
        enum class pending_status_t : uint8_t {
            NO_UPDATE_PENDING = 0,
            UPDATE_META_PENDING,        // pending meta header
            CREATE_FILE_PENDING         // pending file creation and meta header
        };

        static bool     mixmultipart;   // whether multipart uploading can use copy api.
        static bool     streamupload;   // whether stream uploading.

        mutable std::mutex fdent_lock;
        std::string     path;           // object path
        int             physical_fd;    // physical file(cache or temporary file) descriptor
        UntreatedParts  untreated_list; // list of untreated parts that have been written and not yet uploaded(for streamupload)
        fdinfo_map_t    pseudo_fd_map;  // pseudo file descriptor information map
        FILE*           pfile;          // file pointer(tmp file or cache file)
        ino_t           inode;          // inode number for cache file
        headers_t       orgmeta;        // original headers at opening
        off_t           size_orgmeta;   // original file size in original headers

        mutable std::mutex fdent_data_lock;// protects the following members
        PageList        pagelist;
        std::string     cachepath;      // local cache file path
                                        // (if this is empty, does not load/save pagelist.)
        std::string     mirrorpath;     // mirror file path to local cache file path
        pending_status_t pending_status;// status for new file creation and meta update
        struct timespec holding_mtime;  // if mtime is updated while the file is open, it is set time_t value

    private:
        static int FillFile(int fd, unsigned char byte, off_t size, off_t start);
        static ino_t GetInode(int fd);

        void Clear();
        ino_t GetInode() const;
        int OpenMirrorFile();
        int NoCacheLoadAndPost(PseudoFdInfo* pseudo_obj, off_t start = 0, off_t size = 0);  // size=0 means loading to end
        PseudoFdInfo* CheckPseudoFdFlags(int fd, bool writable) REQUIRES(FdEntity::fdent_lock);
        bool IsUploading() REQUIRES(FdEntity::fdent_lock);
        bool SetAllStatus(bool is_loaded);                          // [NOTE] not locking
        bool SetAllStatusUnloaded() { return SetAllStatus(false); }
        int NoCachePreMultipartPost(PseudoFdInfo* pseudo_obj);
        int NoCacheMultipartPost(PseudoFdInfo* pseudo_obj, int tgfd, off_t start, off_t size);
        int NoCacheCompleteMultipartPost(PseudoFdInfo* pseudo_obj);
        int RowFlushNoMultipart(const PseudoFdInfo* pseudo_obj, const char* tpath);
        int RowFlushMultipart(PseudoFdInfo* pseudo_obj, const char* tpath);
        int RowFlushMixMultipart(PseudoFdInfo* pseudo_obj, const char* tpath);
        int RowFlushStreamMultipart(PseudoFdInfo* pseudo_obj, const char* tpath);
        ssize_t WriteNoMultipart(const PseudoFdInfo* pseudo_obj, const char* bytes, off_t start, size_t size);
        ssize_t WriteMultipart(PseudoFdInfo* pseudo_obj, const char* bytes, off_t start, size_t size);
        ssize_t WriteMixMultipart(PseudoFdInfo* pseudo_obj, const char* bytes, off_t start, size_t size);
        ssize_t WriteStreamUpload(PseudoFdInfo* pseudo_obj, const char* bytes, off_t start, size_t size);

        bool ReserveDiskSpace(off_t size);

        bool AddUntreated(off_t start, off_t size);

        bool IsDirtyMetadata() const;

    public:
        static bool GetNoMixMultipart() { return mixmultipart; }
        static bool SetNoMixMultipart();
        static bool GetStreamUpload() { return streamupload; }
        static bool SetStreamUpload(bool isstream);

        explicit FdEntity(const char* tpath = nullptr, const char* cpath = nullptr);
        ~FdEntity();
        FdEntity(const FdEntity&) = delete;
        FdEntity(FdEntity&&) = delete;
        FdEntity& operator=(const FdEntity&) = delete;
        FdEntity& operator=(FdEntity&&) = delete;

        void Close(int fd);
        // TODO: should this require a lock?
        bool IsOpen() const { return (-1 != physical_fd); }
        bool FindPseudoFd(int fd) const {
            const std::lock_guard<std::mutex> lock(fdent_lock);
            return FindPseudoFdWithLock(fd);
        }
        bool FindPseudoFdWithLock(int fd) const REQUIRES(FdEntity::fdent_lock);
        int Open(const headers_t* pmeta, off_t size, const struct timespec& ts_mctime, int flags) REQUIRES(FdEntity::fdent_lock);
        bool LoadAll(int fd, headers_t* pmeta = nullptr, off_t* size = nullptr, bool force_load = false);
        int Dup(int fd) {
            const std::lock_guard<std::mutex> lock(fdent_lock);
            return DupWithLock(fd);
        }
        int DupWithLock(int fd) REQUIRES(FdEntity::fdent_lock);
        int OpenPseudoFd(int flags = O_RDONLY);
        int GetOpenCount() const {
            const std::lock_guard<std::mutex> lock(fdent_lock);
            return GetOpenCountHasLock();
        }
        int GetOpenCountHasLock() const REQUIRES(FdEntity::fdent_lock);
        // TODO: should this require a lock?
        const std::string& GetPath() const { return path; }
        bool RenamePath(const std::string& newpath, std::string& fentmapkey);
        int GetPhysicalFd() const { return physical_fd; }
        bool IsModified() const;
        bool MergeOrgMeta(headers_t& updatemeta);
        int UploadPending(int fd) {
            const std::lock_guard<std::mutex> lock(fdent_lock);
            return UploadPendingHasLock(fd);
        }
        int UploadPendingHasLock(int fd) REQUIRES(FdEntity::fdent_lock);

        bool GetStats(struct stat& st) const {
            const std::lock_guard<std::mutex> lock(fdent_lock);
            return GetStatsHasLock(st);
        }
        bool GetStatsHasLock(struct stat& st) const REQUIRES(FdEntity::fdent_lock);
        int SetCtime(struct timespec time) {
            const std::lock_guard<std::mutex> lock(fdent_lock);
            return SetCtimeHasLock(time);
        }
        int SetCtimeHasLock(struct timespec time) REQUIRES(FdEntity::fdent_lock);
        int SetAtime(struct timespec time) {
            const std::lock_guard<std::mutex> lock(fdent_lock);
            return SetAtimeHasLock(time);
        }
        int SetAtimeHasLock(struct timespec time) REQUIRES(FdEntity::fdent_lock);
        int SetMCtime(struct timespec mtime, struct timespec ctime) {
            const std::lock_guard<std::mutex> lock(fdent_lock);
            return SetMCtimeHasLock(mtime, ctime);
        }
        int SetMCtimeHasLock(struct timespec mtime, struct timespec ctime) REQUIRES(FdEntity::fdent_lock);
        bool UpdateCtime();
        bool UpdateAtime();
        bool UpdateMtime(bool clear_holding_mtime = false);
        bool UpdateMCtime();
        bool SetHoldingMtime(struct timespec mtime);
        bool ClearHoldingMtime() REQUIRES(FdEntity::fdent_lock);
        bool GetSize(off_t& size) const;
        bool GetXattr(std::string& xattr) const;
        bool SetXattr(const std::string& xattr);
        bool SetMode(mode_t mode) {
            const std::lock_guard<std::mutex> lock(fdent_lock);
            return SetModeHasLock(mode);
        }
        bool SetModeHasLock(mode_t mode) REQUIRES(FdEntity::fdent_lock);
        bool SetUId(uid_t uid) {
            const std::lock_guard<std::mutex> lock(fdent_lock);
            return SetUIdHasLock(uid);
        }
        bool SetUIdHasLock(uid_t uid) REQUIRES(FdEntity::fdent_lock);
        bool SetGId(gid_t gid) {
            const std::lock_guard<std::mutex> lock(fdent_lock);
            return SetGIdHasLock(gid);
        }
        bool SetGIdHasLock(gid_t gid) REQUIRES(FdEntity::fdent_lock);
        bool SetContentType(const char* path);

        int Load(off_t start, off_t size, bool is_modified_flag = false) REQUIRES(FdEntity::fdent_lock, FdEntity::fdent_data_lock);  // size=0 means loading to end

        off_t BytesModified();
        int RowFlush(int fd, const char* tpath, bool force_sync = false) {
            const std::lock_guard<std::mutex> lock(fdent_lock);
            return RowFlushHasLock(fd, tpath, force_sync);
        }
        int RowFlushHasLock(int fd, const char* tpath, bool force_sync = false) REQUIRES(FdEntity::fdent_lock);
        int Flush(int fd, bool force_sync = false) {
            const std::lock_guard<std::mutex> lock(fdent_lock);
            return FlushHasLock(fd, force_sync);
        }
        int FlushHasLock(int fd, bool force_sync = false) REQUIRES(FdEntity::fdent_lock) { return RowFlushHasLock(fd, nullptr, force_sync); }

        ssize_t Read(int fd, char* bytes, off_t start, size_t size, bool force_load = false);
        ssize_t Write(int fd, const char* bytes, off_t start, size_t size);

        bool PunchHole(off_t start = 0, size_t size = 0);

        void MarkDirtyNewFile();
        bool IsDirtyNewFile() const;
        void MarkDirtyMetadata();

        bool GetLastUpdateUntreatedPart(off_t& start, off_t& size) const;
        bool ReplaceLastUpdateUntreatedPart(off_t front_start, off_t front_size, off_t behind_start, off_t behind_size);
};

typedef std::map<std::string, std::shared_ptr<FdEntity>> fdent_map_t;           // key=path, value=unique_ptr<FdEntity>

#endif // S3FS_FDCACHE_ENTITY_H_

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
