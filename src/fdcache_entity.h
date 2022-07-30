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

#include <fcntl.h>

#include "autolock.h"
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
        enum pending_status_t {
            NO_UPDATE_PENDING = 0,
            UPDATE_META_PENDING,        // pending meta header
            CREATE_FILE_PENDING         // pending file creation and meta header
        };

        static bool     mixmultipart;   // whether multipart uploading can use copy api.
        static bool     streamupload;   // whether stream uploading.

        pthread_mutex_t fdent_lock;
        bool            is_lock_init;
        std::string     path;           // object path
        int             physical_fd;    // physical file(cache or temporary file) descriptor
        UntreatedParts  untreated_list; // list of untreated parts that have been written and not yet uploaded(for streamupload)
        fdinfo_map_t    pseudo_fd_map;  // pseudo file descriptor information map
        FILE*           pfile;          // file pointer(tmp file or cache file)
        ino_t           inode;          // inode number for cache file
        headers_t       orgmeta;        // original headers at opening
        off_t           size_orgmeta;   // original file size in original headers

        mutable pthread_mutex_t fdent_data_lock;// protects the following members
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
        ino_t GetInode();
        int OpenMirrorFile();
        int NoCacheLoadAndPost(PseudoFdInfo* pseudo_obj, off_t start = 0, off_t size = 0);  // size=0 means loading to end
        PseudoFdInfo* CheckPseudoFdFlags(int fd, bool writable, AutoLock::Type locktype = AutoLock::NONE);
        bool IsUploading(AutoLock::Type locktype = AutoLock::NONE);
        bool SetAllStatus(bool is_loaded);                          // [NOTE] not locking
        bool SetAllStatusUnloaded() { return SetAllStatus(false); }
        int NoCachePreMultipartPost(PseudoFdInfo* pseudo_obj);
        int NoCacheMultipartPost(PseudoFdInfo* pseudo_obj, int tgfd, off_t start, off_t size);
        int NoCacheCompleteMultipartPost(PseudoFdInfo* pseudo_obj);
        int RowFlushNoMultipart(PseudoFdInfo* pseudo_obj, const char* tpath);
        int RowFlushMultipart(PseudoFdInfo* pseudo_obj, const char* tpath);
        int RowFlushMixMultipart(PseudoFdInfo* pseudo_obj, const char* tpath);
        int RowFlushStreamMultipart(PseudoFdInfo* pseudo_obj, const char* tpath);
        ssize_t WriteNoMultipart(PseudoFdInfo* pseudo_obj, const char* bytes, off_t start, size_t size);
        ssize_t WriteMultipart(PseudoFdInfo* pseudo_obj, const char* bytes, off_t start, size_t size);
        ssize_t WriteMixMultipart(PseudoFdInfo* pseudo_obj, const char* bytes, off_t start, size_t size);
        ssize_t WriteStreamUpload(PseudoFdInfo* pseudo_obj, const char* bytes, off_t start, size_t size);

        bool AddUntreated(off_t start, off_t size);

    public:
        static bool GetNoMixMultipart() { return mixmultipart; }
        static bool SetNoMixMultipart();
        static bool GetStreamUpload() { return streamupload; }
        static bool SetStreamUpload(bool isstream);

        explicit FdEntity(const char* tpath = NULL, const char* cpath = NULL);
        ~FdEntity();

        void Close(int fd);
        bool IsOpen() const { return (-1 != physical_fd); }
        bool FindPseudoFd(int fd, AutoLock::Type locktype = AutoLock::NONE);
        int Open(const headers_t* pmeta, off_t size, const struct timespec& ts_mctime, int flags, AutoLock::Type type);
        bool LoadAll(int fd, headers_t* pmeta = NULL, off_t* size = NULL, bool force_load = false);
        int Dup(int fd, AutoLock::Type locktype = AutoLock::NONE);
        int OpenPseudoFd(int flags = O_RDONLY, AutoLock::Type locktype = AutoLock::NONE);
        int GetOpenCount(AutoLock::Type locktype = AutoLock::NONE);
        const char* GetPath() const { return path.c_str(); }
        bool RenamePath(const std::string& newpath, std::string& fentmapkey);
        int GetPhysicalFd() const { return physical_fd; }
        bool IsModified() const;
        bool MergeOrgMeta(headers_t& updatemeta);
        int UploadPending(int fd, AutoLock::Type type);

        bool GetStats(struct stat& st, AutoLock::Type locktype = AutoLock::NONE);
        int SetCtime(struct timespec time, AutoLock::Type locktype = AutoLock::NONE);
        int SetAtime(struct timespec time, AutoLock::Type locktype = AutoLock::NONE);
        int SetMCtime(struct timespec mtime, struct timespec ctime, AutoLock::Type locktype = AutoLock::NONE);
        bool UpdateCtime();
        bool UpdateAtime();
        bool UpdateMtime(bool clear_holding_mtime = false);
        bool UpdateMCtime();
        bool SetHoldingMtime(struct timespec mtime, AutoLock::Type locktype = AutoLock::NONE);
        bool ClearHoldingMtime(AutoLock::Type locktype = AutoLock::NONE);
        bool GetSize(off_t& size);
        bool GetXattr(std::string& xattr);
        bool SetXattr(const std::string& xattr);
        bool SetMode(mode_t mode);
        bool SetUId(uid_t uid);
        bool SetGId(gid_t gid);
        bool SetContentType(const char* path);

        int Load(off_t start, off_t size, AutoLock::Type type, bool is_modified_flag = false);  // size=0 means loading to end

        off_t BytesModified();
        int RowFlush(int fd, const char* tpath, AutoLock::Type type, bool force_sync = false);
        int Flush(int fd, AutoLock::Type type, bool force_sync = false) { return RowFlush(fd, NULL, type, force_sync); }

        ssize_t Read(int fd, char* bytes, off_t start, size_t size, bool force_load = false);
        ssize_t Write(int fd, const char* bytes, off_t start, size_t size);

        bool ReserveDiskSpace(off_t size);
        bool PunchHole(off_t start = 0, size_t size = 0);

        void MarkDirtyNewFile();

        bool GetLastUpdateUntreatedPart(off_t& start, off_t& size);
        bool ReplaceLastUpdateUntreatedPart(off_t front_start, off_t front_size, off_t behind_start, off_t behind_size);
};

typedef std::map<std::string, class FdEntity*> fdent_map_t;   // key=path, value=FdEntity*

#endif // S3FS_FDCACHE_ENTITY_H_

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
