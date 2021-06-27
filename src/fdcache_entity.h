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

#include "autolock.h"
#include "fdcache_page.h"
#include "fdcache_fdinfo.h"
#include "metaheader.h"

//------------------------------------------------
// class FdEntity
//------------------------------------------------
class FdEntity
{
    private:
        static bool     mixmultipart;   // whether multipart uploading can use copy api.

        pthread_mutex_t fdent_lock;
        bool            is_lock_init;
        std::string     path;           // object path
        int             physical_fd;    // physical file(cache or temporary file) descriptor
        fdinfo_map_t    pseudo_fd_map;  // pseudo file descriptor information map
        FILE*           pfile;          // file pointer(tmp file or cache file)
        ino_t           inode;          // inode number for cache file
        headers_t       orgmeta;        // original headers at opening
        off_t           size_orgmeta;   // original file size in original headers

        pthread_mutex_t fdent_data_lock;// protects the following members
        PageList        pagelist;
        std::string     cachepath;      // local cache file path
                                        // (if this is empty, does not load/save pagelist.)
        std::string     mirrorpath;     // mirror file path to local cache file path
        bool            is_meta_pending;
        struct timespec holding_mtime;  // if mtime is updated while the file is open, it is set time_t value

    private:
        static int FillFile(int fd, unsigned char byte, off_t size, off_t start);
        static ino_t GetInode(int fd);

        void Clear();
        ino_t GetInode();
        int OpenMirrorFile();
        int NoCacheLoadAndPost(PseudoFdInfo* pseudo_obj, off_t start = 0, off_t size = 0);  // size=0 means loading to end
        PseudoFdInfo* CheckPseudoFdFlags(int fd, bool writable, bool lock_already_held = false);
        bool IsUploading(bool lock_already_held = false);
        bool SetAllStatus(bool is_loaded);                          // [NOTE] not locking
        bool SetAllStatusUnloaded() { return SetAllStatus(false); }
        int NoCachePreMultipartPost(PseudoFdInfo* pseudo_obj);
        int NoCacheMultipartPost(PseudoFdInfo* pseudo_obj, int tgfd, off_t start, off_t size);
        int NoCacheCompleteMultipartPost(PseudoFdInfo* pseudo_obj);
        int UploadPendingMeta();

    public:
        static bool GetNoMixMultipart() { return mixmultipart; }
        static bool SetNoMixMultipart();

        explicit FdEntity(const char* tpath = NULL, const char* cpath = NULL);
        ~FdEntity();

        void Close(int fd);
        bool IsOpen() const { return (-1 != physical_fd); }
        bool FindPseudoFd(int fd, bool lock_already_held = false);
        int Open(headers_t* pmeta, off_t size, time_t time, int flags, AutoLock::Type type);
        bool LoadAll(int fd, headers_t* pmeta = NULL, off_t* size = NULL, bool force_load = false);
        int Dup(int fd, bool lock_already_held = false);
        int OpenPseudoFd(int flags = O_RDONLY, bool lock_already_held = false);
        int GetOpenCount(bool lock_already_held = false);
        const char* GetPath() const { return path.c_str(); }
        bool RenamePath(const std::string& newpath, std::string& fentmapkey);
        int GetPhysicalFd() const { return physical_fd; }
        bool IsModified() const;
        bool MergeOrgMeta(headers_t& updatemeta);

        bool GetStats(struct stat& st, bool lock_already_held = false);
        int SetCtime(struct timespec time, bool lock_already_held = false);
        int SetAtime(struct timespec time, bool lock_already_held = false);
        int SetMCtime(struct timespec mtime, struct timespec ctime, bool lock_already_held = false);
        bool UpdateCtime();
        bool UpdateAtime();
        bool UpdateMtime(bool clear_holding_mtime = false);
        bool UpdateMCtime();
        bool SetHoldingMtime(struct timespec mtime, bool lock_already_held = false);
        bool ClearHoldingMtime(bool lock_already_held = false);
        bool GetSize(off_t& size);
        bool GetXattr(std::string& xattr);
        bool SetXattr(const std::string& xattr);
        bool SetMode(mode_t mode);
        bool SetUId(uid_t uid);
        bool SetGId(gid_t gid);
        bool SetContentType(const char* path);

        int Load(off_t start, off_t size, AutoLock::Type type, bool is_modified_flag = false);  // size=0 means loading to end

        off_t BytesModified();
        int RowFlush(int fd, const char* tpath, bool force_sync = false);
        int Flush(int fd, bool force_sync = false) { return RowFlush(fd, NULL, force_sync); }

        ssize_t Read(int fd, char* bytes, off_t start, size_t size, bool force_load = false);
        ssize_t Write(int fd, const char* bytes, off_t start, size_t size);

        bool ReserveDiskSpace(off_t size);
        bool PunchHole(off_t start = 0, size_t size = 0);

        // Indicate that a new file's is dirty.  This ensures that both metadata and data are synced during flush.
        void MarkDirtyNewFile() {
            pagelist.SetPageLoadedStatus(0, 1, PageList::PAGE_LOAD_MODIFIED);
            is_meta_pending = true;
        }
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
