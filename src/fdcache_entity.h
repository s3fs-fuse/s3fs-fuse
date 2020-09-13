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

#include "fdcache_page.h"
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
        int             refcnt;         // reference count
        std::string     path;           // object path
        int             fd;             // file descriptor(tmp file or cache file)
        FILE*           pfile;          // file pointer(tmp file or cache file)
        ino_t           inode;          // inode number for cache file
        headers_t       orgmeta;        // original headers at opening
        off_t           size_orgmeta;   // original file size in original headers

        pthread_mutex_t fdent_data_lock;// protects the following members
        PageList        pagelist;
        std::string     upload_id;      // for no cached multipart uploading when no disk space
        etaglist_t      etaglist;       // for no cached multipart uploading when no disk space
        off_t           mp_start;       // start position for no cached multipart(write method only)
        off_t           mp_size;        // size for no cached multipart(write method only)
        std::string     cachepath;      // local cache file path
                                        // (if this is empty, does not load/save pagelist.)
        std::string     mirrorpath;     // mirror file path to local cache file path
        headers_list_t  pending_headers;// pending update headers

    private:
        static int FillFile(int fd, unsigned char byte, off_t size, off_t start);
        static ino_t GetInode(int fd);

        void Clear(void);
        ino_t GetInode(void);
        int OpenMirrorFile(void);
        bool SetAllStatus(bool is_loaded);                          // [NOTE] not locking
        bool SetAllStatusUnloaded(void) { return SetAllStatus(false); }
        int UploadPendingMeta(void);

    public:
        static bool SetNoMixMultipart(void);

        explicit FdEntity(const char* tpath = NULL, const char* cpath = NULL);
        ~FdEntity();

        void Close(void);
        bool IsOpen(void) const { return (-1 != fd); }
        int Open(headers_t* pmeta = NULL, off_t size = -1, time_t time = -1, bool no_fd_lock_wait = false);
        bool OpenAndLoadAll(headers_t* pmeta = NULL, off_t* size = NULL, bool force_load = false);
        int Dup(bool lock_already_held = false);
        int GetRefCnt(void) const { return refcnt; }                // [NOTE] Use only debugging

        const char* GetPath(void) const { return path.c_str(); }
        bool RenamePath(const std::string& newpath, std::string& fentmapkey);
        int GetFd(void) const { return fd; }
        bool IsModified(void) const;
        bool MergeOrgMeta(headers_t& updatemeta);

        bool GetStats(struct stat& st, bool lock_already_held = false);
        int SetCtime(time_t time, bool lock_already_held = false);
        int SetMtime(time_t time, bool lock_already_held = false);
        bool UpdateCtime(void);
        bool UpdateMtime(void);
        bool GetSize(off_t& size);
        bool GetXattr(std::string& xattr);
        bool SetXattr(const std::string& xattr);
        bool SetMode(mode_t mode);
        bool SetUId(uid_t uid);
        bool SetGId(gid_t gid);
        bool SetContentType(const char* path);

        int Load(off_t start = 0, off_t size = 0, bool lock_already_held = false, bool is_modified_flag = false);  // size=0 means loading to end
        int NoCacheLoadAndPost(off_t start = 0, off_t size = 0);   // size=0 means loading to end
        int NoCachePreMultipartPost(void);
        int NoCacheMultipartPost(int tgfd, off_t start, off_t size);
        int NoCacheCompleteMultipartPost(void);

        int RowFlush(const char* tpath, bool force_sync = false);
        int Flush(bool force_sync = false) { return RowFlush(NULL, force_sync); }

        ssize_t Read(char* bytes, off_t start, size_t size, bool force_load = false);
        ssize_t Write(const char* bytes, off_t start, size_t size);

        bool ReserveDiskSpace(off_t size);
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
