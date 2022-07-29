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

#ifndef S3FS_FDCACHE_PAGE_H_
#define S3FS_FDCACHE_PAGE_H_

#include <list>
#include <sys/types.h>

//------------------------------------------------
// Symbols
//------------------------------------------------
// [NOTE]
// If the following symbols in lseek whence are undefined, define them.
// If it is not supported by lseek, s3fs judges by the processing result of lseek.
//
#ifndef SEEK_DATA
#define SEEK_DATA               3
#endif
#ifndef SEEK_HOLE
#define SEEK_HOLE               4
#endif

//------------------------------------------------
// Structure fdpage
//------------------------------------------------
// page block information
struct fdpage
{
    off_t  offset;
    off_t  bytes;
    bool   loaded;
    bool   modified;

    fdpage(off_t start = 0, off_t  size = 0, bool is_loaded = false, bool is_modified = false) :
        offset(start), bytes(size), loaded(is_loaded), modified(is_modified) {}

    off_t next() const
    {
        return (offset + bytes);
    }
    off_t end() const
    {
        return (0 < bytes ? offset + bytes - 1 : 0);
    }
};
typedef std::list<struct fdpage> fdpage_list_t;

//------------------------------------------------
// Class PageList
//------------------------------------------------
class CacheFileStat;
class FdEntity;

// cppcheck-suppress copyCtorAndEqOperator
class PageList
{
    friend class FdEntity;    // only one method access directly pages.

    private:
        fdpage_list_t pages;
        bool          is_shrink;    // [NOTE] true if it has been shrinked even once

    public:
        enum page_status{
            PAGE_NOT_LOAD_MODIFIED = 0,
            PAGE_LOADED,
            PAGE_MODIFIED,
            PAGE_LOAD_MODIFIED
        };

    private:
        static bool GetSparseFilePages(int fd, size_t file_size, fdpage_list_t& sparse_list);
        static bool CheckZeroAreaInFile(int fd, off_t start, size_t bytes);
        static bool CheckAreaInSparseFile(const struct fdpage& checkpage, const fdpage_list_t& sparse_list, int fd, fdpage_list_t& err_area_list, fdpage_list_t& warn_area_list);

        void Clear();
        bool Parse(off_t new_pos);

    public:
        static void FreeList(fdpage_list_t& list);

        explicit PageList(off_t size = 0, bool is_loaded = false, bool is_modified = false, bool shrinked = false);
        explicit PageList(const PageList& other);
        ~PageList();

        bool Init(off_t size, bool is_loaded, bool is_modified);
        off_t Size() const;
        bool Resize(off_t size, bool is_loaded, bool is_modified);

        bool IsPageLoaded(off_t start = 0, off_t size = 0) const;                  // size=0 is checking to end of list
        bool SetPageLoadedStatus(off_t start, off_t size, PageList::page_status pstatus = PAGE_LOADED, bool is_compress = true);
        bool FindUnloadedPage(off_t start, off_t& resstart, off_t& ressize) const;
        off_t GetTotalUnloadedPageSize(off_t start = 0, off_t size = 0, off_t limit_size = 0) const;   // size=0 is checking to end of list
        size_t GetUnloadedPages(fdpage_list_t& unloaded_list, off_t start = 0, off_t size = 0) const;  // size=0 is checking to end of list
        bool GetPageListsForMultipartUpload(fdpage_list_t& dlpages, fdpage_list_t& mixuppages, off_t max_partsize);
        bool GetNoDataPageLists(fdpage_list_t& nodata_pages, off_t start = 0, size_t size = 0);

        off_t BytesModified() const;
        bool IsModified() const;
        bool ClearAllModified();

        bool Compress();
        bool Serialize(CacheFileStat& file, bool is_output, ino_t inode);
        void Dump() const;
        bool CompareSparseFile(int fd, size_t file_size, fdpage_list_t& err_area_list, fdpage_list_t& warn_area_list);
};

#endif // S3FS_FDCACHE_PAGE_H_

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
