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

#ifndef S3FS_FDCACHE_PSEUDOFD_H_
#define S3FS_FDCACHE_PSEUDOFD_H_

//------------------------------------------------
// Typdefs
//------------------------------------------------
// List of pseudo fd in use
//
typedef std::vector<int>    pseudofd_list_t;

//------------------------------------------------
// Class PseudoFdManager
//------------------------------------------------
class PseudoFdManager
{
    private:
        pseudofd_list_t pseudofd_list;
        bool            is_lock_init;
        pthread_mutex_t pseudofd_list_lock;    // protects pseudofd_list

    private:
        static PseudoFdManager& GetManager();

        PseudoFdManager();
        ~PseudoFdManager();

        int GetUnusedMinPseudoFd() const;
        int CreatePseudoFd();
        bool ReleasePseudoFd(int fd);

    public:
        static int Get();
        static bool Release(int fd);
};

#endif // S3FS_FDCACHE_PSEUDOFD_H_

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
