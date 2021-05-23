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

#ifndef S3FS_FDCACHE_FDINFO_H_
#define S3FS_FDCACHE_FDINFO_H_

//------------------------------------------------
// Class PseudoFdInfo
//------------------------------------------------
class PseudoFdInfo
{
    private:
        int             pseudo_fd;
        int             physical_fd;
        int             flags;              // flags at open

    private:
        bool Clear();

    public:
        PseudoFdInfo(int fd = -1, int open_flags = 0);
        ~PseudoFdInfo();

        int GetPhysicalFd() const { return physical_fd; }
        int GetPseudoFd() const { return pseudo_fd; }
        int GetFlags() const { return flags; }
        bool Writable() const;
        bool Readable() const;

        bool Set(int fd, int open_flags);
};

typedef std::map<int, class PseudoFdInfo*> fdinfo_map_t;

#endif // S3FS_FDCACHE_FDINFO_H_

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
