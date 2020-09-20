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

#ifndef S3FS_BODYDATA_H_
#define S3FS_BODYDATA_H_

//----------------------------------------------
// Class BodyData
//----------------------------------------------
// memory class for curl write memory callback 
//
class BodyData
{
    private:
        char*  text;
        size_t lastpos;
        size_t bufsize;

    private:
        bool IsSafeSize(size_t addbytes) const
        {
            return ((lastpos + addbytes + 1) > bufsize ? false : true);
        }
        bool Resize(size_t addbytes);

    public:
        BodyData() : text(NULL), lastpos(0), bufsize(0) {}
        ~BodyData()
        {
            Clear();
        }

        void Clear();
        bool Append(void* ptr, size_t bytes);
        bool Append(void* ptr, size_t blockSize, size_t numBlocks)
        {
            return Append(ptr, (blockSize * numBlocks));
        }
        const char* str() const;
        size_t size() const
        {
            return lastpos;
        }
};

#endif // S3FS_BODYDATA_H_

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
