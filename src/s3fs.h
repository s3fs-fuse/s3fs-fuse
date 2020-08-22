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

#ifndef S3FS_S3FS_H_
#define S3FS_S3FS_H_

#define FUSE_USE_VERSION      26

#include <fuse.h>

#define S3FS_FUSE_EXIT() \
        do{ \
            struct fuse_context* pcxt = fuse_get_context(); \
            if(pcxt){ \
                fuse_exit(pcxt->fuse); \
            } \
        }while(0)

// [NOTE]
// s3fs use many small allocated chunk in heap area for stats
// cache and parsing xml, etc. The OS may decide that giving
// this little memory back to the kernel will cause too much
// overhead and delay the operation.
// Address of gratitude, this workaround quotes a document of
// libxml2.( http://xmlsoft.org/xmlmem.html )
//
// When valgrind is used to test memory leak of s3fs, a large
// amount of chunk may be reported. You can check the memory
// release accurately by defining the S3FS_MALLOC_TRIM flag
// and building it. Also, when executing s3fs, you can define
// the MMAP_THRESHOLD environment variable and check more
// accurate memory leak.( see, man 3 free )
//
#ifdef S3FS_MALLOC_TRIM
#ifdef HAVE_MALLOC_TRIM
#include <malloc.h>
#define S3FS_MALLOCTRIM(pad)    malloc_trim(pad)
#else   // HAVE_MALLOC_TRIM
#define S3FS_MALLOCTRIM(pad)
#endif  // HAVE_MALLOC_TRIM
#else   // S3FS_MALLOC_TRIM
#define S3FS_MALLOCTRIM(pad)
#endif  // S3FS_MALLOC_TRIM

#define S3FS_XMLFREEDOC(doc) \
        do{ \
          xmlFreeDoc(doc); \
          S3FS_MALLOCTRIM(0); \
        }while(0)
#define S3FS_XMLFREE(ptr) \
        do{ \
          xmlFree(ptr); \
          S3FS_MALLOCTRIM(0); \
        }while(0)
#define S3FS_XMLXPATHFREECONTEXT(ctx) \
        do{ \
          xmlXPathFreeContext(ctx); \
          S3FS_MALLOCTRIM(0); \
        }while(0)
#define S3FS_XMLXPATHFREEOBJECT(obj) \
        do{ \
          xmlXPathFreeObject(obj); \
          S3FS_MALLOCTRIM(0); \
        }while(0)

#endif // S3FS_S3FS_H_

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
