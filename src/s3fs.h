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
#ifndef S3FS_S3_H_
#define S3FS_S3_H_

#define FUSE_USE_VERSION      26

static const int64_t FIVE_GB = 5LL * 1024LL * 1024LL * 1024LL;

#include <fuse.h>

#define S3FS_FUSE_EXIT() { \
  struct fuse_context* pcxt = fuse_get_context(); \
  if(pcxt){ \
    fuse_exit(pcxt->fuse); \
  } \
}

//
// s3fs use many small allocated chunk in heap area for
// stats cache and parsing xml, etc. The OS may decide
// that giving this little memory back to the kernel
// will cause too much overhead and delay the operation.
// So s3fs calls malloc_trim function to really get the
// memory back. Following macros is prepared for that
// your system does not have it.
//
// Address of gratitude, this workaround quotes a document
// of libxml2.
// http://xmlsoft.org/xmlmem.html
//
#ifdef HAVE_MALLOC_TRIM

#include <malloc.h>

#define DISPWARN_MALLOCTRIM(str)
#define S3FS_MALLOCTRIM(pad)          malloc_trim(pad)
#define S3FS_XMLFREEDOC(doc) \
        { \
          xmlFreeDoc(doc); \
          S3FS_MALLOCTRIM(0); \
        }
#define S3FS_XMLFREE(ptr) \
        { \
          xmlFree(ptr); \
          S3FS_MALLOCTRIM(0); \
        }
#define S3FS_XMLXPATHFREECONTEXT(ctx) \
        { \
          xmlXPathFreeContext(ctx); \
          S3FS_MALLOCTRIM(0); \
        }
#define S3FS_XMLXPATHFREEOBJECT(obj) \
        { \
          xmlXPathFreeObject(obj); \
          S3FS_MALLOCTRIM(0); \
        }

#else // HAVE_MALLOC_TRIM

#define DISPWARN_MALLOCTRIM(str) \
        fprintf(stderr, "Warning: %s without malloc_trim is possibility of the use memory increase.\n", program_name.c_str())
#define S3FS_MALLOCTRIM(pad)
#define S3FS_XMLFREEDOC(doc)          xmlFreeDoc(doc)
#define S3FS_XMLFREE(ptr)             xmlFree(ptr)
#define S3FS_XMLXPATHFREECONTEXT(ctx) xmlXPathFreeContext(ctx)
#define S3FS_XMLXPATHFREEOBJECT(obj)  xmlXPathFreeObject(obj)

#endif // HAVE_MALLOC_TRIM

#endif // S3FS_S3_H_

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: noet sw=4 ts=4 fdm=marker
* vim<600: noet sw=4 ts=4
*/
