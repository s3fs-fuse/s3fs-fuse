#ifndef S3FS_S3_H_
#define S3FS_S3_H_

#define FUSE_USE_VERSION      26
#define FIVE_GB               5368709120LL

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

//
// For initializing libcurl with NSS
// Normally libcurl initializes the NSS library, but usually allows
// you to initialize s3fs forcibly. Because Memory leak is reported
// in valgrind(about curl_global_init() function), and this is for
// the cancellation. When "--enable-nss-init" option is specified
// at configurarion, it makes NSS_INIT_ENABLED flag into Makefile.
// NOTICE
// This defines and macros is temporary, and this should be deleted.
//
#ifdef NSS_INIT_ENABLED
#include <nss.h>
#include <prinit.h>

#define S3FS_INIT_NSS() \
        { \
          NSS_NoDB_Init(NULL); \
        }
#define S3FS_CLEANUP_NSS() \
        { \
          NSS_Shutdown(); \
          PL_ArenaFinish(); \
          PR_Cleanup(); \
        }

#else // NSS_INIT_ENABLED

#define S3FS_INIT_NSS()
#define S3FS_CLEANUP_NSS()

#endif // NSS_INIT_ENABLED

#endif // S3FS_S3_H_
