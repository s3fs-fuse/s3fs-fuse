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

#endif // S3FS_S3_H_
