#ifndef S3FS_S3_H_
#define S3FS_S3_H_

#define FUSE_USE_VERSION      26
#define MULTIPART_SIZE        10485760     // 10MB
#define MAX_REQUESTS          100          // max number of concurrent HTTP requests
#define MAX_COPY_SOURCE_SIZE  524288000    // 500MB
#define FIVE_GB               5368709120LL

#include <fuse.h>

#define YIKES(result) if (true) { \
  syslog(LOG_ERR, "%d###result=%d", __LINE__, result); \
  return result; \
}

#define S3FS_FUSE_EXIT() { \
  struct fuse_context* pcxt = fuse_get_context(); \
  if(pcxt){ \
    fuse_exit(pcxt->fuse); \
  } \
}

#endif // S3FS_S3_H_
