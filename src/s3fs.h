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

#define FUSE_USE_VERSION      30

#include <fuse.h>

// FUSE_FILL_DIR_DEFAULTS requirse FUSE 3.17
static constexpr fuse_fill_dir_flags S3FS_FUSE_FILL_DIR_DEFAULTS = static_cast<fuse_fill_dir_flags>(0);  // NOLINT(clang-analyzer-optin.core.EnumCastOutOfRange)

#define S3FS_FUSE_EXIT() \
        do{ \
            struct fuse_context* pcxt = fuse_get_context(); \
            if(pcxt){ \
                fuse_exit(pcxt->fuse); \
            } \
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
