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

#ifndef S3FS_COMMON_H_
#define S3FS_COMMON_H_

#include "../config.h"
#include "types.h"
#include "s3fs_logger.h"

//-------------------------------------------------------------------
// Global variables
//-------------------------------------------------------------------
// TODO: namespace these
extern int64_t        FIVE_GB;
extern off_t          MIN_MULTIPART_SIZE;
extern bool           foreground;
extern bool           nomultipart;
extern bool           pathrequeststyle;
extern bool           complement_stat;
extern bool           noxmlns;
extern std::string    program_name;
extern std::string    service_path;
extern std::string    s3host;
extern std::string    bucket;
extern std::string    mount_prefix;
extern std::string    endpoint;
extern std::string    cipher_suites;
extern std::string    instance_name;
extern std::string    aws_profile;

#endif // S3FS_COMMON_H_

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
