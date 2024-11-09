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

#include <string>
#include <sys/types.h>

#include "../config.h"

//-------------------------------------------------------------------
// Global variables
//-------------------------------------------------------------------
// TODO: namespace these
static constexpr int64_t  FIVE_GB            = 5LL * 1024LL * 1024LL * 1024LL;
static constexpr off_t    MIN_MULTIPART_SIZE = 5 * 1024 * 1024;

extern bool           foreground;
extern bool           nomultipart;
extern bool           pathrequeststyle;
extern bool           complement_stat;
extern bool           noxmlns;
extern std::string    program_name;
extern std::string    service_path;
extern std::string    s3host;
extern std::string    mount_prefix;
extern std::string    endpoint;
extern std::string    cipher_suites;
extern std::string    instance_name;

//-------------------------------------------------------------------
// For weak attribute
//-------------------------------------------------------------------
#define	S3FS_FUNCATTR_WEAK __attribute__ ((weak,unused))

//-------------------------------------------------------------------
// For clang -Wthread-safety
//-------------------------------------------------------------------
#if defined(__clang__)
#define THREAD_ANNOTATION_ATTRIBUTE(x)   __attribute__((x))
#else
#define THREAD_ANNOTATION_ATTRIBUTE(x)   // no-op
#endif

#define GUARDED_BY(x) \
    THREAD_ANNOTATION_ATTRIBUTE(guarded_by(x))

#define PT_GUARDED_BY(x) \
    THREAD_ANNOTATION_ATTRIBUTE(pt_guarded_by(x))

#define REQUIRES(...) \
    THREAD_ANNOTATION_ATTRIBUTE(requires_capability(__VA_ARGS__))

#define RETURN_CAPABILITY(...) \
    THREAD_ANNOTATION_ATTRIBUTE(lock_returned(__VA_ARGS__))

#define ACQUIRED_BEFORE(...) \
    THREAD_ANNOTATION_ATTRIBUTE(acquired_before(__VA_ARGS__))

#define ACQUIRED_AFTER(...) \
    THREAD_ANNOTATION_ATTRIBUTE(acquired_after(__VA_ARGS__))

#define NO_THREAD_SAFETY_ANALYSIS \
    THREAD_ANNOTATION_ATTRIBUTE(no_thread_safety_analysis)

#endif // S3FS_COMMON_H_

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
