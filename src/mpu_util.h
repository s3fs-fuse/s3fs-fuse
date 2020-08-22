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

#ifndef S3FS_MPU_UTIL_H_
#define S3FS_MPU_UTIL_H_

#include <string>
#include <list>

//-------------------------------------------------------------------
// Structure / Typedef
//-------------------------------------------------------------------
typedef struct incomplete_multipart_upload_info
{
    std::string key;
    std::string id;
    std::string date;
}INCOMP_MPU_INFO;

typedef std::list<INCOMP_MPU_INFO>      incomp_mpu_list_t;

//-------------------------------------------------------------------
// enum for utility process mode
//-------------------------------------------------------------------
enum utility_incomp_type{
    NO_UTILITY_MODE = 0,      // not utility mode
    INCOMP_TYPE_LIST,         // list of incomplete mpu
    INCOMP_TYPE_ABORT         // delete incomplete mpu
};

extern utility_incomp_type utility_mode;

//-------------------------------------------------------------------
// Functions
//-------------------------------------------------------------------
int s3fs_utility_processing(time_t abort_time);

#endif // S3FS_MPU_UTIL_H_

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
