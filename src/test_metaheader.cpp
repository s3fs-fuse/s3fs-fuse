/*
 * s3fs - FUSE-based file system backed by Amazon S3
 *
 * Copyright(C) 2014 Andrew Gaul <andrew@gaul.org>
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

#include <string>

#include "filetimes.h"
#include "metaheader.h"
#include "test_util.h"

//-------------------------------------------------------------------
// Global variables for test_metaheader
//-------------------------------------------------------------------
bool foreground                   = false;
std::string instance_name;

//
// A time before the epoch is a legitimate timestamp, so it must survive the
// round trip through the metadata headers instead of being treated as a
// missing value and replaced by Last-Modified or by the epoch.
//
static void test_negative_times()
{
    headers_t meta;
    meta["x-amz-meta-mtime"] = "-315619140";     // 1960-01-01
    meta["x-amz-meta-ctime"] = "-315619140";
    meta["x-amz-meta-atime"] = "-315619140";

    ASSERT_EQUALS(static_cast<time_t>(-315619140), get_mtime(meta).tv_sec);
    ASSERT_EQUALS(static_cast<time_t>(-315619140), get_ctime(meta).tv_sec);
    ASSERT_EQUALS(static_cast<time_t>(-315619140), get_atime(meta).tv_sec);

    // nanoseconds are kept alongside a negative number of seconds
    headers_t nsecmeta;
    nsecmeta["x-amz-meta-mtime"] = "-315619140.123";
    ASSERT_EQUALS(static_cast<time_t>(-315619140), get_mtime(nsecmeta).tv_sec);
    ASSERT_EQUALS(static_cast<long>(123), get_mtime(nsecmeta).tv_nsec);
}

//
// An absent header is distinct from a negative one: without overcheck it is
// reported as omitted, and with overcheck it falls back to Last-Modified.
//
static void test_missing_times()
{
    headers_t empty;
    ASSERT_EQUALS(static_cast<long>(UTIME_OMIT), get_mtime(empty, false).tv_nsec);
    ASSERT_EQUALS(static_cast<long>(UTIME_OMIT), get_ctime(empty, false).tv_nsec);
    ASSERT_EQUALS(static_cast<long>(UTIME_OMIT), get_atime(empty, false).tv_nsec);

    headers_t lastmod;
    lastmod["Last-Modified"] = "Mon, 03 Feb 2020 04:05:06 GMT";
    ASSERT_TRUE(0 < get_mtime(lastmod, true).tv_sec);
}

//
// valid_timespec() rejects only the UTIME_OMIT/UTIME_NOW markers; a negative
// number of seconds is an ordinary time.
//
static void test_valid_timespec()
{
    struct timespec negative = {-315619140, 0};
    ASSERT_TRUE(valid_timespec(negative));

    struct timespec epoch = {0, 0};
    ASSERT_TRUE(valid_timespec(epoch));

    struct timespec omit = {0, UTIME_OMIT};
    ASSERT_FALSE(valid_timespec(omit));

    struct timespec now = {0, UTIME_NOW};
    ASSERT_FALSE(valid_timespec(now));
}

int main(int argc, const char *argv[])
{
    test_negative_times();
    test_missing_times();
    test_valid_timespec();

    return 0;
}

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
