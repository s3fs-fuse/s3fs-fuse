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

#ifndef S3FS_FILETIMES_H_
#define S3FS_FILETIMES_H_

#include <cstdint>
#include <string>
#include <sys/stat.h>

//-------------------------------------------------------------------
// Utility for stat time type
//-------------------------------------------------------------------
enum class stat_time_type : uint8_t {
    ATIME,
    MTIME,
    CTIME
};

//-------------------------------------------------------------------
// Utility Functions for timespecs
//-------------------------------------------------------------------
bool valid_timespec(const struct timespec& ts);
constexpr int compare_timespec(const struct timespec& ts1, const struct timespec& ts2);
int compare_timespec(const struct stat& st, stat_time_type type, const struct timespec& ts);
void set_timespec_to_stat(struct stat& st, stat_time_type type, const struct timespec& ts);
struct timespec* set_stat_to_timespec(const struct stat& st, stat_time_type type, struct timespec& ts);
std::string str_stat_time(const struct stat& st, stat_time_type type);
struct timespec* s3fs_realtime(struct timespec& ts);
std::string s3fs_str_realtime();

//-------------------------------------------------------------------
// FileTimes Class
//-------------------------------------------------------------------
// [NOTE]
// In this class, UTIME_OMIT is set when initializing or clearing
// internal data.
// Also, if UTIME_NOW is specified, the value will be corrected to
// the current time and maintained.
//
class FileTimes
{
    private:
        struct timespec  ft_ctime;     // Change time
        struct timespec  ft_atime;     // Access time
        struct timespec  ft_mtime;     // Modification time

    private:
        void Clear(stat_time_type type);

        const struct timespec& GetTime(stat_time_type type) const;
        void GetTime(stat_time_type type, struct timespec& time) const;

        void SetTime(stat_time_type type, struct timespec time);

        bool IsOmit(stat_time_type type) const;

    public:
        explicit FileTimes() : ft_ctime{0, UTIME_OMIT}, ft_atime{0, UTIME_OMIT}, ft_mtime{0, UTIME_OMIT} {}

        // Clear
        void Clear();
        void ClearCTime() { Clear(stat_time_type::CTIME); }
        void ClearATime() { Clear(stat_time_type::ATIME); }
        void ClearMTime() { Clear(stat_time_type::MTIME); }

        // Get value
        const struct timespec& ctime() const { return GetTime(stat_time_type::CTIME); }
        const struct timespec& atime() const { return GetTime(stat_time_type::ATIME); }
        const struct timespec& mtime() const { return GetTime(stat_time_type::MTIME); }

        void GetCTime(struct timespec& time) const { GetTime(stat_time_type::CTIME, time); }
        void GetATime(struct timespec& time) const { GetTime(stat_time_type::ATIME, time); }
        void GetMTime(struct timespec& time) const { GetTime(stat_time_type::MTIME, time); }

        void RefrectFileTimes(struct stat& st) const;

        // Set value
        void SetCTime(struct timespec time) { SetTime(stat_time_type::CTIME, time); }
        void SetATime(struct timespec time) { SetTime(stat_time_type::ATIME, time); }
        void SetMTime(struct timespec time) { SetTime(stat_time_type::MTIME, time); }

        void SetAllNow();
        void SetAll(const struct stat& stbuf, bool no_omit = true);
        void SetAll(struct timespec ts_ctime, struct timespec ts_atime, struct timespec ts_mtime, bool no_omit = true);
        void SetAll(const FileTimes& other, bool no_omit = true);

        // Check
        bool IsOmitCTime() const { return IsOmit(stat_time_type::CTIME); }
        bool IsOmitATime() const { return IsOmit(stat_time_type::ATIME); }
        bool IsOmitMTime() const { return IsOmit(stat_time_type::MTIME); }
};

#endif // S3FS_FILETIMES_H_

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
