/*
 * s3fs - FUSE-based file system backed by Amazon S3
 *
 * Copyright(C) 2007 Takeshi Nakatani <ggtakec.com>
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

#include "filetimes.h"
#include "s3fs_logger.h"
#include "string_util.h"

//-------------------------------------------------------------------
// Utility functions
//-------------------------------------------------------------------
//
// result: -1  ts1 <  ts2
//          0  ts1 == ts2
//          1  ts1 >  ts2
//
bool valid_timespec(const struct timespec& ts)
{
    if(0 > ts.tv_sec || UTIME_OMIT == ts.tv_nsec || UTIME_NOW == ts.tv_nsec){
        return false;
    }
    return true;
}

//
// result: -1  ts1 <  ts2
//          0  ts1 == ts2
//          1  ts1 >  ts2
//
constexpr int compare_timespec(const struct timespec& ts1, const struct timespec& ts2)
{
    if(ts1.tv_sec < ts2.tv_sec){
        return -1;
    }else if(ts1.tv_sec > ts2.tv_sec){
        return 1;
    }else{
        if(ts1.tv_nsec < ts2.tv_nsec){
            return -1;
        }else if(ts1.tv_nsec > ts2.tv_nsec){
            return 1;
        }
    }
    return 0;
}

//
// result: -1  st <  ts
//          0  st == ts
//          1  st >  ts
//
int compare_timespec(const struct stat& st, stat_time_type type, const struct timespec& ts)
{
    struct timespec st_ts;
    set_stat_to_timespec(st, type, st_ts);

    return compare_timespec(st_ts, ts);
}

void set_timespec_to_stat(struct stat& st, stat_time_type type, const struct timespec& ts)
{
    if(stat_time_type::ATIME == type){
        #ifdef __APPLE__
            st.st_atime             = ts.tv_sec;
            st.st_atimespec.tv_nsec = ts.tv_nsec;
        #else
            st.st_atim.tv_sec       = ts.tv_sec;
            st.st_atim.tv_nsec      = ts.tv_nsec;
        #endif
    }else if(stat_time_type::MTIME == type){
        #ifdef __APPLE__
            st.st_mtime             = ts.tv_sec;
            st.st_mtimespec.tv_nsec = ts.tv_nsec;
        #else
            st.st_mtim.tv_sec       = ts.tv_sec;
            st.st_mtim.tv_nsec      = ts.tv_nsec;
        #endif
    }else if(stat_time_type::CTIME == type){
        #ifdef __APPLE__
            st.st_ctime             = ts.tv_sec;
            st.st_ctimespec.tv_nsec = ts.tv_nsec;
        #else
            st.st_ctim.tv_sec       = ts.tv_sec;
            st.st_ctim.tv_nsec      = ts.tv_nsec;
        #endif
    }else{
        S3FS_PRN_ERR("unknown type(%d), so skip to set value.", static_cast<int>(type));
    }
}

struct timespec* set_stat_to_timespec(const struct stat& st, stat_time_type type, struct timespec& ts)
{
    if(stat_time_type::ATIME == type){
        #ifdef __APPLE__
           ts.tv_sec  = st.st_atime;
           ts.tv_nsec = st.st_atimespec.tv_nsec;
        #else
           ts         = st.st_atim;
        #endif
    }else if(stat_time_type::MTIME == type){
        #ifdef __APPLE__
           ts.tv_sec  = st.st_mtime;
           ts.tv_nsec = st.st_mtimespec.tv_nsec;
        #else
           ts         = st.st_mtim;
        #endif
    }else if(stat_time_type::CTIME == type){
        #ifdef __APPLE__
           ts.tv_sec  = st.st_ctime;
           ts.tv_nsec = st.st_ctimespec.tv_nsec;
        #else
           ts         = st.st_ctim;
        #endif
    }else{
        S3FS_PRN_ERR("unknown type(%d), so use 0 as timespec.", static_cast<int>(type));
        ts.tv_sec     = 0;
        ts.tv_nsec    = 0;
    }
    return &ts;
}

std::string str_stat_time(const struct stat& st, stat_time_type type)
{
    struct timespec ts;
    return str(*set_stat_to_timespec(st, type, ts));
}

struct timespec* s3fs_realtime(struct timespec& ts)
{
    if(-1 == clock_gettime(static_cast<clockid_t>(CLOCK_REALTIME), &ts)){
        S3FS_PRN_WARN("failed to clock_gettime by errno(%d)", errno);
        ts.tv_sec  = time(nullptr);
        ts.tv_nsec = 0;
    }
    return &ts;
}

std::string s3fs_str_realtime()
{
    struct timespec ts;
    return str(*s3fs_realtime(ts));
}

//-------------------------------------------------------------------
// FileTimes Class
//-------------------------------------------------------------------
void FileTimes::Clear()
{
    ClearCTime();
    ClearATime();
    ClearMTime();
}

void FileTimes::Clear(stat_time_type type)
{
    if(stat_time_type::CTIME == type){
        ft_ctime = {0, UTIME_OMIT};
    }else if(stat_time_type::ATIME == type){
        ft_atime = {0, UTIME_OMIT};
    }else{  // stat_time_type::MTIME
        ft_mtime = {0, UTIME_OMIT};
    }
}

const struct timespec& FileTimes::GetTime(stat_time_type type) const
{
    if(stat_time_type::CTIME == type){
        return ft_ctime;
    }else if(stat_time_type::ATIME == type){
        return ft_atime;
    }else{  // stat_time_type::MTIME
        return ft_mtime;
    }
}

void FileTimes::GetTime(stat_time_type type, struct timespec& time) const
{
    if(stat_time_type::CTIME == type){
        time = ft_ctime;
    }else if(stat_time_type::ATIME == type){
        time = ft_atime;
    }else{  // stat_time_type::MTIME
        time = ft_mtime;
    }
}

void FileTimes::RefrectFileTimes(struct stat& st) const
{
    if(!IsOmitCTime()){
        set_timespec_to_stat(st, stat_time_type::CTIME, ft_ctime);
    }
    if(!IsOmitATime()){
        set_timespec_to_stat(st, stat_time_type::ATIME, ft_atime);
    }
    if(!IsOmitMTime()){
        set_timespec_to_stat(st, stat_time_type::MTIME, ft_mtime);
    }
}

void FileTimes::SetTime(stat_time_type type, struct timespec time)
{
    if(UTIME_NOW == time.tv_nsec){
        s3fs_realtime(time);
    }
    if(stat_time_type::CTIME == type){
        ft_ctime = time;
    }else if(stat_time_type::ATIME == type){
        ft_atime = time;
    }else{  // stat_time_type::MTIME
        ft_mtime = time;
    }
}

void FileTimes::SetAllNow()
{
    struct timespec time;
    s3fs_realtime(time);
    SetAll(time, time, time);
}

void FileTimes::SetAll(const struct stat& stbuf, bool no_omit)
{
    struct timespec ts_ctime;
    struct timespec ts_atime;
    struct timespec ts_mtime;
    set_stat_to_timespec(stbuf, stat_time_type::CTIME, ts_ctime);
    set_stat_to_timespec(stbuf, stat_time_type::ATIME, ts_atime);
    set_stat_to_timespec(stbuf, stat_time_type::MTIME, ts_mtime);

    SetAll(ts_ctime, ts_atime, ts_mtime, no_omit);
}

void FileTimes::SetAll(struct timespec ts_ctime, struct timespec ts_atime, struct timespec ts_mtime, bool no_omit)
{
    struct timespec ts_now_time;
    s3fs_realtime(ts_now_time);

    if(UTIME_NOW == ts_ctime.tv_nsec){
        SetCTime(ts_now_time);
    }else if(!no_omit || UTIME_OMIT != ts_ctime.tv_nsec){
        SetCTime(ts_ctime);
    }

    if(UTIME_NOW == ts_atime.tv_nsec){
        SetATime(ts_now_time);
    }else if(!no_omit || UTIME_OMIT != ts_atime.tv_nsec){
        SetATime(ts_atime);
    }

    if(UTIME_NOW == ts_mtime.tv_nsec){
        SetMTime(ts_now_time);
    }else if(!no_omit || UTIME_OMIT != ts_mtime.tv_nsec){
        SetMTime(ts_mtime);
    }
}

void FileTimes::SetAll(const FileTimes& other, bool no_omit)
{
    if(!no_omit || !other.IsOmitCTime()){
        SetCTime(other.ctime());
    }
    if(!no_omit || !other.IsOmitATime()){
        SetATime(other.atime());
    }
    if(!no_omit || !other.IsOmitMTime()){
        SetMTime(other.mtime());
    }
}

bool FileTimes::IsOmit(stat_time_type type) const
{
    if(stat_time_type::CTIME == type){
        return (UTIME_OMIT == ft_ctime.tv_nsec);
    }else if(stat_time_type::ATIME == type){
        return (UTIME_OMIT == ft_atime.tv_nsec);
    }else{  // stat_time_type::MTIME
        return (UTIME_OMIT == ft_mtime.tv_nsec);
    }
}

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
