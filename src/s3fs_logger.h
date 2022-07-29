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

#ifndef S3FS_LOGGER_H_
#define S3FS_LOGGER_H_

#include <cstdarg>
#include <cstdio>
#include <string>
#include <syslog.h>
#include <sys/time.h>

#include "common.h"

#ifdef CLOCK_MONOTONIC_COARSE
#define S3FS_CLOCK_MONOTONIC    CLOCK_MONOTONIC_COARSE
#else
// case of OSX
#define S3FS_CLOCK_MONOTONIC    CLOCK_MONOTONIC
#endif

//-------------------------------------------------------------------
// S3fsLog class
//-------------------------------------------------------------------
class S3fsLog
{
    public:
        enum s3fs_log_level{
            LEVEL_CRIT = 0,          // LEVEL_CRIT
            LEVEL_ERR  = 1,          // LEVEL_ERR
            LEVEL_WARN = 3,          // LEVEL_WARNING
            LEVEL_INFO = 7,          // LEVEL_INFO
            LEVEL_DBG  = 15          // LEVEL_DEBUG
        };

    protected:
        static const int         NEST_MAX = 4;
        static const char* const nest_spaces[NEST_MAX];
        static const char        LOGFILEENV[];
        static const char        MSGTIMESTAMP[];

        static S3fsLog*       pSingleton;
        static s3fs_log_level debug_level;
        static FILE*          logfp;
        static std::string*   plogfile;
        static bool           time_stamp;

    protected:
        bool LowLoadEnv();
        bool LowSetLogfile(const char* pfile);
        s3fs_log_level LowSetLogLevel(s3fs_log_level level);
        s3fs_log_level LowBumpupLogLevel();

    public:
        static bool IsS3fsLogLevel(s3fs_log_level level);
        static bool IsS3fsLogCrit()  { return IsS3fsLogLevel(LEVEL_CRIT); }
        static bool IsS3fsLogErr()   { return IsS3fsLogLevel(LEVEL_ERR);  }
        static bool IsS3fsLogWarn()  { return IsS3fsLogLevel(LEVEL_WARN); }
        static bool IsS3fsLogInfo()  { return IsS3fsLogLevel(LEVEL_INFO); }
        static bool IsS3fsLogDbg()   { return IsS3fsLogLevel(LEVEL_DBG);  }

        static int GetSyslogLevel(s3fs_log_level level)
        {
            return ( LEVEL_DBG  == (level & LEVEL_DBG) ? LOG_DEBUG   :
                     LEVEL_INFO == (level & LEVEL_DBG) ? LOG_INFO    :
                     LEVEL_WARN == (level & LEVEL_DBG) ? LOG_WARNING :
                     LEVEL_ERR  == (level & LEVEL_DBG) ? LOG_ERR     : LOG_CRIT );
        }

        static std::string GetCurrentTime();

        static const char* GetLevelString(s3fs_log_level level)
        {
            return ( LEVEL_DBG  == (level & LEVEL_DBG) ? "[DBG] " :
                     LEVEL_INFO == (level & LEVEL_DBG) ? "[INF] " :
                     LEVEL_WARN == (level & LEVEL_DBG) ? "[WAN] " :
                     LEVEL_ERR  == (level & LEVEL_DBG) ? "[ERR] " : "[CRT] " );
        }

        static const char* GetS3fsLogNest(int nest)
        {
            if(nest < NEST_MAX){
                return nest_spaces[nest];
            }else{
                return nest_spaces[NEST_MAX - 1];
            }
        }

        static bool IsSetLogFile()
        {
            return (NULL != logfp);
        }

        static FILE* GetOutputLogFile()
        {
            return (logfp ? logfp : stdout);
        }

        static FILE* GetErrorLogFile()
        {
            return (logfp ? logfp : stderr);
        }

        static void SeekEnd()
        {
            if(logfp){
                fseek(logfp, 0, SEEK_END);
            }
        }

        static void Flush()
        {
            if(logfp){
                fflush(logfp);
            }
        }

        static bool SetLogfile(const char* pfile);
        static bool ReopenLogfile();
        static s3fs_log_level SetLogLevel(s3fs_log_level level);
        static s3fs_log_level BumpupLogLevel();
        static bool SetTimeStamp(bool value);

        explicit S3fsLog();
        ~S3fsLog();
};

//-------------------------------------------------------------------
// Debug macros
//-------------------------------------------------------------------
void s3fs_low_logprn(S3fsLog::s3fs_log_level level, const char* file, const char *func, int line, const char *fmt, ...) __attribute__ ((format (printf, 5, 6)));
#define S3FS_LOW_LOGPRN(level, fmt, ...) \
        do{ \
            s3fs_low_logprn(level, __FILE__, __func__, __LINE__, fmt, ##__VA_ARGS__); \
        }while(0)

void s3fs_low_logprn2(S3fsLog::s3fs_log_level level, int nest, const char* file, const char *func, int line, const char *fmt, ...) __attribute__ ((format (printf, 6, 7)));
#define S3FS_LOW_LOGPRN2(level, nest, fmt, ...) \
        do{ \
            s3fs_low_logprn2(level, nest, __FILE__, __func__, __LINE__, fmt, ##__VA_ARGS__); \
        }while(0)

#define S3FS_LOW_CURLDBG(fmt, ...) \
        do{ \
            if(foreground || S3fsLog::IsSetLogFile()){ \
                S3fsLog::SeekEnd(); \
                fprintf(S3fsLog::GetOutputLogFile(), "%s[CURL DBG] " fmt "%s\n", S3fsLog::GetCurrentTime().c_str(), __VA_ARGS__); \
                S3fsLog::Flush(); \
            }else{ \
                syslog(S3fsLog::GetSyslogLevel(S3fsLog::LEVEL_CRIT), "%s" fmt "%s", instance_name.c_str(), __VA_ARGS__); \
            } \
        }while(0)

#define S3FS_LOW_LOGPRN_EXIT(fmt, ...) \
        do{ \
            if(foreground || S3fsLog::IsSetLogFile()){ \
                S3fsLog::SeekEnd(); \
                fprintf(S3fsLog::GetErrorLogFile(), "s3fs: " fmt "%s\n", __VA_ARGS__); \
                S3fsLog::Flush(); \
            }else{ \
                fprintf(S3fsLog::GetErrorLogFile(), "s3fs: " fmt "%s\n", __VA_ARGS__); \
                syslog(S3fsLog::GetSyslogLevel(S3fsLog::LEVEL_CRIT), "%ss3fs: " fmt "%s", instance_name.c_str(), __VA_ARGS__); \
            } \
        }while(0)

// Special macro for init message
#define S3FS_PRN_INIT_INFO(fmt, ...) \
        do{ \
            if(foreground || S3fsLog::IsSetLogFile()){ \
                S3fsLog::SeekEnd(); \
                fprintf(S3fsLog::GetOutputLogFile(), "%s%s%s%s:%s(%d): " fmt "%s\n", S3fsLog::GetCurrentTime().c_str(), S3fsLog::GetLevelString(S3fsLog::LEVEL_INFO), S3fsLog::GetS3fsLogNest(0), __FILE__, __func__, __LINE__, __VA_ARGS__, ""); \
                S3fsLog::Flush(); \
            }else{ \
                syslog(S3fsLog::GetSyslogLevel(S3fsLog::LEVEL_INFO), "%s%s" fmt "%s", instance_name.c_str(), S3fsLog::GetS3fsLogNest(0), __VA_ARGS__, ""); \
            } \
        }while(0)

#define S3FS_PRN_LAUNCH_INFO(fmt, ...) \
        do{ \
            if(foreground || S3fsLog::IsSetLogFile()){ \
                S3fsLog::SeekEnd(); \
                fprintf(S3fsLog::GetOutputLogFile(), "%s%s" fmt "%s\n", S3fsLog::GetCurrentTime().c_str(), S3fsLog::GetLevelString(S3fsLog::LEVEL_INFO), __VA_ARGS__, ""); \
                S3fsLog::Flush(); \
            }else{ \
                syslog(S3fsLog::GetSyslogLevel(S3fsLog::LEVEL_INFO), "%s" fmt "%s", instance_name.c_str(), __VA_ARGS__, ""); \
            } \
        }while(0)

// Special macro for checking cache files
#define S3FS_LOW_CACHE(fp, fmt, ...) \
        do{ \
            if(foreground || S3fsLog::IsSetLogFile()){ \
                S3fsLog::SeekEnd(); \
                fprintf(fp, fmt "%s\n", __VA_ARGS__); \
                S3fsLog::Flush(); \
            }else{ \
                syslog(S3fsLog::GetSyslogLevel(S3fsLog::LEVEL_INFO), "%s: " fmt "%s", instance_name.c_str(), __VA_ARGS__); \
            } \
        }while(0)

// [NOTE]
// small trick for VA_ARGS
//
#define S3FS_PRN_EXIT(fmt, ...)   S3FS_LOW_LOGPRN_EXIT(fmt, ##__VA_ARGS__, "")
#define S3FS_PRN_CRIT(fmt, ...)   S3FS_LOW_LOGPRN(S3fsLog::LEVEL_CRIT, fmt, ##__VA_ARGS__)
#define S3FS_PRN_ERR(fmt, ...)    S3FS_LOW_LOGPRN(S3fsLog::LEVEL_ERR,  fmt, ##__VA_ARGS__)
#define S3FS_PRN_WARN(fmt, ...)   S3FS_LOW_LOGPRN(S3fsLog::LEVEL_WARN, fmt, ##__VA_ARGS__)
#define S3FS_PRN_DBG(fmt, ...)    S3FS_LOW_LOGPRN(S3fsLog::LEVEL_DBG,  fmt, ##__VA_ARGS__)
#define S3FS_PRN_INFO(fmt, ...)   S3FS_LOW_LOGPRN2(S3fsLog::LEVEL_INFO, 0, fmt, ##__VA_ARGS__)
#define S3FS_PRN_INFO1(fmt, ...)  S3FS_LOW_LOGPRN2(S3fsLog::LEVEL_INFO, 1, fmt, ##__VA_ARGS__)
#define S3FS_PRN_INFO2(fmt, ...)  S3FS_LOW_LOGPRN2(S3fsLog::LEVEL_INFO, 2, fmt, ##__VA_ARGS__)
#define S3FS_PRN_INFO3(fmt, ...)  S3FS_LOW_LOGPRN2(S3fsLog::LEVEL_INFO, 3, fmt, ##__VA_ARGS__)
#define S3FS_PRN_CURL(fmt, ...)   S3FS_LOW_CURLDBG(fmt, ##__VA_ARGS__, "")
#define S3FS_PRN_CACHE(fp, ...)   S3FS_LOW_CACHE(fp, ##__VA_ARGS__, "")

#endif // S3FS_LOGGER_H_

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
