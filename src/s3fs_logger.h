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
#include <cstdint>
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
        enum class Level : uint8_t {
            CRIT = 0,          // LEVEL_CRIT
            ERR  = 1,          // LEVEL_ERR
            WARN = 3,          // LEVEL_WARNING
            INFO = 7,          // LEVEL_INFO
            DBG  = 15          // LEVEL_DEBUG
        };

    protected:
        static constexpr int         NEST_MAX = 4;
        static constexpr const char* nest_spaces[NEST_MAX] = {"", "  ", "    ", "      "};
        static constexpr char        LOGFILEENV[] = "S3FS_LOGFILE";
        static constexpr char        MSGTIMESTAMP[] = "S3FS_MSGTIMESTAMP";

        static S3fsLog*       pSingleton;
        static Level          debug_level;
        static FILE*          logfp;
        static std::string    logfile;
        static bool           time_stamp;

    protected:
        bool LowLoadEnv();
        bool LowSetLogfile(const char* pfile);
        Level LowSetLogLevel(Level level);
        Level LowBumpupLogLevel() const;

    public:
        static bool IsS3fsLogLevel(Level level);
        static bool IsS3fsLogCrit()  { return IsS3fsLogLevel(Level::CRIT); }
        static bool IsS3fsLogErr()   { return IsS3fsLogLevel(Level::ERR);  }
        static bool IsS3fsLogWarn()  { return IsS3fsLogLevel(Level::WARN); }
        static bool IsS3fsLogInfo()  { return IsS3fsLogLevel(Level::INFO); }
        static bool IsS3fsLogDbg()   { return IsS3fsLogLevel(Level::DBG);  }

        static constexpr int GetSyslogLevel(Level level)
        {
            int masked = static_cast<int>(level) & static_cast<int>(Level::DBG);
            return ( static_cast<int>(Level::DBG)  == masked ? LOG_DEBUG   :
                     static_cast<int>(Level::INFO) == masked ? LOG_INFO    :
                     static_cast<int>(Level::WARN) == masked ? LOG_WARNING :
                     static_cast<int>(Level::ERR)  == masked ? LOG_ERR     : LOG_CRIT );
        }

        static std::string GetCurrentTime();

        static constexpr const char* GetLevelString(Level level)
        {
            int masked = static_cast<int>(level) & static_cast<int>(Level::DBG);
            return ( static_cast<int>(Level::DBG)  == masked ? "[DBG] " :
                     static_cast<int>(Level::INFO) == masked ? "[INF] " :
                     static_cast<int>(Level::WARN) == masked ? "[WAN] " :
                     static_cast<int>(Level::ERR)  == masked ? "[ERR] " : "[CRT] " );
        }

        static constexpr const char* GetS3fsLogNest(int nest)
        {
            return nest_spaces[nest < NEST_MAX ? nest : NEST_MAX - 1];
        }

        static bool IsSetLogFile()
        {
            return (nullptr != logfp);
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
        static Level SetLogLevel(Level level);
        static Level BumpupLogLevel();
        static bool SetTimeStamp(bool value);

        explicit S3fsLog();
        ~S3fsLog();
        S3fsLog(const S3fsLog&) = delete;
        S3fsLog(S3fsLog&&) = delete;
        S3fsLog& operator=(const S3fsLog&) = delete;
        S3fsLog& operator=(S3fsLog&&) = delete;
};

//-------------------------------------------------------------------
// Debug macros
//-------------------------------------------------------------------
void s3fs_low_logprn(S3fsLog::Level level, const char* file, const char *func, int line, const char *fmt, ...) __attribute__ ((format (printf, 5, 6)));
#define S3FS_LOW_LOGPRN(level, fmt, ...) \
        do{ \
            s3fs_low_logprn(level, __FILE__, __func__, __LINE__, fmt, ##__VA_ARGS__); \
        }while(0)

void s3fs_low_logprn2(S3fsLog::Level level, int nest, const char* file, const char *func, int line, const char *fmt, ...) __attribute__ ((format (printf, 6, 7)));
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
                syslog(S3fsLog::GetSyslogLevel(S3fsLog::Level::CRIT), "%s" fmt "%s", instance_name.c_str(), __VA_ARGS__); \
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
                syslog(S3fsLog::GetSyslogLevel(S3fsLog::Level::CRIT), "%ss3fs: " fmt "%s", instance_name.c_str(), __VA_ARGS__); \
            } \
        }while(0)

// Special macro for init message
#define S3FS_PRN_INIT_INFO(fmt, ...) \
        do{ \
            if(foreground || S3fsLog::IsSetLogFile()){ \
                S3fsLog::SeekEnd(); \
                fprintf(S3fsLog::GetOutputLogFile(), "%s%s%s%s:%s(%d): " fmt "%s\n", S3fsLog::GetCurrentTime().c_str(), S3fsLog::GetLevelString(S3fsLog::Level::INFO), S3fsLog::GetS3fsLogNest(0), __FILE__, __func__, __LINE__, __VA_ARGS__, ""); \
                S3fsLog::Flush(); \
            }else{ \
                syslog(S3fsLog::GetSyslogLevel(S3fsLog::Level::INFO), "%s%s" fmt "%s", instance_name.c_str(), S3fsLog::GetS3fsLogNest(0), __VA_ARGS__, ""); \
            } \
        }while(0)

#define S3FS_PRN_LAUNCH_INFO(fmt, ...) \
        do{ \
            if(foreground || S3fsLog::IsSetLogFile()){ \
                S3fsLog::SeekEnd(); \
                fprintf(S3fsLog::GetOutputLogFile(), "%s%s" fmt "%s\n", S3fsLog::GetCurrentTime().c_str(), S3fsLog::GetLevelString(S3fsLog::Level::INFO), __VA_ARGS__, ""); \
                S3fsLog::Flush(); \
            }else{ \
                syslog(S3fsLog::GetSyslogLevel(S3fsLog::Level::INFO), "%s" fmt "%s", instance_name.c_str(), __VA_ARGS__, ""); \
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
                syslog(S3fsLog::GetSyslogLevel(S3fsLog::Level::INFO), "%s: " fmt "%s", instance_name.c_str(), __VA_ARGS__); \
            } \
        }while(0)

// [NOTE]
// small trick for VA_ARGS
//
#define S3FS_PRN_EXIT(fmt, ...)   S3FS_LOW_LOGPRN_EXIT(fmt, ##__VA_ARGS__, "")
#define S3FS_PRN_CRIT(fmt, ...)   S3FS_LOW_LOGPRN(S3fsLog::Level::CRIT, fmt, ##__VA_ARGS__)
#define S3FS_PRN_ERR(fmt, ...)    S3FS_LOW_LOGPRN(S3fsLog::Level::ERR,  fmt, ##__VA_ARGS__)
#define S3FS_PRN_WARN(fmt, ...)   S3FS_LOW_LOGPRN(S3fsLog::Level::WARN, fmt, ##__VA_ARGS__)
#define S3FS_PRN_DBG(fmt, ...)    S3FS_LOW_LOGPRN(S3fsLog::Level::DBG,  fmt, ##__VA_ARGS__)
#define S3FS_PRN_INFO(fmt, ...)   S3FS_LOW_LOGPRN2(S3fsLog::Level::INFO, 0, fmt, ##__VA_ARGS__)
#define S3FS_PRN_INFO1(fmt, ...)  S3FS_LOW_LOGPRN2(S3fsLog::Level::INFO, 1, fmt, ##__VA_ARGS__)
#define S3FS_PRN_INFO2(fmt, ...)  S3FS_LOW_LOGPRN2(S3fsLog::Level::INFO, 2, fmt, ##__VA_ARGS__)
#define S3FS_PRN_INFO3(fmt, ...)  S3FS_LOW_LOGPRN2(S3fsLog::Level::INFO, 3, fmt, ##__VA_ARGS__)
#define S3FS_PRN_CURL(fmt, ...)   S3FS_LOW_CURLDBG(fmt, ##__VA_ARGS__, "")
#define S3FS_PRN_CACHE(fp, ...)   S3FS_LOW_CACHE(fp, ##__VA_ARGS__, "")

// Macros to print log with fuse context
#define PRINT_FUSE_CTX(level, indent, fmt, ...) do {                    \
    if(S3fsLog::IsS3fsLogLevel(level)){                                 \
        struct fuse_context *ctx = fuse_get_context();                  \
        if(ctx == NULL){                                                \
            S3FS_LOW_LOGPRN2(level, indent, fmt, ##__VA_ARGS__);        \
        }else{                                                          \
            S3FS_LOW_LOGPRN2(level, indent, fmt"[pid=%u,uid=%u,gid=%u]",\
                ##__VA_ARGS__,                                          \
                (unsigned int)(ctx->pid),                               \
                (unsigned int)(ctx->uid),                               \
                (unsigned int)(ctx->gid));                              \
        }                                                               \
    }                                                                   \
} while (0)

#define FUSE_CTX_INFO(fmt, ...) do {                            \
    PRINT_FUSE_CTX(S3fsLog::Level::INFO, 0, fmt, ##__VA_ARGS__); \
} while (0)

#define FUSE_CTX_INFO1(fmt, ...) do {                           \
    PRINT_FUSE_CTX(S3fsLog::Level::INFO, 1, fmt, ##__VA_ARGS__); \
} while (0)

#define FUSE_CTX_DBG(fmt, ...) do {                                 \
    PRINT_FUSE_CTX(S3fsLog::Level::DBG, 0, fmt, ##__VA_ARGS__);  \
} while (0)

#endif // S3FS_LOGGER_H_

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
