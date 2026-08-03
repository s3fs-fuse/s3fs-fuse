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

#include <cstdint>
#include <cstdio>
#include <string>
#include <syslog.h>

#include "common.h"  // NOLINT(misc-include-cleaner)

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
        // Ordinal severity, ascending verbosity: a message at `level` is shown
        // when level <= debug_level (see IsS3fsLogLevel). CRIT is the floor and
        // is therefore always logged.
        enum class Level : uint8_t {
            CRIT = 0,          // LEVEL_CRIT
            ERR  = 1,          // LEVEL_ERR
            WARN = 2,          // LEVEL_WARNING
            INFO = 3,          // LEVEL_INFO
            DBG  = 4           // LEVEL_DEBUG
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
        static bool IsS3fsLogLevel(Level level)
        {
            return static_cast<int>(level) <= static_cast<int>(debug_level);
        }
        static bool IsS3fsLogCrit()  { return IsS3fsLogLevel(Level::CRIT); }
        static bool IsS3fsLogErr()   { return IsS3fsLogLevel(Level::ERR);  }
        static bool IsS3fsLogWarn()  { return IsS3fsLogLevel(Level::WARN); }
        static bool IsS3fsLogInfo()  { return IsS3fsLogLevel(Level::INFO); }
        static bool IsS3fsLogDbg()   { return IsS3fsLogLevel(Level::DBG);  }

        static constexpr int GetSyslogLevel(Level level)
        {
            return ( Level::DBG  == level ? LOG_DEBUG   :
                     Level::INFO == level ? LOG_INFO    :
                     Level::WARN == level ? LOG_WARNING :
                     Level::ERR  == level ? LOG_ERR     : LOG_CRIT );
        }

        static std::string GetCurrentTime();

        static constexpr const char* GetLevelString(Level level)
        {
            return ( Level::DBG  == level ? "[DBG] " :
                     Level::INFO == level ? "[INF] " :
                     Level::WARN == level ? "[WAN] " :
                     Level::ERR  == level ? "[ERR] " : "[CRT] " );
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

        // Format and write a single log line with one write(2) syscall.
        // Bypasses stdio locking, which deadlocks under concurrent logging
        // on MSYS2 (issue #2850); also makes log lines atomic on all platforms
        // since logfp is opened with O_APPEND.
        static void Printf(FILE* fp, const char* fmt, ...) __attribute__ ((format (printf, 2, 3)));

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
// [NOTE]
// All formatting, branching and output logic lives in the functions
// below, so it is emitted once instead of being inlined at every call
// site. The level-guarded macros keep a cheap inline IsS3fsLogLevel()
// check at the call site so the log arguments are not evaluated when
// the level is disabled; the out-of-line function is called only when
// the check passes. The macros also capture __FILE__/__func__/__LINE__,
// which a plain function cannot obtain on its own before C++20's
// std::source_location.
//
void s3fs_low_logprn(S3fsLog::Level level, const char* file, const char *func, int line, const char *fmt, ...) __attribute__ ((format (printf, 5, 6)));
#define S3FS_LOW_LOGPRN(level, fmt, ...) \
        do{ \
            if(S3fsLog::IsS3fsLogLevel(level)){ \
                s3fs_low_logprn(level, __FILE__, __func__, __LINE__, fmt, ##__VA_ARGS__); \
            } \
        }while(0)

void s3fs_low_logprn2(S3fsLog::Level level, int nest, const char* file, const char *func, int line, const char *fmt, ...) __attribute__ ((format (printf, 6, 7)));
#define S3FS_LOW_LOGPRN2(level, nest, fmt, ...) \
        do{ \
            if(S3fsLog::IsS3fsLogLevel(level)){ \
                s3fs_low_logprn2(level, nest, __FILE__, __func__, __LINE__, fmt, ##__VA_ARGS__); \
            } \
        }while(0)

void s3fs_low_curldbg(const char* fmt, ...) __attribute__ ((format (printf, 1, 2)));

void s3fs_low_logprn_exit(const char* fmt, ...) __attribute__ ((format (printf, 1, 2)));

// Special function for init message
void s3fs_low_init_info(const char* file, const char *func, int line, const char *fmt, ...) __attribute__ ((format (printf, 4, 5)));
#define S3FS_PRN_INIT_INFO(fmt, ...) \
        s3fs_low_init_info(__FILE__, __func__, __LINE__, fmt, ##__VA_ARGS__)

void s3fs_low_launch_info(const char* fmt, ...) __attribute__ ((format (printf, 1, 2)));

// Special function for checking cache files
void s3fs_low_cache(FILE* fp, const char* fmt, ...) __attribute__ ((format (printf, 2, 3)));

#define S3FS_PRN_EXIT(fmt, ...)   s3fs_low_logprn_exit(fmt, ##__VA_ARGS__)
#define S3FS_PRN_CRIT(fmt, ...)   S3FS_LOW_LOGPRN(S3fsLog::Level::CRIT, fmt, ##__VA_ARGS__)
#define S3FS_PRN_ERR(fmt, ...)    S3FS_LOW_LOGPRN(S3fsLog::Level::ERR,  fmt, ##__VA_ARGS__)
#define S3FS_PRN_WARN(fmt, ...)   S3FS_LOW_LOGPRN(S3fsLog::Level::WARN, fmt, ##__VA_ARGS__)
#define S3FS_PRN_DBG(fmt, ...)    S3FS_LOW_LOGPRN(S3fsLog::Level::DBG,  fmt, ##__VA_ARGS__)
#define S3FS_PRN_INFO(fmt, ...)   S3FS_LOW_LOGPRN2(S3fsLog::Level::INFO, 0, fmt, ##__VA_ARGS__)
#define S3FS_PRN_INFO1(fmt, ...)  S3FS_LOW_LOGPRN2(S3fsLog::Level::INFO, 1, fmt, ##__VA_ARGS__)
#define S3FS_PRN_INFO2(fmt, ...)  S3FS_LOW_LOGPRN2(S3fsLog::Level::INFO, 2, fmt, ##__VA_ARGS__)
#define S3FS_PRN_INFO3(fmt, ...)  S3FS_LOW_LOGPRN2(S3fsLog::Level::INFO, 3, fmt, ##__VA_ARGS__)
#define S3FS_PRN_CURL(fmt, ...)   s3fs_low_curldbg(fmt, ##__VA_ARGS__)
#define S3FS_PRN_CACHE(fp, ...)   s3fs_low_cache(fp, ##__VA_ARGS__)
#define S3FS_PRN_LAUNCH_INFO(fmt, ...)  s3fs_low_launch_info(fmt, ##__VA_ARGS__)

// Macros to print log with fuse context
#define PRINT_FUSE_CTX(level, indent, fmt, ...) do {                    \
    if(S3fsLog::IsS3fsLogLevel(level)){                                 \
        struct fuse_context *ctx = fuse_get_context();                  \
        if(ctx == nullptr){                                             \
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
