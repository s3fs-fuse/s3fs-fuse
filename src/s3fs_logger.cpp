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

#include <cstdlib>
#include <iomanip>
#include <sstream>
#include <string>

#include "common.h"
#include "s3fs_logger.h"

//-------------------------------------------------------------------
// S3fsLog class : variables
//-------------------------------------------------------------------
const int               S3fsLog::NEST_MAX;
const char* const       S3fsLog::nest_spaces[S3fsLog::NEST_MAX] = {"", "  ", "    ", "      "};
const char              S3fsLog::LOGFILEENV[]     = "S3FS_LOGFILE";
const char              S3fsLog::MSGTIMESTAMP[]   = "S3FS_MSGTIMESTAMP";
S3fsLog*                S3fsLog::pSingleton       = NULL;
S3fsLog::s3fs_log_level S3fsLog::debug_level      = S3fsLog::LEVEL_CRIT;
FILE*                   S3fsLog::logfp            = NULL;
std::string*            S3fsLog::plogfile         = NULL;
bool                    S3fsLog::time_stamp       = true;

//-------------------------------------------------------------------
// S3fsLog class : class methods
//-------------------------------------------------------------------
bool S3fsLog::IsS3fsLogLevel(s3fs_log_level level)
{
    return (level == (S3fsLog::debug_level & level));
}

std::string S3fsLog::GetCurrentTime()
{
    std::ostringstream current_time;
    if(time_stamp){
        struct timeval  now;
        struct timespec tsnow;
        struct tm res;
        char   tmp[32];
        if(-1 == clock_gettime(S3FS_CLOCK_MONOTONIC, &tsnow)){
            now.tv_sec  = tsnow.tv_sec;
            now.tv_usec = (tsnow.tv_nsec / 1000);
        }else{
            gettimeofday(&now, NULL);
        }
        strftime(tmp, sizeof(tmp), "%Y-%m-%dT%H:%M:%S", gmtime_r(&now.tv_sec, &res));
        current_time << tmp << "." << std::setfill('0') << std::setw(3) << (now.tv_usec / 1000) << "Z ";
    }
    return current_time.str();
}

bool S3fsLog::SetLogfile(const char* pfile)
{
    if(!S3fsLog::pSingleton){
        S3FS_PRN_CRIT("S3fsLog::pSingleton is NULL.");
        return false;
    }
    return S3fsLog::pSingleton->LowSetLogfile(pfile);
}

bool S3fsLog::ReopenLogfile()
{
    if(!S3fsLog::pSingleton){
        S3FS_PRN_CRIT("S3fsLog::pSingleton is NULL.");
        return false;
    }
    if(!S3fsLog::logfp){
        S3FS_PRN_INFO("Currently the log file is output to stdout/stderr.");
        return true;
    }
    if(!S3fsLog::plogfile){
        S3FS_PRN_ERR("There is a problem with the path to the log file being NULL.");
        return false;
    }
    std::string tmp = *(S3fsLog::plogfile);
    return S3fsLog::pSingleton->LowSetLogfile(tmp.c_str());
}

S3fsLog::s3fs_log_level S3fsLog::SetLogLevel(s3fs_log_level level)
{
    if(!S3fsLog::pSingleton){
        S3FS_PRN_CRIT("S3fsLog::pSingleton is NULL.");
        return S3fsLog::debug_level;    // Although it is an error, it returns the current value.
    }
    return S3fsLog::pSingleton->LowSetLogLevel(level);
}

S3fsLog::s3fs_log_level S3fsLog::BumpupLogLevel()
{
    if(!S3fsLog::pSingleton){
        S3FS_PRN_CRIT("S3fsLog::pSingleton is NULL.");
        return S3fsLog::debug_level;    // Although it is an error, it returns the current value.
    }
    return S3fsLog::pSingleton->LowBumpupLogLevel();
}

bool S3fsLog::SetTimeStamp(bool value)
{
    bool old = S3fsLog::time_stamp;
    S3fsLog::time_stamp = value;
    return old;
}

//-------------------------------------------------------------------
// S3fsLog class : methods
//-------------------------------------------------------------------
S3fsLog::S3fsLog()
{
    if(!S3fsLog::pSingleton){
        S3fsLog::pSingleton = this;

        // init syslog(default CRIT)
        openlog("s3fs", LOG_PID | LOG_ODELAY | LOG_NOWAIT, LOG_USER);
        LowLoadEnv();
    }else{
        S3FS_PRN_ERR("Already set singleton object for S3fsLog.");
    }
}

S3fsLog::~S3fsLog()
{
    if(S3fsLog::pSingleton == this){
        FILE*    oldfp = S3fsLog::logfp;
        S3fsLog::logfp = NULL;
        if(oldfp && 0 != fclose(oldfp)){
            S3FS_PRN_ERR("Could not close old log file(%s), but continue...", (S3fsLog::plogfile ? S3fsLog::plogfile->c_str() : "null"));
        }
        if(S3fsLog::plogfile){
            delete S3fsLog::plogfile;
            S3fsLog::plogfile = NULL;
        }
        S3fsLog::pSingleton  = NULL;
        S3fsLog::debug_level = S3fsLog::LEVEL_CRIT;

        closelog();
    }else{
        S3FS_PRN_ERR("This object is not singleton S3fsLog object.");
    }
}

bool S3fsLog::LowLoadEnv()
{
    if(S3fsLog::pSingleton != this){
        S3FS_PRN_ERR("This object is not as same as S3fsLog::pSingleton.");
        return false;
    }
    char*    pEnvVal;
    if(NULL != (pEnvVal = getenv(S3fsLog::LOGFILEENV))){
        if(!SetLogfile(pEnvVal)){
            return false;
        }
    }
    if(NULL != (pEnvVal = getenv(S3fsLog::MSGTIMESTAMP))){
        if(0 == strcasecmp(pEnvVal, "true") || 0 == strcasecmp(pEnvVal, "yes") || 0 == strcasecmp(pEnvVal, "1")){
            S3fsLog::time_stamp = true;
        }else if(0 == strcasecmp(pEnvVal, "false") || 0 == strcasecmp(pEnvVal, "no") || 0 == strcasecmp(pEnvVal, "0")){
            S3fsLog::time_stamp = false;
        }else{
            S3FS_PRN_WARN("Unknown %s environment value(%s) is specified, skip to set time stamp mode.", S3fsLog::MSGTIMESTAMP, pEnvVal);
        }
    }
    return true;
}

bool S3fsLog::LowSetLogfile(const char* pfile)
{
    if(S3fsLog::pSingleton != this){
        S3FS_PRN_ERR("This object is not as same as S3fsLog::pSingleton.");
        return false;
    }

    if(!pfile){
        // close log file if it is opened
        if(S3fsLog::logfp && 0 != fclose(S3fsLog::logfp)){
            S3FS_PRN_ERR("Could not close log file(%s).", (S3fsLog::plogfile ? S3fsLog::plogfile->c_str() : "null"));
            return false;
        }
        S3fsLog::logfp = NULL;
        if(S3fsLog::plogfile){
            delete S3fsLog::plogfile;
            S3fsLog::plogfile = NULL;
        }
    }else{
        // open new log file
        //
        // [NOTE]
        // It will reopen even if it is the same file.
        //
        FILE* newfp;
        if(NULL == (newfp = fopen(pfile, "a+"))){
            S3FS_PRN_ERR("Could not open log file(%s).", pfile);
            return false;
        }

        // switch new log file and close old log file if it is opened
        FILE*    oldfp = S3fsLog::logfp;
        S3fsLog::logfp = newfp;
        if(oldfp && 0 != fclose(oldfp)){
            S3FS_PRN_ERR("Could not close old log file(%s).", (S3fsLog::plogfile ? S3fsLog::plogfile->c_str() : "null"));
            S3fsLog::logfp = oldfp;
            fclose(newfp);
            return false;
        }
        delete S3fsLog::plogfile;
        S3fsLog::plogfile = new std::string(pfile);
    }
    return true;
}

S3fsLog::s3fs_log_level S3fsLog::LowSetLogLevel(s3fs_log_level level)
{
    if(S3fsLog::pSingleton != this){
        S3FS_PRN_ERR("This object is not as same as S3fsLog::pSingleton.");
        return S3fsLog::debug_level;    // Although it is an error, it returns the current value.
    }
    if(level == S3fsLog::debug_level){
        return S3fsLog::debug_level;
    }
    s3fs_log_level old   = S3fsLog::debug_level;
    S3fsLog::debug_level = level;
    setlogmask(LOG_UPTO(GetSyslogLevel(S3fsLog::debug_level)));
    S3FS_PRN_CRIT("change debug level from %sto %s", GetLevelString(old), GetLevelString(S3fsLog::debug_level));
    return old;
}

S3fsLog::s3fs_log_level S3fsLog::LowBumpupLogLevel()
{
    if(S3fsLog::pSingleton != this){
        S3FS_PRN_ERR("This object is not as same as S3fsLog::pSingleton.");
        return S3fsLog::debug_level;    // Although it is an error, it returns the current value.
    }
    s3fs_log_level old   = S3fsLog::debug_level;
    S3fsLog::debug_level = ( LEVEL_CRIT == S3fsLog::debug_level ? LEVEL_ERR  :
                             LEVEL_ERR  == S3fsLog::debug_level ? LEVEL_WARN :
                             LEVEL_WARN == S3fsLog::debug_level ? LEVEL_INFO :
                             LEVEL_INFO == S3fsLog::debug_level ? LEVEL_DBG  : LEVEL_CRIT );
    setlogmask(LOG_UPTO(GetSyslogLevel(S3fsLog::debug_level)));
    S3FS_PRN_CRIT("change debug level from %sto %s", GetLevelString(old), GetLevelString(S3fsLog::debug_level));
    return old;
}

void s3fs_low_logprn(S3fsLog::s3fs_log_level level, const char* file, const char *func, int line, const char *fmt, ...)
{
    if(S3fsLog::IsS3fsLogLevel(level)){
        va_list va;
        va_start(va, fmt);
        size_t len = vsnprintf(NULL, 0, fmt, va) + 1;
        va_end(va);

        char *message = new char[len];
        va_start(va, fmt);
        vsnprintf(message, len, fmt, va);
        va_end(va);

        if(foreground || S3fsLog::IsSetLogFile()){
            S3fsLog::SeekEnd();
            fprintf(S3fsLog::GetOutputLogFile(), "%s%s%s:%s(%d): %s\n", S3fsLog::GetCurrentTime().c_str(), S3fsLog::GetLevelString(level), file, func, line, message);
            S3fsLog::Flush();
        }else{
            // TODO: why does this differ from s3fs_low_logprn2?
            syslog(S3fsLog::GetSyslogLevel(level), "%s%s:%s(%d): %s", instance_name.c_str(), file, func, line, message);
        }

        delete[] message;
    }
}

void s3fs_low_logprn2(S3fsLog::s3fs_log_level level, int nest, const char* file, const char *func, int line, const char *fmt, ...)
{
    if(S3fsLog::IsS3fsLogLevel(level)){
        va_list va;
        va_start(va, fmt);
        size_t len = vsnprintf(NULL, 0, fmt, va) + 1;
        va_end(va);

        char *message = new char[len];
        va_start(va, fmt);
        vsnprintf(message, len, fmt, va);
        va_end(va);

        if(foreground || S3fsLog::IsSetLogFile()){
            S3fsLog::SeekEnd();
            fprintf(S3fsLog::GetOutputLogFile(), "%s%s%s%s:%s(%d): %s\n", S3fsLog::GetCurrentTime().c_str(), S3fsLog::GetLevelString(level), S3fsLog::GetS3fsLogNest(nest), file, func, line, message);
            S3fsLog::Flush();
        }else{
            syslog(S3fsLog::GetSyslogLevel(level), "%s%s%s", instance_name.c_str(), S3fsLog::GetS3fsLogNest(nest), message);
        }

        delete[] message;
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
