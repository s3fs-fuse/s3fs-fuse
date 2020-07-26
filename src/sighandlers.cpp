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

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <syslog.h>
#include <pthread.h>
#include <curl/curl.h>
#include <csignal>

#include <algorithm>
#include <map>
#include <string>
#include <list>
#include <vector>

#include "common.h"
#include "sighandlers.h"
#include "curl.h"
#include "fdcache.h"
#include "psemaphore.h"

using namespace std;

//-------------------------------------------------------------------
// Global variables
//-------------------------------------------------------------------
s3fs_log_level debug_level        = S3FS_LOG_CRIT;
const char*    s3fs_log_nest[S3FS_LOG_NEST_MAX] = {"", "  ", "    ", "      "};

//-------------------------------------------------------------------
// Class S3fsSignals
//-------------------------------------------------------------------
S3fsSignals* S3fsSignals::pSingleton = NULL;
bool S3fsSignals::enableUsr1         = false;

//-------------------------------------------------------------------
// Class methods
//-------------------------------------------------------------------
bool S3fsSignals::Initialize()
{
  if(!S3fsSignals::pSingleton){
    S3fsSignals::pSingleton = new S3fsSignals;
  }
  return true;
}

bool S3fsSignals::Destroy()
{
  if(S3fsSignals::pSingleton){
    delete S3fsSignals::pSingleton;
  }
  return true;
}

void S3fsSignals::HandlerUSR1(int sig)
{
  if(SIGUSR1 != sig){
    S3FS_PRN_ERR("The handler for SIGUSR1 received signal(%d)", sig);
    return;
  }

  S3fsSignals* pSigobj = S3fsSignals::get();
  if(!pSigobj){
    S3FS_PRN_ERR("S3fsSignals object is not initialized.");
    return;
  }

  if(!pSigobj->WakeupUsr1Thread()){
    S3FS_PRN_ERR("Failed to wakeup the thread for SIGUSR1.");
    return;
  }
}

bool S3fsSignals::SetUsr1Handler(const char* path)
{
  // set output file
  if(!FdManager::SetCacheCheckOutput(path)){
    S3FS_PRN_ERR("Could not set output file(%s) for checking cache.", path ? path : "null(stdout)");
    return false;
  }

  S3fsSignals::enableUsr1 = true;

  return true;
}

void* S3fsSignals::CheckCacheWorker(void* arg)
{
  Semaphore* pSem   = static_cast<Semaphore*>(arg);
  if(!pSem){
    pthread_exit(NULL);
  }
  if(!S3fsSignals::enableUsr1){
    pthread_exit(NULL);
  }

  // wait and loop
  while(S3fsSignals::enableUsr1){
    // wait
    pSem->wait();
    if(!S3fsSignals::enableUsr1){
      break;    // assap
    }

    // check all cache
    if(!FdManager::get()->CheckAllCache()){
      S3FS_PRN_ERR("Processing failed due to some problem.");
    }

    // do not allow request queuing
    for(int value = pSem->get_value(); 0 < value; value = pSem->get_value()){
      pSem->wait();
    }
  }
  return NULL;
}

void S3fsSignals::HandlerUSR2(int sig)
{
  if(SIGUSR2 == sig){
    S3fsSignals::BumpupLogLevel();
  }else{
    S3FS_PRN_ERR("The handler for SIGUSR2 received signal(%d)", sig);
  }
}

bool S3fsSignals::InitUsr2Handler()
{
  struct sigaction sa;

  memset(&sa, 0, sizeof(struct sigaction));
  sa.sa_handler = S3fsSignals::HandlerUSR2;
  sa.sa_flags   = SA_RESTART;
  if(0 != sigaction(SIGUSR2, &sa, NULL)){
    return false;
  }
  return true;
}

s3fs_log_level S3fsSignals::SetLogLevel(s3fs_log_level level)
{
  if(level == debug_level){
    return debug_level;
  }
  s3fs_log_level old = debug_level;
  debug_level        = level;
  setlogmask(LOG_UPTO(S3FS_LOG_LEVEL_TO_SYSLOG(debug_level)));
  S3FS_PRN_CRIT("change debug level from %sto %s", S3FS_LOG_LEVEL_STRING(old), S3FS_LOG_LEVEL_STRING(debug_level));
  return old;
}

s3fs_log_level S3fsSignals::BumpupLogLevel()
{
  s3fs_log_level old = debug_level;
  debug_level        = ( S3FS_LOG_CRIT == debug_level ? S3FS_LOG_ERR :
                         S3FS_LOG_ERR  == debug_level ? S3FS_LOG_WARN :
                         S3FS_LOG_WARN == debug_level ? S3FS_LOG_INFO :
                         S3FS_LOG_INFO == debug_level ? S3FS_LOG_DBG :
                         S3FS_LOG_CRIT );
  setlogmask(LOG_UPTO(S3FS_LOG_LEVEL_TO_SYSLOG(debug_level)));
  S3FS_PRN_CRIT("change debug level from %sto %s", S3FS_LOG_LEVEL_STRING(old), S3FS_LOG_LEVEL_STRING(debug_level));
  return old;
}

//-------------------------------------------------------------------
// Methods
//-------------------------------------------------------------------
S3fsSignals::S3fsSignals() : pThreadUsr1(NULL), pSemUsr1(NULL)
{
  if(S3fsSignals::enableUsr1){
    if(!InitUsr1Handler()){
      S3FS_PRN_ERR("failed creating thread for SIGUSR1 handler, but continue...");
    }
  }
  if(!S3fsSignals::InitUsr2Handler()){
    S3FS_PRN_ERR("failed to initialize SIGUSR2 handler for bumping log level, but continue...");
  }
}

S3fsSignals::~S3fsSignals()
{
  if(S3fsSignals::enableUsr1){
    if(!DestroyUsr1Handler()){
      S3FS_PRN_ERR("failed stopping thread for SIGUSR1 handler, but continue...");
    }
  }
}

bool S3fsSignals::InitUsr1Handler()
{
  if(pThreadUsr1 || pSemUsr1){
    S3FS_PRN_ERR("Already run thread for SIGUSR1");
    return false;
  }

  // create thread
  int result;
  pSemUsr1    = new Semaphore(0);
  pThreadUsr1 = new pthread_t;
  if(0 != (result = pthread_create(pThreadUsr1, NULL, S3fsSignals::CheckCacheWorker, static_cast<void*>(pSemUsr1)))){
    S3FS_PRN_ERR("Could not create thread for SIGUSR1 by %d", result);
    delete pSemUsr1;
    delete pThreadUsr1;
    pSemUsr1    = NULL;
    pThreadUsr1 = NULL;
    return false;
  }

  // set handler
  struct sigaction sa;
  memset(&sa, 0, sizeof(struct sigaction));
  sa.sa_handler = S3fsSignals::HandlerUSR1;
  sa.sa_flags   = SA_RESTART;
  if(0 != sigaction(SIGUSR1, &sa, NULL)){
    S3FS_PRN_ERR("Could not set signal handler for SIGUSR1");
    DestroyUsr1Handler();
    return false;
  }

  return true;
}

bool S3fsSignals::DestroyUsr1Handler()
{
  if(!pThreadUsr1 || !pSemUsr1){
    return false;
  }
  // for thread exit
  S3fsSignals::enableUsr1 = false;

  // wakeup thread
  pSemUsr1->post();

  // wait for thread exiting
  void* retval = NULL;
  int   result;
  if(0 != (result = pthread_join(*pThreadUsr1, &retval))){
    S3FS_PRN_ERR("Could not stop thread for SIGUSR1 by %d", result);
    return false;
  }
  delete pSemUsr1;
  delete pThreadUsr1;
  pSemUsr1    = NULL;
  pThreadUsr1 = NULL;

  return true;
}

bool S3fsSignals::WakeupUsr1Thread()
{
  if(!pThreadUsr1 || !pSemUsr1){
    S3FS_PRN_ERR("The thread for SIGUSR1 is not setup.");
    return false;
  }
  pSemUsr1->post();
  return true;
}

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: noet sw=4 ts=4 fdm=marker
* vim<600: noet sw=4 ts=4
*/
