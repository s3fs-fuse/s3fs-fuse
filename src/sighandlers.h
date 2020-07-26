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

#ifndef S3FS_SIGHANDLERS_H_
#define S3FS_SIGHANDLERS_H_

#include "psemaphore.h"

//----------------------------------------------
// class S3fsSignals
//----------------------------------------------
class S3fsSignals
{
  private:
    static S3fsSignals* pSingleton;
	static bool         enableUsr1;

    pthread_t*          pThreadUsr1;
    Semaphore*          pSemUsr1;

  protected:
    static S3fsSignals* get(void) { return pSingleton; }

    static void HandlerUSR1(int sig);
    static void* CheckCacheWorker(void* arg);

    static void HandlerUSR2(int sig);
    static bool InitUsr2Handler(void);

    S3fsSignals();
    ~S3fsSignals();

    bool InitUsr1Handler(void);
    bool DestroyUsr1Handler(void);
    bool WakeupUsr1Thread(void);

  public:
    static bool Initialize(void);
    static bool Destroy(void);

    static bool SetUsr1Handler(const char* path);

    static s3fs_log_level SetLogLevel(s3fs_log_level level);
    static s3fs_log_level BumpupLogLevel(void);
};

#endif // S3FS_SIGHANDLERS_H_

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: noet sw=4 ts=4 fdm=marker
* vim<600: noet sw=4 ts=4
*/
