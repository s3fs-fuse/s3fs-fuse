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

#ifndef S3FS_THREADPOOLMAN_H_
#define S3FS_THREADPOOLMAN_H_

#include <atomic>
#include <list>
#include <memory>
#include <vector>

#include "psemaphore.h"

//------------------------------------------------
// Typedefs for functions and structures
//------------------------------------------------
//
// Prototype function
//
typedef void* (*thpoolman_worker)(void*);               // same as start_routine for pthread_create function

//
// Parameter structure
//
// [NOTE]
// The args member is a value that is an argument of the worker function.
// The psem member is allowed nullptr. If it is not nullptr, the post() method is
// called when finishing the function.
//
struct thpoolman_param
{
    void*            args;
    Semaphore*       psem;
    thpoolman_worker pfunc;

    thpoolman_param() : args(nullptr), psem(nullptr), pfunc(nullptr) {}
};

typedef std::list<std::unique_ptr<thpoolman_param>> thpoolman_params_t;

typedef std::vector<pthread_t> thread_list_t;

//------------------------------------------------
// Class ThreadPoolMan
//------------------------------------------------
class ThreadPoolMan
{
    private:
        static ThreadPoolMan* singleton;

        std::atomic<bool>     is_exit;
        Semaphore             thpoolman_sem;

        bool                  is_lock_init;
        pthread_mutex_t       thread_list_lock;
        thread_list_t         thread_list;

        thpoolman_params_t    instruction_list;

    private:
        static void* Worker(void* arg);

        explicit ThreadPoolMan(int count = 1);
        ~ThreadPoolMan();
        ThreadPoolMan(const ThreadPoolMan&) = delete;
        ThreadPoolMan(ThreadPoolMan&&) = delete;
        ThreadPoolMan& operator=(const ThreadPoolMan&) = delete;
        ThreadPoolMan& operator=(ThreadPoolMan&&) = delete;

        bool IsExit() const;
        void SetExitFlag(bool exit_flag);

        bool StopThreads();
        bool StartThreads(int count);
        bool SetInstruction(std::unique_ptr<thpoolman_param> pparam);

    public:
        static bool Initialize(int count);
        static void Destroy();
        static bool Instruct(std::unique_ptr<thpoolman_param> pparam);
};

#endif // S3FS_THREADPOOLMAN_H_

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
