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

#include <cstdio>
#include <cstdlib>
#include <errno.h>
#include <stdint.h>

#include "s3fs_logger.h"
#include "threadpoolman.h"
#include "autolock.h"

//------------------------------------------------
// ThreadPoolMan class variables
//------------------------------------------------
ThreadPoolMan* ThreadPoolMan::singleton = NULL;

//------------------------------------------------
// ThreadPoolMan class methods
//------------------------------------------------
bool ThreadPoolMan::Initialize(int count)
{
    if(ThreadPoolMan::singleton){
        S3FS_PRN_WARN("Already singleton for Thread Manager is existed, then re-create it.");
        ThreadPoolMan::Destroy();
    }
    ThreadPoolMan::singleton = new ThreadPoolMan(count);
    return true;
}

void ThreadPoolMan::Destroy()
{
    if(ThreadPoolMan::singleton){
        delete ThreadPoolMan::singleton;
        ThreadPoolMan::singleton = NULL;
    }
}

bool ThreadPoolMan::Instruct(thpoolman_param* pparam)
{
    if(!ThreadPoolMan::singleton){
        S3FS_PRN_WARN("The singleton object is not initialized yet.");
        return false;
    }
    return ThreadPoolMan::singleton->SetInstruction(pparam);
}

//
// Thread worker
//
void* ThreadPoolMan::Worker(void* arg)
{
    ThreadPoolMan* psingleton = static_cast<ThreadPoolMan*>(arg);

    if(!psingleton){
        S3FS_PRN_ERR("The parameter for worker thread is invalid.");
        return reinterpret_cast<void*>(-EIO);
    }
    S3FS_PRN_INFO3("Start worker thread in ThreadPoolMan.");

    while(!psingleton->IsExit()){
        // wait
        psingleton->thpoolman_sem.wait();

        if(psingleton->IsExit()){
            break;
        }

        // get instruction
        thpoolman_param* pparam;
        {
            AutoLock auto_lock(&(psingleton->thread_list_lock));

            if(!psingleton->instruction_list.empty()){
                pparam = psingleton->instruction_list.front();
                psingleton->instruction_list.pop_front();
                if(!pparam){
                    S3FS_PRN_WARN("Got a semaphore, but the instruction is empty.");
                }
            }else{
                S3FS_PRN_WARN("Got a semaphore, but there is no instruction.");
                pparam = NULL;
            }
        }

        if(pparam){
            void* retval     = pparam->pfunc(pparam->args);
            if(NULL != retval){
                S3FS_PRN_WARN("The instruction function returned with somthign error code(%ld).", reinterpret_cast<long>(retval));
            }
            if(pparam->psem){
                pparam->psem->post();
            }
            delete pparam;
        }
    }

    return NULL;
}

//------------------------------------------------
// ThreadPoolMan methods
//------------------------------------------------
ThreadPoolMan::ThreadPoolMan(int count) : is_exit(false), thpoolman_sem(0), is_lock_init(false), is_exit_flag_init(false)
{
    if(count < 1){
        S3FS_PRN_CRIT("Failed to creating singleton for Thread Manager, because thread count(%d) is under 1.", count);
        abort();
    }
    if(ThreadPoolMan::singleton){
        S3FS_PRN_CRIT("Already singleton for Thread Manager is existed.");
        abort();
    }

    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
#if S3FS_PTHREAD_ERRORCHECK
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK);
#endif

    int result;
    if(0 != (result = pthread_mutex_init(&thread_list_lock, &attr))){
        S3FS_PRN_CRIT("failed to init thread_list_lock: %d", result);
        abort();
    }
    is_lock_init = true;

    if(0 != (result = pthread_mutex_init(&thread_exit_flag_lock, &attr))){
        S3FS_PRN_CRIT("failed to init thread_exit_flag_lock: %d", result);
        abort();
    }
    is_exit_flag_init = true;

    // create threads
    if(!StartThreads(count)){
        S3FS_PRN_ERR("Failed starting threads at initializing.");
        abort();
    }
}

ThreadPoolMan::~ThreadPoolMan()
{
    StopThreads();

    if(is_lock_init){
        int result;
        if(0 != (result = pthread_mutex_destroy(&thread_list_lock))){
            S3FS_PRN_CRIT("failed to destroy thread_list_lock: %d", result);
            abort();
        }
        is_lock_init = false;
    }
    if(is_exit_flag_init ){
        int result;
        if(0 != (result = pthread_mutex_destroy(&thread_exit_flag_lock))){
            S3FS_PRN_CRIT("failed to destroy thread_exit_flag_lock: %d", result);
            abort();
        }
        is_exit_flag_init  = false;
    }
}

bool ThreadPoolMan::IsExit()
{
    AutoLock auto_lock(&thread_exit_flag_lock);
    return is_exit;
}

void ThreadPoolMan::SetExitFlag(bool exit_flag)
{
    AutoLock auto_lock(&thread_exit_flag_lock);
    is_exit = exit_flag;
}

bool ThreadPoolMan::StopThreads()
{
    if(thread_list.empty()){
        S3FS_PRN_INFO("Any threads are running now, then nothing to do.");
        return true;
    }

    // all threads to exit
    SetExitFlag(true);
    for(uint waitcnt = thread_list.size(); 0 < waitcnt; --waitcnt){
        thpoolman_sem.post();
    }

    // wait for threads exiting
    for(thread_list_t::const_iterator iter = thread_list.begin(); iter != thread_list.end(); ++iter){
        void* retval = NULL;
        int   result = pthread_join(*iter, &retval);
        if(result){
            S3FS_PRN_ERR("failed pthread_join - result(%d)", result);
        }else{
            S3FS_PRN_DBG("succeed pthread_join - return code(%ld)", reinterpret_cast<long>(retval));
        }
    }
    thread_list.clear();

    // reset semaphore(to zero)
    while(thpoolman_sem.try_wait()){
    }

    // clear instructions
    for(thpoolman_params_t::const_iterator iter = instruction_list.begin(); iter != instruction_list.end(); ++iter){
        thpoolman_param* pparam = *iter;
        delete pparam;
    }
    instruction_list.clear();

    return true;
}

bool ThreadPoolMan::StartThreads(int count)
{
    if(count < 1){
        S3FS_PRN_ERR("Failed to creating threads, because thread count(%d) is under 1.", count);
        return false;
    }

    // stop all thread if they are running.
    if(!StopThreads()){
        S3FS_PRN_ERR("Failed to stop existed threads.");
        return false;
    }

    // create all threads
    SetExitFlag(false);
    for(int cnt = 0; cnt < count; ++cnt){
        // run thread
        pthread_t thread;
        int       result;
        if(0 != (result = pthread_create(&thread, NULL, ThreadPoolMan::Worker, static_cast<void*>(this)))){
            S3FS_PRN_ERR("failed pthread_create with return code(%d)", result);
            StopThreads();        // if possible, stop all threads
            return false;
        }
        thread_list.push_back(thread);
    }
    return true;
}

bool ThreadPoolMan::SetInstruction(thpoolman_param* pparam)
{
    if(!pparam){
        S3FS_PRN_ERR("The parameter value is NULL.");
        return false;
    }

    // set parameter to list
    {
        AutoLock auto_lock(&thread_list_lock);
        instruction_list.push_back(pparam);
    }

    // run thread
    thpoolman_sem.post();

    return true;
}

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
