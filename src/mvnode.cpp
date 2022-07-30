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
#include <cstring>

#include "s3fs.h"
#include "mvnode.h"

//-------------------------------------------------------------------
// Utility functions for moving objects
//-------------------------------------------------------------------
MVNODE *create_mvnode(const char *old_path, const char *new_path, bool is_dir, bool normdir)
{
    MVNODE *p;
    char *p_old_path;
    char *p_new_path;

    if(NULL == (p_old_path = strdup(old_path))){
        printf("create_mvnode: could not allocation memory for p_old_path\n");
        S3FS_FUSE_EXIT();
        return NULL;
    }

    if(NULL == (p_new_path = strdup(new_path))){
        free(p_old_path);
        printf("create_mvnode: could not allocation memory for p_new_path\n");
        S3FS_FUSE_EXIT();
        return NULL;
    }

    p = new MVNODE();
    p->old_path   = p_old_path;
    p->new_path   = p_new_path;
    p->is_dir     = is_dir;
    p->is_normdir = normdir;
    p->prev = NULL;
    p->next = NULL;
    return p;
}

//
// Add sorted MVNODE data(Ascending order)
//
MVNODE *add_mvnode(MVNODE** head, MVNODE** tail, const char *old_path, const char *new_path, bool is_dir, bool normdir)
{
    if(!head || !tail){
        return NULL;
    }

    MVNODE* cur;
    MVNODE* mvnew;
    for(cur = *head; cur; cur = cur->next){
        if(cur->is_dir == is_dir){
            int nResult = strcmp(cur->old_path, old_path);
            if(0 == nResult){
                // Found same old_path.
                return cur;

            }else if(0 > nResult){
                // next check.
                // ex: cur("abc"), mvnew("abcd")
                // ex: cur("abc"), mvnew("abd")
                continue;

            }else{
                // Add into before cur-pos.
                // ex: cur("abc"), mvnew("ab")
                // ex: cur("abc"), mvnew("abb")
                if(NULL == (mvnew = create_mvnode(old_path, new_path, is_dir, normdir))){
                    return NULL;
                }
                if(cur->prev){
                    (cur->prev)->next = mvnew;
                }else{
                    *head = mvnew;
                }
                mvnew->prev = cur->prev;
                mvnew->next = cur;
                cur->prev = mvnew;

                return mvnew;
            }
        }
    }
    // Add into tail.
    if(NULL == (mvnew = create_mvnode(old_path, new_path, is_dir, normdir))){
        return NULL;
    }
    mvnew->prev = (*tail);
    if(*tail){
        (*tail)->next = mvnew;
    }
    (*tail) = mvnew;
    if(!(*head)){
        (*head) = mvnew;
    }
    return mvnew;
}

void free_mvnodes(MVNODE *head)
{
    MVNODE *my_head;
    MVNODE *next;

    for(my_head = head, next = NULL; my_head; my_head = next){
        next = my_head->next;
        free(my_head->old_path);
        free(my_head->new_path);
        delete my_head;
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
