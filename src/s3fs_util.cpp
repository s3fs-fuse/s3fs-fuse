/*
 * s3fs - FUSE-based file system backed by Amazon S3
 *
 * Copyright 2007-2013 Takeshi Nakatani <ggtakec.com>
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <libgen.h>
#include <pwd.h>
#include <grp.h>
#include <syslog.h>

#include <string>
#include <sstream>
#include <map>

#include "common.h"
#include "s3fs_util.h"
#include "s3fs.h"

using namespace std;

//-------------------------------------------------------------------
// Global valiables
//-------------------------------------------------------------------
std::string mount_prefix   = "";

//-------------------------------------------------------------------
// Utility
//-------------------------------------------------------------------
string get_realpath(const char *path) {
  string realpath = mount_prefix;
  realpath += path;

  return realpath;
}

//-------------------------------------------------------------------
// Utility for listing objects
//-------------------------------------------------------------------
// [Change]
// The s3_object's name member can be set "dir" or "dir/" as directory name.
// Both of names are same directory s3_object.
// "dir/" is given priority to over "dir".
//
// [Notice]
// If there are "dir" and "dir/" object on S3, s3fs only recognizes "dir/".
// On this case, user can not know the "dir" object.
//
int insert_object(const char *name, struct s3_object **head)
{
  struct s3_object *cur_object;
  struct s3_object *new_object;
  int nLen = name ? strlen(name) : 0;
  int is_have_ndelimiter = 0;

  // search same name object
  if(nLen && '/' == name[nLen - 1]){
    // case of "dir/"
    nLen--;
    is_have_ndelimiter = 1;
  }
  for(cur_object = *head; nLen && cur_object; cur_object = cur_object->next){
    if(0 == strncmp(cur_object->name, name, nLen)){
      int cLen = strlen(cur_object->name);
      int is_have_cdelimiter = 0;

      if('/' == cur_object->name[cLen - 1]){
        cLen--;
        is_have_cdelimiter = 1;
      }
      if(cLen == nLen){
        // same object
        if(is_have_cdelimiter == is_have_ndelimiter){
          // perfect same object
          return 0;
        }
        if(is_have_cdelimiter){
          // already set "dir/"
          return 0;
        }
        // new object is "dir/", replace name.
        free(cur_object->name);
        if(NULL == (cur_object->name = strdup(name))){
          printf("insert_object: could not allocate memory\n");
          S3FS_FUSE_EXIT();
          return -1;
        }
        return 0;
      }
    }
  }

  // Not found same object.
  new_object = (struct s3_object *) malloc(sizeof(struct s3_object));
  if(new_object == NULL) {
    printf("insert_object: could not allocate memory\n");
    S3FS_FUSE_EXIT();
    return -1;
  }

  if(NULL == (new_object->name = strdup(name))){
    free(new_object);
    printf("insert_object: could not allocate memory\n");
    S3FS_FUSE_EXIT();
    return -1;
  }

  if((*head) == NULL)
    new_object->next = NULL;
  else
    new_object->next = (*head);

  *head = new_object;

  return 0;
}

int free_object(struct s3_object *object)
{
  free(object->name);
  free(object);
  object = NULL;

  return 0;
}

int free_object_list(struct s3_object *head)
{
  struct s3_object *tmp = NULL;
  struct s3_object *current = head;

  current = head;
  while(current != NULL) {
    tmp = current;
    current = current->next;
    free_object(tmp);
  }

  return 0;
}

//-------------------------------------------------------------------
// Utility functions for moving objects
//-------------------------------------------------------------------
MVNODE *create_mvnode(const char *old_path, const char *new_path, bool is_dir)
{
  MVNODE *p;
  char *p_old_path;
  char *p_new_path;

  p = (MVNODE *) malloc(sizeof(MVNODE));
  if (p == NULL) {
    printf("create_mvnode: could not allocation memory for p\n");
    S3FS_FUSE_EXIT();
    return NULL;
  }

  if(NULL == (p_old_path = strdup(old_path))){
    free(p);
    printf("create_mvnode: could not allocation memory for p_old_path\n");
    S3FS_FUSE_EXIT();
    return NULL;
  }

  if(NULL == (p_new_path = strdup(new_path))){ 
    free(p);
    free(p_old_path);
    printf("create_mvnode: could not allocation memory for p_new_path\n");
    S3FS_FUSE_EXIT();
    return NULL;
  }

  p->old_path = p_old_path;
  p->new_path = p_new_path;
  p->is_dir = is_dir;
  p->prev = NULL;
  p->next = NULL;
  return p;
}

//
// Add sorted MVNODE data(Ascending order) 
//
MVNODE *add_mvnode(MVNODE** head, MVNODE** tail, const char *old_path, const char *new_path, bool is_dir)
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
        if(NULL == (mvnew = create_mvnode(old_path, new_path, is_dir))){
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
  if(NULL == (mvnew = create_mvnode(old_path, new_path, is_dir))){
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
    free(my_head);
  }
  return;
}

//-------------------------------------------------------------------
// Utility for UID/GID
//-------------------------------------------------------------------
// get user name from uid
string get_username(uid_t uid)
{
  struct passwd* ppw;
  if(NULL == (ppw = getpwuid(uid)) || NULL == ppw->pw_name){
    FGPRINT("    could not get username(errno=%d).\n", (int)errno);
    SYSLOGDBG("could not get username(errno=%d).\n", (int)errno);
    return NULL;
  }
  return string(ppw->pw_name);
}

// check uid in group(gid)
int is_uid_inculde_group(uid_t uid, gid_t gid)
{
  static size_t maxlen = 0;	// set onece
  int result;
  char* pbuf;
  struct group ginfo;
  struct group* pginfo = NULL;

  // make buffer
  if(0 == maxlen){
    if(0 > (maxlen = (size_t)sysconf(_SC_GETGR_R_SIZE_MAX))){
      FGPRINT("    could not get max name length.\n");
      SYSLOGDBG("could not get max name length.\n");
      maxlen = 0;
      return -ERANGE;
    }
  }
  if(NULL == (pbuf = (char*)malloc(sizeof(char) * maxlen))){
    FGPRINT("    failed to allocate memory.\n");
    SYSLOGERR("failed to allocate memory.\n");
    return -ENOMEM;
  }
  // get group infomation
  if(0 != (result = getgrgid_r(gid, &ginfo, pbuf, maxlen, &pginfo))){
    FGPRINT("    could not get group infomation.\n");
    SYSLOGDBG("could not get group infomation.\n");
    free(pbuf);
    return -result;
  }

  // check group
  if(NULL == pginfo){
    // there is not gid in group.
    free(pbuf);
    return -EINVAL;
  }

  string username = get_username(uid);

  char** ppgr_mem;
  for(ppgr_mem = pginfo->gr_mem; ppgr_mem && *ppgr_mem; ppgr_mem++){
    if(username == *ppgr_mem){
      // Found username in group.
      free(pbuf);
      return 1;
    }
  }
  free(pbuf);
  return 0;
}

//-------------------------------------------------------------------
// Utility for file and directory
//-------------------------------------------------------------------
// safe variant of dirname
// dirname clobbers path so let it operate on a tmp copy
string mydirname(string path)
{
  return string(dirname(&path[0]));
}

// safe variant of basename
// basename clobbers path so let it operate on a tmp copy
string mybasename(string path)
{
  return string(basename(&path[0]));
}

// mkdir --parents
int mkdirp(const string& path, mode_t mode)
{
  string base;
  string component;
  stringstream ss(path);
  while (getline(ss, component, '/')) {
    base += "/" + component;
    mkdir(base.c_str(), mode);
  }
  return 0;
}

//-------------------------------------------------------------------
// Utility functions for convert
//-------------------------------------------------------------------
time_t get_mtime(const char *s)
{
  return (time_t) strtoul(s, (char **) NULL, 10);
}

off_t get_size(const char *s)
{
  return (off_t) strtoul(s, (char **) NULL, 10);
}

mode_t get_mode(const char *s)
{
  return (mode_t) strtoul(s, (char **) NULL, 10);
}

uid_t get_uid(const char *s)
{
  return (uid_t) strtoul(s, (char **) NULL, 10);
}

gid_t get_gid(const char *s)
{
  return (gid_t) strtoul(s, (char **) NULL, 10);
}

blkcnt_t get_blocks(off_t size)
{
  return size / 512 + 1;
}

//-------------------------------------------------------------------
// Help
//-------------------------------------------------------------------
void show_usage (void)
{
  printf("Usage: %s BUCKET:[PATH] MOUNTPOINT [OPTION]...\n",
    program_name.c_str());
}

void show_help (void)
{
  show_usage();
  printf( 
    "\n"
    "Mount an Amazon S3 bucket as a file system.\n"
    "\n"
    "   General forms for s3fs and FUSE/mount options:\n"
    "      -o opt[,opt...]\n"
    "      -o opt [-o opt] ...\n"
    "\n"
    "s3fs Options:\n"
    "\n"
    "   Most s3fs options are given in the form where \"opt\" is:\n"
    "\n"
    "             <option_name>=<option_value>\n"
    "\n"
    "   default_acl (default=\"private\")\n"
    "     - the default canned acl to apply to all written s3 objects\n"
    "          see http://aws.amazon.com/documentation/s3/ for the \n"
    "          full list of canned acls\n"
    "\n"
    "   retries (default=\"2\")\n"
    "      - number of times to retry a failed s3 transaction\n"
    "\n"
    "   use_cache (default=\"\" which means disabled)\n"
    "      - local folder to use for local file cache\n"
    "\n"
    "   use_rrs (default=\"\" which means diabled)\n"
    "      - use Amazon's Reduced Redundancy Storage when set to 1\n"
    "\n"
    "   public_bucket (default=\"\" which means disabled)\n"
    "      - anonymously mount a public bucket when set to 1\n"
    "\n"
    "   passwd_file (default=\"\")\n"
    "      - specify which s3fs password file to use\n"
    "\n"
    "   connect_timeout (default=\"10\" seconds)\n"
    "      - time to wait for connection before giving up\n"
    "\n"
    "   readwrite_timeout (default=\"30\" seconds)\n"
    "      - time to wait between read/write activity before giving up\n"
    "\n"
    "   max_stat_cache_size (default=\"10000\" entries (about 4MB))\n"
    "      - maximum number of entries in the stat cache\n"
    "\n"
    "   stat_cache_expire (default is no expire)\n"
    "      - specify expire time(seconds) for entries in the stat cache.\n"
    "\n"
    "   url (default=\"http://s3.amazonaws.com\")\n"
    "      - sets the url to use to access amazon s3\n"
    "\n"
    "   nomultipart - disable multipart uploads\n"
    "\n"
    "   noxmlns - disable registing xml name space.\n"
    "        disable registing xml name space for response of \n"
    "        ListBucketResult and ListVersionsResult etc. Default name \n"
    "        space is looked up from \"http://s3.amazonaws.com/doc/2006-03-01\".\n"
    "\n"
    "   nocopyapi - for other incomplete compatibility object storage.\n"
    "        For a distributed object storage which is compatibility S3\n"
    "        API without PUT(copy api).\n"
    "        If you set this option, s3fs do not use PUT with \n"
    "        \"x-amz-copy-source\"(copy api). Because traffic is increased\n"
    "        2-3 times by this option, we do not recommend this.\n"
    "\n"
    "   norenameapi - for other incomplete compatibility object storage.\n"
    "        For a distributed object storage which is compatibility S3\n"
    "        API without PUT(copy api).\n"
    "        This option is a subset of nocopyapi option. The nocopyapi\n"
    "        option does not use copy-api for all command(ex. chmod, chown,\n"
    "        touch, mv, etc), but this option does not use copy-api for\n"
    "        only rename command(ex. mv). If this option is specified with\n"
    "        nocopapi, the s3fs ignores it.\n"
    "\n"
    "FUSE/mount Options:\n"
    "\n"
    "   Most of the generic mount options described in 'man mount' are\n"
    "   supported (ro, rw, suid, nosuid, dev, nodev, exec, noexec, atime,\n"
    "   noatime, sync async, dirsync).  Filesystems are mounted with\n"
    "   '-onodev,nosuid' by default, which can only be overridden by a\n"
    "   privileged user.\n"
    "   \n"
    "   There are many FUSE specific mount options that can be specified.\n"
    "   e.g. allow_other  See the FUSE's README for the full set.\n"
    "\n"
    "Miscellaneous Options:\n"
    "\n"
    " -h, --help        Output this help.\n"
    "     --version     Output version info.\n"
    " -d  --debug       Turn on DEBUG messages to syslog. Specifying -d\n"
    "                   twice turns on FUSE debug messages to STDOUT.\n"
    " -f                FUSE foreground option - do not run as daemon.\n"
    " -s                FUSE singlethread option\n"
    "                   disable multi-threaded operation\n"
    "\n"
    "\n"
    "Report bugs to <s3fs-devel@googlegroups.com>\n"
    "s3fs home page: <http://code.google.com/p/s3fs/>\n"
  );
  return;
}

void show_version(void)
{
  printf(
  "Amazon Simple Storage Service File System %s\n"
  "Copyright (C) 2010 Randy Rizun <rrizun@gmail.com>\n"
  "License GPL2: GNU GPL version 2 <http://gnu.org/licenses/gpl.html>\n"
  "This is free software: you are free to change and redistribute it.\n"
  "There is NO WARRANTY, to the extent permitted by law.\n", VERSION );
  return;
}

