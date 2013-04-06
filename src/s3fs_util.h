#ifndef S3FS_S3FS_UTIL_H_
#define S3FS_S3FS_UTIL_H_

//-------------------------------------------------------------------
// Typedef
//-------------------------------------------------------------------
struct s3_object {
  char* name;
  char* etag;
  struct s3_object *next;
};

typedef struct mvnode {
   char *old_path;
   char *new_path;
   bool is_dir;
   struct mvnode *prev;
   struct mvnode *next;
} MVNODE;


//-------------------------------------------------------------------
// Functions
//-------------------------------------------------------------------
std::string get_realpath(const char *path);

int insert_object(const char* name, const char* etag, struct s3_object** head);
int free_object(struct s3_object *object);
int free_object_list(struct s3_object *head);

MVNODE *create_mvnode(const char *old_path, const char *new_path, bool is_dir);
MVNODE *add_mvnode(MVNODE** head, MVNODE** tail, const char *old_path, const char *new_path, bool is_dir);
void free_mvnodes(MVNODE *head);

std::string get_username(uid_t uid);
int is_uid_inculde_group(uid_t uid, gid_t gid);

std::string mydirname(std::string path);
std::string mybasename(std::string path);
int mkdirp(const std::string& path, mode_t mode);

time_t get_mtime(const char *s);
off_t get_size(const char *s);
mode_t get_mode(const char *s);
uid_t get_uid(const char *s);
gid_t get_gid(const char *s);
blkcnt_t get_blocks(off_t size);
time_t get_lastmodified(const char* s);

void show_usage(void);
void show_help(void);
void show_version(void);

#endif // S3FS_S3FS_UTIL_H_
