#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

static const char FILE_CONTENT[] = "XXXX";

static char *
filename_to_mkstemp_template(const char *file)
{
  size_t len = strlen(file);
  static const char suffix[] = ".XXXXXX";
  size_t new_len = len + sizeof(suffix);
  char *ret_str = calloc(1, new_len);
  int ret = snprintf(ret_str, new_len, "%s%s", file, suffix);
  assert(ret == new_len - 1);
  assert(ret_str[new_len] == '\0');
  return ret_str;
}

static off_t
get_file_size(const char *file)
{
  struct stat ss;
  int ret = lstat(file, &ss);
  assert(ret == 0);
  return ss.st_size;
}

static void
test_rename_before_close(const char *file)
{
  char *template = filename_to_mkstemp_template(file);
  int fd = mkstemp(template);
  assert(fd >= 0);

  int ret = write(fd, FILE_CONTENT, sizeof(FILE_CONTENT));
  assert(ret == sizeof(FILE_CONTENT));

  ret = fsync(fd);
  assert(ret == 0);

  assert(get_file_size(template) == sizeof(FILE_CONTENT));

  ret = rename(template, file);
  assert(ret == 0);

  ret = close(fd);
  assert(ret == 0);

  assert(get_file_size(file) == sizeof(FILE_CONTENT));
}

int
main(int argc, char *argv[])
{
  if (argc < 2) {
    printf("Usage: %s <file>", argv[0]);
    return 1;
  }

  test_rename_before_close(argv[1]);
  return 0;
}
