/*
 * s3fs - FUSE-based file system backed by Amazon S3
 *
 * Copyright(C) 2021 Andrew Gaul <andrew@gaul.org>
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

// Generate junk data at high speed.  An alternative to dd if=/dev/urandom.

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
    if (argc != 2) {
        return 1;
    }
    long long count = strtoull(argv[1], NULL, 10);
    char buf[128 * 1024];
    long long i;
    for (i = 0; i < count; i += sizeof(buf)) {
        long long j;
        for (j = 0; j < sizeof(buf) / sizeof(i); ++j) {
            *((long long *)buf + j) = i / sizeof(i) + j;
        }
        fwrite(buf, 1, sizeof(buf) > count - i ? count - i : sizeof(buf), stdout);
    }
    return 0;
}

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
