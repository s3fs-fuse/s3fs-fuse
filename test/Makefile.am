######################################################################
# s3fs - FUSE-based file system backed by Amazon S3
#
# Copyright 2007-2008 Randy Rizun <rrizun@gmail.com>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
######################################################################

TESTS=small-integration-test.sh

EXTRA_DIST = \
    integration-test-common.sh \
    small-integration-test.sh \
    mergedir.sh \
    sample_delcache.sh \
    sample_ahbe.conf

testdir = test

noinst_PROGRAMS = \
    junk_data \
    write_multiblock \
    mknod_test

junk_data_SOURCES = junk_data.c
write_multiblock_SOURCES = write_multiblock.cc
mknod_test_SOURCES = mknod_test.c

#
# Local variables:
# tab-width: 4
# c-basic-offset: 4
# End:
# vim600: expandtab sw=4 ts=4 fdm=marker
# vim<600: expandtab sw=4 ts=4
#
