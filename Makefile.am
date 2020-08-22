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
SUBDIRS=src test doc

EXTRA_DIST=doc default_commit_hash

dist-hook:
	rm -rf `find $(distdir)/doc -type d -name .svn`
	rm -f `find $(distdir)/doc -type f -name Makefile`

release : dist ../utils/release.sh
	../utils/release.sh $(DIST_ARCHIVES)

cppcheck:
	cppcheck --quiet --error-exitcode=1 \
            --inline-suppr \
            --std=c++03 \
            --xml \
            -D HAVE_ATTR_XATTR_H \
            -D HAVE_SYS_EXTATTR_H \
            -D HAVE_MALLOC_TRIM \
            -U CURLE_PEER_FAILED_VERIFICATION \
            -U P_tmpdir \
            -U ENOATTR \
            --enable=warning,style,information,missingInclude \
            --suppress=missingIncludeSystem \
            --suppress=unmatchedSuppression \
            src/ test/

#
# Local variables:
# tab-width: 4
# c-basic-offset: 4
# End:
# vim600: expandtab sw=4 ts= fdm=marker
# vim<600: expandtab sw=4 ts=4
#
