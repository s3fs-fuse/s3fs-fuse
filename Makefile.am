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

.PHONY: cppcheck shellcheck

cppcheck:
	cppcheck --quiet --error-exitcode=1 \
            --inline-suppr \
            --std=c++03 \
            --xml \
            -D HAVE_ATTR_XATTR_H \
            -D HAVE_SYS_EXTATTR_H \
            -D HAVE_MALLOC_TRIM \
            -U CURLE_PEER_FAILED_VERIFICATION \
            -U ENOATTR \
            --enable=warning,style,information,missingInclude \
            --suppress=missingIncludeSystem \
            --suppress=unmatchedSuppression \
            src/ test/

#
# ShellCheck
#
SHELLCHECK_CMD = shellcheck
SHELLCHECK_SH_OPT = --shell=sh
SHELLCHECK_BASH_OPT = --shell=bash

# [NOTE]
# To control error warnings as a whole, specify the "SC<number>" with the following variables.
#
SHELLCHECK_COMMON_IGN = --exclude=SC1091
SHELLCHECK_CUSTOM_IGN = --exclude=SC1091

shellcheck:
	@if type shellcheck > /dev/null 2>&1; then \
		echo "* ShellCheck version"; \
		$(SHELLCHECK_CMD) --version; \
		echo ""; \
		echo "* Check all sh files with ShellCheck"; \
		LC_ALL=C.UTF-8 $(SHELLCHECK_CMD) $(SHELLCHECK_SH_OPT) $(SHELLCHECK_COMMON_IGN) $$(grep '#![[:space:]]*/bin/sh' $$(find . -type f -name \*.sh) | sed -e 's|^\(.*\):#\!.*$$|\1|g') || exit 1; \
		echo "-> No error was detected."; \
		echo ""; \
		echo "* Check all bash files with ShellCheck"; \
		LC_ALL=C.UTF-8 $(SHELLCHECK_CMD) $(SHELLCHECK_BASH_OPT) $(SHELLCHECK_COMMON_IGN) $$(grep '#![[:space:]]*/bin/bash' $$(find . -type f -name \*.sh) | sed -e 's|^\(.*\):#\!.*$$|\1|g') || exit 1; \
		echo "-> No error was detected."; \
	else \
		echo "* ShellCheck is not installed, so skip this."; \
	fi

#
# Local variables:
# tab-width: 4
# c-basic-offset: 4
# End:
# vim600: expandtab sw=4 ts= fdm=marker
# vim<600: expandtab sw=4 ts=4
#
