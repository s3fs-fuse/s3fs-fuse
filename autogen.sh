#!/bin/sh
#
# This file is part of S3FS.
# 
# Copyright 2009, 2010 Free Software Foundation, Inc.
# 
# S3FS is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or (at
# your option) any later version.
# 
# S3FS is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program. If not, see http://www.gnu.org/licenses/. 
# 
#  See the file ChangeLog for a revision history. 

echo "--- Make commit hash file -------"

SHORTHASH=""
if command -v git > /dev/null 2>&1 && test -d .git; then
    if SHORTHASH=$(git rev-parse --short HEAD); then
        echo " -> Git commit hash : ${SHORTHASH}"
    else
        echo " -> Not get git commit hash"
    fi
else
    echo " -> Not found git command or .git directory"
fi
echo "${SHORTHASH}" > default_commit_hash

echo "--- Finished commit hash file ---"

echo "--- Start autotools -------------"

autoupdate \
&& aclocal \
&& autoheader \
&& automake --add-missing \
&& autoconf

echo "--- Finished autotools ----------"

exit 0

#
# Local variables:
# tab-width: 4
# c-basic-offset: 4
# End:
# vim600: expandtab sw=4 ts=4 fdm=marker
# vim<600: expandtab sw=4 ts=4
#
