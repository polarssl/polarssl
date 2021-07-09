#!/bin/sh
###########################################################################
#
#  Copyright 2016-2018, ARM Limited, All Rights Reserved
#  SPDX-License-Identifier: Apache-2.0
#
#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#
###########################################################################

# Check if all commits since a specified commit (not including that commit)
# build and pass some basic checks.

ORIGIN=origin/development
BRANCH=$(git rev-parse --abbrev-ref HEAD)
STATUS=0

usage() {
    echo "Usage: ./$(basename $0) [<origin-branch>]"
    echo "    <origin-branch> The branch to test back to (defaults to $ORIGIN)"
}

if test $# -gt 1; then
    # There are too many arguments. Show help and exit with an error.
    usage
    exit 1
elif test $# -ge 1; then
    # The optional <origin-branch> argument is present. Replace the default
    # value of ORIGIN with the <origin-branch> argument.
    ORIGIN=$1
fi

# Check for detached head
if [ "$BRANCH" = "HEAD" ]; then
    echo "Please make a branch to run this script from. This script moves"
    echo "around in history and needs a way back to the starting point."
    exit 1
fi

# Check for modified files
DIFF=$(git diff)
if [ "$DIFF" != "" ]; then
    echo "You have modified files. Those changes will be lost when running"
    echo "this script, so please commit or stash them first."
    exit 1
fi

# Check for untracked files
MODIFIED=$(git status | grep 'Untracked')
if [ "$MODIFIED" != "" ]; then
    echo "You currently have untracked files. Untracked files may interfere"
    echo "with this script, so please clean those up."
    exit 1
fi

# Come up with the list of commits between the ORIGIN and HEAD, starting from
# the oldest commit.
COMMITS=$(git rev-list --reverse $ORIGIN..HEAD)

# Test each commit with make clean and make.
echo "$COMMITS"
for COMMIT in $COMMITS; do
    echo "----- Testing commit $COMMIT -----"
    make clean && \
    git checkout $COMMIT && \
    ./tests/scripts/recursion.pl library/*.c && \
    ./tests/scripts/check-generated-files.sh && \
    ./tests/scripts/check-doxy-blocks.pl && \
    ./tests/scripts/check-names.sh && \
    ./tests/scripts/check-files.py && \
    ./tests/scripts/doxygen.sh && \
    make && \
    make test && \
    ./programs/test/selftest -x timing

    # Note that `selftest` is run to check that `programs` were built correctly
    # and function, not to test the library. The timing self test is excluded
    # to save time.

    if [ $? -eq 0 ]; then
        echo $COMMIT - passed
    else
        echo $COMMIT - failed
        echo Returning to $BRANCH
        STATUS=1
        break
    fi
done

# Go back to the original starting point, to avoid leaving the user in detached
# HEAD state.
git checkout $BRANCH
exit $STATUS
