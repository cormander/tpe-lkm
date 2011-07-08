#!/bin/bash

module_name=tpe
v=1.0

RPM_DIR=$(rpm --eval '%{_rpmdir}' 2> /dev/null)
RPM_SOURCES=$(rpm --eval '%{_sourcedir}' 2> /dev/null)

# simple check to make sure we're in the right directoy
git log &> /dev/null

if [ $? -ne 0 ]; then
	echo "Don't appear to be in the git directory!"
	exit 1
fi

# check to make sure those RPM directories exist

if [ ! -d "$RPM_DIR" ] || [ ! -d "$RPM_SOURCES" ]; then
	echo "Please configure your RPM build tree correctly."
	exit 1
fi

BRANCH=$(git branch | grep '\*' | sed 's/\* //')

echo "*** Building RPM using git branch $BRANCH ***"

git archive --format=tar --prefix="$module_name-$v/" $BRANCH | gzip -9 > "$RPM_SOURCES/$module_name-$v.tar.gz"

if [ $? -ne 0 ]; then
	echo "The git-archive command failed"
	exit 1
fi

rpmbuild -ba $module_name.spec

exit $?

