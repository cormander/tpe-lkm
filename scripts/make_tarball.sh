#!/bin/bash

# simple check to make sure we're in the right directory....
git log &> /dev/null

if [ $? -ne 0 ]; then
	echo "Don't appear to be in the git directory."
	exit 1
fi

RPM_SOURCES=$(rpm --eval '%{_sourcedir}' 2> /dev/null)

if [ ! -d "$RPM_SOURCES" ]; then
	echo "I want to put the tarball into the RPM_SOURCES sources directory, but \`rpm --eval '%{_sourcedir}'\` didn't return a directory that exists."
	exit 1
fi

git_changes_work=$(git diff 2> /dev/null | wc -l)
git_changes_index=$(git diff --cached 2> /dev/null | wc -l)

# add the two wc together
git_changes=$(expr "$git_changes_work" "+" "$git_changes_index")

if [ $git_changes -gt 0 ]; then

	echo "You have differences between your working tree and/or index from the current HEAD."
	echo "Please commit them before building the tarball."

	exit 1

fi

version=$(grep VERSION tpe_module.c | cut -d '"' -f 2)

make clean &> /dev/null

BRANCH=$(git branch | grep '^\*' | awk '{print $2}')

echo "Making tarball from the \"$BRANCH\" branch => $RPM_SOURCES/tpe-lkm-$version.tar.gz"

git archive --format=tar --prefix="tpe-lkm-$version/" $BRANCH | gzip -9 > "$RPM_SOURCES/tpe-lkm-$version.tar.gz"

