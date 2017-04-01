#!/bin/bash

uid=$1

cp -a /bin/true /tmp/tpetest

# this is supposed to fail
sudo -u "#$uid" /tmp/tpetest

if [ $? == 0 ]; then
	echo "$path could execute"
	ret=1
fi

setfattr -n security.tpe -v "soften_exec:soften_mmap" /tmp/tpetest

# this should now work
sudo -u "#$uid" /tmp/tpetest

if [ $? != 0 ]; then
	echo "/tmp/tpetest could NOT execute"
	ret=1
fi

setfattr -x security.tpe /tmp/tpetest

# this is supposed to fail
sudo -u "#$uid" /tmp/tpetest

if [ $? == 0 ]; then
	echo "/tmp/tpetest could execute"
	ret=1
fi

rm -f /tmp/tpetest

exit $ret

