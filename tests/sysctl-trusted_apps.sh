#!/bin/bash

uid=$1

cp -a /bin/true /tmp/tpetest

# this is supposed to fail
sudo -u "#$uid" /tmp/tpetest

if [ $? == 0 ]; then
	echo "/tmp/tpetest could execute"
	ret=1
fi

echo /tmp/tpetest > /proc/sys/tpe/trusted_apps

# this should now work
sudo -u "#$uid" /tmp/tpetest

if [ $? != 0 ]; then
	echo "/tmp/tpetest could NOT execute"
	ret=1
fi

echo > /proc/sys/tpe/trusted_apps

# this is supposed to fail
sudo -u "#$uid" /tmp/tpetest

if [ $? == 0 ]; then
	echo "/tmp/tpetest could execute"
	ret=1
fi

rm -f /tmp/tpetest

exit $ret

