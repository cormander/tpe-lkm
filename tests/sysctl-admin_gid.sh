#!/bin/bash

uid=$1

# make sure it's off
sysctl tpe.admin_gid=0

cp -a /bin/true /bin/tpebintest

chown 1:1 /bin/tpebintest

# this is supposed to fail
sudo -u "#$uid" /bin/tpebintest

if [ $? == 0 ]; then
	echo "/bin/tpebintest owner 1:1 could execute"
	ret=1
fi

# now turn it on

sysctl tpe.admin_gid=1

# exec should work now

sudo -u "#$uid" /bin/tpebintest

if [ $? != 0 ]; then
	echo "/bin/tpebintest owner 1:1 could NOT execute"
	ret=1
fi

# now try the same thing for a directory

mkdir -p /bin/tpetest/
chown 1:1 /bin/tpetest/
cp /bin/true /bin/tpetest/

sudo -u "#$uid" /bin/tpetest/true

if [ $? != 0 ]; then
	echo "/bin/tpetest/true could NOT execute"
	ret=1
fi

# now turn it back off

sysctl tpe.admin_gid=0

sudo -u "#$uid" /bin/tpetest/true

if [ $? == 0 ]; then
	echo "/bin/tpetest/true could execute"
	ret=1
fi

rm -rf /bin/tpebintest /bin/tpetest/

exit $ret

