#!/bin/bash

uid=$1

# make sure it's off
sysctl tpe.trusted_gid=0

cp -a /bin/true /bin/tpebintest

chown $uid:$uid /bin/tpebintest

# this is supposed to fail
sudo -u "#$uid" /bin/tpebintest

if [ $? == 0 ]; then
	echo "/bin/tpebintest owner $uid:$uid could execute"
	ret=1
fi

# now turn it on

sysctl tpe.trusted_gid=$uid

# exec should work now

sudo -u "#$uid" /bin/tpebintest

if [ $? != 0 ]; then
	echo "/bin/tpebintest owner $uid:$uid could NOT execute"
	ret=1
fi

# now try the same thing for a directory

mkdir -p /bin/tpetest/
chown $uid:$uid /bin/tpetest/
cp /bin/true /bin/tpetest/

sudo -u "#$uid" /bin/tpetest/true

if [ $? != 0 ]; then
	echo "/bin/tpetest/true could NOT execute"
	ret=1
fi

# now turn it back off

sysctl tpe.trusted_gid=0

sudo -u "#$uid" /bin/tpetest/true

if [ $? == 0 ]; then
	echo "/bin/tpetest/true could execute"
	ret=1
fi

rm -rf /bin/tpebintest /bin/tpetest/

exit $ret

