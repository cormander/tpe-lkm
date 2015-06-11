#!/bin/bash

uid=$1

# make sure it's on
sysctl tpe.group_writable=1

cp -a /bin/true /bin/tpebintest

chmod 775 /bin/tpebintest

# this is supposed to fail
sudo -u "#$uid" /bin/tpebintest

if [ $? == 0 ]; then
	echo "/bin/tpebintest perms 775 could execute"
	ret=1
fi

# now turn it off

sysctl tpe.group_writable=0

# exec should work now

sudo -u "#$uid" /bin/tpebintest

if [ $? != 0 ]; then
	echo "/bin/tpebintest perms 775 could NOT execute"
	ret=1
fi

# now try the same thing for a directory

mkdir -p /bin/tpetest/
chmod 775 /bin/tpetest/
cp /bin/true /bin/tpetest/

# it's still off - should work

sudo -u "#$uid" /bin/tpetest/true

if [ $? != 0 ]; then
	echo "/bin/tpetest/true could NOT execute"
	ret=1
fi

# now turn it back on

sysctl tpe.group_writable=1

sudo -u "#$uid" /bin/tpetest/true

if [ $? == 0 ]; then
	echo "/bin/tpetest/true could execute"
	ret=1
fi

rm -rf /bin/tpebintest /bin/tpetest/

exit $ret

