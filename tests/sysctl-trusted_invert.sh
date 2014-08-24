#!/bin/bash

uid=$1

# make sure it's off
sysctl tpe.trusted_invert=0
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

sysctl tpe.trusted_invert=1
sysctl tpe.trusted_gid=$uid

# still supposed to fail

sudo -u "#$uid" /bin/tpebintest

if [ $? == 0 ]; then
        echo "/bin/tpebintest owner $uid:$uid could execute"
        ret=1
fi

# but another user shouldn't fail

sudo -u "#1" /bin/tpebintest

if [ $? != 0 ]; then
        echo "/bin/tpebintest uid 1 could NOT execute $uid:$uid file"
        ret=1
fi

# now turn just the gid off

sysctl tpe.trusted_gid=0

# exec should work now

sudo -u "#$uid" /bin/tpebintest

if [ $? != 0 ]; then
	echo "/bin/tpebintest owner $uid:$uid could NOT execute"
	ret=1
fi

# and should work for other users too

sudo -u "#1" /bin/tpebintest

if [ $? != 0 ]; then
        echo "/bin/tpebintest uid 1 could NOT execute $uid:$uid file"
        ret=1
fi

# now turn it back off

sysctl tpe.trusted_invert=0

rm -rf /bin/tpebintest

exit $ret

