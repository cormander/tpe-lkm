#!/bin/bash

uid=$1

# make sure it's off
sysctl tpe.trusted_gid=$uid
sysctl tpe.strict=0

cp -a /bin/true /bin/tpebintest

chown 1:1 /bin/tpebintest

# this is supposed to pass
sudo -u "#$uid" /bin/tpebintest

if [ $? != 0 ]; then
	echo "/bin/tpebintest owner 1:1 could NOT execute"
	ret=1
fi

# now turn it on

sysctl tpe.strict=1

# exec should fail

sudo -u "#$uid" /bin/tpebintest

if [ $? == 0 ]; then
	echo "/bin/tpebintest owner 1:1 could execute"
	ret=1
fi

sysctl tpe.trusted_gid=0

rm -rf /bin/tpebintest

exit $ret

