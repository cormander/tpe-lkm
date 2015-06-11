#!/bin/bash

uid=$1

# trun it on
sysctl tpe.softmode=1

cp -a /bin/true /bin/tpebintest

chmod 777 /bin/tpebintest

# this is supposed to pass
sudo -u "#$uid" /bin/tpebintest

if [ $? != 0 ]; then
	echo "/bin/tpebintest perms 777 could NOT execute"
	ret=1
fi

# now turn it off

sysctl tpe.softmode=0

# exec shouldn't work now

sudo -u "#$uid" /bin/tpebintest

if [ $? == 0 ]; then
	echo "/bin/tpebintest perms 777 could execute"
	ret=1
fi

rm -rf /bin/tpebintest

exit $ret

