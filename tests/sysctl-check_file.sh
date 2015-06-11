#!/bin/bash

uid=$1

# make sure it's on
sysctl tpe.check_file=1

cp -a /bin/true /bin/tpebintest

chmod 777 /bin/tpebintest

# this is supposed to fail
sudo -u "#$uid" /bin/tpebintest

if [ $? == 0 ]; then
	ret=1
fi

# now turn it off

sysctl tpe.check_file=0

# exec should work now

sudo -u "#$uid" /bin/tpebintest

if [ $? != 0 ]; then
	ret=1
fi

rm -f /bin/tpebintest

sysctl tpe.check_file=1

exit $ret

