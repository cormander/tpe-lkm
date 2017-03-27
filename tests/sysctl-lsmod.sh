#!/bin/bash

uid=$1

# turn it on
sysctl tpe.extras.lsmod=1

# this isn't supposed to work
sudo -u "#$uid" head /proc/modules &> /dev/null

if [ $? == 0 ]; then
	echo "could read /proc/modules"
	ret=1
fi

# now turn it off

sysctl tpe.extras.lsmod=0

# should work now

sudo -u "#$uid" head /proc/modules &> /dev/null

if [ $? != 0 ]; then
	echo "could NOT read /proc/modules"
	ret=1
fi

exit $ret

