#!/bin/bash

uid=$1

# make sure it's off
sysctl tpe.dmz_gid=0

# this is supposed to work
sudo -u "#$uid" /bin/true

if [ $? != 0 ]; then
	echo "/bin/true could not execute"
	ret=1
fi

# now turn it on (assume uid and gid are the same)

sysctl tpe.dmz_gid=$uid

#  no execs should work now

sudo -u "#$uid" /bin/true

if [ $? == 0 ]; then
	echo "/bin/true could execute"
	ret=1
fi

# now turn it back off

sysctl tpe.dmz_gid=0

exit $ret

