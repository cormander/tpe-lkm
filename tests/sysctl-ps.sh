#!/bin/bash

uid=$1

# turn it on
sysctl tpe.extras.ps=1

# this isn't supposed to work
count=$(sudo -u "#$uid" ps auxf 2> /dev/null | grep '^root' | wc -l)

if [ $count != 0 ]; then
	echo "user can see other processes"
	ret=1
fi

# set the gid
sysctl tpe.extras.ps_gid=$uid

# this should work

count=$(sudo -u "#$uid" ps auxf 2> /dev/null | grep '^root' | wc -l)

if [ $count == 0 ]; then
	echo "user can NOT see other processes"
	ret=1
fi

# now turn it off

sysctl tpe.extras.ps=0

# should work now

count=$(sudo -u "#$uid" ps auxf 2> /dev/null | grep '^root' | wc -l)

if [ $count == 0 ]; then
	echo "user can NOT see other processes"
	ret=1
fi

# reset gid as well
sysctl tpe.extras.ps_gid=0

exit $ret

