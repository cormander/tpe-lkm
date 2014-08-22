#!/bin/bash

uid=$1

# turn it on
sysctl tpe.extras.proc_kallsyms=1

# this isn't supposed to work
sudo -u "#$uid" head /proc/kallsyms &> /dev/null

if [ $? == 0 ]; then
	echo "could read /proc/kallsyms"
	ret=1
fi

# now turn it off

sysctl tpe.extras.proc_kallsyms=0

# should work now

sudo -u "#$uid" head /proc/kallsyms &> /dev/null

if [ $? != 0 ]; then
	echo "could NOT read /proc/kallsyms"
	ret=1
fi

exit $ret

