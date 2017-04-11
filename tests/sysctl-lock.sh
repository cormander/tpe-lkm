#!/bin/bash

uid=$1
ret=0

# turn it on then off
sysctl tpe.lock=1
sysctl tpe.lock=0

# now check

sysctl tpe.lock | grep 1 &> /dev/null

if [ $? -ne 0 ]; then
	echo "tpe lock not working!"
	ret=1
fi

# trun off ftrace_enabled
sysctl kernel.ftrace_enabled=0

# and check

sysctl kernel.ftrace_enabled | grep 1 &> /dev/null

if [ $? -ne 0 ]; then
	echo "ftrace lock not working!"
	ret=1
fi

# in-case the above failed
sysctl kernel.ftrace_enabled=1

exit $ret

