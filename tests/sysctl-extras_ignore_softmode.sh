#!/bin/bash

uid=$1

cd $(dirname $0)

# tun on softmode
sysctl tpe.softmode=1
sysctl tpe.extras.ignore_softmode=0

# this is supposed to fail
./sysctl-ps.sh $uid

if [ $? == 0 ]; then
	echo "ps executed in softmode"
	ret=1
fi

# this too

./sysctl-proc_kallsyms.sh $uid

if [ $? == 0 ]; then
	echo "kallsyms executed in softmode"
	ret=1
fi

# now on ignore
sysctl tpe.extras.ignore_softmode=1

# this should work now
./sysctl-ps.sh $uid

if [ $? != 0 ]; then
	echo "ignore_softmode failed on ps"
	ret=1
fi

# this too

if [ $? != 0 ]; then
	echo "ignore_softmode failed on kallsyms"
	ret=1
fi

# revert
sysctl tpe.softmode=0
sysctl tpe.extras.ignore_softmode=0

exit $ret

