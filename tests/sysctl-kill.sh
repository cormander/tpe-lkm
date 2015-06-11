#!/bin/bash

uid=$1

sudo -u "#$uid" cp /bin/true /tmp/tpe-tests

sysctl tpe.kill=1

sudo -u "#$uid" sh -c '/tmp/tpe-tests'

if [ $? -ne 137 ]; then
	echo "Exit status of sudo subshell wasn't 137"
	ret=1
fi

sysctl tpe.kill=0

rm -f /tmp/tpe-tests

exit $ret

