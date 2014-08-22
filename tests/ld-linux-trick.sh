#!/bin/bash

uid=$1

if [ -d /lib64 ]; then
	ldso=$(ls /lib64/ld*so | head -n1)
else
	ldso=$(ls /lib/ld*so | head -n1)
fi

sudo -u "#$uid" cp /bin/true /tmp/tpe-tests
sudo -u "#$uid" $ldso /tmp/tpe-tests

ret=$?

rm -f /tmp/tpe-tests

if [ $ret == 0 ]; then
	exit 1;
else
	exit 0;
fi

