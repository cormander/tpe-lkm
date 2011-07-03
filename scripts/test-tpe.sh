#!/bin/bash

MODULE=$1

# a set of simple, not-well-thought-out tests I occasionally run to make
# sure everything still works, or at least appears to work :P

if [ -z "$UID" ] || [ $UID != 0 ]; then

	echo "Tests must be ran as the root user."
	exit 1

fi

if [ ! -f $MODULE.ko ]; then

	echo "Couldn't find $MODULE"
	exit 1

fi

/sbin/rmmod $MODULE 2> /dev/null
/sbin/insmod $MODULE.ko

if [ $? -ne 0 ]; then

	echo "Unable to insert $MODULE module"
	echo FAIL
	exit 1

fi

# you use have an sshd user, and it shouldn't have a shell. I'm not
# going to bother to check

sudo -u sshd cp /bin/true /tmp/true
sudo -u sshd /tmp/true 2> /dev/null

if [ $? -ne 0 ]; then
	echo PASS
	ret=0;
else
	echo FAIL
	ret=1
fi

sudo -u sshd $(ls /lib{64,}/ld-2*.so | head -n1) /tmp/true 2> /dev/null

if [ $? -ne 0 ]; then
	echo PASS
else
	echo FAIL
	ret=1
fi

rm -f /tmp/true

/sbin/rmmod $MODULE

exit $ret

