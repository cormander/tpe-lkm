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

# run all tests in the "tests" directory, giving a UID as the argument

uid=$(grep sshd /etc/passwd | cut -d : -f 3)

for test in $(find tests/ -type f -executable); do 

	./$test $uid

	if [ $? -eq 0 ]; then
		echo PASS
	else
		echo FAIL
		ret=1
	fi
done

/sbin/rmmod $MODULE

exit $ret

