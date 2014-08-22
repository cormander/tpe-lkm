#!/bin/bash

source /etc/profile

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

echo -e "\\033[1;31mLoading kernel module $MODULE\\033[0;39m"

/sbin/rmmod $MODULE 2> /dev/null
/sbin/insmod $MODULE.ko

if [ $? -ne 0 ]; then
	echo "Unable to insert $MODULE module"
	exit 1
fi

# run all tests in the "tests" directory, giving a UID as the argument

uid=$(grep sshd /etc/passwd | cut -d : -f 3)

rm -f tests.out

for test in $(find tests/ -type f -perm /o+x | grep -v sysctl-lock) tests/sysctl-lock.sh; do 

	echo -ne "\\033[1;33mExecuting test: \\033[0;39m$test"
	echo "Executing test: $test" >> tests.out

	./$test $uid >> tests.out 2>&1

	ret=$?

	if [ $ret -eq 0 ]; then
		echo -ne "\\033[60G[\\033[1;32mPASS\\033[0;39m]\n"
		echo "[PASS]" >> tests.out
	elif [ $ret -eq 255 ]; then
		echo -ne "\\033[60G[\\033[1;33mSKIP\\033[0;39m]\n"
		echo "[SKIP]" >> tests.out
	else
		echo -ne "\\033[60G[\\033[1;31mFAIL\\033[0;39m]\n"
		echo "[FAIL]" >> tests.out
		allret=1
	fi
done

echo -e "\\033[1;31mUnloading kernel module $MODULE\\033[0;39m"

/sbin/rmmod $MODULE

echo -e "\\033[1;33mTest output saved to: \\033[0;39mtests.out"

exit $allret

