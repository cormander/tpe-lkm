#!/bin/bash

uid=$1

cp -a /bin/true /tmp/tpetest

# this is supposed to fail
sudo -u "#$uid" /tmp/tpetest

if [ $? == 0 ]; then
	echo "$path could execute"
	ret=1
fi

setfattr -n security.tpe -v "soften_exec:soften_mmap" /tmp/tpetest

# this should now work
sudo -u "#$uid" /tmp/tpetest

if [ $? != 0 ]; then
	echo "/tmp/tpetest could NOT execute"
	ret=1
fi

echo 0 > /proc/sys/tpe/xattr_soften

# this should fail
sudo -u "#$uid" /tmp/tpetest

if [ $? == 0 ]; then
	echo "/tmp/tpetest could execute"
	ret=1
fi

setfattr -x security.tpe /tmp/tpetest

echo 1 > /proc/sys/tpe/xattr_soften

# this is supposed to fail
sudo -u "#$uid" /tmp/tpetest

if [ $? == 0 ]; then
	echo "/tmp/tpetest could execute"
	ret=1
fi

#
# multi-soften tests
#

sysctl tpe.extras.lsmod=1
sysctl tpe.extras.proc_kallsyms=1

# this should fail
sudo -u "#$uid" ./tests/setfattr-multi-test

if [ $? -eq 0 ]; then
	echo "setfattr-multi-test could execute"
	ret=1
fi

setfattr -n security.tpe -v "soften_exec:soften_mmap:soften_lsmod:soften_kallsyms" tests/setfattr-multi-test

# this should pass now
sudo -u "#$uid" ./tests/setfattr-multi-test

if [ $? -ne 0 ]; then
	echo "setfattr-multi-test not could execute"
	ret=1
fi

# cleanup
rm -f tests/setfattr-multi-test
sysctl tpe.extras.lsmod=0
sysctl tpe.extras.proc_kallsyms=0

rm -f /tmp/tpetest

exit $ret

