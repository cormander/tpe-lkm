#!/bin/bash

uid=$1

# build what is probably isn't a complete path of this system, but good enough for a test
h_path=$PATH:/usr/lib64:$(for i in $(ps aux | awk '{print $11}' | grep '^/' | sort -u); do ldd $i 2> /dev/null; done | sort -u | awk '{print $3}' | sort -u | grep -v 0x | sed 's|/[^/]*$||' | sort -u | grep '^/' | tr '\n' ':' | sed 's/:$//')

# some sanity checks on length
len=$(echo $h_path | wc -m)

if [ $len -lt 10 ] || [ $len -gt 1024 ]; then
	# exit here, not safe to continue
	echo "test \$h_path is too long."
	exit 1
fi

echo PATH="$h_path"

mkdir /notinthepath/

cp /bin/true /notinthepath/

# this should work
sudo -u "#$uid" /notinthepath/true

if [ $? != 0 ]; then
	echo "Could NOT execute /notinthepath/true"
	ret=1
fi

# set the hardcoded_path
echo "$h_path" > /proc/sys/tpe/hardcoded_path

# this should fail
sudo -u "#$uid" /notinthepath/true

if [ $? == 0 ]; then
        echo "Could execute /notinthepath/true"
        ret=1
fi

# this should work

sudo -u "#$uid" /bin/true

if [ $? != 0 ]; then
	echo "Could NOT execute /bin/true"
	ret=1
fi

echo "" > /proc/sys/tpe/hardcoded_path

# this should work
sudo -u "#$uid" /notinthepath/true

if [ $? != 0 ]; then
	echo "Could NOT execute /notinthepath/true"
	ret=1
fi

rm -rf /notinthepath

exit $ret

