#!/bin/bash

uid=$1

# build what is probably a complete path of this system
h_path=$PATH:$(find /{,usr}/{,s}bin/ -type f -executable -exec ldd {} \; 2> /dev/null | sort -u | awk '{print $3}' | sort -u | grep -v 0x | sed 's|/[^/]*$||' | sort -u | grep '^/' | tr '\n' ':' | sed 's/:$//')

# some sanity checks on length
len=$(echo $h_path | wc -m)

if [ $len -lt 10 ] || [ $len -gt 1024 ]; then
	# exit here, not safe to continue
	exit 1
fi

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

echo "" > /proc/sys/tpe/hardcoded_path

# this should work
sudo -u "#$uid" /notinthepath/true

if [ $? != 0 ]; then
	echo "Could NOT execute /notinthepath/true"
	ret=1
fi

rm -rf /notinthepath

exit $ret

