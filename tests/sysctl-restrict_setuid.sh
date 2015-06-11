#!/bin/bash

uid=$1

kversion=$(uname -r | cut -d - -f 1)
kmajor=$(echo $kversion | cut -d . -f 1)
kminor=$(echo $kversion | cut -d . -f 2)
krel=$(echo $kversion | cut -d . -f 3)

# no harden support in EL5
if [ $kmajor -lt 3 ] && [ $krel -lt 19 ]; then
	echo "setuid protection not supported in this kernel"
	exit -1
fi

# make sure it's off
sysctl tpe.extras.restrict_setuid=0

cp $(dirname $0)/../scripts/setuid-test /bin/tpebintest
chown root:root /bin/tpebintest
chmod 4755 /bin/tpebintest

# exec should work

sudo -u "#$uid" /bin/tpebintest

if [ $? != 0 ]; then
	echo "/bin/tpebintest could NOT setuid"
	ret=1
fi

# now turn it on

sysctl tpe.extras.restrict_setuid=1

# exec should'nt work now

sudo -u "#$uid" /bin/tpebintest

if [ $? == 0 ]; then
	echo "/bin/tpebintest could setuid"
	ret=1
fi

# now turn it back off

sysctl tpe.extras.restrict_setuid=0

rm -rf /bin/tpebintest

exit $ret

