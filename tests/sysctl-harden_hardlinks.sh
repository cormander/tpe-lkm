#!/bin/bash

uid=$1

# this test is moot if upstream
if [ -f /proc/sys/fs/protected_hardlinks ]; then
	echo "hardlink protection is in the upstream kernel"
	exit -1
fi

kversion=$(uname -r | cut -d - -f 1)
kmajor=$(echo $kversion | cut -d . -f 1)
kminor=$(echo $kversion | cut -d . -f 2)
krel=$(echo $kversion | cut -d . -f 3)

# no harden support in EL5
if [ $kmajor -lt 3 ] && [ $krel -lt 19 ]; then
	echo "hardlink protection not supported in this kernel"
	exit -1
fi

# make sure it's off
sysctl tpe.extras.harden_hardlinks=0

sudo -u "#1" mkdir /tmp/tpetestdir_1/
sudo -u "#1" touch /tmp/tpetestdir_1/test
chmod 755 /tmp/tpetestdir_1/
chmod 644 /tmp/tpetestdir_1/test

sudo -u "#$uid" mkdir /tmp/tpetestdir_$uid/
sudo -u "#$uid" ln /tmp/tpetestdir_1/test /tmp/tpetestdir_$uid/link

if [ $? -ne 0 ]; then
        echo "User $uid could NOT create a hardlink to uid 1"
        ret=1
fi

rm -f /tmp/tpetestdir_$uid/link

# turn it on
sysctl tpe.extras.harden_hardlinks=1

# this shouldn't work now

sudo -u "#$uid" ln /tmp/tpetestdir_1/test /tmp/tpetestdir_$uid/link

if [ $? -eq 0 ]; then
	echo "User $uid could create a hardlink to uid 1"
	ret=1
fi

# turn it back off
sysctl tpe.extras.harden_hardlinks=0

rm -rf /tmp/tpetestdir_1/ /tmp/tpetestdir_$uid/

exit $ret

