#!/bin/bash

uid=$1

# this test is moot if upstream
if [ -f /proc/sys/fs/protected_symlinks ]; then
	echo "symlink protection is in the upstream kernel"
        exit -1
fi

# make sure it's off
sysctl tpe.extras.harden_symlink=0

sudo -u "#1" mkdir /tmp/tpetestdir_1/
chmod 755 /tmp/tpetestdir_1/

sudo -u "#$uid" mkdir /tmp/tpetestdir_$uid/
sudo -u "#$uid" ln -s /tmp/tpetestdir_1 /tmp/tpetestdir_$uid/link

# this should work

sudo -u "#$uid" ls /tmp/tpetestdir_$uid/link

if [ $? -ne 0 ]; then
	echo "User $uid could NOT read symlink to uid 1"
	ret=1
fi

# turn it on
sysctl tpe.extras.harden_symlink=1

# this shouldn't work now

sudo -u "#$uid" ls /tmp/tpetestdir_$uid/link &> /dev/null

if [ $? -eq 0 ]; then
	echo "User $uid could read symlink to uid 1"
	ret=1
fi

# turn it back off
sysctl tpe.extras.harden_symlink=0

rm -rf /tmp/tpetestdir_1/ /tmp/tpetestdir_$uid/

exit $ret

