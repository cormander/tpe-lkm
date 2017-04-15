#!/bin/bash

uid=$1

ret=0

ldso=$(ls /lib64/ld*linux*so* | head -n1)
sudo -u "#$uid" cp /bin/true /tmp/tpe-tests

# this should fail
sudo -u "#$uid" perl -e "\$ret = system('$ldso /tmp/tpe-tests'); print \"\$ret\n\"; exit (\$ret >> 8)"

if [ $? -eq 0 ]; then
	echo "perl could mmap subshell"
	ret=1
fi

# set soften flag
setfattr -n security.tpe -v "soften_mmap" /usr/bin/perl

# this should succeed
sudo -u "#$uid" perl -e "\$ret = system('$ldso /tmp/tpe-tests'); print \"\$ret\n\"; exit (\$ret >> 8)"

if [ $? -ne 0 ]; then
	echo "perl could not mmap subshell"
	ret=1
fi

setfattr -x security.tpe /usr/bin/perl

rm -f /tmp/tpe-tests

exit $ret

