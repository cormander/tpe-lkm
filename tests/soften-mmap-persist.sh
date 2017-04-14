#!/bin/bash

LIB=/usr/lib64/perl5/vendor_perl/auto/Time/HiRes/HiRes.so

uid=$1

ret=0

# this should succeed
sudo -u "#$uid" perl -e 'use Time::HiRes'

if [ $? -ne 0 ]; then
	echo "perl Time::hiRes not installed?"
	exit 1
fi

chown $uid $LIB

# this shoudl fail
sudo -u "#$uid" perl -e 'use Time::HiRes'

if [ $? -eq 0 ]; then
	echo "perl was able to mmap $LIB"
	ret=1
fi

# set soften flag
setfattr -n security.tpe -v "soften_mmap" /usr/bin/perl

# this should succeed
sudo -u "#$uid" perl -e 'use Time::HiRes'

if [ $? -ne 0 ]; then
	echo "perl was unable to persist soften_mmap"
	ret=1
fi

setfattr -x security.tpe /usr/bin/perl

chown root $LIB

# this should succeed
sudo -u "#$uid" perl -e 'use Time::HiRes'

if [ $? -ne 0 ]; then
	echo "perl Time::hiRes stopped working?"
	ret=1
fi

exit $ret

