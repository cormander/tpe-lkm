#!/bin/bash

if [ ! -x /usr/bin/setfattr ]; then
	echo "Could not find /usr/bin/setfattr"
	exit 1
fi

cat /etc/sysconfig/tpe-whitelist | while read bin; do
	[ ! -f "$bin" ] && continue
	setfattr -n security.tpe -v "soften_mmap" "$bin"
done

