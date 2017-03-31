#!/bin/bash

if [ ! -x /usr/bin/setfattr ]; then
	echo "Could not find /usr/bin/setfattr"
	exit 1
fi

WHITELIST_MMAP="/usr/bin/gnome-session /usr/bin/gnome-shell /usr/lib64/thunderbird/thunderbird"

for bin in $WHITELIST_MMAP; do
	[ ! -f $bin ] && continue
	setfattr -n security.tpe -v "soften_mmap" $bin
done

