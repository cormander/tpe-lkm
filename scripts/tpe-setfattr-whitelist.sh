#!/bin/bash

if [ ! -x /usr/bin/setfattr ]; then
	echo "Could not find /usr/bin/setfattr"
	exit 1
fi

for syscall in mmap mprotect exec setuid lsmod ptrace uname; do

	cat /etc/sysconfig/tpe-$syscall-whitelist 2> /dev/null | while read bin; do
		[ ! -f "$bin" ] && continue
		echo "tpe: whitelisting \"$bin\" for \"$syscall\" syscall"
		setfattr -n security.tpe -v "soften_$syscall" "$bin"
	done

done

