#!/bin/bash

if [ ! -x /usr/bin/setfattr ]; then
	echo "Could not find /usr/bin/setfattr"
	exit 1
fi

if [ ! -x /usr/bin/getfattr ]; then
	echo "Could not find /usr/bin/getfattr"
	exit 1
fi

for syscall in mmap mprotect exec setuid lsmod ptrace uname; do

	cat /etc/sysconfig/tpe-$syscall-whitelist 2> /dev/null | while read bin; do
		[ ! -f "$bin" ] && continue
		echo "tpe: whitelisting \"$bin\" for \"$syscall\" syscall"

		# first get what soften_X may already exist, minus this one
		flags=$(getfattr -n security.tpe $bin 2> /dev/null | grep security.tpe | cut -d '"' -f 2 | sed "s/soften_$syscall//")

		# ensure no stray colons
		new_flags=$(echo "$flags:soften_$syscall" | sed 's/^://' | sed 's/:$//')

		setfattr -n security.tpe -v "$new_flags" "$bin"
	done

done

