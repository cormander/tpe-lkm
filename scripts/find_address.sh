#!/bin/bash

lookup_symbol() {

	addr=$(grep " $symbol$" $1 2> /dev/null | awk '{print $1}')

	if [ -n "$addr" ] && [ "$addr" != "00000000" ] && [ "$addr" != "0000000000000000" ]; then
		echo $addr
		exit 0
	fi

}

symbol=$1

if [ -z "$symbol" ]; then
	echo "Please specify the kernel symbol to lookup the address for."
	exit 1
fi

in_env=$(eval echo \$addr_$symbol)

if [ -n "$in_env" ]; then
	echo $in_env
	exit 0
fi

lookup_symbol /proc/kallsyms
lookup_symbol /boot/System.map-$(uname -r)

echo "Unable to find address for symbol '$symbol'"

exit 1

