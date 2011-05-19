#!/bin/bash

if [ -d "/usr/src/kernels/$(uname -r)" ]; then
	echo /usr/src/kernels/$(uname -r)
	exit 0
fi

if [ -d "/usr/src/linux-headers-$(uname -r)" ]; then
	echo /usr/src/linux-headers-$(uname -r)
	exit 0
fi

exit 1

