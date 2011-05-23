#!/bin/bash

kver=$(uname -r)

for dir in \
	"/usr/src/kernels/$kver-$(arch)" \
	"/usr/src/kernels/$kver)" \
	"/usr/src/linux-headers-$kver" \
	"/lib/modules/$kver/build"; do
	if [ -d $dir ]; then
		echo $dir
		exit 0
	fi
done

exit 1

