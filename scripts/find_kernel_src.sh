#!/bin/bash

# look in the most common places for the kernel headers.
# because it's nice to just type "make" and let the scripts do all the work

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

cat <<EOF >&2

ERROR:
	Unable to find kernel header files to build this module.
	Is the kernel-devel package matching your kernel installed?
	Your kernel version string is: $kver

EOF

exit 1

