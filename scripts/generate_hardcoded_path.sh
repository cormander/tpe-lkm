#!/in/bash
#
# Script to generate a good "starting point" for the tpe hardcoded_path option.
# It gives you your $PATH, and appends the paths of any required libraries of
# the binaries installed in your $PATH.
#

if [ -z "$UID" ] || [ $UID != 0 ]; then

	echo "You need to run this script as root."
	exit 1

fi

if [ -n "$SUDO_USER" ]; then

	echo "Get a root login shell (ie; sudo su - ), then run this."
	exit 1

fi

if [ ! -x /usr/bin/ldd ]; then

	echo "You need the /usr/bin/ldd tool to execute this."
	exit 1

fi

libs=$(for dir in $(echo $PATH | sed 's/:/ /g'); do

	find $dir -maxdepth 1 -type f -perm /111 -exec ldd {} \; 2> /dev/null

done | grep '=>' | awk '{print $3}' | sed 's|\(.*\)/.*|\1|' | grep -v '(0x' | sort -u | tr '\n' ':' | sed 's/:$//')

echo $PATH:$libs

