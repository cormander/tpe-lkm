#!/bin/bash

# test that the sysctl files actually change when you tell them to
# also make sure the expected defaults are set for the rest of the tests

# dmz_gid and kill aren't listed, they're dangerous to turn on in a test
# like this, so just explicitly turn them off
sysctl tpe.dmz_gid=0
sysctl tpe.kill=0

sysctls_on="strict check_file group_writable"
sysctls_off="softmode trusted_gid trusted_invert admin_gid paranoid extras.lsmod extras.proc_kallsyms extras.ps extras.ps_gid extras.harden_symlink extras.harden_hardlinks extras.restrict_setuid"

function set_config() {

	invert=$1

	if [ $invert -eq 0 ]; then
		off=0
		on=1
	else
		off=1
		on=0
	fi

	for i in $sysctls_on; do
		sysctl tpe.$i=$on
	done

	for i in $sysctls_off; do
		sysctl tpe.$i=$off
	done

}

function check_config() {

	invert=$1

        if [ $invert -eq 0 ]; then
                off=0
                on=1
        else
                off=1
                on=0
        fi

	# now check that they are all configured as expected

	for i in $sysctls_on; do
		sysctl tpe.$i | grep " = $on"

		if [ $? -ne 0 ]; then
			echo "tpe.$i wasn't set as expected, invert=$invert"
			ret=1
		fi
	done

	for i in $sysctls_off; do
		sysctl tpe.$i | grep " = $off"

		if [ $? -ne 0 ]; then
			ret=1
		fi
	done

}

set_config 1
check_config 1
set_config 0
check_config 0

exit $ret

