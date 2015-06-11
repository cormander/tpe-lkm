#!/bin/bash

source "$(dirname $0)/../scripts/functions"

# test that the sysctl files actually change when you tell them to
# also make sure the expected defaults are set for the rest of the tests

# make sure the default configs are right
check_config 0

# now test the configs changes persist
set_config 1
check_config 1

# now make sure the default config is restored
set_config 0
check_config 0

exit $ret

