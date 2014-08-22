#!/bin/bash

uid=$1

# turn it on then off
sysctl tpe.lock=1
sysctl tpe.lock=0

# now check

sysctl tpe.lock | grep 1 &> /dev/null

ret=$?

exit $ret

