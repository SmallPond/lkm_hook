#!/bin/bash

KVER=$(cut -f 3 -d ' ' /proc/version | cut -f 1 -d '-')

python -c "print ((`echo ${KVER} | cut -f 1 -d '.'` << 16) + (`echo ${KVER} | cut -f 2 -d '.'` << 8) + `echo ${KVER} | cut -f 3 -d '.'`)"
