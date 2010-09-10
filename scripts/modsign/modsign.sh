#!/bin/bash
###############################################################################
#
# Copyright (C) 2004 Red Hat, Inc. All Rights Reserved.
# Written by David Howells (dhowells@redhat.com)
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version
# 2 of the License, or (at your option) any later version.
#
###############################################################################

verbose=

if [ $# -gt 1 -a "x$1" = "x-v" ]
    then
    verbose=-v
    shift
fi

if [ $# = 0 ]
    then
	echo
	echo "usage: $0 [-v] <module_to_sign> [<key_name>]"
	echo
	exit 1
fi

module=$1

if [ -z "$KEYFLAGS" ]
    then
    KEYFLAGS="--no-default-keyring --secret-keyring ../kernel.sec --keyring ../kernel.pub"
fi

if [ $# -eq 2 ]
    then
    KEYFLAGS="$KEYFLAGS --default-key $2"
fi

# strip out only the sections that we care about
scripts/modsign/mod-extract $verbose $module $module.out || exit $?

# sign the sections
gpg --no-greeting $KEYFLAGS -b $module.out || exit $?

# check the signature
#gpg --verify rxrpc.ko.out.sig rxrpc.ko.out

## sha1 the sections
#sha1sum $module.out | awk "{print \$1}" > $module.sha1

# add the encrypted data to the module
objcopy --add-section .module_sig=$module.out.sig $module $module.signed || exit $?
objcopy --set-section-flags .module_sig=alloc $module.signed || exit $?
rm -f $module.out*
