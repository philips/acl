#
# Copyright (c) 2001-2002 Silicon Graphics, Inc.  All Rights Reserved.
#

TOPDIR = ..
include $(TOPDIR)/include/builddefs

TESTS = $(wildcard *.test)
ROOT = $(wildcard root/*.test)
NFS = $(wildcard nfs/*.test)
LSRCFILES = run make-tree $(TESTS) $(ROOT) $(NFS)

include $(BUILDRULES)

default install install-dev install-lib:

PATH := $(abspath ../getfacl/):$(abspath ../setfacl/):$(abspath ../chacl/):$(PATH)

tests: $(TESTS)
root-tests: $(ROOT)
nfs-tests: $(NFS)

$(TESTS):
	@echo "*** $@ ***"; perl run $@

$(NFS):
	@echo "NFS specific tests"; @echo "*** $@ ***"; perl run $@

$(ROOT):
	@echo "Note: Tests must run as root"; @echo "*** $@ ***"; perl run $@

.PHONY: $(TESTS) $(NFS) $(ROOT)
.NOTPARALLEL:


