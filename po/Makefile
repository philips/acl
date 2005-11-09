#
# Copyright (c) 2001-2002 Silicon Graphics, Inc.  All Rights Reserved.
#

TOPDIR = ..
include $(TOPDIR)/include/builddefs

LINGUAS = de fr pl
LSRCFILES = $(LINGUAS:%=%.po) $(PKG_NAME).pot

XGETTEXTFILES =	$(TOPDIR)/chacl/chacl.c \
		$(TOPDIR)/setfacl/do_set.c \
		$(TOPDIR)/setfacl/setfacl.c \
		$(TOPDIR)/getfacl/getfacl.c \
		$(TOPDIR)/libacl/acl_error.c \
		$(TOPDIR)/libacl/perm_copy_fd.c \
		$(TOPDIR)/libacl/perm_copy_file.c

default: $(LINGUAS:%=%.mo)

include $(BUILDRULES)

install: default
	$(INSTALL_LINGUAS)

install-dev install-lib:
