#
# Copyright (c) 2001 Silicon Graphics, Inc.  All Rights Reserved.
# 
# This program is free software; you can redistribute it and/or modify it
# under the terms of version 2 of the GNU General Public License as
# published by the Free Software Foundation.
# 
# This program is distributed in the hope that it would be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# 
# Further, this software is distributed without any warranty that it is
# free of the rightful claim of any third person regarding infringement
# or the like.  Any license provided herein, whether implied or
# otherwise, applies only to this software file.  Patent licenses, if
# any, provided herein do not apply to combinations of this program with
# other software, or any other product whatsoever.
# 
# You should have received a copy of the GNU General Public License along
# with this program; if not, write the Free Software Foundation, Inc., 59
# Temple Place - Suite 330, Boston MA 02111-1307, USA.
# 
# Contact information: Silicon Graphics, Inc., 1600 Amphitheatre Pkwy,
# Mountain View, CA  94043, or:
# 
# http://www.sgi.com 
# 
# For further information regarding this notice, see: 
# 
# http://oss.sgi.com/projects/GenInfo/SGIGPLNoticeExplan/
#

TOPDIR = ..
include $(TOPDIR)/include/builddefs

GETFACL = getfacl
SETFACL = setfacl

CFILES  = do_set.c parse.c sequence.c user_group.c walk_tree.c \
	  $(GETFACL).c $(SETFACL).c

GETFOBJ = $(GETFACL).o user_group.o walk_tree.o
SETFOBJ = $(SETFACL).o do_set.o parse.o sequence.o user_group.o walk_tree.o

LLDLIBS = $(LIBACL)
LTDEPENDENCIES = $(LIBACL)

LDIRT   = $(GETFACL) $(SETFACL)
LCFLAGS = -DPACKAGE=\"$(PKG_NAME)\" -DSTR_VERSION=\"$(PKG_VERSION)\" \
	  -DLOCALEDIR=NULL

default: $(GETFACL) $(SETFACL)

include $(BUILDRULES)

$(GETFACL): $(GETFOBJ)
	$(LTLINK) -o $@ $(CFLAGS) $(GETFOBJ) $(LDFLAGS) $(LDLIBS)
$(SETFACL): $(SETFOBJ)
	$(LTLINK) -o $@ $(CFLAGS) $(SETFOBJ) $(LDFLAGS) $(LDLIBS)

install: default
	$(INSTALL) -m 755 -d $(PKG_BIN_DIR)
	$(LTINSTALL) -m 755 $(GETFACL) $(PKG_BIN_DIR)
	$(LTINSTALL) -m 755 $(SETFACL) $(PKG_BIN_DIR)
install-dev:
