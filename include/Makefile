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

SYSDIR = sys
LIBDIR = acl

HFILES = acl.h libacl.h acl_ea.h
LSRCFILES = builddefs.in buildrules config.h.in
LDIRT = $(SYSDIR) $(LIBDIR)

default:
	rm -f $(SYSDIR) $(LIBDIR)
	$(LN_S) . $(SYSDIR)
	$(LN_S) . $(LIBDIR)

include $(BUILDRULES)

install-dev: default
	$(INSTALL) -m 755 -d $(PKG_INC_DIR)
	$(INSTALL) -m 755 -d $(PKG_INC_DIR)/$(SYSDIR)
	$(INSTALL) -m 644 acl.h $(PKG_INC_DIR)/$(SYSDIR)/acl.h
	$(INSTALL) -m 755 -d $(PKG_INC_DIR)/$(LIBDIR)
	$(INSTALL) -m 644 libacl.h $(PKG_INC_DIR)/$(LIBDIR)/libacl.h
install install-lib:
