/*
  File: acl_extended_fd.c

  Copyright (C) 2000
  Andreas Gruenbacher, <a.gruenbacher@computer.org>

  This program is free software; you can redistribute it and/or
  modify it under the terms of the GNU Library General Public
  License as published by the Free Software Foundation; either
  version 2 of the License, or (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Library General Public License for more details.

  You should have received a copy of the GNU Library General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#include <unistd.h>
#include <attr/xattr.h>
#include "libacl.h"

#include "byteorder.h"
#include "acl_ea.h"


int
acl_extended_fd(
	int fd)
{
	int base_size = sizeof(acl_ea_header) + 3 * sizeof(acl_ea_entry);
	int retval;

	retval = fgetxattr(fd, ACL_EA_ACCESS, NULL, 0);
	if (retval < 0 && errno != ENOATTR)
		return -1;
	if (retval > base_size)
		return 1;
	retval = fgetxattr(fd, ACL_EA_DEFAULT, NULL, 0);
	if (retval < 0 && errno != ENOATTR)
		return -1;
	if (retval >= base_size)
		return 1;
	return 0;
}

