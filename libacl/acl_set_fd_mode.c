/*
  File: acl_set_fd_mode.c

  Copyright (C) 1999, 2000
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

#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>
#include <acl/libacl.h>
#include "libacl.h"


/*
Same as acl_set_fd, but uses file mode permission bits.
*/

int
acl_set_fd_mode(int fd, acl_t acl)
{
	struct stat st;
	mode_t mode;
	int error;
	
	error = acl_equiv_mode(acl, &mode);
	if (error != 0) {
		if (error > 0)
			errno = ENOTSUP;
		return -1;
	}
	if (fstat(fd, &st) != 0)
		return -1;
	mode |= st.st_mode & ~(S_IRWXU|S_IRWXG|S_IRWXO);
	return fchmod(fd, mode);
}

