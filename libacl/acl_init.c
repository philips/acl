/*
  File: acl_init.c

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

#include "libacl.h"


acl_obj *
__acl_init_obj(
	void)
{
	acl_obj *acl_obj_p = new_obj_p(acl);
	if (!acl_obj_p)
		return NULL;
	acl_obj_p->aused = 0;
	acl_obj_p->aprev = acl_obj_p->anext = (acl_entry_obj *)acl_obj_p;
	acl_obj_p->acurr = (acl_entry_obj *)acl_obj_p;
	return acl_obj_p;
}


/* 23.4.20 */
acl_t
acl_init(
	int count)
{
	if (count < 0) {
		errno = EINVAL;
		return NULL;
	}
	return int2ext(__acl_init_obj());
}

