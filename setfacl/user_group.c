/*
  File: user_group.c
  (Linux Access Control List Management)

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

#include <stdlib.h>
#include "user_group.h"


const char *
user_name(
	uid_t uid)
{
	struct passwd *passwd = getpwuid(uid);

	if (passwd != NULL)
		return passwd->pw_name;
	else
		return NULL;
}


const char *
group_name(
	gid_t gid)
{
	struct group *group = getgrgid(gid);

	if (group != NULL)
		return group->gr_name;
	else
		return NULL;
}

