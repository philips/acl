/*
  File: acl_to_any_text.c

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
#include <string.h>
#include <acl/libacl.h>
#include "libacl.h"

char *
acl_to_any_text(acl_t acl, ssize_t *len_p, const char *prefix, char separator,
	const char *suffix, int options)
{
	acl_obj *acl_obj_p = ext2int(acl, acl);
	ssize_t size, len = 0, entry_len = 0,
		suffix_len = suffix ? strlen(suffix) : 0;
	string_obj *string_obj_p, *tmp;
	acl_entry_obj *entry_obj_p, *mask_obj_p = NULL;
	if (!acl_obj_p)
		return NULL;
	size = acl->a_used * 15 + 1;
	string_obj_p = new_var_obj_p(string, size);
	if (!string_obj_p)
		return NULL;

	if (options & (TEXT_SOME_EFFECTIVE|TEXT_ALL_EFFECTIVE)) {
		/* fetch the ACL_MASK entry */
		FOREACH_ACL_ENTRY(entry_obj_p, acl_obj_p) {
			if (entry_obj_p->etag == ACL_MASK) {
				mask_obj_p = entry_obj_p;
				break;
			}
		}
	}

	FOREACH_ACL_ENTRY(entry_obj_p, acl_obj_p) {
		if (len + entry_len + 1 > size) {
			while (len + entry_len + 1 > size)
				size <<= 1;
			tmp = realloc_var_obj_p(string, string_obj_p, size);
			if (tmp == NULL)
				goto fail;
			string_obj_p = tmp;
		}

		entry_len = acl_entry_to_any_str(int2ext(entry_obj_p),
		                                 string_obj_p->sstr + len,
						 size-len,
						 int2ext(mask_obj_p),
						 prefix,
						 options);
		if (entry_len < 0)
			goto fail;
		if (len + entry_len + suffix_len + 1 > size)
			continue;
		len += entry_len;
		string_obj_p->sstr[len] = separator;
		len++;
	}
	if (len)
		len--;
	if (len && suffix) {
		strcpy(string_obj_p->sstr + len, suffix);
		len += suffix_len;
	} else
		string_obj_p->sstr[len] = '\0';

	if (len_p)
		*len_p = len;
	return (char *)int2ext(string_obj_p);

fail:
	free_obj_p(string_obj_p);
	return NULL;
}

