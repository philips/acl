/*
  File: acl_print.c

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
#include <acl/libacl.h>
#include "libacl.h"


/*
  Print an ACL to a stream.

  returns
  	the number of characters written, or -1 on error.
*/

int
acl_print(
	FILE *file,
	acl_t acl,
	const char *prefix,
	int options)
{
	acl_obj *acl_obj_p = ext2int(acl, acl);
	acl_entry_obj *entry_obj_p, *mask_obj_p = NULL;
	int n, len, count = 0, written = 0, size = 256;
	char *text_p, *tmp;
	if (!acl_obj_p)
		return -1;
	text_p = (char*)malloc(size);
	if (text_p == NULL)
		return -1;

	if (options & (TEXT_SOME_EFFECTIVE|TEXT_ALL_EFFECTIVE)) {
		/* fetch the ACL_MASK entry */
		FOREACH_ACL_ENTRY(entry_obj_p, acl_obj_p) {
			if (entry_obj_p->etag == ACL_MASK) {
				mask_obj_p = entry_obj_p;
				break;
			}
		}
	}

	count = acl_entries(acl);

	FOREACH_ACL_ENTRY(entry_obj_p, acl_obj_p) {
		len = acl_entry_to_any_str(int2ext(entry_obj_p), text_p, size,
					  int2ext(mask_obj_p), prefix, options);
		if (len < 0)
			goto fail;
		if (size < len) {
			while (size < len)
				size <<= 1;
			tmp = (char*)realloc(text_p, size);
			if (!tmp)
				goto fail;
			text_p = tmp;
			continue;
		}

		if (options & TEXT_NO_ENDOFLINE) {
			if (--count)
				n = fprintf(file, "%s,", text_p);
			else
				n = fprintf(file, "%s", text_p);
		}
		else
			n = fprintf(file, "%s\n", text_p);
		if (n < 0)
			goto fail;
		written += n;
	}

	free(text_p);
	return written;

fail:
	free(text_p);
	return -1;
}

