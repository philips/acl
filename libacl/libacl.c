/*
  Original version;
  Copyright (C) 1999, 2000, 2001
  Andreas Gruenbacher <a.gruenbacher@computer.org>

  SGI modifications to original;
  Copyright (C) 2001 Silicon Graphics, Inc.

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
#include <stdlib.h>
#include <sys/stat.h>
#include <acl/libacl.h>

#define setoserror(x)		(errno = (x))
#define FAIL_CHECK(error) 	({ return error; })

/*
 * Check if an ACL is valid.
 * The id fields of ACL entries that don't use them are ignored.
 * 
 * ``last'' contains the index of the last valid entry found after
 * acl_check returns.
 *
 * Returns 0 on success, -1 on error, or an ACL_*_ERROR value for
 * invalid ACLs.
 */
int
acl_check (acl_t acl, int *last)
{
	int i;
	id_t qual = 0;
	int state = ACL_USER_OBJ;
	int needs_mask = 0;
	acl_entry_t ace;

	if (!acl) {
		setoserror (EINVAL);
		return -1;
	}
	acl_entry_sort(acl);
	if (last)
		*last = 0;

	for (i = 0; i < acl->acl_cnt; i++) {
		ace = &acl->acl_entry[i];

		/* Check permissions for ~(ACL_READ|ACL_WRITE|ACL_EXECUTE) */
		switch (ace->ae_tag) {
		case ACL_USER_OBJ:
			if (state == ACL_USER_OBJ) {
				qual = 0;
				state = ACL_USER;
				break;
			}
			FAIL_CHECK (ACL_MULTI_ERROR);

		case ACL_USER:
			if (state != ACL_USER)
				FAIL_CHECK (ACL_MISS_ERROR);
			if (ace->ae_id < qual || ace->ae_id == ACL_UNDEFINED_ID)
				FAIL_CHECK (ACL_DUPLICATE_ERROR);
			qual = ace->ae_id + 1;
			needs_mask = 1;
			break;

		case ACL_GROUP_OBJ:
			if (state == ACL_USER) {
				qual = 0;
				state = ACL_GROUP;
				break;
			}
			if (state >= ACL_GROUP)
				FAIL_CHECK(ACL_MULTI_ERROR);
			FAIL_CHECK(ACL_MISS_ERROR);

		case ACL_GROUP:
			if (state != ACL_GROUP)
				FAIL_CHECK(ACL_MISS_ERROR);
			if (ace->ae_id < qual || ace->ae_id == ACL_UNDEFINED_ID)
				FAIL_CHECK(ACL_DUPLICATE_ERROR);
			qual = ace->ae_id + 1;
			needs_mask = 1;
			break;

		case ACL_MASK:
			if (state == ACL_GROUP) {
				state = ACL_OTHER;
				break;
			}
			if (state >= ACL_OTHER)
				FAIL_CHECK (ACL_MULTI_ERROR);
			FAIL_CHECK (ACL_MISS_ERROR);

		case ACL_OTHER:
			if ((state == ACL_OTHER) ||
			    (state == ACL_GROUP && !needs_mask)) {
				state = 0;
				break;
			}
			FAIL_CHECK (ACL_MISS_ERROR);

		default:
			FAIL_CHECK (ACL_ENTRY_ERROR);
		}
		if (last)
			(*last)++;
	}

	if (state != 0)
		FAIL_CHECK (ACL_MISS_ERROR);
	return 0;
}

int
acl_cmp (acl_t b1, acl_t b2)
{
	int i;
	acl_entry_t ace1, ace2;

	if (!b1 || !b2)
		return -1;

	if (b1->acl_cnt != b2->acl_cnt)
		return 1;

	for (i = 0; i < b1->acl_cnt; i++) {
		ace1 = &b1->acl_entry[i];
		ace2 = &b2->acl_entry[i];
		if (ace1->ae_tag != ace2->ae_tag)
			return 1;
		if (ace1->ae_perm != ace2->ae_perm)
			return 1;
		switch (ace1->ae_tag) {
		case ACL_USER:
		case ACL_GROUP:
			if (ace1->ae_id != ace2->ae_id)
				return 1;
		}
	}
	return 0;
}

/*
 * Create an ACL from a file mode, return the new ACL.
 */
acl_t
acl_from_mode (mode_t mode)
{
	acl_t acl;

	if ((acl = acl_init (3)) == NULL)
		return NULL;

	acl->acl_entry[0].ae_tag  = ACL_USER_OBJ;
	acl->acl_entry[0].ae_id   = ACL_UNDEFINED_ID;
	acl->acl_entry[0].ae_perm = (mode & S_IRWXU) >> 6;

	acl->acl_entry[1].ae_tag  = ACL_GROUP_OBJ;
	acl->acl_entry[1].ae_id   = ACL_UNDEFINED_ID;
	acl->acl_entry[1].ae_perm = (mode & S_IRWXG) >> 3;

	acl->acl_entry[2].ae_tag  = ACL_OTHER;
	acl->acl_entry[2].ae_id   = ACL_UNDEFINED_ID;
	acl->acl_entry[2].ae_perm = mode & S_IRWXO;

	return acl;
}

int
acl_equiv_mode (acl_t acl, mode_t *mode_p)
{
	int i, not_equiv = 0;
	mode_t mode = 0;
	acl_entry_t ace;

	if (!acl)
		return -1;

	for (i = 0; i < acl->acl_cnt; i++) {
		ace = &acl->acl_entry[i];
		switch (ace->ae_tag) {
		case ACL_USER_OBJ:
			mode |= (ace->ae_perm & S_IRWXO) << 6;
			break;
		case ACL_GROUP_OBJ:
			mode |= (ace->ae_perm & S_IRWXO) << 3;
			break;
		case ACL_OTHER:
			mode |= (ace->ae_perm & S_IRWXO);
			break;
		case ACL_USER:
		case ACL_GROUP:
		case ACL_MASK:
			not_equiv = 1;
			break;
		default:
			setoserror (EINVAL);
			return -1;
		}
	}
	if (mode_p)
		*mode_p = mode;
	return not_equiv;
}

acl_t
acl_get_file_mode (const char *path)
{
	struct stat st;

	if (stat (path, &st) != 0)
		return NULL;
	return acl_from_mode (st.st_mode);
}

int
acl_set_file_mode (const char *path, acl_type_t type, acl_t acl)
{
	struct stat st;
	mode_t mode;
	int error;

	switch (type) {
	case ACL_TYPE_ACCESS:
		error = acl_equiv_mode (acl, &mode);
		if (error != 0) {
			if (error > 0)
				setoserror (ENOTSUP);
			return -1;
		}
		if (stat (path, &st) != 0)
			return -1;
		mode |= st.st_mode & ~(S_IRWXU|S_IRWXG|S_IRWXO);
		return chmod (path, mode);

	case ACL_TYPE_DEFAULT:
		if (acl_entries (acl) == 0)
			return 0;
		setoserror (ENOTSUP);
		return -1;

	default:
	}
	setoserror (EINVAL);
	return -1;
}

int
acl_entries (acl_t acl)
{
	if (acl == NULL) {
		setoserror (EINVAL);
		return -1;
	}
	return acl->acl_cnt;
}

const char *
acl_error (int code)
{
	switch (code) {
	case ACL_MULTI_ERROR:
		return "Multiple entries";
	case ACL_DUPLICATE_ERROR:
		return "Duplicate entries";
	case ACL_MISS_ERROR:
		return "Missing or wrong entry";
	case ACL_ENTRY_ERROR:
		return "Invalid entry type";
	default:
	}
	return NULL;
}
