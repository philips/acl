/*
 * Copyright (c) 2001 Silicon Graphics, Inc.  All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it would be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * Further, this software is distributed without any warranty that it is
 * free of the rightful claim of any third person regarding infringement
 * or the like.  Any license provided herein, whether implied or
 * otherwise, applies only to this software file.  Patent licenses, if
 * any, provided herein do not apply to combinations of this program with
 * other software, or any other product whatsoever.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write the Free Software Foundation, Inc., 59
 * Temple Place - Suite 330, Boston MA 02111-1307, USA.
 *
 * Contact information: Silicon Graphics, Inc., 1600 Amphitheatre Pkwy,
 * Mountain View, CA  94043, or:
 *
 * http://www.sgi.com
 *
 * For further information regarding this notice, see:
 *
 * http://oss.sgi.com/projects/GenInfo/SGIGPLNoticeExplan/
 */
#ifndef _SYS_ACL_H
#define _SYS_ACL_H

/*
 * Data types and functions for POSIX P1003.1e Access Control Lists (ACLs)
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>

/*
 * Number of "base" ACL entries (USER_OBJ, GROUP_OBJ, MASK, & OTHER_OBJ)
 */
#define NACLBASE	4
#define ACL_MAX_ENTRIES 25	/* Arbitrarily chosen number */

/*
 * Data types required by POSIX P1003.1eD15
 */
typedef ushort	acl_perm_t;
typedef int	acl_type_t;
typedef int	acl_tag_t;

struct acl_entry {
	acl_tag_t 		ae_tag;
	id_t			ae_id;
	acl_perm_t		ae_perm;	
};

struct acl {
	int			acl_cnt;	/* Number of entries */
	struct acl_entry	acl_entry[ACL_MAX_ENTRIES];
};

typedef struct acl * acl_t;
typedef struct acl_entry * acl_entry_t;
typedef acl_perm_t * acl_permset_t;
typedef unsigned int acl_compat_t;

/* 23.2.2 acl_perm_t values */
#define ACL_PERM_NONE		0x00
#define ACL_READ		0x04
#define ACL_WRITE		0x02
#define ACL_EXECUTE		0x01

/* 23.2.5 acl_tag_t values */
#define ACL_UNDEFINED_TAG	0x00			/* undefined tag */
#define ACL_USER_OBJ		0x01			/* owner */
#define ACL_USER		0x02			/* additional users */
#define ACL_GROUP_OBJ		0x04			/* group */
#define ACL_GROUP		0x08			/* additional groups */
#define ACL_MASK		0x10			/* mask entry */
#define ACL_OTHER_OBJ		0x20			/* other entry */
#define ACL_OTHER		0x20			/* POSIX other entry */

/* 23.3.6 acl_type_t values */
#define ACL_TYPE_ACCESS		0x00
#define ACL_TYPE_DEFAULT	0x01

/* 23.2.7 ACL qualifier constants */
#define ACL_UNDEFINED_ID	((unsigned int)-1)

/* 23.2.8 ACL entry constants */
#define ACL_FIRST_ENTRY		0x00
#define ACL_NEXT_ENTRY		0x01

/*        ACL compatibility flags */
#define ACL_COMPAT_DEFAULT	0x00
#define ACL_COMPAT_IRIXGET	0x01

/*
 * An IRIX defined macro not in P1003.1e.
 * With ACL_COMPAT_IRIXGET set it used to signify an empty ACL.
 * It is also used to delete an ACL.
 */
#define ACL_NOT_PRESENT	-1


/* ACL manipulation */
extern acl_t acl_init (int __count);
extern acl_t acl_dup (acl_t __src_acl);
extern int acl_free (void *__obj);
extern int acl_valid (acl_t __acl);

/* Entry manipulation */
extern int acl_copy_entry (acl_entry_t __dest_ace, acl_entry_t __src_ace);
extern int acl_create_entry (acl_t *__aclp, acl_entry_t *__acep);
extern int acl_delete_entry (acl_t __acl, acl_entry_t __ace);
extern int acl_get_entry (acl_t __acl, int __index, acl_entry_t *__acep);
extern void acl_entry_sort (acl_t __acl);

/* Manipulate ACL entry permissions */
extern int acl_add_perm (acl_permset_t __pset, acl_perm_t __p);
extern int acl_calc_mask (acl_t *__aclp);
extern int acl_clear_perms (acl_permset_t __pset);
extern int acl_delete_perm (acl_permset_t __pset, acl_perm_t __p);
extern int acl_get_perm (acl_permset_t __pset, acl_perm_t __p);
extern int acl_get_permset (acl_entry_t __ace, acl_permset_t *__psetp);
extern int acl_set_permset (acl_entry_t __ace, acl_permset_t __pset);

/* Manipulate ACL entry tag type and qualifier */
extern void *acl_get_qualifier (acl_entry_t __ace);
extern int acl_get_tag_type (acl_entry_t __ace, acl_tag_t *__tagp);
extern int acl_set_qualifier (acl_entry_t __ace, const void *__obj);
extern int acl_set_tag_type (acl_entry_t __ace, acl_tag_t __tag);

/* Format translation */
extern ssize_t acl_copy_ext (void *__obj, acl_t __acl, ssize_t __bufsz);
extern acl_t acl_copy_int (const void *__obj);
extern acl_t acl_from_text (const char *__text);
extern ssize_t acl_size (acl_t __acl);
extern char *acl_to_text (acl_t __acl, ssize_t *__lenp);
extern char *acl_to_short_text (acl_t __acl, ssize_t *__lenp);

/* Object manipulation */
extern int acl_delete_def_file (const char *__file);
extern acl_t acl_get_fd (int __fd);
extern acl_t acl_get_file (const char *__file, acl_type_t __type);
extern int acl_set_fd (int __fd, acl_t __acl);
extern int acl_set_file (const char *__file, acl_type_t __type, acl_t __acl);

/* Compatibility with other implementations */
extern void acl_set_compat (acl_compat_t __flags);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_ACL_H */
