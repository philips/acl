/*
  File: acl_ea.h

  (extended attribute representation of access control lists)

  (C) 2002 Andreas Gruenbacher, <a.gruenbacher@computer.org>
*/

#define ACL_EA_ACCESS		"system.posix_acl_access"
#define ACL_EA_DEFAULT		"system.posix_acl_default"

#define ACL_EA_VERSION		0x0002

typedef struct {
	__u16		e_tag;
	__u16		e_perm;
	__u32		e_id;
} acl_ea_entry;

typedef struct {
	__u32		a_version;
	acl_ea_entry	a_entries[0];
} acl_ea_header;

static inline size_t acl_ea_size(int count)
{
	return sizeof(acl_ea_header) + count * sizeof(acl_ea_entry);
}

static inline int acl_ea_count(size_t size)
{
	if (size < sizeof(acl_ea_header))
		return -1;
	size -= sizeof(acl_ea_header);
	if (size % sizeof(acl_ea_entry))
		return -1;
	return size / sizeof(acl_ea_entry);
}

