#include <errno.h>
#include <stdlib.h>
#include "libobj.h"

#ifdef LIBACL_DEBUG
# include <stdio.h>
#endif

/* object creation, destruction, conversion and validation */

void *
__new_obj_p(int magic, size_t size)
{
	obj_prefix *obj_p = (obj_prefix *)malloc(size);
	if (obj_p)
		obj_p->p_magic = magic;
	return obj_p;
}


void
__free_obj_p(obj_prefix *obj_p)
{
	obj_p->p_magic = 0;
	free(obj_p);
}


obj_prefix *
__check_obj_p(obj_prefix *obj_p, int magic)
{
	if (!obj_p || obj_p->p_magic != magic) {
		errno = EINVAL;
		return NULL;
	}
	return obj_p;
}


#ifdef LIBACL_DEBUG
obj_prefix *
__ext2int_and_check(void *ext_p, int magic, const char *typename)
#else
obj_prefix *
__ext2int_and_check(void *ext_p, int magic)
#endif
{
	obj_prefix *obj_p = ((obj_prefix *)ext_p)-1;
	if (!ext_p) {
#ifdef LIBACL_DEBUG
		fprintf(stderr, "invalid %s object at %p\n",
		        typename, obj_p);
#endif
		errno = EINVAL;
		return NULL;
	}
	return __check_obj_p(obj_p, magic);
}

