/* Tests ACL library memory allocation */

#include <stdio.h>
#include <sys/acl.h>

#include "check.h"

int main(void)
{
	acl_entry_t entry1, entry2;
	void *id_p;
	acl_permset_t permset;
	acl_t acl;
	void *v_p = NULL;
	void **v_pp = &v_p;
	char *text;
	
	/* used by macros*/
	int res;

	/* parameter 1 = succeeds */
	P( 1, acl = acl_from_text("user::rw-, group::r--, other:-") );
	P( 1, text = acl_to_text(acl, NULL) );
	I( 1, acl_free(text) );
	I( 0, acl_free(text) );
	P( 1, acl = acl_init(0) );
	I( 1, acl_create_entry(&acl, &entry1) );
	I( 0, acl_create_entry(NULL, &entry1) );
	I( 0, acl_create_entry(v_p, &entry1) );
	I( 0, acl_create_entry((void*)&v_p, &entry1) );
	I( 0, acl_create_entry(&acl, NULL) );
	I( 0, acl_copy_entry(entry1, entry2) ); 
	I( 0, acl_copy_entry(entry1, v_p) ); 
	I( 0, acl_free(entry1) );
	I( 1, acl_create_entry(&acl, &entry2) );
	I( 1, acl_copy_entry(entry2, entry1) );
	P( 0, id_p = acl_get_qualifier(entry2) );
	I( 1, acl_set_tag_type(entry2, ACL_USER) );
	P( 1, id_p = acl_get_qualifier(entry2) );
	I( 1, acl_get_permset(entry2, &permset) );
	I( 0, acl_free(permset) );
	I( 1, acl_free(id_p) );
	I( 0, acl_free(id_p) ); 
	I( 1, acl_free(acl) );
	I( 0, acl_free(acl) ); 
	I( 0, acl_free(v_pp) );

	return 0;
}

