#include <stdio.h>
#include <sys/acl.h>
#include <string.h>

#include "check.h"

int main(void)
{
	acl_t acl;
	char *text;
	int res;

	P(1, acl = acl_from_text("user::rwx") );
	P(1, text = acl_to_text(acl, NULL) );
	I(1, strcmp(text, "user::rwx") );
	I(1, acl_free(text) );
	P(1, acl = acl_from_text("user::rwx,g::rw") );
	P(1, text = acl_to_text(acl, NULL) );
	I(1, strcmp(text, "user::rwx\ngroup::rw-") );
	I(1, acl_free(text) );

	return 0;
}

