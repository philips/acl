#include <errno.h>
#include <string.h>

#define OK "\033[32mok\033[m"
#define ERROR "\033[31m\033[1mfailed\033[m"
/* integer result */
#define I(e, x) \
	({ res = ((x)==0); \
	   fprintf(stderr, "[%d] " ## #x ## " : %s -- %s\n", \
	            __LINE__, \
		    res ? "" : strerror(errno), \
	            (res == e) ? OK : ERROR \
		    ); })
/* pointer result */
#define P(e, x) \
	({ res = ((x) != NULL); \
	   fprintf(stderr, "[%d] " ## #x ## " : %s -- %s\n", \
	            __LINE__, \
		    res ? "" : strerror(errno), \
	            (res == e) ? OK : ERROR \
		    ); })
