#ifdef HAVE_EXPLICIT_BZERO

int dummy;

#else

#include <stdlib.h>

void explicit_bzero(void* s, size_t n)
{
	volatile char* buf = (volatile char*)s;
	while(n--)
		*buf++ = '\0';
}
#endif
