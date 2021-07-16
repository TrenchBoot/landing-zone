#include <types.h>

void *(memcpy)(void *dst, const void *src, size_t count)
{
	const char *s = src;
	char *d = dst;

	while (count--)
		*d++ = *s++;

	return dst;
}

void *(memset)(void *dst, int c, size_t n)
{
	char *d = dst;

	while ( n-- )
		*d++ = c;

	return dst;
}

size_t (strlen)(const char *s)
{
	size_t c = 0;

	while (*s++)
		c++;

	return c;
}
