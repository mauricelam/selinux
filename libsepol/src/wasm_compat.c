#include <stdlib.h>
#include <errno.h>

/* Emscripten's stdlib.h declares reallocarray but the library doesn't always
   provide it. We provide a non-static version here that matches the
   declaration in stdlib.h to avoid conflicts with the static inline
   definition in private.h. */
void* reallocarray(void *ptr, size_t nmemb, size_t size) {
	if (size && nmemb > (size_t)-1 / size) {
		errno = ENOMEM;
		return NULL;
	}
	return realloc(ptr, nmemb * size);
}
