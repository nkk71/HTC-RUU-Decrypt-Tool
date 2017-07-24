/* misc.c - Store all functions that are unable to be catagorized clearly
 */

#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/stat.h>

int mkdir_p(const char *pathname, mode_t mode) {
	char *path = strdup(pathname), *p;
	errno = 0;
	for (p = path + 1; *p; ++p) {
		if (*p == '/') {
			*p = '\0';
			if (mkdir(path, mode) == -1) {
				if (errno != EEXIST)
					return -1;
			}
			*p = '/';
		}
	}
	if (mkdir(path, mode) == -1) {
		if (errno != EEXIST)
			return -1;
	}
	free(path);
	return 0;
}
