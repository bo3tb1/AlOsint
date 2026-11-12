#include <stdio.h>

int alosint_write_file(const char *path, const char *data, int len)
{
    if (path == NULL || data == NULL || len < 0) {
        return -1;
    }

    FILE *f = fopen(path, "wb");
    if (f == NULL) {
        return -1;
    }

    size_t written = fwrite(data, 1, (size_t)len, f);
    if (fclose(f) != 0) {
        return -1;
    }
    return written == (size_t)len ? 0 : -1;
}
