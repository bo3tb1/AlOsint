#include "json_writer.h"

#include <limits.h>
#include <string.h>

int alosint_json_escape(const char *in, char *out, int max_len)
{
    if (in == NULL || out == NULL || max_len <= 0) {
        return -1;
    }

    static const char hex[] = "0123456789abcdef";

    size_t limit = (size_t)max_len - 1; /* reserve one byte for the NUL */
    size_t o = 0;

    for (const unsigned char *p = (const unsigned char *)in; *p != '\0'; p++) {
        unsigned char c = *p;
        char seq[6];
        size_t n;

        switch (c) {
            case '"':  seq[0] = '\\'; seq[1] = '"';  n = 2; break;
            case '\\': seq[0] = '\\'; seq[1] = '\\'; n = 2; break;
            case '\n': seq[0] = '\\'; seq[1] = 'n';  n = 2; break;
            case '\r': seq[0] = '\\'; seq[1] = 'r';  n = 2; break;
            case '\t': seq[0] = '\\'; seq[1] = 't';  n = 2; break;
            case '\b': seq[0] = '\\'; seq[1] = 'b';  n = 2; break;
            case '\f': seq[0] = '\\'; seq[1] = 'f';  n = 2; break;
            default:
                if (c < 0x20) {
                    seq[0] = '\\';
                    seq[1] = 'u';
                    seq[2] = '0';
                    seq[3] = '0';
                    seq[4] = hex[(c >> 4) & 0x0f];
                    seq[5] = hex[c & 0x0f];
                    n = 6;
                } else {
                    seq[0] = (char)c;
                    n = 1;
                }
                break;
        }

        if (o + n > limit) {
            break; /* whole sequence would not fit: stop on a clean boundary */
        }
        for (size_t k = 0; k < n; k++) {
            out[o++] = seq[k];
        }
    }

    out[o] = '\0';
    return (int)o;
}

int alosint_json_escape_len(const char *in)
{
    if (in == NULL) {
        return -1;
    }

    size_t len = strlen(in);

    /* Worst case is 6 bytes per input byte (\u00XX) plus the NUL. Guard the
     * multiplication so an over-long input reports failure instead of wrapping. */
    if (len > (size_t)(INT_MAX - 1) / 6) {
        return -1;
    }

    return (int)(6 * len + 1);
}
