#include "crtsh_extract.h"

#include <string.h>

#define CRTSH_NAME_MAX 255  /* a DNS name is at most 253 chars; round up */

static int is_ws(char c)
{
    return c == ' ' || c == '\t' || c == '\n' ||
           c == '\r' || c == '\f' || c == '\v';
}

static char to_lower(unsigned char c)
{
    return (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : (char)c;
}

/* Is `name` (length nlen) already written as a line of `buf` (length blen)? */
static int line_present(const char *buf, size_t blen, const char *name, size_t nlen)
{
    size_t i = 0;
    while (i < blen) {
        size_t j = i;
        while (j < blen && buf[j] != '\n') {
            j++;
        }
        if ((j - i) == nlen && memcmp(buf + i, name, nlen) == 0) {
            return 1;
        }
        i = (j < blen) ? (j + 1) : j;
    }
    return 0;
}

/* Append "name\n" to out (capacity cap, incl. NUL), keeping it NUL-terminated.
 * Returns 1 if it was written, 0 if it did not fit. */
static int append_line(char *out, size_t cap, size_t *olen,
                       const char *name, size_t nlen)
{
    if (*olen + nlen + 2 > cap) { /* name + '\n' + '\0' */
        return 0;
    }
    memcpy(out + *olen, name, nlen);
    *olen += nlen;
    out[(*olen)++] = '\n';
    out[*olen] = '\0';
    return 1;
}

/* Normalize one raw name token and, if it matches, de-dup and append it. */
static void process_token(const char *raw, size_t rawlen,
                          const char *domain_lc, size_t dlen,
                          char *out, size_t cap, size_t *olen, int *count)
{
    /* Trim leading/trailing whitespace. */
    size_t s = 0;
    size_t e = rawlen;
    while (s < e && is_ws(raw[s])) {
        s++;
    }
    while (e > s && is_ws(raw[e - 1])) {
        e--;
    }

    /* Strip a single leading "*." wildcard. */
    if ((e - s) >= 2 && raw[s] == '*' && raw[s + 1] == '.') {
        s += 2;
    }

    size_t len = e - s;
    if (len == 0 || len > CRTSH_NAME_MAX) {
        return; /* empty, or implausibly long */
    }

    char name[CRTSH_NAME_MAX + 1];
    for (size_t i = 0; i < len; i++) {
        name[i] = to_lower((unsigned char)raw[s + i]);
    }
    name[len] = '\0';

    /* Keep only names equal to, or a sub-domain of, the target domain. */
    int match = 0;
    if (len == dlen && memcmp(name, domain_lc, dlen) == 0) {
        match = 1; /* exact apex */
    } else if (len > dlen + 1 &&
               name[len - dlen - 1] == '.' &&
               memcmp(name + (len - dlen), domain_lc, dlen) == 0) {
        match = 1; /* "<label>.<domain>" */
    }
    if (!match) {
        return;
    }

    if (line_present(out, *olen, name, len)) {
        return;
    }
    if (append_line(out, cap, olen, name, len)) {
        (*count)++;
    }
}

/* Scan one "name_value" string value starting at its opening quote `p`.
 * Decodes \" and \n (and a few harmless extras), splits on decoded newlines,
 * and feeds each token to process_token. Returns the pointer just past the
 * closing quote, or NULL if the string is unterminated. */
static const char *scan_name_value(const char *p,
                                   const char *domain_lc, size_t dlen,
                                   char *out, size_t cap, size_t *olen, int *count)
{
    p++; /* skip opening quote */

    char tok[CRTSH_NAME_MAX + 1];
    size_t tlen = 0;

    while (*p != '\0' && *p != '"') {
        char c = *p;
        if (c == '\\') {
            p++;
            if (*p == '\0') {
                break;
            }
            if (*p == 'n') {
                /* Decoded newline: split here. */
                process_token(tok, tlen, domain_lc, dlen, out, cap, olen, count);
                tlen = 0;
                p++;
                continue;
            } else if (*p == '"') {
                c = '"';
            } else if (*p == '\\') {
                c = '\\';
            } else if (*p == '/') {
                c = '/';
            } else if (*p == 't') {
                c = '\t';
            } else if (*p == 'r') {
                c = '\r';
            } else {
                c = *p; /* unknown escape: drop backslash, keep the char */
            }
        }
        if (tlen < CRTSH_NAME_MAX) {
            tok[tlen++] = c;
        }
        /* Overlong tokens are silently capped; they cannot match a domain. */
        p++;
    }

    /* Finalize the trailing token. */
    process_token(tok, tlen, domain_lc, dlen, out, cap, olen, count);

    if (*p != '"') {
        return NULL; /* unterminated string */
    }
    return p + 1;
}

int alosint_crtsh_extract_unique(const char *json_str, const char *domain,
                                 char *out_buf, int max_len)
{
    if (out_buf == NULL || max_len <= 0) {
        return -1;
    }
    out_buf[0] = '\0';

    if (json_str == NULL || json_str[0] == '\0' || domain == NULL) {
        return -1;
    }

    size_t dlen = strlen(domain);
    if (dlen == 0 || dlen > CRTSH_NAME_MAX) {
        return -1;
    }
    char domain_lc[CRTSH_NAME_MAX + 1];
    for (size_t i = 0; i < dlen; i++) {
        domain_lc[i] = to_lower((unsigned char)domain[i]);
    }
    domain_lc[dlen] = '\0';

    size_t cap = (size_t)max_len;
    size_t olen = 0;
    int count = 0;
    int found = 0;

    const char *p = json_str;
    while ((p = strstr(p, "\"name_value\"")) != NULL) {
        found = 1;
        const char *after = p + strlen("\"name_value\"");

        /* Walk from the key to the value's opening quote, stopping early if the
         * value is not a string (e.g. null). */
        const char *q = after;
        while (*q != '\0' && *q != '"' && *q != '}' && *q != ',') {
            q++;
        }
        if (*q != '"') {
            p = after;
            continue;
        }

        const char *endp = scan_name_value(q, domain_lc, dlen,
                                           out_buf, cap, &olen, &count);
        p = (endp != NULL) ? endp : after;
    }

    if (!found) {
        return -1;
    }
    return count;
}
