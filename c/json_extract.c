#include "json_extract.h"

#include <stdio.h>
#include <string.h>

/* Copy a JSON string literal into `dst` (capacity `cap`, always NUL-terminated).
 * `p` must point at the opening quote. A small set of escapes is decoded;
 * \uXXXX is emitted verbatim for ASCII code points and as '?' otherwise.
 * Returns a pointer just past the closing quote, or NULL on malformed input. */
static const char *copy_json_string(const char *p, char *dst, size_t cap)
{
    if (cap == 0 || *p != '"') {
        return NULL;
    }
    p++;

    size_t o = 0;
    while (*p != '\0' && *p != '"') {
        char c = *p;
        if (c == '\\') {
            p++;
            if (*p == '\0') {
                break;
            }
            switch (*p) {
                case 'n':  c = '\n'; break;
                case 't':  c = '\t'; break;
                case 'r':  c = '\r'; break;
                case 'b':  c = '\b'; break;
                case 'f':  c = '\f'; break;
                case '/':  c = '/';  break;
                case '\\': c = '\\'; break;
                case '"':  c = '"';  break;
                case 'u': {
                    int code = 0;
                    int ok = 1;
                    for (int k = 1; k <= 4; k++) {
                        char h = p[k];
                        int v;
                        if (h >= '0' && h <= '9')      { v = h - '0'; }
                        else if (h >= 'a' && h <= 'f') { v = 10 + (h - 'a'); }
                        else if (h >= 'A' && h <= 'F') { v = 10 + (h - 'A'); }
                        else { ok = 0; break; }
                        code = code * 16 + v;
                    }
                    if (ok) {
                        p += 4;
                        c = (code < 0x80) ? (char)code : '?';
                    } else {
                        c = '?';
                    }
                    break;
                }
                default: c = *p; break;
            }
        }
        if (o + 1 < cap) {
            dst[o++] = c;
        }
        p++;
    }

    dst[o < cap ? o : cap - 1] = '\0';
    if (*p != '"') {
        return NULL;
    }
    return p + 1;
}

/* From `at`, skip forward to the next '"' (not past `limit` when non-NULL) and
 * return it, or NULL if none is found first. */
static const char *next_quote(const char *at, const char *limit)
{
    while (*at != '\0' && *at != '"') {
        if (limit != NULL && at >= limit) {
            return NULL;
        }
        at++;
    }
    return (*at == '"') ? at : NULL;
}

/* Extract the registrar name into `dst`. Returns 1 on success. */
static int extract_registrar(const char *json, char *dst, size_t cap)
{
    /* Prefer the vCard "fn" that follows the registrar role; fall back to the
     * first "fn" anywhere in the document. */
    const char *anchor = strstr(json, "\"registrar\"");
    const char *fn = NULL;
    if (anchor != NULL) {
        fn = strstr(anchor, "\"fn\"");
    }
    if (fn == NULL) {
        fn = strstr(json, "\"fn\"");
    }
    if (fn == NULL) {
        return 0;
    }

    /* vCard shape: ["fn", {params}, "text", "<value>"]. Find the "text" type
     * marker, then the quoted value right after it. */
    const char *text = strstr(fn, "\"text\"");
    const char *start = (text != NULL) ? (text + 6) : (fn + 4);
    const char *q = next_quote(start, NULL);
    if (q == NULL) {
        return 0;
    }

    return copy_json_string(q, dst, cap) != NULL && dst[0] != '\0';
}

/* Find the end (matching '}') of the object that begins at `obj_start`. */
static const char *object_end(const char *obj_start)
{
    int depth = 0;
    for (const char *e = obj_start; *e != '\0'; e++) {
        if (*e == '{') {
            depth++;
        } else if (*e == '}') {
            depth--;
            if (depth == 0) {
                return e;
            }
        }
    }
    return NULL;
}

/* Extract the "registration" event date (trimmed to YYYY-MM-DD) into `dst`.
 * Returns 1 on success. Tolerant of field ordering within the event object. */
static int extract_registration_date(const char *json, char *dst, size_t cap)
{
    const char *events = strstr(json, "\"events\"");
    const char *p = (events != NULL) ? events : json;

    while ((p = strstr(p, "\"eventAction\"")) != NULL) {
        const char *after_key = p + strlen("\"eventAction\"");
        const char *av = next_quote(after_key, NULL);

        char action[32];
        action[0] = '\0';
        if (av != NULL) {
            copy_json_string(av, action, sizeof(action));
        }

        if (strcmp(action, "registration") == 0) {
            /* Bound the enclosing event object so we read *its* eventDate,
             * regardless of whether it appears before or after eventAction. */
            const char *obj_start = p;
            while (obj_start > json && *obj_start != '{') {
                obj_start--;
            }
            const char *obj_end = object_end(obj_start);

            const char *d = strstr(obj_start, "\"eventDate\"");
            if (d != NULL && (obj_end == NULL || d < obj_end)) {
                const char *dv = next_quote(d + strlen("\"eventDate\""), obj_end);
                char date[48];
                if (dv != NULL && copy_json_string(dv, date, sizeof(date)) != NULL) {
                    size_t i = 0;
                    while (date[i] != '\0' && date[i] != 'T' && i + 1 < cap) {
                        dst[i] = date[i];
                        i++;
                    }
                    dst[i] = '\0';
                    if (dst[0] != '\0') {
                        return 1;
                    }
                }
            }
        }

        p = after_key; /* guarantee forward progress */
    }
    return 0;
}

void alosint_extract_rdap_summary(const char *json_str, char *out_buf, int max_len)
{
    if (out_buf == NULL || max_len <= 0) {
        return;
    }
    out_buf[0] = '\0';

    char registrar[256];
    char date[32];
    registrar[0] = '\0';
    date[0] = '\0';

    if (json_str != NULL) {
        if (!extract_registrar(json_str, registrar, sizeof(registrar))) {
            registrar[0] = '\0';
        }
        if (!extract_registration_date(json_str, date, sizeof(date))) {
            date[0] = '\0';
        }
    }

    if (registrar[0] == '\0') {
        snprintf(registrar, sizeof(registrar), "Unknown");
    }
    if (date[0] == '\0') {
        snprintf(date, sizeof(date), "Unknown");
    }

    snprintf(out_buf, (size_t)max_len, "Registrar: %s | Registered: %s",
             registrar, date);
}
