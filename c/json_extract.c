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

/* Extract the string value of a TOP-LEVEL key `key` (a direct member of the
 * root object, nesting depth 1) into `dst`. Returns 1 on success.
 *
 * Depth awareness matters: RDAP documents repeat common keys like "type" and
 * "name" inside nested "links"/"notices"/"entities" arrays (e.g. a link's media
 * type "application/rdap+json"), so a naive first-match would grab the wrong
 * one. We track object/array nesting, skip over string contents, and only
 * consider a key when it sits directly in the root object. */
static int extract_string_field(const char *json, const char *key,
                                char *dst, size_t cap)
{
    size_t keylen = strlen(key);
    int depth = 0;

    const char *p = json;
    while (*p != '\0') {
        char c = *p;

        if (c == '"') {
            /* Span the whole string literal so its bytes never affect depth. */
            const char *s = p;
            const char *q = p + 1;
            while (*q != '\0' && *q != '"') {
                if (*q == '\\' && q[1] != '\0') {
                    q += 2;
                } else {
                    q++;
                }
            }
            if (*q != '"') {
                return 0; /* unterminated string */
            }

            const char *after = q + 1;
            const char *t = after;
            while (*t == ' ' || *t == '\t' || *t == '\n' || *t == '\r') {
                t++;
            }

            /* A key is a string immediately followed by ':'. */
            if (*t == ':' && depth == 1) {
                size_t slen = (size_t)(q - (s + 1));
                if (slen == keylen && memcmp(s + 1, key, keylen) == 0) {
                    const char *v = t + 1;
                    while (*v == ' ' || *v == '\t' || *v == '\n' || *v == '\r') {
                        v++;
                    }
                    if (*v != '"') {
                        return 0; /* value is not a string */
                    }
                    return copy_json_string(v, dst, cap) != NULL && dst[0] != '\0';
                }
            }

            p = after;
            continue;
        }

        if (c == '{' || c == '[') {
            depth++;
        } else if (c == '}' || c == ']') {
            if (depth > 0) {
                depth--;
            }
        }
        p++;
    }

    return 0;
}

/* Find the string value of the first "key":"value" at or after `from`.
 * Returns 1 on success (value copied into dst). */
static int field_string_from(const char *from, const char *key,
                             char *dst, size_t cap)
{
    char needle[32];
    int kn = snprintf(needle, sizeof(needle), "\"%s\"", key);
    if (kn < 0 || (size_t)kn >= sizeof(needle)) {
        return 0;
    }

    const char *k = strstr(from, needle);
    if (k == NULL) {
        return 0;
    }

    const char *p = k + kn;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') {
        p++;
    }
    if (*p != ':') {
        return 0;
    }
    p++;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') {
        p++;
    }
    if (*p != '"') {
        return 0;
    }
    return copy_json_string(p, dst, cap) != NULL && dst[0] != '\0';
}

/* Country name = the last non-empty newline-separated line of the first vCard
 * "adr" label found at or after `from` (the label is a newline-joined postal
 * address ending in the country, e.g. "...\nUnited States"). */
static int label_country_from(const char *from, char *dst, size_t cap)
{
    char label[256];
    if (!field_string_from(from, "label", label, sizeof(label))) {
        return 0; /* copy_json_string already decoded \n into real newlines */
    }

    size_t len = strlen(label);
    while (len > 0 && (label[len - 1] == '\n' || label[len - 1] == '\r' ||
                       label[len - 1] == ' '  || label[len - 1] == '\t')) {
        len--;
    }
    size_t s = len;
    while (s > 0 && label[s - 1] != '\n') {
        s--;
    }

    size_t llen = len - s;
    if (llen == 0 || llen + 1 > cap) {
        return 0;
    }
    memcpy(dst, label + s, llen);
    dst[llen] = '\0';
    return 1;
}

/* A country for the entity region at/after `from`: prefer an explicit "country"
 * field (RIRs such as RIPE/APNIC emit a 2-letter code), else the vCard adr
 * label's country name (ARIN carries the country only there). */
static int country_from(const char *from, char *dst, size_t cap)
{
    if (field_string_from(from, "country", dst, cap)) {
        return 1;
    }
    return label_country_from(from, dst, cap);
}

/* Fallback when there is no top-level "country": search entity data, preferring
 * the registrant entity, then administrative, then any entity. Within an entity
 * "roles" precedes its vCard, so the first country/label after a role keyword
 * belongs to that entity. */
static int extract_nested_country(const char *json, char *dst, size_t cap)
{
    const char *reg = strstr(json, "\"registrant\"");
    if (reg != NULL && country_from(reg, dst, cap)) {
        return 1;
    }

    const char *adm = strstr(json, "\"administrative\"");
    if (adm != NULL && country_from(adm, dst, cap)) {
        return 1;
    }

    const char *ent = strstr(json, "\"entities\"");
    return country_from(ent != NULL ? ent : json, dst, cap);
}

void alosint_extract_rdap_ip_summary(const char *json_str, char *out_buf, int max_len)
{
    if (out_buf == NULL || max_len <= 0) {
        return;
    }
    out_buf[0] = '\0';

    char name[128];
    char start[64];
    char end[64];
    char country[48];
    char type[64];
    name[0] = start[0] = end[0] = country[0] = type[0] = '\0';

    if (json_str != NULL) {
        /* Network identifier: prefer "name", fall back to the registry "handle". */
        if (!extract_string_field(json_str, "name", name, sizeof(name)) &&
            !extract_string_field(json_str, "handle", name, sizeof(name))) {
            name[0] = '\0';
        }
        if (!extract_string_field(json_str, "startAddress", start, sizeof(start))) {
            start[0] = '\0';
        }
        if (!extract_string_field(json_str, "endAddress", end, sizeof(end))) {
            end[0] = '\0';
        }
        /* Primary: top-level "country" (RIRs like APNIC). Fallback: a country
         * found inside entity objects (ARIN carries it only in the vCard adr
         * label, e.g. Google/Cloudflare). */
        if (!extract_string_field(json_str, "country", country, sizeof(country)) &&
            !extract_nested_country(json_str, country, sizeof(country))) {
            country[0] = '\0';
        }
        if (!extract_string_field(json_str, "type", type, sizeof(type))) {
            type[0] = '\0';
        }
    }

    if (name[0] == '\0')    { snprintf(name, sizeof(name), "Unknown"); }
    if (start[0] == '\0')   { snprintf(start, sizeof(start), "Unknown"); }
    if (end[0] == '\0')     { snprintf(end, sizeof(end), "Unknown"); }
    if (country[0] == '\0') { snprintf(country, sizeof(country), "Unknown"); }
    if (type[0] == '\0')    { snprintf(type, sizeof(type), "Unknown"); }

    snprintf(out_buf, (size_t)max_len,
             "Network: %s | Range: %s-%s | Country: %s | Type: %s",
             name, start, end, country, type);
}
