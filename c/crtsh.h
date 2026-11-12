#ifndef ALOSINT_CRTSH_H
#define ALOSINT_CRTSH_H

/* Query crt.sh for certificates covering sub-domains of `domain`
 * (q=%25.<domain>). Writes the raw JSON into json_out (bounded by max_len).
 * Returns 0 on success, -1 on transport error, -2 on HTTP error. */
int alosint_crtsh_lookup(const char *domain, char *json_out, int max_len);

/* Query crt.sh for certificates mentioning `email` (q=<url-encoded-email>).
 * The email is URL-encoded before use and must contain '@'. Writes the raw
 * JSON into json_out (bounded by max_len).
 * Returns 0 on success, -1 on bad input/transport error, -2 on HTTP error. */
int alosint_crtsh_lookup_email(const char *email, char *json_out, int max_len);

#endif /* ALOSINT_CRTSH_H */
