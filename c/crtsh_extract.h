#ifndef ALOSINT_CRTSH_EXTRACT_H
#define ALOSINT_CRTSH_EXTRACT_H

/*
 * alosint_crtsh_extract_unique — distill a crt.sh JSON response into a
 * newline-separated list of unique sub-domains of `domain`.
 *
 * crt.sh returns a JSON array of certificate objects, each with a "name_value"
 * field that may itself hold several newline-separated names. This function
 * collects every name that belongs to `domain`, normalizes and de-duplicates
 * them, and writes them one per line.
 *
 * For each name found it: trims surrounding whitespace, strips a single leading
 * "*." wildcard, lowercases it, skips empties, and keeps it only when it equals
 * `domain` or ends with "." + `domain` (all comparisons case-insensitive).
 *
 * Parameters:
 *   json_str  NUL-terminated crt.sh JSON (borrowed, read-only).
 *   domain    NUL-terminated apex domain to filter by (borrowed, read-only).
 *   out_buf   caller-owned buffer; receives "name\n" per unique name and is
 *             always NUL-terminated overall. Writes never exceed max_len.
 *   max_len   capacity of out_buf in bytes, including the terminating NUL.
 *
 * Ownership: allocates no heap (stack buffers only); never frees caller memory.
 *
 * Returns:
 *   >=0  the number of unique names written to out_buf.
 *   -1   json_str is NULL/empty, or malformed (contains no "name_value" key),
 *        or arguments are otherwise unusable.
 */
int alosint_crtsh_extract_unique(const char *json_str, const char *domain,
                                 char *out_buf, int max_len);

/*
 * alosint_crtsh_extract_emails — collect unique email-like "name_value" entries
 * from a crt.sh JSON response.
 *
 * Splits each "name_value" on newlines (as alosint_crtsh_extract_unique does),
 * trims whitespace, and keeps a token only when it contains '@' and no interior
 * whitespace. Keeps original case, de-duplicates, and writes one per line;
 * out_buf is always NUL-terminated and writes never exceed max_len.
 *
 * Returns the number of unique emails written, or -1 if json_str is NULL/empty,
 * malformed (no "name_value" key), or out_buf is NULL / max_len <= 0.
 */
int alosint_crtsh_extract_emails(const char *json_str, char *out_buf, int max_len);

#endif /* ALOSINT_CRTSH_EXTRACT_H */
