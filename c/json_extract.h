#ifndef ALOSINT_JSON_EXTRACT_H
#define ALOSINT_JSON_EXTRACT_H

/*
 * alosint_extract_rdap_summary — distill a raw RDAP JSON document into a short,
 * human-readable one-line summary.
 *
 * Extracts the registrar's formatted name (the registrar entity's vCard "fn",
 * falling back to the first "fn" in the document) and the "registration" event
 * date from the "events" array, then writes a line of the form:
 *
 *     Registrar: Example Registrar, Inc. | Registered: 1995-08-14
 *
 * Missing fields are rendered as "Unknown" so the output is always well formed.
 *
 * Parameters:
 *   json_str  NUL-terminated RDAP JSON (borrowed, read-only; may be NULL).
 *   out_buf   caller-owned buffer that receives the NUL-terminated summary.
 *   max_len   capacity of out_buf in bytes, including the terminating NUL.
 *
 * Ownership: the caller owns out_buf; this function only writes into it, never
 * exceeds max_len, and allocates nothing the caller must free. It never fails
 * loudly — on bad input it writes an "Unknown"/empty summary instead.
 */
void alosint_extract_rdap_summary(const char *json_str, char *out_buf, int max_len);

/*
 * alosint_extract_rdap_ip_summary — distill an RDAP *IP* JSON document into a
 * one-line summary:
 *
 *     Network: <name> | Range: <start>-<end> | Country: <cc> | Type: <type>
 *
 * Fields come from the top-level "name" (falling back to "handle"),
 * "startAddress", "endAddress", "country", and "type". Missing fields render as
 * "Unknown". Always NUL-terminated; writes never exceed max_len. On NULL/empty
 * input it writes an all-"Unknown" summary.
 */
void alosint_extract_rdap_ip_summary(const char *json_str, char *out_buf, int max_len);

#endif /* ALOSINT_JSON_EXTRACT_H */
