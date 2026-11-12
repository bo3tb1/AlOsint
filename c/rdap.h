#ifndef ALOSINT_RDAP_H
#define ALOSINT_RDAP_H

/*
 * alosint_rdap_lookup — fetch the RDAP (modern WHOIS) record for a domain.
 *
 * Performs an HTTPS GET to https://rdap.org/domain/<domain> (following the
 * bootstrap redirect to the authoritative registry/registrar RDAP server) and
 * writes the raw JSON response into the caller-owned buffer.
 *
 * Parameters:
 *   domain    NUL-terminated domain name to query (borrowed, read-only).
 *   json_out  caller-owned buffer that receives the NUL-terminated JSON body;
 *             written by this function, never exceeds max_len bytes.
 *   max_len   capacity of json_out in bytes, including the terminating NUL.
 *             A body larger than max_len-1 is truncated to fit.
 *
 * Ownership: the caller owns json_out; this function only writes into it and
 * never allocates memory the caller must free.
 *
 * Returns:
 *    0  success; json_out holds the (possibly truncated) NUL-terminated body.
 *   -1  transport/curl error, or bad arguments.
 *   -2  HTTP error (response status outside 2xx).
 * On any failure json_out is NUL-terminated (empty when nothing was received).
 */
int alosint_rdap_lookup(const char *domain, char *json_out, int max_len);

/*
 * alosint_rdap_lookup_ip — fetch the RDAP record for an IP address.
 *
 * Validates `ip` as an IPv4 or IPv6 literal (inet_pton) and performs an HTTPS
 * GET to https://rdap.org/ip/<ip> (which redirects to the authoritative RIR),
 * writing the raw JSON response into json_out. Same proxy/TLS/SSRF handling and
 * buffer bounds as alosint_rdap_lookup.
 *
 * Parameters:
 *   ip        NUL-terminated IPv4 or IPv6 address (borrowed, read-only).
 *   json_out  caller-owned buffer for the NUL-terminated JSON body.
 *   max_len   capacity of json_out in bytes, including the terminating NUL.
 *
 * Returns:
 *    0  success.
 *   -1  invalid IP, transport/curl error, or bad arguments.
 *   -2  HTTP error (response status outside 2xx).
 */
int alosint_rdap_lookup_ip(const char *ip, char *json_out, int max_len);

#endif /* ALOSINT_RDAP_H */
