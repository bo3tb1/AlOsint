#ifndef ALOSINT_DNS_H
#define ALOSINT_DNS_H

/*
 * alosint_dns_lookup — resolve a hostname to its first IPv4 (A) address.
 *
 * Parameters:
 *   domain   NUL-terminated hostname to resolve (borrowed, read-only).
 *   ip_out   caller-owned buffer that receives a NUL-terminated dotted-quad
 *            string (e.g. "93.184.216.34"); written by this function.
 *   max_len  capacity of ip_out in bytes, including the terminating NUL.
 *
 * Ownership: the caller owns ip_out; this function only writes into it and
 * never exceeds max_len. No memory crosses the FFI boundary to be freed.
 *
 * Returns:
 *    0  success; ip_out holds a NUL-terminated IPv4 string.
 *   <0  failure (bad arguments, resolution error, no IPv4 address, or the
 *       result did not fit in max_len). On failure ip_out is set to "" when
 *       max_len permits.
 */
int alosint_dns_lookup(const char *domain, char *ip_out, int max_len);

#endif /* ALOSINT_DNS_H */
