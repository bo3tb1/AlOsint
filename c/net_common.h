#ifndef ALOSINT_NET_COMMON_H
#define ALOSINT_NET_COMMON_H

/*
 * Shared network configuration for every libcurl call site.
 *
 * This header is deliberately free of <curl/curl.h>: the CURL easy handle is
 * passed as an opaque void*, so Goose and other translation units can declare
 * the proxy toggle without pulling in libcurl's headers.
 */

/* Enable (enabled != 0) or disable (0) routing all requests through the Tor
 * SOCKS5 proxy at 127.0.0.1:9050. Process-wide module-level state. */
void alosint_set_tor(int enabled);

/* Returns the current Tor routing state: 1 if enabled, 0 otherwise. */
int alosint_get_tor(void);

/*
 * Apply the shared proxy options to a CURL easy handle (passed as void*).
 * When Tor is enabled this sets CURLOPT_PROXY to "socks5h://127.0.0.1:9050"
 * and CURLOPT_PROXYTYPE to CURLPROXY_SOCKS5_HOSTNAME (so DNS is resolved by the
 * proxy, inside Tor). When disabled, it is a no-op. Call it right after
 * curl_easy_init(), before any other option is set on the handle.
 */
void alosint_apply_curl_options(void *curl);

#endif /* ALOSINT_NET_COMMON_H */
