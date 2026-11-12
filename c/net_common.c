#include "net_common.h"

#include <curl/curl.h>

/* Module-level Tor routing state, shared across all libcurl call sites. */
static int g_tor_enabled = 0;

void alosint_set_tor(int enabled)
{
    g_tor_enabled = (enabled != 0) ? 1 : 0;
}

int alosint_get_tor(void)
{
    return g_tor_enabled;
}

int alosint_apply_curl_options(void *curl)
{
    if (curl == NULL) {
        return -1;
    }
    if (g_tor_enabled == 0) {
        return 0; /* no-op: direct requests are intentional when Tor is off */
    }

    CURL *handle = (CURL *)curl;

    /* "socks5h" makes libcurl hand the hostname to the proxy for resolution, so
     * DNS happens inside Tor and never leaks to the local resolver. Setting the
     * proxy type explicitly matches the scheme. Every option is checked: if any
     * fails while Tor is enabled we report failure so the caller aborts rather
     * than sending the request unproxied (which would deanonymize the user). */
    if (curl_easy_setopt(handle, CURLOPT_PROXY, "socks5h://127.0.0.1:9050") != CURLE_OK) {
        return -1;
    }
    if (curl_easy_setopt(handle, CURLOPT_PROXYTYPE,
                         (long)CURLPROXY_SOCKS5_HOSTNAME) != CURLE_OK) {
        return -1;
    }
    /* Ignore any NO_PROXY/no_proxy environment exclusion so it cannot route a
     * request around Tor. */
    if (curl_easy_setopt(handle, CURLOPT_NOPROXY, "") != CURLE_OK) {
        return -1;
    }
    return 0;
}
