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

void alosint_apply_curl_options(void *curl)
{
    if (curl == NULL || g_tor_enabled == 0) {
        return;
    }

    CURL *handle = (CURL *)curl;

    /* "socks5h" makes libcurl hand the hostname to the proxy for resolution, so
     * DNS happens inside Tor and never leaks to the local resolver. Setting the
     * proxy type explicitly matches the scheme. */
    curl_easy_setopt(handle, CURLOPT_PROXY, "socks5h://127.0.0.1:9050");
    curl_easy_setopt(handle, CURLOPT_PROXYTYPE, (long)CURLPROXY_SOCKS5_HOSTNAME);
}
