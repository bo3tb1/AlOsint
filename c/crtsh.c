#include "crtsh.h"

#include <stdio.h>
#include <string.h>

#include <curl/curl.h>

struct crtsh_sink {
    char  *buf;
    size_t cap;
    size_t len;
};

static size_t crtsh_write_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    size_t incoming = size * nmemb;
    struct crtsh_sink *s = (struct crtsh_sink *)userdata;

    if (s->len < s->cap) {
        size_t room = s->cap - s->len;
        size_t copy = incoming < room ? incoming : room;
        memcpy(s->buf + s->len, ptr, copy);
        s->len += copy;
    }

    return incoming;
}

static int crtsh_valid_domain(const char *d)
{
    size_t len = strlen(d);
    if (len == 0 || len > 253) {
        return 0;
    }

    size_t label = 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)d[i];
        if (c == '.') {
            if (label == 0) {
                return 0;
            }
            label = 0;
            continue;
        }
        int ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                 (c >= '0' && c <= '9') || c == '-';
        if (!ok) {
            return 0;
        }
        if (++label > 63) {
            return 0;
        }
    }
    if (label == 0) {
        return 0;
    }
    return 1;
}

int alosint_crtsh_lookup(const char *domain, char *json_out, int max_len)
{
    if (domain == NULL || json_out == NULL || max_len <= 0) {
        return -1;
    }

    json_out[0] = '\0';

    if (!crtsh_valid_domain(domain)) {
        return -1;
    }

    char url[600];
    int n = snprintf(url, sizeof(url), "https://crt.sh/?q=%%25.%s&output=json", domain);
    if (n < 0 || (size_t)n >= sizeof(url)) {
        return -1;
    }

    CURL *curl = curl_easy_init();
    if (curl == NULL) {
        return -1;
    }

    struct crtsh_sink sink;
    sink.buf = json_out;
    sink.cap = (size_t)max_len - 1;
    sink.len = 0;

#define CRTSH_SET(opt, val)                                     \
    do {                                                        \
        if (curl_easy_setopt(curl, (opt), (val)) != CURLE_OK) { \
            curl_easy_cleanup(curl);                            \
            return -1;                                          \
        }                                                       \
    } while (0)

    CRTSH_SET(CURLOPT_URL, url);
    CRTSH_SET(CURLOPT_WRITEFUNCTION, crtsh_write_cb);
    CRTSH_SET(CURLOPT_WRITEDATA, &sink);
    CRTSH_SET(CURLOPT_CONNECTTIMEOUT, 10L);
    CRTSH_SET(CURLOPT_TIMEOUT, 30L);
    CRTSH_SET(CURLOPT_USERAGENT, "alosint/0.1");
    CRTSH_SET(CURLOPT_ACCEPT_ENCODING, "");
    CRTSH_SET(CURLOPT_NOSIGNAL, 1L);
    CRTSH_SET(CURLOPT_SSL_VERIFYPEER, 1L);
    CRTSH_SET(CURLOPT_SSL_VERIFYHOST, 2L);

#if defined(LIBCURL_VERSION_NUM) && LIBCURL_VERSION_NUM >= 0x075500
    CRTSH_SET(CURLOPT_PROTOCOLS_STR, "https");
#else
    CRTSH_SET(CURLOPT_PROTOCOLS, (long)CURLPROTO_HTTPS);
#endif

#undef CRTSH_SET

    CURLcode res = curl_easy_perform(curl);

    json_out[sink.len] = '\0';

    if (res != CURLE_OK) {
        curl_easy_cleanup(curl);
        return -1;
    }

    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_easy_cleanup(curl);

    if (http_code < 200 || http_code >= 300) {
        return -2;
    }
    return 0;
}
