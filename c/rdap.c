#include "rdap.h"

#include <stdio.h>
#include <string.h>

#include <curl/curl.h>

/* Bounded write sink: C copies at most `cap` bytes into a caller-owned buffer,
 * tracking how many were stored. The transfer is always fully consumed so
 * libcurl completes cleanly even when the body is truncated. */
struct rdap_sink {
    char  *buf;
    size_t cap;   /* bytes available for payload (NUL reserved separately) */
    size_t len;   /* bytes actually stored, 0..=cap */
};

static size_t rdap_write_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    size_t incoming = size * nmemb;
    struct rdap_sink *s = (struct rdap_sink *)userdata;

    if (s->len < s->cap) {
        size_t room = s->cap - s->len;
        size_t copy = incoming < room ? incoming : room;
        memcpy(s->buf + s->len, ptr, copy);
        s->len += copy;
    }

    /* Report the full count: returning less would abort the transfer. */
    return incoming;
}

int alosint_rdap_lookup(const char *domain, char *json_out, int max_len)
{
    if (domain == NULL || json_out == NULL || max_len <= 0) {
        return -1;
    }

    /* Never leave the output uninitialized for callers that ignore the code. */
    json_out[0] = '\0';

    char url[600];
    int n = snprintf(url, sizeof(url), "https://rdap.org/domain/%s", domain);
    if (n < 0 || (size_t)n >= sizeof(url)) {
        return -1; /* domain too long to form a bounded URL */
    }

    CURL *curl = curl_easy_init();
    if (curl == NULL) {
        return -1;
    }

    struct rdap_sink sink;
    sink.buf = json_out;
    sink.cap = (size_t)max_len - 1; /* reserve one byte for the NUL terminator */
    sink.len = 0;

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, rdap_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &sink);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L); /* rdap.org bootstraps via redirect */
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 8L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "alosint/0.1");
    curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, ""); /* accept any supported encoding */
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

    CURLcode res = curl_easy_perform(curl);

    /* Terminate whatever was captured (sink.len <= max_len-1, so this is safe). */
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
