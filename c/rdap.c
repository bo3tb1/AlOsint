/* inet_pton/ntohl are POSIX.1-2001; request them under a strict -std=c99
 * build. Must precede any system header. */
#define _POSIX_C_SOURCE 200112L

#include "rdap.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <arpa/inet.h>
#include <netinet/in.h>

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

/* Accept only a conservative hostname grammar before placing the value into a
 * URL: ASCII letters/digits/hyphen in dot-separated labels (IDNs must be passed
 * as xn-- A-labels). This forbids '/', '?', '#', '@', '%', ':', whitespace and
 * any other character that could restructure the request URL. */
static int rdap_valid_domain(const char *d)
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
                return 0; /* empty label: leading dot or ".." */
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
            return 0; /* label longer than DNS allows */
        }
    }
    if (label == 0) {
        return 0; /* trailing dot */
    }
    return 1;
}

/* CURLOPT_PREREQFUNCTION (SSRF guard) needs libcurl >= 7.80.0. */
#if defined(LIBCURL_VERSION_NUM) && LIBCURL_VERSION_NUM >= 0x075000
#define RDAP_HAVE_PREREQ 1

/* `a` is an IPv4 address in host byte order. */
static int rdap_ipv4_is_private(uint32_t a)
{
    if ((a >> 24) == 0)   return 1;                 /* 0.0.0.0/8   "this host" */
    if ((a >> 24) == 10)  return 1;                 /* 10.0.0.0/8   private    */
    if ((a >> 24) == 127) return 1;                 /* 127.0.0.0/8  loopback   */
    if ((a >> 16) == (((uint32_t)169 << 8) | 254)) return 1; /* 169.254/16 link-local (metadata) */
    if ((a >> 20) == (((uint32_t)172 << 4) | 1))   return 1; /* 172.16.0.0/12  private  */
    if ((a >> 16) == (((uint32_t)192 << 8) | 168)) return 1; /* 192.168.0.0/16 private  */
    if ((a >> 22) == (((uint32_t)100 << 2) | 1))   return 1; /* 100.64.0.0/10  CGNAT    */
    return 0;
}

static int rdap_ip_is_private(const char *ip)
{
    struct in_addr v4;
    if (inet_pton(AF_INET, ip, &v4) == 1) {
        return rdap_ipv4_is_private(ntohl(v4.s_addr));
    }

    struct in6_addr v6;
    if (inet_pton(AF_INET6, ip, &v6) == 1) {
        const unsigned char *b = v6.s6_addr;

        int all_zero = 1;
        for (int i = 0; i < 16; i++) {
            if (b[i] != 0) { all_zero = 0; break; }
        }
        if (all_zero) {
            return 1; /* ::  unspecified */
        }
        if (b[0] == 0xfe && (b[1] & 0xc0) == 0x80) {
            return 1; /* fe80::/10 link-local */
        }
        if ((b[0] & 0xfe) == 0xfc) {
            return 1; /* fc00::/7 unique local */
        }

        /* ::1 loopback and ::ffff:a.b.c.d IPv4-mapped (/96). */
        static const unsigned char loopback[16] =
            { 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1 };
        if (memcmp(b, loopback, 16) == 0) {
            return 1;
        }
        static const unsigned char mapped_prefix[12] =
            { 0,0,0,0, 0,0,0,0, 0,0,0xff,0xff };
        if (memcmp(b, mapped_prefix, 12) == 0) {
            uint32_t a = ((uint32_t)b[12] << 24) | ((uint32_t)b[13] << 16) |
                         ((uint32_t)b[14] << 8)  |  (uint32_t)b[15];
            return rdap_ipv4_is_private(a);
        }
        return 0;
    }

    return 0; /* unparseable address: let libcurl decide */
}

/* Runs after DNS resolution and before each request (including every redirect
 * hop). Aborting here turns an SSRF attempt into a transport error. */
static int rdap_prereq_cb(void *clientp,
                          char *conn_primary_ip, char *conn_local_ip,
                          int conn_primary_port, int conn_local_port)
{
    (void)clientp;
    (void)conn_local_ip;
    (void)conn_primary_port;
    (void)conn_local_port;

    if (conn_primary_ip != NULL && rdap_ip_is_private(conn_primary_ip)) {
        return CURL_PREREQFUNC_ABORT;
    }
    return CURL_PREREQFUNC_OK;
}
#endif /* libcurl >= 7.80.0 */

int alosint_rdap_lookup(const char *domain, char *json_out, int max_len)
{
    if (domain == NULL || json_out == NULL || max_len <= 0) {
        return -1;
    }

    /* Never leave the output uninitialized for callers that ignore the code. */
    json_out[0] = '\0';

    /* Validate before interpolating into the URL (defends against URL
     * injection). Invalid input is a client/transport error. */
    if (!rdap_valid_domain(domain)) {
        return -1;
    }

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

    /* Constrain the scheme to HTTPS for the initial request and for every
     * redirect target, so a redirect cannot escape to file://, gopher://, etc. */
#if defined(LIBCURL_VERSION_NUM) && LIBCURL_VERSION_NUM >= 0x075500
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "https");
    curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS_STR, "https");
#else
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS, (long)CURLPROTO_HTTPS);
    curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS, (long)CURLPROTO_HTTPS);
#endif

    /* Reject connections to private/loopback/link-local hosts (SSRF guard). */
#ifdef RDAP_HAVE_PREREQ
    curl_easy_setopt(curl, CURLOPT_PREREQFUNCTION, rdap_prereq_cb);
#endif

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
