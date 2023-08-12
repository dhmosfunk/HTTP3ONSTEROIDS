![](assets/images/image.png)

## Table of contents
- [Vulnerability Description](#vulnerability-description)
    - [Source Code Review](#source-code-review)
- [Lab Setup](#lab-setup)
    - [Identifying the issue](#identifying-the-issue)
- [References](#references)



## Vulnerability Description
HAProxy's HTTP/3 implementation fails to block a **malformed HTTP header field name**, and **when deployed in front of a server that incorrectly process this malformed header**, it may be used to conduct an HTTP request/response smuggling attack. A remote attacker may alter a legitimate user's request. As a result, the attacker may obtain sensitive information or cause a denial-of-service (DoS) condition.

[https://jvn.jp/en/jp/JVN38170084/](https://jvn.jp/en/jp/JVN38170084/)


### Source Code Review
A very good approach before starting any research on CVEs is to begin by reading the vulnerability description and then check if the commit(s) for patching are available. \
In my case, the commit was available, and it is evident that the developers of HAProxy forgot to include the **[RFC 9114 4.1.2. Malformed Requests and Responses](https://datatracker.ietf.org/doc/html/rfc9114#name-malformed-requests-and-resp)** checks during the parsing of the standard headers on **HTTP3 implementation**.

Refer to the patch commit below.
```diff
--- a/src/h3.c
+++ b/src/h3.c
@@ -352,7 +352,27 @@ static ssize_t h3_headers_to_htx(struct qcs *qcs, const struct buffer *buf,
        //struct ist scheme = IST_NULL, authority = IST_NULL;
        struct ist authority = IST_NULL;
        int hdr_idx, ret;
-       int cookie = -1, last_cookie = -1;
+       int cookie = -1, last_cookie = -1, i;
+
+       /* RFC 9114 4.1.2. Malformed Requests and Responses
+        *
+        * A malformed request or response is one that is an otherwise valid
+        * sequence of frames but is invalid due to:
+        * - the presence of prohibited fields or pseudo-header fields,
+        * - the absence of mandatory pseudo-header fields,
+        * - invalid values for pseudo-header fields,
+        * - pseudo-header fields after fields,
+        * - an invalid sequence of HTTP messages,
+        * - the inclusion of uppercase field names, or
+        * - the inclusion of invalid characters in field names or values.
+        *
+        * [...]
+        *
+        * Intermediaries that process HTTP requests or responses (i.e., any
+        * intermediary not acting as a tunnel) MUST NOT forward a malformed
+        * request or response. Malformed requests or responses that are
+        * detected MUST be treated as a stream error of type H3_MESSAGE_ERROR.
+        */
 
        TRACE_ENTER(H3_EV_RX_FRAME|H3_EV_RX_HDR, qcs->qcc->conn, qcs);
 
@@ -416,6 +436,14 @@ static ssize_t h3_headers_to_htx(struct qcs *qcs, const struct buffer *buf,
                if (isteq(list[hdr_idx].n, ist("")))
                        break;
 
+               for (i = 0; i < list[hdr_idx].n.len; ++i) {
+                       const char c = list[hdr_idx].n.ptr[i];
+                       if ((uint8_t)(c - 'A') < 'Z' - 'A' || !HTTP_IS_TOKEN(c)) {
+                               TRACE_ERROR("invalid characters in field name", H3_EV_RX_FRAME|H3_EV_RX_HDR, qcs->qcc->conn, qcs);
+                               return -1;
+                       }
+               }
+
                if (isteq(list[hdr_idx].n, ist("cookie"))) {
                        http_cookie_register(list, hdr_idx, &cookie, &last_cookie);
                        continue;
```

[Repositories - haproxy-2.7.git/commit](https://git.haproxy.org/?p=haproxy-2.7.git;a=blobdiff;f=src/h3.c;h=5f1c68a29e5d05f4ce18e8dfea2334b7009aa03e;hp=97e821efefb3d52b4d55d311c4043194247ad2ea;hb=3ca4223c5e1f18a19dc93b0b09ffdbd295554d46;hpb=20bd4a8d1507e3ee6d52cc5af6c23a006b0e3a75)

Below, you can find the code that demonstrates the absence of header name sanitization in the implementation of handling standard headers on **HAProxy 2.7.0**.
```c
/* 
src/h3.c 
lines: 413 - 428
*/

/* now treat standard headers */
hdr_idx = 0;
while (1) {
    if (isteq(list[hdr_idx].n, ist("")))
        break;
    if (isteq(list[hdr_idx].n, ist("cookie"))) {
        http_cookie_register(list, hdr_idx, & cookie, & last_cookie);
        continue;
    }
    if (!istmatch(list[hdr_idx].n, ist(":")))
        htx_add_header(htx, list[hdr_idx].n, list[hdr_idx].v);
    ++hdr_idx;
}
```

Below, you can find the code that is used to check if header name is valid. \
\
The code starts with a for loop that iterates through each character of a header field name. The loop runs from `i = 0` to `i < list[hdr_idx0.n.len]`, where `list` is an array or structure containing header information, and `hdr_idx` is an index representing the spicific header being checked.\
Inside the loop , the code extracts the current character `c` from the header field name.
`list[hdr_idx].n.ptr[i]` accesses the character at the `i`-th position in the header field's name. 
The next part of the code contains an `if` statement. It checks whether the current character `c` satisfies one of two conditions:
- `(uint8_t)(c - 'A') < 'Z' - 'A'`: This checks if the character is an uppercase letter (A to Z) by subtracting 'A' from `c` and casting the result to `uint8_t` If the result is less than the difference between 'Z' and 'A', then the character is an uppercase letter.
- `!HTTP_IS_TOKEN(c)`: This condition checks if the character is a valid HTTP token character. The `HTTP_IS_TOKEN` works by first checking if the header name contains any tokens. A token is a sequence of characters that is not a reserved character in the HTTP protocol. Reserved characters are characters that have special meaning in the HTTP protocol, e.g. `:`, `/`, `?`, and `#`.
```c
/* 
src/h3.c 
lines: 439 - 445
*/
for (i = 0; i < list[hdr_idx].n.len; ++i) {
    const char c = list[hdr_idx].n.ptr[i];
    if ((uint8_t)(c - 'A') < 'Z' - 'A' || !HTTP_IS_TOKEN(c)) {
        TRACE_ERROR("invalid characters in field name", H3_EV_RX_FRAME | H3_EV_RX_HDR, qcs -> qcc -> conn, qcs);
        return -1;
    }
}
```


## Lab Setup
The entire lab is running on Docker. You can run the lab with the following commands:
1. `cd /lab`
2. `docker-compose up --build`

Please note that the Docker build will take **15-20** minutes to finish. \
However, before running the lab, you have to make some configuration changes:

`/lab/haproxy/conf/haproxy.cfg`
```bash
...
default_backend api_server

backend api_server
  balance roundrobin
  server api_server [YOUR-LOCAL-IPv4]:8080 # replace with local IPv4
```

`/etc/hosts`
```bash
[YOUR-LOCAL-IPv4]   foo.com
```

`/lab/docker-compose.yml` \
You can choose between the vulnerable version and the patched version by changing the argument's value to **'vuln'** or **'patched'** to conduct your test on it.
```
...
    args:
        - haproxy_version=patched || vuln
...
```

and finally import the **minica.crt** certificate in your browser.

⚠️ Please run the lab in a Linux environment.


## Identifying the issue

Sending the following curl request:
- `curl --http3 -H "foooooo\r\n: barr" -iL -k  https://192.168.1.104/`

Vulnerable version response:
```
HTTP/3 200 
server: Werkzeug/2.3.6 Python/3.8.17  
date: Sat, 12 Aug 2023 13:10:52 GMT   
content-type: text/html; charset=utf-8
content-length: 76
alt-svc: h3=":443";ma=900;

Host: 192.168.1.104
User-Agent: curl/8.1.2-DEV
Accept: */*
Foooooo\R\N: barr <-- Malformed header
```

Patched version response:
```
curl: (56) HTTP/3 stream 0 reset by server
```

Based on the above findings, the corresponding responses indicate that the vulnerable version of HAProxy allowed the **\r\n** prefix to pass through to the backend server, whereas the patched version dropped the connection between the client and HAProxy.

---

An attacker can conduct an HTTP Request Smuggling attack based on backend behavior and how the backend server will treat the malformed header. In my view, the most significant concern is that an attacker could exploit the aforementioned CVE to carry out a Denial of Service (DoS) attack.


## References:
[https://jvn.jp/en/jp/JVN38170084/](https://jvn.jp/en/jp/JVN38170084/) \
[https://github.com/haproxytechblog/haproxy-2.6-http3](https://github.com/haproxytechblog/haproxy-2.6-http3) \
[https://www.haproxy.com/blog/how-to-enable-quic-load-balancing-on-haproxy](https://www.haproxy.com/blog/how-to-enable-quic-load-balancing-on-haproxy) \
[https://git.haproxy.org/](https://git.haproxy.org/) \
[https://github.com/jsha/minica](https://github.com/jsha/minica) \
[https://curl.se/docs/http3.html](https://curl.se/docs/http3.html)