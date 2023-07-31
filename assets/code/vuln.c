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