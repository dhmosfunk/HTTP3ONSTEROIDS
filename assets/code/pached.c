 /* now treat standard headers */
 hdr_idx = 0;
 while (1) {
     if (isteq(list[hdr_idx].n, ist("")))
         break;

     for (i = 0; i < list[hdr_idx].n.len; ++i) {
         const char c = list[hdr_idx].n.ptr[i];
         if ((uint8_t)(c - 'A') < 'Z' - 'A' || !HTTP_IS_TOKEN(c)) {
             TRACE_ERROR("invalid characters in field name", H3_EV_RX_FRAME | H3_EV_RX_HDR, qcs -> qcc -> conn, qcs);
             return -1;
         }
     }

     if (isteq(list[hdr_idx].n, ist("cookie"))) {
         http_cookie_register(list, hdr_idx, & cookie, & last_cookie);
         continue;
     }

     if (!istmatch(list[hdr_idx].n, ist(":")))
         htx_add_header(htx, list[hdr_idx].n, list[hdr_idx].v);

     ++hdr_idx;
 }