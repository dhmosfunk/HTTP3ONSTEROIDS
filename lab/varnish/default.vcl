vcl 4.0;

backend default {
    .host = "backend-server";
    .port = "8080";
}

sub vcl_recv {
    if (req.restarts == 0) {
        if (req.http.X-Forwarded-For) {
            set req.http.X-Forwarded-For = req.http.X-Forwarded-For + ", " + client.ip;
        } else {
            set req.http.X-Forwarded-For = client.ip;
        }
    }
}

sub vcl_backend_response {
    if (beresp.status == 200) {
        set beresp.ttl = 5m;
    }
}