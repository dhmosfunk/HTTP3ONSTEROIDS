FROM debian:latest

RUN apt update && apt upgrade -y && apt install -y \
    make \
    ca-certificates \
    gcc \
    libssl-dev \
    wget \
    lua5.3 \
    libpcre3-dev \
    zlib1g-dev \
    liblua5.3-dev \
    perl \
    libfindbin-libs-perl \
    git

# Fix error with lua libraries
ENV LUA_LIB_NAME lua5.3
ENV C_INCLUDE_PATH /usr/include/lua5.3

# Install and compile compatible OpenSSL to QUIC protocol.
RUN git clone https://github.com/quictls/openssl \
    && cd openssl \
    && git checkout OpenSSL_1_1_1t+quic \
    && mkdir -p /opt/quictls \
    && ./config --prefix=/opt/quictls enable-tls1_3 enable-quic \
    && make \
    && make install

ARG haproxy_version

# Install and compile vulnerable version of haproxy
RUN if [ "$haproxy_version" = "vuln" ]; then \
        # Vulnerable version
        wget https://www.haproxy.org/download/2.7/src/haproxy-2.7.0.tar.gz; \ 
    elif [ "$haproxy_version" = "patched" ]; then \
        # Patched version
        wget https://www.haproxy.org/download/2.8/src/haproxy-2.8.1.tar.gz; \
    else \
        # Invalid version
        echo "Invalid HAProxy version specified"; \
        exit 1; \
    fi 

RUN tar -xf haproxy-*.tar.gz &&\
    cd haproxy-* && \
    make TARGET=linux-glibc \
        USE_OPENSSL=1 \
        USE_ZLIB=1 \
        USE_PCRE=1 \
        USE_LIBCRYPT=1 \
        USE_REGPARAM=1 \
        USE_THREAD=1 \
        USE_PTHREAD_PSHARED=1 \
        USE_TFO=1 \
        USE_NFQUEUE=1 \
        USE_LUA=1 \
        USE_DYNODE=1 \
        USE_QUIC=1 \
        USE_QUIC_FRAME_GQUIC=1 \
        SSL_INC=/opt/quictls/include \
        SSL_LIB=/opt/quictls/lib \
        LDFLAGS="-Wl,-rpath,/opt/quictls/lib" \
    && make install-bin \
    && mv haproxy /usr/bin

RUN mkdir -p /etc/haproxy \
    && mkdir -p /run/haproxy \
    && mkdir -p /etc/haproxy/certs 

COPY conf/haproxy.cfg /etc/haproxy/haproxy.cfg
COPY conf/certs/. /etc/haproxy/certs/.

EXPOSE 80 443

CMD ["haproxy", "-f", "/etc/haproxy/haproxy.cfg"] 
