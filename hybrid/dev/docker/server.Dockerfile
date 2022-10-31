FROM gcr.io/spiffe-io/spire-server:1.4.4 AS spire-server-psat-iid
COPY ./build/linux/amd64/hybrid_server /usr/local/bin/serverattestor
RUN chmod +x /usr/local/bin/serverattestor
