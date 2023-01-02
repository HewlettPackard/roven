FROM gcr.io/spiffe-io/spire-server:1.5.1 AS spire-server-psat-iid
COPY ./build/linux/amd64/hybridserver /usr/local/bin/serverattestor
RUN chmod +x /usr/local/bin/serverattestor
