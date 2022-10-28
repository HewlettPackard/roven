FROM gcr.io/spiffe-io/spire-agent:1.4.4 AS spire-agent-psat-iid
COPY ./build/linux/amd64/hybrid_agent /usr/local/bin/agentattestor
RUN chmod +x /usr/local/bin/agentattestor
