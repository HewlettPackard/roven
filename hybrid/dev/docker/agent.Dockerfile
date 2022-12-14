FROM gcr.io/spiffe-io/spire-agent:1.5.1 AS spire-agent-psat-iid
COPY ./build/linux/amd64/hybridagent /usr/local/bin/agentattestor
RUN chmod +x /usr/local/bin/agentattestor
