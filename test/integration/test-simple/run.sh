#!/bin/bash

set -e

log-debug "Creating kind cluster"

kind-create-stdin "$(replace "HOST_PATH" "$HOME/k8s-mount" kind-conf.yaml)"

log-debug "Deploying SPIRE"

server_hash=$(file-checksum $BASE_DIR/build/linux/amd64/devid_psat_attestor_server)
agent_hash=$(file-checksum $BASE_DIR/build/linux/amd64/devid_psat_attestor_agent)

kubectl-apply-stdin "$(replace-plugin-checksum $server_hash spire-server.yaml)"
kubectl-apply-stdin "$(replace-plugin-checksum $agent_hash spire-agent.yaml)"

log-debug "Waiting for deployments to be ready"

kubectl rollout status daemonset -n spire spire-agent --timeout 1m
kubectl wait --for=condition=ready --timeout=1m pod -n spire -l app=spire-server
kubectl wait --for=condition=ready --timeout=1m pod -n spire -l app=spire-agent

log-debug "Checking assertions"

log-debug "Checking node attestation"

assert_regex='.*\"Node attestation was successful.*\"spiffe:\/\/example.org\/spire\/agent\/k8s_psat_tpm_devid\/demo-cluster\/[a-z0-9\-]{36}\"'
wait-for 20 "until kubectl logs -n spire -l app=spire-agent -c spire-agent | grep -E '$assert_regex'; do sleep 1; done"

kind delete cluster
