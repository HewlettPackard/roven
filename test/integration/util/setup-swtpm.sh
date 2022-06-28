#!/bin/bash

source $(dirname "$0")/common.sh

mkdir $MOUNT_DIR;

log-debug "Setting up provisioning"
(cd dev/provisioning; make build; make setup-provisioning)

log-debug "Running swptm"
(cd dev/provisioning; make run-swtpm &)
wait-for 20 "while [ ! -f $DEFAULT_TPM_SOCKET ]; do sleep 1; done"

log-debug "Running provisioning server"
(cd dev/provisioning && make provisioning-server &)

log-debug "Waiting for provisioning server to be ready"
wait-for 20 'until echo > /dev/tcp/localhost/8443; do sleep 1 && date; done' 2>/dev/null
test $? -eq 0 || (echo "Server provisioning not initialized."; exit 1)

log-debug "Running provisioning agent"
(cd dev/provisioning; make provisioning-agent)

log-debug "Copying all files to cluster mount directory"
cp build/linux/amd64/devid_psat_attestor_* dev/provisioning/swtpm-container/manufacture-tpm/output/ekroot.pem dev/provisioning/conf/server/provisioning-ca.crt dev/provisioning/out/devid-* $MOUNT_DIR
