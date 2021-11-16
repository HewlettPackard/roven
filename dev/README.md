# Development hints

## Provisioning

There's a [Makefile](./provisioning/Makefile) in the `provisioning` directory that helps with the common tasks.

### Using software TPM (swtpm) to provision DevID certificates

1. (Optional) Clone and build the provisioning tool: `make build`
2. Create and setup certificates: `make setup-provisioning`
3. Clone and run swtpm: `make run-swtpm`. _(runs on /tmp/swtpm.sock by default. To specify a path, set DEFAULT_TPM_SOCKET when invoking this make target)_
4. Run the provisioning server: `make provisioning-server`
5. Run the provisioning agent: `make provisioning-agent` _(runs on /tmp/swtpm.sock by default. To specify a path, set DEFAULT_TPM_SOCKET when invoking this make target)_

The DevID certificates will be in `dev/provisioning/out/`, unless a different `out_dir` is set in [`agent.conf`](provisioning/conf/agent/agent.conf)

### Using hardware TPM to provision DevID certificates

1. (Optional) Clone and build the provisioning tool: `make build`
2. Create and setup certificates: `make setup-provisioning`
3. Edit [server.conf](provisioning/conf/server/server.conf), uncomment the lines below `Production certificate chain`, and comment the line below `Development root certificate`
4. Edit [agent.conf](provisioning/conf/agent/agent.conf), comment `tpm_path` or set it to your hardware tpm file path
5. Run the provisioning server: `make provisioning-server`
6. Run the provisioning agent: `make provisioning-agent`

