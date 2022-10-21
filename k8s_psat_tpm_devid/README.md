[![PR Build](https://github.com/HewlettPackard/roven/actions/workflows/k8s_psat_tpm_devid-pr-build.yaml/badge.svg)](https://github.com/HewlettPackard/roven/actions/workflows/k8s_psat_tpm_devid-pr-build.yaml)

# k8s_psat_tpm_devid Node Attestor

`k8s_psat_tpm_devid` is a hybrid, external node attestor plugin for SPIRE, and it combines the power of two built in plugins: `k8s_psat` and `tpm_devid`.

## Basic deployment

As to run any SPIRE external plugin, there are a some extra considerations we need to worry about when deploying. For instance, we'll have to calculate the plugin sha256sum and use it in the configuration, and also serve the plugin's agent and server binaries together in the containers running SPIRE Server and Agent. Other specific requirements appear because of Kubernetes and TPM, and also because of having to combine those. 

For simplicity, this deployment will not require availability of a real TPM. It will instead use a TPM simulator called `swtpm`, that outputs a socket file instead of a device file. This facilitate exposing the socket along with all other required files through the usage of a `hostPath` volumeMount into a Kubernetes cluster. This example will use a single-node, `kind` cluster.


### Deploying through Kubernetes `hostPath` support via `Kind`:

Start by building the binaries

`make build`

Create the directory we will share with the cluster

`mkdir k8s-mount`

We need to provide both the agent and server side plugins sha256 in the configuration files. To calculate the sha256 checksum for the binaries run:

`sha256sum build/linux/amd64/devid_psat_attestor_agent`

`sha256sum build/linux/amd64/devid_psat_attestor_server`

Now update the respective server and agent configmap `plugin_checksum` fields (under `dev/common`) with the generated values.

Before jumping into the next step, we need to set up `swtpm`. Please follow the steps described [here](dev/README.md) and come back when you're done. Remember to set `DEFAULT_TPM_SOCKET` to the `k8s-mount` directory we created when running steps `3` and `5`.

Finally, copy all the needed files to the mount directory:

`cp build/linux/amd64/devid_psat_attestor_* dev/provisioning/swtpm-container/manufacture-tpm/output/ekroot.pem dev/provisioning/conf/server/provisioning-ca.crt dev/provisioning/out/devid-* k8s-mount/`

Time to set up our cluster.

The extra consideration here is providing the `hostPath`. For that, we need to tell kind the path to the mount directory. 

Update the hostPath field under `dev/kind/kind-conf.yaml` with the **absolute path** of the directory `k8s-mount` we created.

Now provide the configuration file when creating the cluster:

`kind create cluster --config dev/kind/kind-conf.yaml`

Deploy spire:

`cd dev/kind`

`./deploy-spire.sh`

