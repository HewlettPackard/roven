# Project Roven

Project Roven is a set of hybrid external [node attestors](https://spiffe.io/docs/latest/spire-about/spire-concepts/#node-attestation) for [SPIRE](https://github.com/spiffe/spire).

## Kubernetes PSAT + TPM Device ID Node Attestor

[`k8s_psat_tpm_devid`](k8s_psat_tpm_devid/README.md) is a hybrid, external node attestor plugin for SPIRE, and it combines the power of two built in plugins: [`k8s_psat`](https://github.com/spiffe/spire/blob/main/doc/plugin_server_nodeattestor_k8s_psat.md) and [`tpm_devid`](https://github.com/spiffe/spire/blob/main/doc/plugin_server_nodeattestor_tpm_devid.md).

## Hybrid Node Attestor

[`hybrid`](hybrid/README.md) node attestor plugin for SPIRE is an external plugin, that combines the power of most of the built-in plugin supported by SPIRE. With this approach you can use any combination of the built-in supported plugins in order to attest the node. For example, you can mix the k8s_psat and the aws_iid plugins to attest that the agent node is running on an AWS EKS or an EC2 instance with a self managed k8s cluster.
