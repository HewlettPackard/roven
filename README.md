# Project Roven

Project Roven is a set of hybrid [node attestors](https://spiffe.io/docs/latest/spire-about/spire-concepts/#node-attestation) for [SPIRE](https://github.com/spiffe/spire).

## Kubernetes PSAT + TPM Device ID Node Attestor

[`k8s_psat_tpm_devid`](k8s_psat_tpm_devid/README.md) is a hybrid, external node attestor plugin for SPIRE, and it combines the power of two built in plugins: `k8s_psat` and `tpm_devid`.

# Hybrid Node Attestor

[`hybrid`](hybrid/README.md) node attestor plugin for SPIRE is an external plugin, that combines the power of most of the built-in plugin supported by SPIRE. With this approach you can use any combination of the built-in supported plugins in order to attest the node. For example, you can mix the k8s_psat and the aws_iid plugins to attest that the agent node is running on an AWS EKS or an EC2 instance with a self managed k8s cluster.
