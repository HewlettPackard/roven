#!/bin/bash

set -e

kubectl apply -f ../common/spire-namespace.yaml;

kubectl apply -f ../common

sleep 1;

kubectl apply -f agent-daemonset.yaml
kubectl apply -f server-statefulset.yaml
