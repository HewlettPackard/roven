#!/bin/bash

timestamp() {
    date -u "+[%Y-%m-%dT%H:%M:%SZ]"
}

log-debug() {
    echo "$(timestamp) $*"
}

file-checksum() {
    sha256sum $* | sed 's/ .*//g'
}

replace-plugin-checksum() {
    replace "plugin_checksum = \".*\"" "plugin_checksum = \"$1\"" $2
}

replace() {
    sed -e "s:$1:$2:g" $3
}

kubectl-apply-stdin() {
    echo "$*" | kubectl apply -f -
}

kind-create-stdin() {
    echo "$*" | kind create cluster --wait 1m --config -
}

wait-for() {
    timeout $1 bash -c "$2"
}
