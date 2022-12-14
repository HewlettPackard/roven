#!/bin/bash

ROOTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
COMMON="${ROOTDIR}/common"

# shellcheck source=./common
source "${COMMON}"

[ -n "$1" ] || fail-now "must pass the test suite directory as the first argument"
[ -d "$1" ] || fail-now "$1 does not exist or is not a directory"

TESTDIR="$( cd "$1" && pwd )"
TESTNAME="$(basename "${TESTDIR}")"

log-debug "running \"${TESTNAME}\" test suite..."

[ -x "${TESTDIR}"/teardown ] || fail-now "missing required teardown script or it is not executable"
[ -f "${TESTDIR}"/README.md ] || fail-now "missing required README.md file"


#################################################
# Execute the test suite
#################################################
run-step() {
    local script="$1"
    if [ ! -x "$script" ]; then
        log-warn "skipping \"$script\"; not executable"
        return
    fi
    log-debug "executing $(basename "$script")..."

    bash -s <<STEPSCRIPT
set -e -o pipefail
source "${COMMON}"
source "${script}"
STEPSCRIPT
}

cd "${TESTDIR}" || fail-now "cannot change to run directory"
shopt -s nullglob
steps=( ??-* )
if [ ${#steps[@]} -eq 0 ]; then
    fail-now "test suite has no steps"
fi
for step in "${steps[@]}"; do
    if ! run-step "$step"; then
        fail-now "step $(basename "$step") failed"
    fi
done