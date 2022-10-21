#!/bin/bash

set -e

SCRIPT_DIR=$(dirname -- "$0")

source $SCRIPT_DIR/util/common.sh

for dir in $SCRIPT_DIR/test-*/
do
    dir=${dir%*/}
    echo "Running ${dir##*/}..."
    export BASE_DIR=$(pwd)
    cd $dir; source $BASE_DIR/$dir/run.sh
done
