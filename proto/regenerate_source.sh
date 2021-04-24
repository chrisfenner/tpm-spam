#!/bin/bash
# Run this script to regenerate generated proto code with any changes to the
# policy.proto
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
pushd ${DIR} > /dev/null
protoc ./policy.proto --go_out=..
popd > /dev/null
