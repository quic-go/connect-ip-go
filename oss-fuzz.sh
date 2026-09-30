#!/bin/bash

set -euo pipefail

cd "$GOPATH/src/github.com/quic-go/connect-ip-go"
source .clusterfuzzlite/build.sh
