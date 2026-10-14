#!/bin/bash

set -euo pipefail

echo "Build date (UTC): $(date -u '+%Y-%m-%dT%H:%M:%SZ')"

cd "$GOPATH/src/github.com/quic-go/connect-ip-go"
git log -1 --format='connect-ip-go revision: %H (%cI) %s'
source .clusterfuzzlite/build.sh
