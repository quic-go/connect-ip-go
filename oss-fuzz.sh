#!/bin/bash

set -euo pipefail

cd "$GOPATH/src/github.com/quic-go/connect-ip-go"

compile_native_go_fuzzer_v2 github.com/quic-go/connect-ip-go FuzzIncomingDatagram incoming_datagram_fuzzer
