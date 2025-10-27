#!/usr/bin/env bash
set -euo pipefail
TARGET="$1"
PAYLOAD="$2"
# Default runs with network none to be safe
docker run --rm --network none curlimages/curl:8.2.1 -sS -X GET --path-as-is -- "$TARGET?p=$PAYLOAD" || true
