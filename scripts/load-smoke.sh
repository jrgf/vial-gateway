#!/usr/bin/env bash
set -euo pipefail

gateway_url="${GATEWAY_URL:-http://127.0.0.1:8080}"
api_key="${API_KEY:-development-only-key}"
requests="${REQUESTS:-100}"
concurrency="${CONCURRENCY:-10}"
max_p95="${MAX_P95_SECONDS:-0.5}"
results="$(mktemp)"
trap 'rm -f "$results"' EXIT

export gateway_url api_key results
seq "$requests" | xargs -P "$concurrency" -I '{}' sh -c \
  'curl --silent --output /dev/null --write-out "%{http_code} %{time_total}\n" -H "X-API-Key: $api_key" "$gateway_url/api/users/load?request={}" >>"$results"'

success="$(awk '$1 == 200 {count++} END {print count+0}' "$results")"
p95="$(awk '{print $2}' "$results" | sort -n | awk -v count="$requests" 'NR >= int(count*0.95+0.999) {print; exit}')"
awk -v success="$success" -v total="$requests" -v p95="$p95" -v maximum="$max_p95" \
  'BEGIN {printf "success=%d/%d p95=%0.3fs limit=%0.3fs\n",success,total,p95,maximum; exit !(success==total && p95<=maximum)}'
