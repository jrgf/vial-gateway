#!/usr/bin/env bash
set -euo pipefail

gateway_url="${GATEWAY_URL:-http://127.0.0.1:8080}"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
API_KEY="${API_KEY:-development-only-key}"

curl_args=(--silent --show-error --include --connect-timeout 2 --max-time 5)

request() {
  printf '\n=== %s ===\n' "$1"
  shift
  curl "${curl_args[@]}" "$@"
  printf '\n'
}

request "liveness: expect 204" \
  "$gateway_url/health/live"

request "readiness: expect 204 while both backends are running" \
  "$gateway_url/health/ready"

request "missing API key: expect 401 JSON fault" \
  "$gateway_url/api/users/42"

request "users proxy: expect 200, upstream path /42, and query preserved" \
  -H "X-API-Key: $API_KEY" \
  -H "X-Request-ID: curl-users-1" \
  "$gateway_url/api/users/42?expand=roles"

request "orders proxy: expect 200 and JSON body preserved" \
  -X POST \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"sku":"vial-1","quantity":2}' \
  "$gateway_url/api/orders/"

request "CORS preflight: expect 204 for the configured origin" \
  -X OPTIONS \
  -H "Origin: http://localhost:3000" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: Content-Type, X-API-Key" \
  "$gateway_url/api/orders/"

request "unknown route: expect 404 JSON fault" \
  "$gateway_url/not-found"
