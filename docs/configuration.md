# Configuration reference

The gateway loads JSON from `--config` and then applies supported environment overrides. See [config.example.json](../config.example.json) for a complete runnable example. Durations use Go duration strings such as `500ms`, `10s`, or `5m`.

## Application settings

| Field | Purpose |
| --- | --- |
| `environment` | `development`, `test`, or a production value. Production enables stricter OIDC, CORS, and Dynamic DNS checks. |
| `http.host`, `http.port` | Listener address. Override with `VIAL_HTTP_HOST` and `VIAL_HTTP_PORT`. |
| `redis_url` | `redis://` or `rediss://` connection URL. Override with `VIAL_REDIS_URL`. |
| `control_only` | Runs the control service without data-plane routes. Override with `VIAL_CONTROL_ONLY`. |
| `admin` | OIDC, bootstrap authentication, external URL, and session settings. |
| `tls.cert_file`, `tls.key_file` | Optional direct TLS certificate and key. Configure both or neither. |
| `gateway` | Versioned data-plane configuration described below. |

Secrets should come from the environment or a secret manager. `VIAL_DYNAMIC_DNS_BEARER_TOKEN` is intentionally excluded from serialized configuration versions.

## Gateway settings

| Field | Purpose |
| --- | --- |
| `schema_version` | Must currently be `1`. |
| `version` | Positive immutable version identifier. The admin UI creates and atomically activates new versions. |
| `routes` | Ordered route declarations. At least one is required on a data-plane instance. |
| `auth_policies` | Named `none`, `api_key`, or `jwt` policies. |
| `rate_policies` | Named distributed Redis token-bucket policies. |
| `cache_policies` | Named Redis response-cache policies. |
| `trusted_proxies` | IP addresses or CIDRs allowed to supply a prior `X-Forwarded-For` chain. |
| `cors_allowed_origins` | Exact allowed origins. `*` is development-only. |
| `max_header_bytes` | Maximum calculated request-header bytes. |
| `telemetry` | Service name and optional OTLP/HTTP trace endpoint. |
| `dynamic_dns` | Optional external-IP discovery and DNS update worker. |

## Routes

| Field | Purpose |
| --- | --- |
| `name` | Unique route and metrics label. |
| `hosts` | Optional exact hosts; empty matches all hosts. |
| `methods` | Allowed HTTP methods. The admin UI supports standard and custom methods. |
| `path_prefix`, `path_rewrite` | Incoming prefix and replacement prefix. Both use leading `/`. |
| `rewrite_redirects` | When true, rewrites same-upstream `Location` headers under `path_prefix`; external redirects remain unchanged. Useful for web applications mounted below `/`. |
| `upstreams` | One or more absolute HTTP or HTTPS base URLs. Credentials, queries, and fragments are rejected. |
| `health_path`, `health_interval` | Optional active health check. The default interval is `10s`. |
| `timeout` | Route deadline; defaults to `15s`. |
| `max_body_bytes` | Request and buffered-response limit; defaults to 1 MiB. |
| `auth_policy`, `scopes` | Named policy and required scopes. |
| `rate_policy` | Named distributed rate policy. |
| `concurrency` | Local in-flight request limit; zero is unlimited. |
| `retries` | Additional attempts for idempotent methods only. |
| `circuit_breaker` | Per-upstream consecutive failures and open duration. |
| `cache_policy` | Named cache policy for GET/HEAD responses. |
| `request_transform`, `response_transform` | Header and bounded top-level JSON operations. |
| `streaming` | Streams bodies and disables retries, JSON body transforms, and caching. |

Upstreams are selected round-robin from currently healthy endpoints. HTTPS uses Go's standard transport, system CA roots, SNI, connection pooling, and HTTP/2 when available. Custom CA bundles and upstream mTLS are not currently configurable.

## Authentication policies

`api_key` policies contain SHA-256 digests, never plaintext keys. Each key has a name and scopes. Redis-created keys are also accepted and can be revoked from the admin UI.

`jwt` policies require `issuer`, `jwks_url`, and at least one audience. The gateway validates the signature, expiry, issuer, audience, subject, and route scopes. JWKS data refreshes periodically.

## Rate and cache policies

A rate policy defines `requests`, optional `burst`, and `window`. Buckets are shared through Redis and keyed by route plus principal or client IP. Redis errors fail open and increment `vial_gateway_rate_limit_fail_open_total`.

A cache policy defines `ttl`, `max_body_bytes`, `per_principal`, and optional `vary_headers`. Authenticated routes must use `per_principal: true`. Only GET/HEAD responses are cached, and request/response `Cache-Control` directives are respected.

## Transformations

Header transforms support `set_headers` and `remove_headers`. JSON transforms support top-level `add`, `remove`, and `rename`; payloads must be JSON objects and stay within route limits. A route may contain at most 128 transformation operations.

## Dynamic DNS

When enabled, `check_url` returns the public IPv4 or IPv6 address and `update_url` must contain `{ip}`. `interval` is at least `10s`; `timeout` must be positive and no greater than the interval. Production URLs must use HTTPS.

The worker checks immediately and then on each interval. It updates only when the canonical address changes and records a successful address only after a 2xx provider response. Configure an optional bearer credential with `VIAL_DYNAMIC_DNS_BEARER_TOKEN`.

## Admin environment overrides

| Variable | Purpose |
| --- | --- |
| `VIAL_ADMIN_ENABLED` | Enable the admin control plane. |
| `VIAL_ADMIN_EXTERNAL_URL` | Public base URL used for redirects and secure-cookie behavior. |
| `VIAL_ADMIN_BOOTSTRAP_KEY_SHA256` | Optional bootstrap admin-key SHA-256 digest. |
| `VIAL_ADMIN_OIDC_ISSUER` | OIDC issuer URL. |
| `VIAL_ADMIN_OIDC_CLIENT_ID` | OIDC client ID. |
| `VIAL_ADMIN_OIDC_CLIENT_SECRET` | OIDC client secret. |
| `VIAL_ADMIN_PROMETHEUS_URL` | Prometheus base URL used by the admin statistics screen. |
| `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` | Overrides `gateway.telemetry.otlp_http_endpoint`. |

Production admin deployments require OIDC, an HTTPS external URL, and the `gateway.admin` scope. Register `${external_url}/admin/callback` with the provider.
