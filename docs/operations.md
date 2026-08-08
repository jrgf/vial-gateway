# Operations guide

## Health and telemetry

| Endpoint | Meaning |
| --- | --- |
| `GET /health/live` | Process is running; returns 204. |
| `GET /health/ready` | A configuration is active and every route has a healthy upstream; returns 204 or 503. |
| `GET /metrics` | Prometheus exposition endpoint. |
| `GET /admin/v1/status` | Authenticated active version, route, policy, upstream, telemetry, and Dynamic DNS state. |

Key metrics:

- `vial_gateway_requests_total{route,status}`
- `vial_gateway_upstream_attempts_total{route,endpoint,result}`
- `vial_gateway_reloads_total{result}`
- `vial_gateway_rate_limit_fail_open_total`
- `vial_gateway_cache_total{route,result}`
- `vial_gateway_dynamic_dns_updates_total{result}`

Set `gateway.telemetry.otlp_http_endpoint` or `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` to export traces over OTLP/HTTP.

The first admin screen summarizes the last five minutes from Prometheus: request rate, 5xx rate, upstream failures, cache hit rate, and traffic by route. Set `admin.prometheus_url` or `VIAL_ADMIN_PROMETHEUS_URL`; the screen reports unavailable without affecting gateway traffic when Prometheus cannot be reached. Audit events are shown newest first in pages of 25.

## Configuration lifecycle

The admin console at `/admin` is the normal management surface:

1. Edit routes, policies, Dynamic DNS, or the complete JSON document.
2. Validate and store a new immutable version.
3. Activate it with an optimistic current-version check.
4. Gateways receive Redis pub/sub notification and also poll every five seconds.
5. Roll back by activating an older version.
6. Delete old versions only after they are inactive.

Activations compile a complete new router before swapping it into service. Invalid routes leave the prior snapshot active.

`SIGHUP` reloads the local file-backed gateway and, when direct TLS is already enabled, stages a replacement certificate before changing the router. A reload cannot switch between plain HTTP and direct TLS because that requires replacing the listener; restart the process for that change.

## Redis behavior

Redis stores configuration versions, the active pointer, sessions, dynamic API-key metadata, audit events, distributed rate buckets, and cached responses.

- Existing gateways continue serving their last-good snapshot during a Redis outage.
- New gateways start from the bootstrap file.
- Rate limiting fails open with logs and a metric.
- Authentication does not fail open.
- Admin mutations and distributed cache operations remain unavailable until Redis recovers.

Enable Redis persistence and back it up according to the service's recovery objectives. For a managed deployment, use TLS (`rediss://`), authentication, restricted networking, and provider-supported snapshots.

## Common diagnostics

### Readiness is 503

Open `/admin`, inspect **Routes & upstreams**, then verify DNS, network policy, the upstream certificate chain, and `health_path`. Readiness requires at least one healthy endpoint per route.

### A configuration does not appear on every replica

Check Redis connectivity and `vial_gateway_reloads_total`. Replicas poll every five seconds, so missed pub/sub notifications should self-heal. A rejected version remains visible in logs with its validation error.

### Admin login loops or reports missing state

Verify that users always access the exact host in `admin.external_url`, the provider callback is `${external_url}/admin/callback`, cookies are allowed, Redis is reachable, and clocks are synchronized. Production requires HTTPS.

### Rate limiting is unexpectedly permissive

Check `vial_gateway_rate_limit_fail_open_total` and Redis logs. This behavior is deliberate during Redis failures.

### Dynamic DNS does not update

Check that both URLs use HTTPS in production, `update_url` contains `{ip}`, the check endpoint returns only a public address, the interval is at least `10s`, and the provider token is present when required. The worker logs provider and discovery failures without logging the token.

## Backup and rollback

- Back up Redis before application upgrades or schema migrations.
- Retain at least one known-good inactive configuration version.
- Roll back configuration from `/admin` without redeploying.
- Roll back code by restoring the previous immutable image digest.
- If Redis must be rebuilt, the bootstrap file becomes the initial active configuration for new data-plane instances.
