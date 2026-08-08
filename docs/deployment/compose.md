# Docker Compose deployment

The Compose stack is the supported integration and evaluation environment. It runs Redis with AOF, two sample upstreams, one gateway, one control service, a development-only OIDC provider, Prometheus, an OpenTelemetry Collector, and Tempo.

The sample upstreams use the opt-in `demo` profile. The data-plane gateway starts without it so it can serve routes managed through the control plane.

Do not expose the bundled credentials or demo OIDC provider to an untrusted network.

## Prerequisites

- Docker Engine or Docker Desktop with Compose v2
- Free local ports 8080, 8081, 9090, 3200, and 25556, unless overridden
- About 2 GB of available memory for the complete observability stack

## Start

```sh
docker compose --profile demo up --build --detach
docker compose ps
```

Default endpoints:

| Service | URL |
| --- | --- |
| Gateway | `http://127.0.0.1:8080` |
| Admin console | `http://127.0.0.1:8081/admin` |
| Prometheus | `http://127.0.0.1:9090` |
| Tempo API | `http://127.0.0.1:3200` |

The development admin login is `admin@example.com` / `admin`. The sample data-plane key is `development-only-key`; the bootstrap admin key is `development-admin-key`.

Override host ports without changing Compose:

```sh
GATEWAY_PORT=18080 \
CONTROL_PORT=18081 \
PROMETHEUS_PORT=19090 \
TEMPO_PORT=13200 \
OIDC_PORT=15556 \
docker compose --profile demo up --build --detach
```

Use the same variables on later Compose commands so Compose retains the intended published ports.

## Validate

```sh
docker compose config --quiet
./scripts/curl-smoke.sh
./scripts/load-smoke.sh
```

For non-default gateway ports:

```sh
GATEWAY_URL=http://127.0.0.1:18080 ./scripts/curl-smoke.sh
GATEWAY_URL=http://127.0.0.1:18080 ./scripts/load-smoke.sh
```

The smoke script checks liveness, readiness, authentication, both sample routes, body proxying, CORS, and the JSON 404 response. The load check defaults to 100 requests at concurrency 10 and enforces a 500 ms p95 threshold.

## Configuration and persistence

- Gateway bootstrap: [deploy/compose/gateway.json](../../deploy/compose/gateway.json)
- Control bootstrap: [deploy/compose/control.json](../../deploy/compose/control.json)
- Prometheus: [deploy/compose/prometheus.yml](../../deploy/compose/prometheus.yml)
- Collector: [deploy/compose/otel-collector.yml](../../deploy/compose/otel-collector.yml)
- Tempo: [deploy/compose/tempo.yml](../../deploy/compose/tempo.yml)

Redis, Prometheus, and Tempo use named volumes. Once Redis has an active configuration, editing the gateway bootstrap file does not overwrite it. Use the admin UI to create and activate versions, or deliberately recreate the Redis volume when resetting a development environment.

Inspect service logs with:

```sh
docker compose logs --tail=200 gateway control redis
```

## Stop or reset

Stop containers while preserving data:

```sh
docker compose down
```

`docker compose down --volumes` also permanently deletes Redis configuration, sessions, keys, audit data, cache entries, metrics, and traces. Use it only when a complete local reset is intended.

## Single-host production adaptation

Compose is useful for a controlled single-host deployment, but the checked-in file is development-only. Before adapting it:

- Remove `oidc` and configure a real provider.
- Replace all example keys and secrets.
- Terminate TLS at a trusted reverse proxy or configure direct TLS files.
- Bind Redis and observability services to private networks only.
- Add image digests, resource limits, log shipping, backup, and monitoring.
- Use managed or separately operated Redis when configuration availability matters.

For a multi-replica deployment, use the [Kubernetes guide](kubernetes.md).
