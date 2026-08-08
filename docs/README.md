# Vial Gateway documentation

Vial Gateway is split into a reloadable data plane and a Redis-backed control plane. Start with the root [README](../README.md) for a local demo, then use the guides below for configuration and deployment.

## Guides

| Guide | Use it for |
| --- | --- |
| [Configuration](configuration.md) | Gateway schema, routes, policies, transforms, telemetry, Dynamic DNS, and environment overrides |
| [Operations](operations.md) | Health, metrics, configuration lifecycle, failure behavior, backup, and troubleshooting |
| [Docker Compose deployment](deployment/compose.md) | Running and validating the complete local integration stack |
| [Kubernetes deployment](deployment/kubernetes.md) | Production preparation, secrets, ingress TLS, rollout, verification, and rollback |

## Runtime architecture

```text
                     ┌──────────────┐
Admin browser ──────▶│ Control plane│──────┐
                     └──────────────┘      │ versions, sessions,
                                           │ keys, audit, pub/sub
                                           ▼
Clients ──▶ TLS/Ingress ──▶ Gateway replicas ──▶ Redis
                              │       │
                              │       └────────▶ Prometheus / OTLP
                              ▼
                         HTTPS/HTTP upstreams
```

The control plane stores immutable configuration versions and publishes activation events. Each gateway atomically swaps a compiled route snapshot and continues serving its last-good snapshot if Redis becomes unavailable. A polling loop repairs convergence after missed pub/sub events.

## Supported deployment shape

- Ingress-terminated TLS is the default production topology.
- Gateway replicas and the control service share Redis.
- The control service owns `/admin` and `/admin/v1`; data-plane replicas own application routes.
- Static upstream URLs may use HTTP or HTTPS. HTTPS uses normal hostname and system-CA verification.
- The bundled Redis and demo OIDC provider are development examples, not production identity or HA data services.

