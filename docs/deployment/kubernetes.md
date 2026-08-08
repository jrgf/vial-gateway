# Kubernetes deployment

[deploy/kubernetes/all.yaml](../../deploy/kubernetes/all.yaml) is a plain-manifest deployment example containing two gateway replicas, a separate control deployment, a sample upstream, Redis with AOF and a PVC, Services, ingress TLS routing, probes, resource limits, and ingress NetworkPolicies.

The manifest is a demo starting point. Do not apply it unchanged to production: it contains placeholder hosts, credentials, image names, and a single-node Redis deployment.

## Prerequisites

- Kubernetes 1.29 or newer
- An ingress controller compatible with `networking.k8s.io/v1`
- A default `ReadWriteOnce` StorageClass, unless using managed Redis
- A DNS name and TLS certificate
- An OIDC client with Authorization Code flow and callback `https://HOST/admin/callback`
- A registry-hosted immutable gateway image

Create the target namespace before creating secrets or applying resources:

```sh
kubectl create namespace vial-gateway
```

## 1. Build and publish an image

```sh
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  --tag registry.example.com/platform/vial-gateway:VERSION \
  --push .
```

Replace every `vial-gateway:local` reference with an immutable tag or digest. The same image contains the `gateway`, `backend`, and development-only `demo-oidc` binaries; production deployments use `gateway` only.

## 2. Prepare configuration

Copy the manifest into environment-specific deployment configuration and update both ConfigMap documents:

- Set the public ingress host in the Ingress and `admin.external_url`.
- Configure the real OIDC issuer, client ID, scopes, and registered callback.
- Replace sample upstream URLs, routes, policy names, API-key digests, and scopes.
- Set trusted proxy CIDRs to the actual ingress/network ranges; do not copy broad private ranges without confirming the topology.
- Set the OTLP endpoint if a collector is available.
- Keep `control_only: true` for the control deployment.

Bootstrap versions are used when Redis has no active configuration. After first activation, update routes through `/admin`; changing the ConfigMap alone does not replace an existing Redis active version.

## 3. Create secrets

Do not commit real values into `stringData`. Remove or replace the example Secret document and create a secret through the cluster's secret-management workflow. Required values are:

| Key | Requirement |
| --- | --- |
| `VIAL_REDIS_URL` | Use a private authenticated `rediss://` endpoint in production. |
| `VIAL_ADMIN_OIDC_CLIENT_SECRET` | OIDC confidential-client secret, if required by the provider. |
| `VIAL_ADMIN_BOOTSTRAP_KEY_SHA256` | Optional emergency/bootstrap admin-key SHA-256 digest. |
| `VIAL_DYNAMIC_DNS_BEARER_TOKEN` | Optional DNS-provider bearer token; omit when unused. |

Prefer External Secrets, Sealed Secrets, or the platform's native secret integration. Restrict secret access to the gateway and control service accounts.

Create or synchronize the ingress certificate under the name referenced by the Ingress:

```sh
kubectl -n vial-gateway create secret tls vial-gateway-tls \
  --cert=path/to/fullchain.pem \
  --key=path/to/private-key.pem
```

With cert-manager, replace this manual secret step with an appropriate `Certificate` resource.

## 4. Redis choice

The included Redis deployment is suitable for a demo or disposable environment. Production should normally use managed or HA Redis with:

- TLS and authentication
- A persistence and backup policy
- Multi-zone failover appropriate to the control-plane SLO
- Restricted network access
- Capacity monitoring for cache, rate buckets, sessions, audit events, and versions

When using managed Redis, remove the Redis Deployment, Service, and PVC and set `VIAL_REDIS_URL` accordingly.

## 5. Apply and observe

```sh
kubectl -n vial-gateway apply -f deploy/kubernetes/all.yaml
kubectl -n vial-gateway rollout status deployment/redis --timeout=180s
kubectl -n vial-gateway rollout status deployment/vial-control --timeout=180s
kubectl -n vial-gateway rollout status deployment/vial-gateway --timeout=180s
kubectl -n vial-gateway get pods,service,ingress
```

Skip the Redis rollout command when using a managed service. Confirm the ingress address, then point DNS at it.

## 6. Verify

Before exposing traffic:

1. Confirm every gateway and control pod reports ready.
2. Confirm `/health/live` and `/health/ready` return 204 through the intended paths.
3. Sign in to `https://HOST/admin` and verify the expected issuer and `gateway.admin` scope.
4. Inspect route health and active version convergence on the admin dashboard.
5. Send an authenticated request through every critical route and method.
6. Confirm Prometheus scraping and OTLP trace delivery.
7. Exercise a configuration activation and rollback.
8. Verify Redis backup and restore procedures in a non-production environment.

## Network and security notes

- The Ingress sends `/admin` to `vial-control` and all other paths to `vial-gateway`.
- The Redis NetworkPolicy admits the gateway and control pods only.
- The sample upstream NetworkPolicy admits gateway pods only.
- Add namespace-level default-deny policies and explicit DNS, OIDC/JWKS, OTLP, HTTPS-upstream, and Dynamic DNS egress rules according to the cluster CNI.
- Pods run as non-root, drop Linux capabilities, disable privilege escalation, and use read-only root filesystems.
- Keep the control service at one replica unless session and OIDC flows have been validated under the chosen ingress behavior; Redis already provides shared session state.

## Upgrade

1. Back up Redis and retain a known-good configuration version.
2. Publish a new immutable image digest.
3. Review configuration-schema compatibility and release notes.
4. Update the control deployment first and verify `/admin` plus its readiness probe.
5. Roll the gateway deployment and watch readiness, reload rejection metrics, 5xx rate, and latency.
6. Verify all replicas report the same active version.

Kubernetes rolling updates preserve traffic only when capacity, readiness, disruption budgets, and ingress behavior are configured for the cluster. Add a `PodDisruptionBudget` and topology spread constraints when production availability requires them.

## Rollback

Configuration rollback does not require a deployment: activate a known-good inactive version from `/admin`.

For a binary rollback, restore the previous image digest and wait for rollout completion:

```sh
kubectl -n vial-gateway rollout undo deployment/vial-control
kubectl -n vial-gateway rollout undo deployment/vial-gateway
kubectl -n vial-gateway rollout status deployment/vial-control --timeout=180s
kubectl -n vial-gateway rollout status deployment/vial-gateway --timeout=180s
```

If Redis is unavailable, existing gateway pods retain their last-good in-memory route snapshot. Avoid restarting all replicas until Redis is restored unless the bootstrap ConfigMap is known to contain a safe fallback configuration.
