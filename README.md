# Vault Dynamic Database Credentials — Agent Injector on Kubernetes

A working demonstration of [HashiCorp Vault](https://developer.hashicorp.com/vault) issuing
**dynamic PostgreSQL credentials** to a Kubernetes workload using the
[Vault Agent Injector](https://developer.hashicorp.com/vault/docs/platform/k8s/injector).

The application never talks to Vault. A sidecar authenticates on its behalf, renders a
short-lived database credential to a file, renews it, and replaces it when it can no longer be
renewed. The app just reads the file. The web UI makes that lifecycle visible — including a live
countdown to the moment the PostgreSQL role is destroyed.

> ### ⚠️ This is a demonstration, not a production application
>
> **The application has no authentication or authorisation.** Any caller that can reach it can
> invoke `/api/read`, which executes a database query and returns the results. It is designed to be
> reached with `kubectl port-forward` and nothing else — do not put a Service, Ingress, Route or
> LoadBalancer in front of it.
>
> The example configuration also uses very short credential TTLs (1 minute / 5 minutes) so the
> lifecycle is visible while you watch it, and disables TLS on the database connection for
> simplicity. Both are wrong for a real deployment. See
> [Configure Vault](#2-configure-vault) for what to change.

<!-- ------------------------------------------------------------------ -->

## Contents

- [How it works](#how-it-works)
- [Repository layout](#repository-layout)
- [Prerequisites](#prerequisites)
- [1. Configure PostgreSQL](#1-configure-postgresql)
- [2. Configure Vault](#2-configure-vault)
- [3. Build and push the image](#3-build-and-push-the-image)
- [4. Deploy](#4-deploy)
- [5. Open the UI](#5-open-the-ui)
- [Configuration reference](#configuration-reference)
- [API endpoints](#api-endpoints)
- [Verifying credential lifecycle](#verifying-credential-lifecycle)
- [Troubleshooting](#troubleshooting)

<!-- ------------------------------------------------------------------ -->

## How it works

```
   ServiceAccount token
            │
            ▼
   ┌──────────────────┐   Kubernetes auth    ┌───────────────┐
   │   vault-agent    │ ───────────────────► │     Vault     │
   │    (sidecar)     │ ◄─────────────────── │  database/    │
   └────────┬─────────┘   dynamic credential │  secrets      │
            │                                └───────┬───────┘
            │ renders                                │ CREATE ROLE
            ▼                                        ▼
  /vault/secrets/db-creds.json              ┌────────────────┐
            │                               │   PostgreSQL   │
            │ read on every request         │  ephemeral user│
            ▼                               └────────────────┘
   ┌──────────────────┐                              ▲
   │  application     │ ─────────────────────────────┘
   │  (Flask)         │        connects with the injected credential
   └──────────────────┘
```

1. The pod's [ServiceAccount token](https://kubernetes.io/docs/concepts/security/service-accounts/)
   is projected into the Vault Agent sidecar.
2. The Agent exchanges it for a Vault token via
   [Kubernetes auth](https://developer.hashicorp.com/vault/docs/auth/kubernetes).
3. The Agent requests a credential from the
   [database secrets engine](https://developer.hashicorp.com/vault/docs/secrets/databases/postgresql).
   Vault runs `CREATE ROLE` against PostgreSQL and returns a username and password with a
   [lease](https://developer.hashicorp.com/vault/docs/concepts/lease).
4. The Agent renders it to `/vault/secrets/db-creds.json` and **renews the lease** until
   `max_ttl` is reached, at which point it fetches a replacement.
5. Vault revokes the expired lease. PostgreSQL drops the role.
6. The application re-reads the file on every request, so it always uses the current credential.

**The application holds no Vault token, no Vault address, and no database password.**

<!-- ------------------------------------------------------------------ -->

## Repository layout

| Path | Purpose |
|---|---|
| `app/app.py` | The Flask application. Reads the injected credential, connects to PostgreSQL, and reports which identity actually executed the query. Derives credential age and remaining lifetime. |
| `app/templates/index.html` | Single-page UI. All CSS and JS are inlined — there is no `static/` directory, so the `<style>` block here is the only place to change appearance. |
| `app/Dockerfile` | Builds the application image. Python 3.12 slim, no build tooling in the final image. |
| `app/requirements.txt` | Python dependencies — Flask and `psycopg2-binary`. Deliberately no Vault client library. |
| `deploy/serviceaccount.yaml` | The ServiceAccount the pod runs as. Vault's Kubernetes auth role is bound to this identity. |
| `deploy/deployment.yaml` | The Deployment. All Vault configuration lives in the [annotations](https://developer.hashicorp.com/vault/docs/platform/k8s/injector/annotations) — auth path, role, secret path, and the template that renders the credential file. |
| `tests/` | Scripts that verify what actually happens to an open database connection when its credential is rotated and revoked. See [below](#verifying-credential-lifecycle). |

### What the `tests/` directory is for

The demo shows credentials being issued and expiring. It does not, by itself, show what that means
for an application that holds **open database connections** — which every real application does,
through a connection pool.

The scripts in `tests/` answer that empirically. They open a single connection, hold it across a
rotation and the subsequent revocation, and record what happens. The findings determine how much
work adopting dynamic credentials actually requires:

- The connection is **not closed** when the credential is revoked — it stays open indefinitely.
- All table access is **denied**, so revocation is effective for its security purpose.
- `SELECT 1` **still succeeds** — and that is the default health-check query for
  [HikariCP](https://github.com/brettwooldridge/HikariCP) and most connection pools, so a pool
  reports the connection healthy while every real query on it fails.

See [`tests/README.md`](tests/README.md) for how to run them and how to read the output.

<!-- ------------------------------------------------------------------ -->

## Prerequisites

- A Kubernetes cluster with the
  [Vault Helm chart](https://developer.hashicorp.com/vault/docs/platform/k8s/helm) installed and
  the **Agent Injector enabled** (`injector.enabled=true`, the chart default)
- A reachable PostgreSQL instance
- `kubectl`, `docker` (or `podman`), and the `vault` CLI
- A container registry you can push to

> **Vault Enterprise note.** The manifests set a Vault
> [namespace](https://developer.hashicorp.com/vault/docs/enterprise/namespaces), which is an
> Enterprise feature. On Vault Community Edition, remove the
> `vault.hashicorp.com/namespace` annotation from `deploy/deployment.yaml` and leave
> `VAULT_NAMESPACE` unset.

<!-- ------------------------------------------------------------------ -->

## 1. Configure PostgreSQL

Create the privilege role that dynamic users will inherit, and the demo table:

```sql
CREATE ROLE demo_readonly;

CREATE TABLE IF NOT EXISTS products (
    id          SERIAL PRIMARY KEY,
    name        TEXT NOT NULL,
    price       NUMERIC(12,2) NOT NULL,
    description TEXT,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

GRANT CONNECT ON DATABASE postgres TO demo_readonly;
GRANT USAGE  ON SCHEMA public      TO demo_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO demo_readonly;

ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT ON TABLES TO demo_readonly;

INSERT INTO products (name, price, description)
VALUES ('Example widget', 19.99, 'Seed row so the demo has something to read');
```

Vault also needs an account that can create and drop roles:

```sql
CREATE ROLE vault_admin WITH LOGIN PASSWORD 'change-me' CREATEROLE;
GRANT demo_readonly TO vault_admin WITH ADMIN OPTION;
```

<!-- ------------------------------------------------------------------ -->

## 2. Configure Vault

```bash
export VAULT_ADDR=https://vault.example.com:8200
export VAULT_NAMESPACE=my-org        # Enterprise only — omit on Community Edition
```

### Kubernetes auth

```bash
vault auth enable -path=demo-auth-mount kubernetes

vault write auth/demo-auth-mount/config \
    kubernetes_host="https://kubernetes.default.svc:443"

vault write auth/demo-auth-mount/role/vault-agent-demo \
    bound_service_account_names=vault-agent-demo \
    bound_service_account_namespaces=vault-demo \
    policies=demo-agent-policy \
    ttl=1h
```

### Database secrets engine

```bash
vault secrets enable -path=demo-db database

vault write demo-db/config/postgres \
    plugin_name=postgresql-database-plugin \
    allowed_roles="demo-agent-reader" \
    connection_url="postgresql://{{username}}:{{password}}@postgres-postgresql.postgres.svc.cluster.local:5432/postgres?sslmode=disable" \
    username="vault_admin" \
    password="change-me"
```

> **`sslmode=disable` is for a lab cluster only.** It sends the Vault-to-database connection —
> including every credential Vault creates — in cleartext. For anything real use `sslmode=verify-full`
> with the database's CA certificate. See
> [PostgreSQL SSL support](https://www.postgresql.org/docs/current/libpq-ssl.html) and the
> [database secrets engine TLS options](https://developer.hashicorp.com/vault/docs/secrets/databases/postgresql).

```bash
vault write demo-db/roles/demo-agent-reader \
    db_name=postgres \
    creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT demo_readonly TO \"{{name}}\";" \
    revocation_statements="REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM \"{{name}}\"; REVOKE USAGE ON SCHEMA public FROM \"{{name}}\"; REVOKE demo_readonly FROM \"{{name}}\"; DROP ROLE IF EXISTS \"{{name}}\";" \
    default_ttl="1m" \
    max_ttl="5m"
```

The short TTLs make the lifecycle visible in a live demo. **Use realistic values in production** —
hours, not minutes.

### Policy

```bash
vault policy write demo-agent-policy - <<EOF
path "demo-db/creds/demo-agent-reader" {
  capabilities = ["read"]
}
EOF
```

> If you change `default_ttl` or `max_ttl`, update `VAULT_DB_TTL` and `VAULT_DB_MAX_TTL` in
> `deploy/deployment.yaml` to match. The application cannot discover them — it deliberately never
> contacts Vault — so the UI countdown depends on these being kept in step.

<!-- ------------------------------------------------------------------ -->

## 3. Build and push the image

Replace `<YOUR-REGISTRY>` throughout with your registry path.

> **Building on Apple Silicon?** `--platform linux/amd64` is required if your cluster nodes are
> amd64. An arm64 image pushes and deploys without complaint, then crashes with
> `exec format error`. See
> [Docker multi-platform builds](https://docs.docker.com/build/building/multi-platform/).

```bash
cd app
docker build --platform linux/amd64 -t <YOUR-REGISTRY>/vault-agent-db-demo:v1 .
```

### Amazon ECR

Full guide: [Pushing a Docker image to ECR](https://docs.aws.amazon.com/AmazonECR/latest/userguide/docker-push-ecr-image.html)

```bash
export AWS_REGION=us-east-1
export ACCOUNT_ID=<your-account-id>

aws ecr create-repository --repository-name vault-agent-db-demo --region $AWS_REGION

aws ecr get-login-password --region $AWS_REGION \
  | docker login --username AWS --password-stdin $ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com

docker tag  vault-agent-db-demo:v1 $ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/vault-agent-db-demo:v1
docker push $ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/vault-agent-db-demo:v1
```

### GitHub Container Registry

Full guide: [Working with the Container registry](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry)

```bash
echo $GITHUB_TOKEN | docker login ghcr.io -u <username> --password-stdin
docker tag  vault-agent-db-demo:v1 ghcr.io/<username>/vault-agent-db-demo:v1
docker push ghcr.io/<username>/vault-agent-db-demo:v1
```

Other registries: [Docker Hub](https://docs.docker.com/docker-hub/repos/push-pull/) ·
[Azure ACR](https://learn.microsoft.com/en-us/azure/container-registry/container-registry-get-started-docker-cli) ·
[Google Artifact Registry](https://cloud.google.com/artifact-registry/docs/docker/pushing-and-pulling)

Finally, set the image in `deploy/deployment.yaml`:

```yaml
image: "<YOUR-REGISTRY>/vault-agent-db-demo:v1"
```

<!-- ------------------------------------------------------------------ -->

## 4. Deploy

```bash
kubectl create namespace vault-demo
kubectl apply -f deploy/serviceaccount.yaml
kubectl apply -f deploy/deployment.yaml
kubectl -n vault-demo rollout status deployment/vault-agent-db-demo
```

A healthy pod shows **2/2** containers — the application plus the injected `vault-agent` sidecar.
If it shows 1/1, the injector did not fire; see [Troubleshooting](#troubleshooting).

The Deployment uses `strategy: Recreate` rather than the default rolling update. A rolling update
needs capacity for two pods simultaneously, which fails on clusters at their per-node pod limit.
Recreate stops the old pod first, at the cost of a few seconds of downtime per deploy.

No Service is included — the demo is intended to be reached with a port-forward. Add one if you
need it.

<!-- ------------------------------------------------------------------ -->

## 5. Open the UI

```bash
kubectl -n vault-demo port-forward deployment/vault-agent-db-demo 8080:8080
```

Then open <http://localhost:8080>.

The page shows:

- **Credential Lease** — a countdown to the moment the PostgreSQL role is revoked and dropped,
  anchored to when Vault issued the credential rather than to when the page was opened. It also
  counts rotations observed while the page is open, and flashes when one occurs.
- **PostgreSQL Identity** — `current_user`, `session_user`, and role memberships as reported by
  the database itself. This is evidence rather than assertion: the ephemeral user really does
  inherit `demo_readonly`.

Leave the page open. At roughly 85% of `max_ttl` the credential rotates: the username changes in
place, the counter increments, and the identity panel is marked stale until you re-run the query.

<!-- ------------------------------------------------------------------ -->

## Configuration reference

All values are `os.environ.get()` with a working default, and are also set explicitly in
`deploy/deployment.yaml`. **Change both or they drift.**

| Variable | Default | Purpose |
|---|---|---|
| `SECRET_FILE` | `/vault/secrets/db-creds.json` | Path the Agent renders the credential to |
| `DB_HOST` | `postgres-postgresql.postgres.svc.cluster.local` | PostgreSQL host |
| `DB_PORT` | `5432` | PostgreSQL port |
| `DB_NAME` | `postgres` | Database name |
| `VAULT_DB_TTL` | `60` | Lease TTL in seconds — the **renewal interval**, displayed only |
| `VAULT_DB_MAX_TTL` | `300` | Maximum credential lifetime in seconds — what the UI counts down |
| `VAULT_NAMESPACE` | `my-org` | Displayed only; Enterprise namespaces |
| `VAULT_AUTH_ROLE` | `vault-agent-demo` | Displayed only |
| `VAULT_DB_ROLE` | `demo-agent-reader` | Displayed only |
| `KUBERNETES_SERVICE_ACCOUNT` | `vault-agent-demo` | Displayed only |
| `KUBERNETES_NAMESPACE` | `vault-demo` | Displayed only |

Variables marked *displayed only* are shown in the UI for narration. They do not affect behaviour —
the real configuration lives in the Deployment annotations, which the Agent reads.

`VAULT_DB_TTL` and `VAULT_DB_MAX_TTL` **must match the Vault role**, since the application has no
way to discover them.

<!-- ------------------------------------------------------------------ -->

## API endpoints

| Endpoint | Method | Returns |
|---|---|---|
| `/` | GET | The UI |
| `/api/status` | GET | Whether a credential is available; also the readiness and liveness probe target |
| `/api/credential` | GET | Current username, lease ID, and derived timing — polled by the UI every 2s |
| `/api/read` | POST | Connects to PostgreSQL and returns the identity the query ran as |
| `/api/db-identity` | GET | Database identity only, without lifecycle detail |

### How remaining lifetime is derived

`lease_duration` in the injected file is the **renewal interval**, not the credential's lifetime,
and it does not change as the lease is renewed. It cannot be used for a countdown.

Instead, the application recovers the issue time from the username. Vault's default PostgreSQL
username template ends with a UNIX timestamp:

```
v-us-west--demo-age-8Gt1WQ0vyEgpiTbVgrCi-1788327392
                                         └── issued at
```

That value matches both the Vault lease's `issue_time` and the mtime of the rendered file. Remaining
lifetime is then `(issued_at + max_ttl) − now`, computed server-side so the countdown follows the
cluster's clock rather than the viewer's browser. If a role uses a custom `username_template`
without a trailing timestamp, the application falls back to the file's mtime.

<!-- ------------------------------------------------------------------ -->

## Verifying credential lifecycle

The UI shows credentials being issued and expiring. To see what that means for an application
holding open connections, run the scripts in [`tests/`](tests/README.md).

```bash
export POD=$(kubectl -n vault-demo get pod -l app=vault-agent-db-demo -o jsonpath='{.items[0].metadata.name}')

kubectl -n vault-demo exec -i $POD -c vault-agent-db-demo \
  -- python - < tests/held_connection_timeline.py
```

They run inside the application pod, which already has the dependencies and the credential file, so
there is nothing to install and nothing to deploy.

<!-- ------------------------------------------------------------------ -->

## Troubleshooting

**Pod shows 1/1 instead of 2/2** — the injector did not fire. Confirm the Agent Injector is running
(`kubectl get pods -n vault -l app.kubernetes.io/name=vault-agent-injector`) and that the
`vault.hashicorp.com/agent-inject: "true"` annotation is on the **pod template**, not the Deployment
metadata.

**Pod stuck in `Init:0/1`** — the Agent's init container cannot authenticate. Check
`kubectl -n vault-demo logs <pod> -c vault-agent-init`. Usually the Kubernetes auth role's
`bound_service_account_names` or `bound_service_account_namespaces` do not match.

**Credential file missing or empty** — check `kubectl -n vault-demo logs <pod> -c vault-agent`.
Template rendering failures surface there, not in the application container.

**Confusing 403 or 404 from Vault** — on Vault Enterprise, a missing namespace produces misleading
errors rather than an obvious one. Confirm the `vault.hashicorp.com/namespace` annotation.

**Countdown shows the wrong duration** — `VAULT_DB_MAX_TTL` does not match the Vault role. Compare
against `vault read demo-db/roles/demo-agent-reader`.

**`permission denied for table products`** — the dynamic user did not inherit `demo_readonly`.
Check the role's `creation_statements` include the `GRANT`.

**`exec format error` in the pod** — the image architecture does not match the nodes. Rebuild with
`--platform linux/amd64`.

<!-- ------------------------------------------------------------------ -->

## Further reading

- [Vault Agent Injector](https://developer.hashicorp.com/vault/docs/platform/k8s/injector) ·
  [annotation reference](https://developer.hashicorp.com/vault/docs/platform/k8s/injector/annotations)
- [Database secrets engine](https://developer.hashicorp.com/vault/docs/secrets/databases) ·
  [PostgreSQL plugin](https://developer.hashicorp.com/vault/docs/secrets/databases/postgresql)
- [Kubernetes auth method](https://developer.hashicorp.com/vault/docs/auth/kubernetes)
- [Leases, renewal and revocation](https://developer.hashicorp.com/vault/docs/concepts/lease)
- [PostgreSQL `pg_hba.conf`](https://www.postgresql.org/docs/current/auth-pg-hba-conf.html)

## License

Provided as-is for demonstration and evaluation purposes.
