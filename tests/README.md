# Connection lifetime tests

Dynamic database credentials expire. Applications hold **open connections** in a pool. These two
scripts establish what actually happens where those facts meet:

> *What becomes of a database connection that was opened with a credential that is later revoked?*

The answer determines how much work adopting dynamic credentials requires, and it is not what most
people assume.

Both scripts run **inside the running application pod**, which already has `psycopg2` and the
Agent-rendered credential at `/vault/secrets/db-creds.json`. Nothing to install, nothing to deploy,
no changes to the application.

| Script | Runtime | Question it answers |
|---|---|---|
| `held_connection_timeline.py` | ~8 min | *When* does a held connection break — and does it ever close? |
| `revoked_connection_battery.py` | ~5 min | *What* can a connection still do after its credential is revoked? |

Both are read-only apart from a single `INSERT` in the battery that is expected to be refused.

---

## Setup

```bash
export POD=$(kubectl -n vault-demo get pod -l app=vault-agent-db-demo -o jsonpath='{.items[0].metadata.name}')
echo "using pod: $POD"
```

Re-run after any redeploy — the pod name changes.

---

## Test 1 — Timeline

```bash
kubectl -n vault-demo exec -i $POD -c vault-agent-db-demo \
  -- python - < tests/held_connection_timeline.py
```

Opens one connection, holds it, and reports every 15 seconds: whether the credential file has
rotated, whether the PostgreSQL role still exists, whether a query still succeeds, and whether the
driver still considers the socket open.

### Sample output

```
[09:23:27] HELD CONNECTION opening as v-us-west--demo-age-ug6VMdw7...-1788340754
[09:23:28] connected, backend_pid=449091
[09:23:28] t+  0s file=same    role:EXISTS   closed=0 | HELD-CONN OK
[09:23:43] t+ 15s file=ROTATED role:EXISTS   closed=0 | HELD-CONN OK
[09:24:13] t+ 45s file=ROTATED role:EXISTS   closed=0 | HELD-CONN OK
[09:24:28] t+ 60s file=ROTATED role:DROPPED  closed=0 | HELD-CONN FAIL UndefinedObject: invalid role OID: 161688
[09:31:14] t+466s file=ROTATED role:DROPPED  closed=0 | HELD-CONN FAIL UndefinedObject: invalid role OID: 161688
```

### Reading it

**`file=same` → `file=ROTATED`.** Vault Agent has rendered a new credential and the application has
moved on. The held connection is unaffected, and the old role is still alive.

**`role:EXISTS` → `role:DROPPED`.** Roughly 45 seconds later, Vault revokes the old lease and
PostgreSQL drops the role. **Rotation and revocation are separate events** — a new credential
appearing does not mean the old one is gone.

**`closed=0` throughout.** The important column. PostgreSQL never terminated the session. Minutes
after revocation it is still open, still failing, and nothing has reaped it. It does not recover.

Interrupt with `Ctrl-C` once `role:DROPPED` appears if you do not need the full run.

---

## Test 2 — What survives revocation

```bash
kubectl -n vault-demo exec -i $POD -c vault-agent-db-demo \
  -- python - < tests/revoked_connection_battery.py
```

Waits for revocation automatically, then runs six queries on the held connection to map precisely
what still works.

### Sample output

```
[09:28:40] role DROPPED -- running battery on the held connection
[09:28:40] socket still open? conn.closed=0
  OK    SELECT 1                       -> (1,)
  OK    SELECT now()                   -> datetime.datetime(2026, 9, 2, 9, 28, 40)
  FAIL  SELECT count(*) FROM products  -> InsufficientPrivilege: permission denied for table products
  FAIL  SELECT current_user            -> UndefinedObject: invalid role OID: 161690
  FAIL  SELECT session_user            -> UndefinedObject: invalid role OID: 161690
  FAIL  INSERT INTO products ...       -> InsufficientPrivilege: permission denied for table products
```

### Reading it

The results split cleanly into two conclusions that point in opposite directions.

**Revocation is effective.** No table access survives — reads and writes both return
`permission denied`, and the session's own identity no longer resolves. A connection held open past
expiry cannot reach a single row. From a security standpoint, revocation does exactly what it
claims.

**But the connection is a zombie.** `SELECT 1` still returns `1` — and that is the default
connection-validation query for [HikariCP](https://github.com/brettwooldridge/HikariCP), Apache
Commons DBCP, and most other pools. A pool health check therefore reports this connection as
healthy and hands it to the application, where every real query fails.

That combination is what makes this expensive in production. The failure does not appear at
rotation; it appears later, on whichever request happens to draw the bad connection, as an
intermittent error correlating with no deployment and no traffic change. The standard health check
will not catch it.

---

## Confirming nothing was left behind

```bash
PGPW=$(kubectl -n postgres get secret postgres-postgresql -o jsonpath='{.data.postgres-password}' | base64 -d)

kubectl -n postgres exec postgres-postgresql-0 -- env PGPASSWORD="$PGPW" \
  psql -U postgres -d postgres -tAc \
  "SELECT pid, usename, state FROM pg_stat_activity WHERE usename LIKE 'v-%'"

kubectl -n postgres exec postgres-postgresql-0 -- env PGPASSWORD="$PGPW" \
  psql -U postgres -d postgres -tAc \
  "SELECT rolname FROM pg_roles WHERE rolname LIKE 'v-%'"
```

Both scripts close their connections on exit, so the first query should return nothing and the
second should show only the currently live credential.

Adjust the namespace, pod name and secret name to match your PostgreSQL deployment.

---

## Reproducing by hand with `psql`

The same test without the scripts, if you prefer to watch it interactively.

```bash
CREDS=$(kubectl -n vault-demo exec $POD -c vault-agent -- cat /vault/secrets/db-creds.json)
DBUSER=$(echo "$CREDS" | jq -r .username)
DBPASS=$(echo "$CREDS" | jq -r .password)
echo "holding connection as: $DBUSER"

kubectl -n postgres exec -it postgres-postgresql-0 -- \
  env PGPASSWORD="$DBPASS" psql -h 127.0.0.1 -U "$DBUSER" -d postgres
```

Run `SELECT current_user;` to confirm it works, then leave the session idle until the credential has
rotated and the old lease has expired — roughly `max_ttl` plus the remainder of the last lease. Then
run:

```sql
SELECT 1;                          -- succeeds: this is the pool's health check
SELECT current_user;               -- ERROR: invalid role OID
SELECT count(*) FROM products;     -- ERROR: permission denied
```

Use an existing pod that already has a `psql` client rather than starting a throwaway one with
`kubectl run` — on a cluster near its per-node pod limit, a new pod may sit in `Pending`.

---

## What to do about it

The remedy is configuration rather than a rewrite. Two settings, and both are needed:

**1. Acquire credentials per connection, not per process.** The pool must call a provider function
each time it opens a new physical connection, rather than reading a username and password once at
startup. Otherwise replacement connections reuse a credential that no longer exists.

**2. Retire connections before their credential expires.** Set the maximum connection lifetime below
Vault's `max_ttl`. Connections then age out and rebuild themselves with a current credential, and no
rotation event ever has to be detected.

| Pool | Setting |
|---|---|
| HikariCP (Java / Spring Boot) | [`maxLifetime`](https://github.com/brettwooldridge/HikariCP#gear-configuration-knobs-baby) |
| SQLAlchemy (Python) | [`pool_recycle`](https://docs.sqlalchemy.org/en/20/core/pooling.html#setting-pool-recycle) |
| Go `database/sql` | [`SetConnMaxLifetime`](https://pkg.go.dev/database/sql#DB.SetConnMaxLifetime) |
| Npgsql (.NET) | [`Connection Lifetime`](https://www.npgsql.org/doc/connection-string-parameters.html) |
| PgBouncer | [`server_lifetime`](https://www.pgbouncer.org/config.html) |

**Do not rely on `SELECT 1` validation to detect this** — as the battery shows, it will not.

If pooling happens in PgBouncer rather than the application, `server_lifetime` is where this is
configured, which moves the fix from each application team to the platform team.

### A note on other databases

These findings are PostgreSQL-specific. Oracle behaves differently in one important respect:
`DROP USER` against a connected user returns `ORA-01940: cannot drop a user that is currently
connected`. **Revocation itself fails** rather than leaving a zombie connection behind, so
revocation statements must lock the account and terminate its sessions before dropping. On Oracle,
setting a connection lifetime below `max_ttl` is not only about avoiding application errors — it is
what makes revocation possible at all.

---

## Tunables

Both scripts read these from the environment:

| Variable | Default | Used by |
|---|---|---|
| `DURATION_SECONDS` | `480` | timeline |
| `INTERVAL_SECONDS` | `15` | timeline |
| `POLL_SECONDS` | `5` | battery |
| `WAIT_TIMEOUT_SECONDS` | `600` | battery |
| `SECRET_FILE` | `/vault/secrets/db-creds.json` | both |
| `DB_HOST` / `DB_PORT` / `DB_NAME` | inherited from the pod | both |

Pass one through `kubectl exec` with `env`:

```bash
kubectl -n vault-demo exec -i $POD -c vault-agent-db-demo \
  -- env DURATION_SECONDS=240 python - < tests/held_connection_timeline.py
```

---

## Troubleshooting

**`gave up waiting`** — the battery timed out before revocation occurred. Confirm the role's
`max_ttl` and raise `WAIT_TIMEOUT_SECONDS` if it is longer than 600 seconds.

**Output is hard to follow** — run the scripts one at a time. Two held connections at once produces
interleaved results.

**Timing feels slow** — revocation lags rotation by the remainder of the old lease, so a full cycle
takes `max_ttl` plus that tail. Starting immediately after a rotation means the longest wait.
