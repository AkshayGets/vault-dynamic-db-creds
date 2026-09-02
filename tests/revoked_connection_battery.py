"""
What a database connection can still do after its credential is revoked.

Opens ONE PostgreSQL connection with the credential Vault Agent has
currently rendered, waits until Vault has actually revoked it and
PostgreSQL has dropped the role, then runs a battery of queries on that
same connection to establish precisely what survives.

The result splits by audience:

    Security  -- no table access survives. The session cannot read or
                 write a single row.
    Platform  -- SELECT 1 still succeeds. That is the default
                 connection-validation query for HikariCP and most
                 other pools, so a pool health check reports this
                 connection healthy while every real query on it fails.

Run inside the application pod, which already has psycopg2 and the
Agent-rendered secret mounted:

    kubectl -n vault-demo exec -i $POD -c vault-agent-db-demo \
        -- python - < revoked_connection_battery.py

Read-only except for one INSERT that is expected to be refused.
"""

import json
import os
import time

from datetime import datetime, timezone

import psycopg2


# ============================================================
# Configuration
# ============================================================

SECRET_FILE = os.environ.get(
    "SECRET_FILE",
    "/vault/secrets/db-creds.json",
)

DB_HOST = os.environ.get(
    "DB_HOST",
    "postgres-postgresql.postgres.svc.cluster.local",
)

DB_PORT = int(
    os.environ.get("DB_PORT", "5432")
)

DB_NAME = os.environ.get(
    "DB_NAME",
    "postgres",
)

POLL_SECONDS = int(
    os.environ.get("POLL_SECONDS", "5")
)

# Give up if revocation never arrives, rather than hanging in front of
# an audience. Comfortably longer than max_ttl plus the lease tail.
WAIT_TIMEOUT_SECONDS = int(
    os.environ.get("WAIT_TIMEOUT_SECONDS", "600")
)


# The battery. Ordered so the demo builds: the two that survive first,
# then the three that prove data access is gone.
BATTERY = [
    (
        "SELECT 1",
        "trivial -- no catalog or role lookup",
    ),
    (
        "SELECT now()",
        "builtin function",
    ),
    (
        "SELECT count(*) FROM products",
        "real table -- privilege check",
    ),
    (
        "SELECT current_user",
        "resolves the role OID",
    ),
    (
        "SELECT session_user",
        "resolves the role OID",
    ),
    (
        "INSERT INTO products (name, price) VALUES ('x', 1)",
        "write attempt",
    ),
]


# ============================================================
# Helpers
# ============================================================

def read_credentials():
    with open(SECRET_FILE, "r") as f:
        return json.load(f)


def timestamp():
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


def connect(credentials):
    return psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        database=DB_NAME,
        user=credentials["username"],
        password=credentials["password"],
        connect_timeout=5,
    )


def role_is_gone(rolname):
    """
    Ask, over a FRESH connection using the current credential, whether
    the named role has been dropped yet.
    """

    probe = None

    try:
        probe = connect(read_credentials())

        cur = probe.cursor()

        cur.execute(
            "SELECT count(*) FROM pg_roles WHERE rolname = %s",
            (rolname,),
        )

        gone = cur.fetchone()[0] == 0

        cur.close()

        return gone

    finally:
        if probe:
            probe.close()


# ============================================================
# Main
# ============================================================

def main():

    credentials = read_credentials()

    held_user = credentials["username"]

    conn = connect(credentials)

    # Autocommit so each battery statement is its own transaction and
    # one failure does not abort the rest.
    conn.autocommit = True

    print(
        f"[{timestamp()}] held connection as {held_user}",
        flush=True,
    )

    print(
        f"[{timestamp()}] backend_pid={conn.get_backend_pid()}  "
        f"waiting for revocation...",
        flush=True,
    )

    # --------------------------------------------------------
    # Wait for Vault to revoke and PostgreSQL to drop the role
    # --------------------------------------------------------

    started = time.time()

    while True:

        if time.time() - started > WAIT_TIMEOUT_SECONDS:

            print(
                f"[{timestamp()}] gave up waiting after "
                f"{WAIT_TIMEOUT_SECONDS}s -- is the role's max_ttl "
                f"longer than expected?",
                flush=True,
            )

            conn.close()

            return

        try:
            if role_is_gone(held_user):

                print(
                    f"[{timestamp()}] role DROPPED -- running "
                    f"battery on the held connection",
                    flush=True,
                )

                break

        except Exception as e:

            print(
                f"[{timestamp()}] probe error {type(e).__name__}",
                flush=True,
            )

        time.sleep(POLL_SECONDS)

    # --------------------------------------------------------
    # The battery
    # --------------------------------------------------------

    print(
        f"[{timestamp()}] socket still open? "
        f"conn.closed={conn.closed}",
        flush=True,
    )

    for sql, why in BATTERY:

        try:
            cur = conn.cursor()

            cur.execute(sql)

            try:
                result = str(cur.fetchone())[:40]
            except Exception:
                result = "(no rows returned)"

            cur.close()

            print(
                f"  OK    {sql[:44]:46} -> {result}   [{why}]",
                flush=True,
            )

        except Exception as e:

            print(
                f"  FAIL  {sql[:44]:46} -> "
                f"{type(e).__name__}: {str(e).strip()[:60]}   [{why}]",
                flush=True,
            )

            try:
                conn.rollback()
            except Exception:
                pass

    print(
        f"[{timestamp()}] final conn.closed={conn.closed}",
        flush=True,
    )

    conn.close()


if __name__ == "__main__":
    main()
