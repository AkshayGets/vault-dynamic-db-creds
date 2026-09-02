"""
Timeline of a held database connection across a credential rotation.

Opens ONE PostgreSQL connection using the credential Vault Agent has
currently rendered, then holds it open and probes it every 15 seconds.
That single held connection stands in for one connection sitting in an
application's connection pool.

Three things are recorded on every tick:

    1. Has the rendered credential file rotated?
    2. Does the PostgreSQL role the connection authenticated as
       still exist?
    3. Does a query on the held connection still succeed, and does
       the driver still consider the socket open?

Run inside the application pod, which already has psycopg2 and the
Agent-rendered secret mounted:

    kubectl -n vault-demo exec -i $POD -c vault-agent-db-demo \
        -- python - < held_connection_timeline.py

Read-only. Opens and closes connections; changes no data.
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

# Run long enough to cross a revocation boundary. Revocation lags
# rotation by the remainder of the old lease, so this needs to exceed
# max_ttl plus that tail -- 480s is comfortable against a 300s max_ttl.
DURATION_SECONDS = int(
    os.environ.get("DURATION_SECONDS", "480")
)

INTERVAL_SECONDS = int(
    os.environ.get("INTERVAL_SECONDS", "15")
)


# ============================================================
# Helpers
# ============================================================

def read_credentials():
    """
    Read whatever credential Vault Agent has currently rendered.
    """

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


def role_exists(rolname):
    """
    Check whether a role still exists, using a FRESH connection with
    whatever credential is current.

    This has to be independent of the held connection -- once the held
    connection's role is dropped it can no longer answer questions
    about itself.
    """

    probe = None

    try:
        probe = connect(read_credentials())

        cur = probe.cursor()

        cur.execute(
            "SELECT count(*) FROM pg_roles WHERE rolname = %s",
            (rolname,),
        )

        found = cur.fetchone()[0] > 0

        cur.close()

        return "role:EXISTS " if found else "role:DROPPED"

    except Exception as e:
        return f"probe_fail({type(e).__name__})"

    finally:
        if probe:
            probe.close()


# ============================================================
# Main
# ============================================================

def main():

    credentials = read_credentials()

    held_user = credentials["username"]

    print(
        f"[{timestamp()}] HELD CONNECTION opening as {held_user}",
        flush=True,
    )

    conn = connect(credentials)

    # Autocommit so a failed statement does not poison the ones
    # after it with "current transaction is aborted".
    conn.autocommit = True

    print(
        f"[{timestamp()}] connected, "
        f"backend_pid={conn.get_backend_pid()}",
        flush=True,
    )

    print(f"[{timestamp()}] {'-' * 95}", flush=True)

    started = time.time()

    while time.time() - started < DURATION_SECONDS:

        # ----------------------------------------------------
        # Has Vault Agent rendered a different credential?
        # ----------------------------------------------------

        current_user = read_credentials().get("username")

        rotated = (
            "ROTATED"
            if current_user != held_user
            else "same  "
        )

        # ----------------------------------------------------
        # Does the held connection still work?
        # ----------------------------------------------------

        try:
            cur = conn.cursor()

            cur.execute("SELECT current_user")

            held_status = (
                "HELD-CONN OK "
                f"(current_user={cur.fetchone()[0][:28]})"
            )

            cur.close()

        except Exception as e:

            held_status = (
                f"HELD-CONN FAIL {type(e).__name__}: "
                f"{str(e).strip()[:70]}"
            )

            try:
                conn.rollback()
            except Exception:
                pass

        # ----------------------------------------------------
        # Report
        # ----------------------------------------------------

        elapsed = int(time.time() - started)

        print(
            f"[{timestamp()}] t+{elapsed:3}s "
            f"file={rotated} "
            f"{role_exists(held_user)} "
            f"closed={conn.closed} | {held_status}",
            flush=True,
        )

        time.sleep(INTERVAL_SECONDS)

    conn.close()

    print(f"[{timestamp()}] done", flush=True)


if __name__ == "__main__":
    main()
