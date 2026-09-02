import json
import os
import re
import time
from datetime import datetime, timezone

import psycopg2
from flask import Flask, jsonify, render_template


app = Flask(__name__)


# ============================================================
# Configuration
# ============================================================

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

VAULT_NAMESPACE = os.environ.get(
    "VAULT_NAMESPACE",
    "my-org",
)

VAULT_AUTH_ROLE = os.environ.get(
    "VAULT_AUTH_ROLE",
    "vault-agent-demo",
)

VAULT_DB_ROLE = os.environ.get(
    "VAULT_DB_ROLE",
    "demo-agent-reader",
)

KUBERNETES_SERVICE_ACCOUNT = os.environ.get(
    "KUBERNETES_SERVICE_ACCOUNT",
    "vault-agent-demo",
)

KUBERNETES_NAMESPACE = os.environ.get(
    "KUBERNETES_NAMESPACE",
    "vault-demo",
)

SECRET_FILE = os.environ.get(
    "SECRET_FILE",
    "/vault/secrets/db-creds.json",
)

# TTL of the dynamic role, in seconds.
#
# This is the *renewal interval*, not the lifetime of the
# credential. Vault Agent renews the lease on this cadence for
# as long as the lease is renewable.
VAULT_DB_TTL = int(
    os.environ.get("VAULT_DB_TTL", "60")
)

# Maximum lifetime of a single dynamic credential, in seconds.
#
# Once this is reached the lease can no longer be renewed:
# Vault revokes it, PostgreSQL drops the role, and Vault Agent
# renders a replacement credential. This — not VAULT_DB_TTL —
# is the number the UI counts down.
VAULT_DB_MAX_TTL = int(
    os.environ.get("VAULT_DB_MAX_TTL", "300")
)


# ============================================================
# Helpers
# ============================================================

def utc_now():
    return datetime.now(timezone.utc)


def read_injected_credentials():
    """
    Read credentials rendered by Vault Agent Injector.

    The application itself does NOT authenticate to Vault.
    Vault Agent handles authentication and secret rendering.
    """

    with open(SECRET_FILE, "r") as f:
        data = json.load(f)

    return data


# Vault's default PostgreSQL username template ends with the
# UNIX timestamp at which the credential was created:
#
#     v-us-west--demo-age-8Gt1WQ0vyEgpiTbVgrCi-1788327392
#                                              ^^^^^^^^^^
#
# Verified against two independent sources: the Vault lease's
# issue_time, and the mtime of the rendered secret file. All
# three agree to the second.
USERNAME_ISSUED_AT = re.compile(r"-(\d{9,11})$")


def parse_issued_at(username):
    """
    Recover a dynamic credential's issue time from its username.

    Returns None if the database role uses a custom
    username_template that does not end in a UNIX timestamp.
    """

    if not username:
        return None

    match = USERNAME_ISSUED_AT.search(username)

    if not match:
        return None

    return int(match.group(1))


def secret_file_mtime():
    """
    Render time of the injected credential file.

    Vault Agent rewrites this file only when the credential
    itself changes — a lease renewal leaves it byte-identical —
    so its mtime is when the current credential was rendered.
    """

    return int(
        os.stat(SECRET_FILE).st_mtime
    )


def credential_timing(credentials):
    """
    Work out how much real life the current credential has left.

    The lease_duration in the injected file is the renewal
    interval (60s), not the credential's lifetime. Vault Agent
    renews on that cadence until max_ttl is reached, at which
    point the credential is revoked and replaced. The number
    worth showing an audience is therefore measured against
    max_ttl, from the moment the credential was issued.

    Computed server-side so the countdown is anchored to the
    cluster's clock rather than the viewer's browser clock.
    """

    issued_at = parse_issued_at(
        credentials.get("username")
    )

    issued_at_source = "username"

    if issued_at is None:

        issued_at = secret_file_mtime()

        issued_at_source = "file_mtime"

    now = int(time.time())

    expires_at = issued_at + VAULT_DB_MAX_TTL

    return {
        "issued_at": issued_at,

        "issued_at_iso": datetime.fromtimestamp(
            issued_at,
            timezone.utc,
        ).isoformat(),

        "issued_at_source": issued_at_source,

        "age_seconds": max(0, now - issued_at),

        "expires_at": expires_at,

        "expires_at_iso": datetime.fromtimestamp(
            expires_at,
            timezone.utc,
        ).isoformat(),

        "remaining_seconds": max(0, expires_at - now),

        "max_ttl_seconds": VAULT_DB_MAX_TTL,

        "lease_ttl_seconds": VAULT_DB_TTL,

        "server_now": now,
    }


def connect_postgres(username, password):
    """
    Connect to PostgreSQL using credentials supplied
    by Vault Agent.
    """

    return psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        database=DB_NAME,
        user=username,
        password=password,
        connect_timeout=5,
    )


def query_database():
    """
    Connect using the currently injected credentials and
    return PostgreSQL identity / role information.
    """

    credentials = read_injected_credentials()

    username = credentials["username"]
    password = credentials["password"]

    conn = None
    cur = None

    try:
        conn = connect_postgres(username, password)
        cur = conn.cursor()

        cur.execute(
            """
            SELECT
                current_user,
                session_user,
                current_database()
            """
        )

        identity = cur.fetchone()

        cur.execute(
            """
            SELECT
                r.rolname
            FROM pg_auth_members m
            JOIN pg_roles r
              ON r.oid = m.roleid
            JOIN pg_roles member_role
              ON member_role.oid = m.member
            WHERE member_role.rolname = current_user
            ORDER BY r.rolname
            """
        )

        memberships = [
            row[0]
            for row in cur.fetchall()
        ]

        return {
            "current_user": identity[0],
            "session_user": identity[1],
            "database": identity[2],
            "role_memberships": memberships,
        }

    finally:
        if cur:
            cur.close()

        if conn:
            conn.close()


def get_lifecycle():
    """
    Build the information displayed by the UI.

    This information comes from the file rendered by
    Vault Agent.
    """

    credentials = read_injected_credentials()

    lease_duration = credentials.get(
        "lease_duration",
        0,
    )

    generated_at = credentials.get(
        "generated_at",
    )

    return {
        "username": credentials.get("username"),
        "lease_id": credentials.get("lease_id"),
        "lease_duration": lease_duration,
        "generated_at": generated_at,
        "secret_file": SECRET_FILE,
        "vault_namespace": VAULT_NAMESPACE,
        "vault_auth_role": VAULT_AUTH_ROLE,
        "vault_db_role": VAULT_DB_ROLE,
        "kubernetes_service_account": KUBERNETES_SERVICE_ACCOUNT,
        "kubernetes_namespace": KUBERNETES_NAMESPACE,
    }


# ============================================================
# UI
# ============================================================

@app.get("/")
def index():
    return render_template(
        "index.html",
        vault_namespace=VAULT_NAMESPACE,
        vault_auth_role=VAULT_AUTH_ROLE,
        vault_db_role=VAULT_DB_ROLE,
        kubernetes_service_account=KUBERNETES_SERVICE_ACCOUNT,
        kubernetes_namespace=KUBERNETES_NAMESPACE,
        secret_file=SECRET_FILE,
    )


# ============================================================
# Status
# ============================================================

@app.get("/api/status")
def status():

    try:

        credentials = read_injected_credentials()

        return jsonify({
            "success": True,
            "application": "Vault Agent Injector DB Demo",
            "vault": {
                "namespace": VAULT_NAMESPACE,
                "authentication": "Kubernetes Auth via Vault Agent",
                "auth_role": VAULT_AUTH_ROLE,
                "database_role": VAULT_DB_ROLE,
            },
            "kubernetes": {
                "namespace": KUBERNETES_NAMESPACE,
                "service_account": KUBERNETES_SERVICE_ACCOUNT,
            },
            "injection": {
                "secret_file": SECRET_FILE,
                "credentials_available": True,
            },
            "credential": {
                "username": credentials.get("username"),
                "lease_id": credentials.get("lease_id"),
                "lease_duration": credentials.get(
                    "lease_duration"
                ),
                "timing": credential_timing(credentials),
            },
        })

    except Exception as e:

        return jsonify({
            "success": False,
            "error": str(e),
        }), 500


# ============================================================
# Read / query operation
# ============================================================

@app.post("/api/read")
def api_read():

    started = time.time()

    try:

        credentials = read_injected_credentials()

        db_result = query_database()

        elapsed_ms = round(
            (time.time() - started) * 1000,
            2,
        )

        return jsonify({
            "success": True,

            "lifecycle": {
                "kubernetes_service_account":
                    KUBERNETES_SERVICE_ACCOUNT,

                "kubernetes_namespace":
                    KUBERNETES_NAMESPACE,

                "vault_namespace":
                    VAULT_NAMESPACE,

                "vault_auth_role":
                    VAULT_AUTH_ROLE,

                "vault_database_role":
                    VAULT_DB_ROLE,

                "secret_file":
                    SECRET_FILE,

                "generated_username":
                    credentials.get("username"),

                "lease_id":
                    credentials.get("lease_id"),

                "lease_duration_seconds":
                    credentials.get("lease_duration"),

                "timing":
                    credential_timing(credentials),
            },

            "database": db_result,

            "elapsed_ms": elapsed_ms,
        })

    except Exception as e:

        return jsonify({
            "success": False,
            "error": str(e),
        }), 500


# ============================================================
# Credential inspection
# ============================================================

@app.get("/api/credential")
def credential():

    try:

        credentials = read_injected_credentials()

        return jsonify({
            "success": True,
            "username": credentials.get("username"),
            "lease_id": credentials.get("lease_id"),
            "lease_duration": credentials.get(
                "lease_duration"
            ),
            "timing": credential_timing(credentials),
            "secret_file": SECRET_FILE,
        })

    except Exception as e:

        return jsonify({
            "success": False,
            "error": str(e),
        }), 500


# ============================================================
# Database identity
# ============================================================

@app.get("/api/db-identity")
def db_identity():

    try:

        result = query_database()

        return jsonify({
            "success": True,
            "database": result,
        })

    except Exception as e:

        return jsonify({
            "success": False,
            "error": str(e),
        }), 500


# ============================================================
# Main
# ============================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=8080,
    )
