import os
from contextlib import contextmanager

import psycopg
from psycopg.rows import dict_row

DATABASE_URL = os.getenv("DATABASE_URL") or os.getenv("NEON_DATABASE_URL")

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS apk_scans (
    id BIGSERIAL PRIMARY KEY,
    file_name TEXT NOT NULL,
    sha256 CHAR(64) NOT NULL,
    size_mb DOUBLE PRECISION,
    package_name TEXT,
    version TEXT,
    androguard_used BOOLEAN DEFAULT FALSE,
    certificate_present BOOLEAN DEFAULT FALSE,
    risk_score INTEGER,
    classification TEXT,
    summary TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_apk_scans_sha256 ON apk_scans(sha256);
CREATE INDEX IF NOT EXISTS idx_apk_scans_created_at ON apk_scans(created_at DESC);

CREATE TABLE IF NOT EXISTS apk_permissions (
    id BIGSERIAL PRIMARY KEY,
    scan_id BIGINT NOT NULL REFERENCES apk_scans(id) ON DELETE CASCADE,
    permission TEXT NOT NULL,
    risk_points INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_apk_permissions_scan_id ON apk_permissions(scan_id);

CREATE TABLE IF NOT EXISTS apk_components (
    id BIGSERIAL PRIMARY KEY,
    scan_id BIGINT NOT NULL REFERENCES apk_scans(id) ON DELETE CASCADE,
    component_type TEXT NOT NULL,
    component_name TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_apk_components_scan_id ON apk_components(scan_id);

CREATE TABLE IF NOT EXISTS apk_intents (
    id BIGSERIAL PRIMARY KEY,
    scan_id BIGINT NOT NULL REFERENCES apk_scans(id) ON DELETE CASCADE,
    intent_name TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_apk_intents_scan_id ON apk_intents(scan_id);

CREATE TABLE IF NOT EXISTS apk_apis (
    id BIGSERIAL PRIMARY KEY,
    scan_id BIGINT NOT NULL REFERENCES apk_scans(id) ON DELETE CASCADE,
    api_name TEXT NOT NULL,
    risk_points INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_apk_apis_scan_id ON apk_apis(scan_id);

CREATE TABLE IF NOT EXISTS apk_network_indicators (
    id BIGSERIAL PRIMARY KEY,
    scan_id BIGINT NOT NULL REFERENCES apk_scans(id) ON DELETE CASCADE,
    indicator_type TEXT NOT NULL,
    indicator_value TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_apk_network_scan_id ON apk_network_indicators(scan_id);

CREATE TABLE IF NOT EXISTS risk_factors (
    id BIGSERIAL PRIMARY KEY,
    scan_id BIGINT NOT NULL REFERENCES apk_scans(id) ON DELETE CASCADE,
    severity TEXT,
    title TEXT NOT NULL,
    detail TEXT,
    points INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_risk_factors_scan_id ON risk_factors(scan_id);

CREATE TABLE IF NOT EXISTS scan_scores (
    id BIGSERIAL PRIMARY KEY,
    scan_id BIGINT NOT NULL UNIQUE REFERENCES apk_scans(id) ON DELETE CASCADE,
    permissions INTEGER DEFAULT 0,
    api_behavior INTEGER DEFAULT 0,
    components INTEGER DEFAULT 0,
    network INTEGER DEFAULT 0,
    obfuscation INTEGER DEFAULT 0,
    certificate INTEGER DEFAULT 0,
    other INTEGER DEFAULT 0
);
"""


def is_configured():
    return bool(DATABASE_URL)


@contextmanager
def get_connection():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is not configured")
    conn = psycopg.connect(DATABASE_URL, row_factory=dict_row, connect_timeout=10)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    if not DATABASE_URL:
        return False
    with get_connection() as conn:
        conn.execute(SCHEMA_SQL)
    return True


def save_analysis(result):
    """Save one complete analyzer result and all child findings."""
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO apk_scans
                    (file_name, sha256, size_mb, package_name, version,
                     androguard_used, certificate_present, risk_score,
                     classification, summary)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
                """,
                (
                    result.get("file"),
                    result.get("sha256"),
                    result.get("size_mb"),
                    result.get("package"),
                    result.get("version"),
                    bool(result.get("androguard")),
                    bool(result.get("certificate_present", False)),
                    result.get("risk_score"),
                    result.get("classification"),
                    result.get("summary"),
                ),
            )
            scan_id = cur.fetchone()["id"]

            permission_rows = []
            from analyzer import DANGEROUS_PERMISSIONS
            for permission in result.get("permissions", []):
                permission_rows.append(
                    (scan_id, permission, DANGEROUS_PERMISSIONS.get(permission, 0))
                )
            if permission_rows:
                cur.executemany(
                    "INSERT INTO apk_permissions (scan_id, permission, risk_points) VALUES (%s, %s, %s)",
                    permission_rows,
                )

            component_rows = []
            for component_type in ("activities", "services", "receivers", "providers"):
                for name in result.get(component_type, []):
                    component_rows.append((scan_id, component_type, name))
            if component_rows:
                cur.executemany(
                    "INSERT INTO apk_components (scan_id, component_type, component_name) VALUES (%s, %s, %s)",
                    component_rows,
                )

            intent_rows = [(scan_id, x) for x in result.get("intents", [])]
            if intent_rows:
                cur.executemany(
                    "INSERT INTO apk_intents (scan_id, intent_name) VALUES (%s, %s)",
                    intent_rows,
                )

            from analyzer import SUSPICIOUS_APIS
            api_rows = [
                (scan_id, api, SUSPICIOUS_APIS.get(api, 0))
                for api in result.get("suspicious_apis", [])
            ]
            if api_rows:
                cur.executemany(
                    "INSERT INTO apk_apis (scan_id, api_name, risk_points) VALUES (%s, %s, %s)",
                    api_rows,
                )

            network_rows = (
                [(scan_id, "url", x) for x in result.get("urls", [])]
                + [(scan_id, "ip", x) for x in result.get("ips", [])]
            )
            if network_rows:
                cur.executemany(
                    "INSERT INTO apk_network_indicators (scan_id, indicator_type, indicator_value) VALUES (%s, %s, %s)",
                    network_rows,
                )

            factor_rows = [
                (scan_id, x.get("severity"), x.get("title"), x.get("detail"), x.get("points", 0))
                for x in result.get("risk_factors", [])
            ]
            if factor_rows:
                cur.executemany(
                    "INSERT INTO risk_factors (scan_id, severity, title, detail, points) VALUES (%s, %s, %s, %s, %s)",
                    factor_rows,
                )

            scores = result.get("scores", {})
            cur.execute(
                """
                INSERT INTO scan_scores
                    (scan_id, permissions, api_behavior, components, network,
                     obfuscation, certificate, other)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    scan_id,
                    scores.get("permissions", 0),
                    scores.get("api_behavior", 0),
                    scores.get("components", 0),
                    scores.get("network", 0),
                    scores.get("obfuscation", 0),
                    scores.get("certificate", 0),
                    scores.get("other", 0),
                ),
            )

    return scan_id
