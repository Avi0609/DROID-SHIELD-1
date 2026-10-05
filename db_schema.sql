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
