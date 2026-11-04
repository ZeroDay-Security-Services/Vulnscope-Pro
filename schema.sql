-- VulnScope Pro — SQLite schema.
-- This is the canonical schema; bootstrap.php executes it on startup so a
-- fresh deployment (or the Docker pre-created empty DB file) converges here.

CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT,
    ip_address TEXT,
    risk_score INTEGER,
    nmap_output TEXT,
    intelligence_data TEXT,
    vulnerabilities TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 30-minute scan result cache to make repeat scans instant
CREATE TABLE IF NOT EXISTS scan_cache (
    ip_key TEXT PRIMARY KEY,
    response_json TEXT,
    cached_at INTEGER
);

-- Persistent upstream-intelligence cache (CVE details, vendor feeds, EPSS).
-- Shared by the Vulnerability-Lookup client so repeat scans stay fast and
-- rate-limit friendly.
CREATE TABLE IF NOT EXISTS intel_cache (
    cache_key TEXT PRIMARY KEY,
    payload TEXT,
    cached_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_scans_target ON scans (target);
CREATE INDEX IF NOT EXISTS idx_scans_time ON scans (timestamp);
CREATE INDEX IF NOT EXISTS idx_intel_age ON intel_cache (cached_at);

-- =========================================================================
-- Collaborative CVD layer (Vulnerability-Lookup parity)
-- =========================================================================

-- Analyst sightings on vulnerabilities (seen / exploited / confirmed / patched…)
CREATE TABLE IF NOT EXISTS sightings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vuln_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    target TEXT,
    author TEXT,
    note TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_sightings_vuln ON sightings (vuln_id);

-- Analyst notes / comments attached to advisories
CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vuln_id TEXT NOT NULL,
    author TEXT,
    body TEXT NOT NULL,
    severity_vote TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_comments_vuln ON comments (vuln_id);

-- Bundles: group related advisories in a case/track
CREATE TABLE IF NOT EXISTS bundles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    vuln_ids TEXT NOT NULL DEFAULT '[]',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME
);

-- Watchlists: monitor vendor:product pairs for new advisories
CREATE TABLE IF NOT EXISTS watchlists (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vendor TEXT NOT NULL,
    product TEXT NOT NULL,
    min_cvss REAL DEFAULT 0.0,
    webhook_url TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_checked DATETIME
);

-- Notifications queued/delivered by watchlist + hazard alerting
CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    watchlist_id INTEGER,
    vuln_id TEXT,
    payload TEXT,
    delivered INTEGER DEFAULT 0,
    error TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_notifications_pending ON notifications (watchlist_id, delivered);

-- Deduplication of advisories already seen per watchlist
CREATE TABLE IF NOT EXISTS seen_vulns (
    watchlist_id INTEGER,
    vuln_id TEXT,
    seen_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (watchlist_id, vuln_id)
);

-- =========================================================================
-- Intercepting-proxy layer (ZAP parity): request history + manual replay
-- =========================================================================
CREATE TABLE IF NOT EXISTS http_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts DATETIME DEFAULT CURRENT_TIMESTAMP,
    session TEXT,
    method TEXT NOT NULL,
    url TEXT NOT NULL,
    host TEXT,
    status INTEGER,
    size INTEGER,
    ms INTEGER,
    entry_type TEXT DEFAULT 'scan',
    request_head TEXT,
    response_head TEXT,
    request_body TEXT,
    response_body TEXT
);
CREATE INDEX IF NOT EXISTS idx_http_host ON http_history (host);
CREATE INDEX IF NOT EXISTS idx_http_ts ON http_history (ts);

-- =========================================================================
-- Scan contexts & policies (ZAP parity)
-- =========================================================================

-- Context: scope + optional authenticated-session parameters
CREATE TABLE IF NOT EXISTS contexts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    scope TEXT,
    auth_type TEXT DEFAULT 'none',          -- none | auto-cookie | basic
    auth_url TEXT,
    auth_method TEXT DEFAULT 'POST',
    auth_payload TEXT,                      -- template with {username}/{password}
    username TEXT,
    password TEXT,
    headers TEXT DEFAULT '[]',              -- always-send headers
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Policy: per rule-group strength & alert threshold
CREATE TABLE IF NOT EXISTS scan_policies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    is_default INTEGER DEFAULT 0,
    config TEXT NOT NULL DEFAULT '{}',      -- {group: threshold, ...} + requests multiplier
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
