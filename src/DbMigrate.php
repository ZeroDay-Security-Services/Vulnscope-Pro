<?php
/**
 * VulnScope Pro — lightweight schema migrations.
 *
 * schema.sql covers fresh installs (CREATE TABLE IF NOT EXISTS), but an
 * existing database predating a feature release needs additive ALTERs.
 * vs_ensure_column() is idempotent: it checks pragma table_info first.
 */
declare(strict_types=1);

function vs_ensure_column(PDO $pdo, string $table, string $column, string $ddl): void
{
    static $checked = [];
    $key = $table . '.' . $column;
    if (isset($checked[$key])) {
        return;
    }
    try {
        $stmt = $pdo->prepare('PRAGMA table_info(' . basename($table) . ')');
        $stmt->execute();
        $cols = $stmt->fetchAll(PDO::FETCH_COLUMN, 1);
        if (!in_array($column, $cols, true)) {
            $pdo->exec('ALTER TABLE ' . basename($table) . ' ADD COLUMN ' . $column . ' ' . $ddl);
        }
        $checked[$key] = true;
    } catch (Throwable $e) {
        // Best-effort; the catch on the queries that use the column handles it.
    }
}

/** Ensure all migration-era columns exist (called from bootstrap). */
function vs_migrate_schema(PDO $pdo): void
{
    // Watchlists gained Notification-model fields (Vulnerability-Lookup parity).
    vs_ensure_column($pdo, 'watchlists', 'frequency',      "TEXT DEFAULT 'daily'");
    vs_ensure_column($pdo, 'watchlists', 'hazard_threshold', "INTEGER DEFAULT 0");
    vs_ensure_column($pdo, 'watchlists', 'hazard_alerted', "INTEGER DEFAULT 0");
    vs_ensure_column($pdo, 'watchlists', 'is_active',      "INTEGER DEFAULT 1");

    // http_history gained transcripts.
    vs_ensure_column($pdo, 'http_history', 'request_head',  'TEXT');
    vs_ensure_column($pdo, 'http_history', 'response_head', 'TEXT');

    // Contexts gained a verified logged-in indicator.
    vs_ensure_column($pdo, 'contexts', 'indicator', "TEXT DEFAULT ''");
}
