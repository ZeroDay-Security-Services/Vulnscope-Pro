<?php
/**
 * VulnScope Pro — database access wrapper (Phase 1 shell).
 *
 * The monolith used a bare `$db` PDO handle (global) plus inline SQL in the
 * router. This class gives the schema a home; Phase 1 keeps behavior
 * identical by exposing the same handle. Later phases (auth tables, audit
 * log) will migrate the inline SQL here.
 */
declare(strict_types=1);

final class Database
{
    private static ?PDO $handle = null;

    public static function pdo(): ?PDO
    {
        if (self::$handle === null) {
            self::$handle = $GLOBALS['db'] ?? null;
        }
        return self::$handle;
    }
}

/** Shared PDO handle for functional modules (VulnLookup cache, intel, etc.). */
function vs_db(): ?PDO
{
    return Database::pdo();
}
