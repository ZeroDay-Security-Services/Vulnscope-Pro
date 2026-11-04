<?php
/**
 * VulnScope Pro — application bootstrap.
 * Single entry-point include for both public/index.php and public/api.php:
 * session, error handling, config, and the SQLite database handle.
 *
 * The fatal-error shutdown handler is carried over verbatim in behavior:
 * fatals bypass try/catch, so this converts them into a JSON diagnostic
 * instead of a blank HTTP 500.
 */
declare(strict_types=1);

require_once __DIR__ . '/config.php';

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

error_reporting(E_ALL);
ini_set('display_errors', '0');
ini_set('log_errors', '1');
set_time_limit(300);

register_shutdown_function(function () {
    $e = error_get_last();
    if ($e && in_array($e['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR], true)) {
        if (!headers_sent()) {
            http_response_code(500);
            header('Content-Type: application/json');
        }
        echo json_encode([
            'success' => false,
            'message' => 'PHP fatal: ' . $e['message'] . ' in ' . basename($e['file']) . ' on line ' . $e['line'],
        ]);
    }
});

/* =========================================================
   DATABASE — schema lives in schema.sql
   ========================================================= */
$db = null;
if (extension_loaded('pdo_sqlite')) {
    try {
        $db = new PDO('sqlite:' . DB_PATH);
        $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $db->exec(file_get_contents(__DIR__ . '/schema.sql'));
    } catch (Exception $e) {
        error_log('DB init: ' . $e->getMessage());
    }
}

/* Additive migrations for databases created before this release. */
if ($db) {
    require_once __DIR__ . '/src/DbMigrate.php';
    try {
        vs_migrate_schema($db);
    } catch (Throwable $e) {
        error_log('DB migrate: ' . $e->getMessage());
    }
}

/*
 * src/ files define plain functions (not classes), so they must be loaded
 * unconditionally — autoloading only works for classes.
 */
foreach (glob(__DIR__ . '/src/*.php') as $srcFile) {
    require_once $srcFile;
}

/* Class autoloader (classes not covered above, e.g. Database). */
spl_autoload_register(function (string $class): void {
    $file = __DIR__ . '/src/' . $class . '.php';
    if (is_file($file)) {
        require_once $file;
    }
});
