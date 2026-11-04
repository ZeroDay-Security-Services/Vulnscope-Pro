<?php
/**
 * VulnScope Pro — environment-driven configuration.
 * Every value can be overridden via environment variables (Docker -e,
 * Render dashboard, or a real .env loader). Defaults preserved from the
 * pre-split monolith.
 */
declare(strict_types=1);

defined('DB_PATH')            or define('DB_PATH',            getenv('DB_PATH')            ?: 'vulnscope_v2.sqlite');
defined('SCAN_TOKEN')         or define('SCAN_TOKEN',         getenv('SCAN_TOKEN')         ?: 'SECURE_SCAN_TOKEN_2024');
// NOTE: getenv('X') for an UNSET var returns '' (or false), and
// filter_var('', FILTER_VALIDATE_BOOLEAN) === false — which would silently
// flip the default. Unset/empty must fall through to the monolith default (true).
$_vs_internal = getenv('ALLOW_INTERNAL_SCAN');
defined('ALLOW_INTERNAL_SCAN') or define('ALLOW_INTERNAL_SCAN',
    ($_vs_internal === false || $_vs_internal === null || $_vs_internal === '')
        ? true
        : filter_var($_vs_internal, FILTER_VALIDATE_BOOLEAN)
);
unset($_vs_internal);

// API keys — loaded from environment variables (set in Render dashboard or .env)
defined('NVD_API_KEY')      or define('NVD_API_KEY',      getenv('NVD_API_KEY')      ?: '');
defined('SHODAN_API_KEY')   or define('SHODAN_API_KEY',   getenv('SHODAN_API_KEY')   ?: '');
defined('CENSYS_API_TOKEN') or define('CENSYS_API_TOKEN', getenv('CENSYS_API_TOKEN') ?: '');
defined('OPENCVE_USER')     or define('OPENCVE_USER',     getenv('OPENCVE_USER')     ?: '');
defined('OPENCVE_PASS')     or define('OPENCVE_PASS',     getenv('OPENCVE_PASS')     ?: '');

// Intel API endpoints
define('CIRCL_API_BASE',   'https://cve.circl.lu/api/');
define('NVD_API_BASE',     'https://services.nvd.nist.gov/rest/json/cves/2.0');
define('OPENCVE_API_BASE', 'https://app.opencve.io/api/v2/');
