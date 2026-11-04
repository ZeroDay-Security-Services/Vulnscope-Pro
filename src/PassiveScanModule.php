<?php
/**
 * VulnScope Pro — Passive scanner (ZAP passive-scan rules equivalent).
 *
 * Analyses the responses the spider already collected. No new traffic, no
 * payloads: it flags missing/weak security headers, cookie mistakes, CORS
 * misconfiguration, information disclosure, insecure form handling and
 * exposed sensitive files.
 *
 * Every alert carries the fields the report layer needs: rule id, name,
 * risk, confidence, CWE, evidence, solution and references.
 */
declare(strict_types=1);

/** Map a qualitative risk level to a CVSS-like score for risk aggregation. */
function vs_risk_cvss(string $risk): float
{
    return [
        'Critical' => 9.3,
        'High'     => 7.5,
        'Medium'   => 5.4,
        'Low'      => 3.1,
        'Info'     => 0.0,
    ][$risk] ?? 0.0;
}

/** A ZAP-style alert record. */
function vs_alert(array $a): array
{
    $risk = $a['risk'] ?? 'Info';
    return [
        'id'            => $a['id'] ?? ('VSP-PAS-' . strtoupper(substr(md5(($a['name'] ?? '') . ($a['url'] ?? '')), 0, 8))),
        'rule'          => $a['rule'] ?? '',
        'name'          => $a['name'] ?? 'Security observation',
        'type'          => $a['type'] ?? 'passive',
        'severity'      => $risk,
        'risk'          => $risk,
        'confidence'    => $a['confidence'] ?? 'Medium',
        'cvss'          => $a['cvss'] ?? vs_risk_cvss($risk),
        'cwe'           => $a['cwe'] ?? '',
        'summary'       => $a['summary'] ?? '',
        'evidence'      => $a['evidence'] ?? '',
        'solution'      => $a['solution'] ?? '',
        'reference'     => $a['reference'] ?? '',
        'url'           => $a['url'] ?? '',
        'param'         => $a['param'] ?? '',
        'payload'       => $a['payload'] ?? '',
        'method'        => $a['method'] ?? 'GET',
        'source'        => $a['source'] ?? 'Passive Scanner',
        'affected_service' => $a['affected_service'] ?? ($a['url'] ?? ''),
        'port'          => $a['port'] ?? '',
        'published'     => '',
        'vector'        => '',
    ];
}

/** Parse all Set-Cookie lines from a raw header block into name/attributes. */
function vs_parse_cookies(string $rawHeaders): array
{
    $cookies = [];
    if (preg_match_all('/^Set-Cookie:\s*([^=\r\n]+)=([^\r\n]*)/mi', $rawHeaders, $m, PREG_SET_ORDER)) {
        foreach ($m as $c) {
            $name = trim($c[1]);
            $rest = $c[2];
            $attrs = ['secure' => (bool)preg_match('/;\s*secure/i', $rest), 'httponly' => (bool)preg_match('/;\s*httponly/i', $rest)];
            $sameSite = '';
            if (preg_match('/;\s*samesite=([^;\s]+)/i', $rest, $sm)) {
                $sameSite = strtolower(trim($sm[1]));
            }
            $attrs['samesite'] = $sameSite;
            if ($name !== '' && !isset($cookies[$name])) {
                $cookies[$name] = $attrs;
            }
        }
    }
    return $cookies;
}

/**
 * Run passive rules over spider output.
 *
 * $ctx: 'port' (int), 'fuzz' (Module 2 output), 'base' (string), 'tls' (bool)
 */
function vs_passive_scan(array $spider, array $ctx = []): array
{
    $started = microtime(true);
    $base    = rtrim((string)($ctx['base'] ?? ($spider['base_url'] ?? '')), '/');
    $port    = (string)($ctx['port'] ?? '');
    $isHttps = str_starts_with($base, 'https://');
    $alerts  = [];
    $seen    = [];

    /**
     * Emit an alert. Global rules collapse to one alert that lists the
     * affected URLs instead of flooding the report with duplicates.
     */
    $emit = function (array $alert, bool $global = false) use (&$alerts, &$seen): void {
        $rule = $alert['rule'] ?? '';
        $url  = $alert['url'] ?? '';
        // Include evidence so two distinct observations of the same rule on the
        // same URL are kept, while exact duplicates collapse.
        $key  = $global ? $rule : $rule . '|' . $url . '|' . md5((string)($alert['evidence'] ?? ''));
        if (isset($seen[$key])) {
            if ($global && !empty($url)) {
                $alerts[$seen[$key]]['affected_urls'][] = $url;
                $alerts[$seen[$key]]['affected_urls'] = array_slice(array_values(array_unique($alerts[$seen[$key]]['affected_urls'])), 0, 12);
                $alerts[$seen[$key]]['affected_count'] = ($alerts[$seen[$key]]['affected_count'] ?? 1) + 1;
            }
            return;
        }
        $alert['affected_service'] = $alert['affected_service'] ?? $url;
        $alert['port'] = $alert['port'] ?? '';
        if ($global && $url !== '') {
            $alert['affected_urls'] = [$url];
            $alert['affected_count'] = 1;
        }
        $seen[$key] = count($alerts);
        $alerts[] = $alert;
    };

    $pages = array_values(array_filter($spider['pages'] ?? [], fn($p) => isset($p['headers']) && is_array($p['headers'])));
    if (!$pages) {
        return [
            'alerts' => [],
            'summary' => ['total' => 0, 'critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0, 'info' => 0],
            'rules_run' => 0,
            'duration_ms' => 0,
        ];
    }

    $security = [
        'content-security-policy'  => ['CSP Missing', 'Medium', 'CWE-693',
            'Content-Security-Policy header is not set, so the browser has no restriction on script sources and can execute injected inline script.',
            'Set a restrictive Content-Security-Policy, e.g. "default-src \'self\'; script-src \'self\'; object-src \'none\'; base-uri \'self\'".',
            'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP'],
        'strict-transport-security'=> ['HSTS Missing', 'Medium', 'CWE-319',
            'Strict-Transport-Security is absent, so the first request can be downgraded to plain HTTP and intercepted.',
            'Serve all traffic over HTTPS and send "Strict-Transport-Security: max-age=31536000; includeSubDomains" on HTTPS responses.',
            'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security'],
        'x-frame-options'          => ['Clickjacking Protection Missing', 'Medium', 'CWE-1021',
            'Neither X-Frame-Options nor CSP frame-ancestors restricts framing, allowing the page to be embedded in an attacker-controlled site.',
            'Send "X-Frame-Options: DENY" (or SAMEORIGIN) and/or "Content-Security-Policy: frame-ancestors \'none\'".',
            'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options'],
        'x-content-type-options'   => ['MIME Sniffing Protection Missing', 'Low', 'CWE-693',
            'X-Content-Type-Options is not set, so browsers may MIME-sniff responses and execute content as a different type.',
            'Send "X-Content-Type-Options: nosniff" on every response.',
            'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options'],
        'referrer-policy'          => ['Referrer-Policy Header Missing', 'Low', 'CWE-200',
            'Referrer-Policy is not set, so full URLs (which may contain tokens or identifiers) can leak to third-party sites.',
            'Send "Referrer-Policy: strict-origin-when-cross-origin" (or stricter).',
            'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy'],
        'permissions-policy'       => ['Permissions-Policy Header Missing', 'Info', 'CWE-693',
            'Permissions-Policy is not set, so powerful browser features (camera, geolocation, clipboard) stay enabled for embedded content.',
            'Send a Permissions-Policy that disables features the application does not use.',
            'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy'],
    ];

    // --- Header rules: evaluate per page, collapse globally -------------
    foreach ($pages as $page) {
        $h = $page['headers'];
        $url = $page['final_url'] ?? $page['url'];
        $raw = $page['raw_headers'] ?? '';

        foreach ($security as $header => [$label, $risk, $cwe, $summary, $solution, $ref]) {
            if ($header === 'strict-transport-security' && !$isHttps) {
                continue;
            }
            if (!isset($h[$header]) || trim((string)$h[$header]) === '') {
                $emit(vs_alert([
                    'id'       => 'VSP-PAS-' . strtoupper(substr(md5($header), 0, 6)),
                    'rule'     => 'header-' . $header,
                    'name'     => $label,
                    'risk'     => $risk,
                    'confidence' => 'High',
                    'cwe'      => $cwe,
                    'summary'  => $summary,
                    'evidence' => 'Response from ' . $url . ' does not include the ' . $header . ' header.',
                    'solution' => $solution,
                    'reference'=> $ref,
                    'url'      => $url,
                    'port'     => $port,
                ]), true);
            }
        }

        // CSP quality (present but weak)
        if (!empty($h['content-security-policy'])) {
            $csp = strtolower($h['content-security-policy']);
            if (str_contains($csp, "unsafe-inline") || str_contains($csp, "unsafe-eval")) {
                $emit(vs_alert([
                    'rule'     => 'csp-weak',
                    'name'     => 'Weak Content Security Policy',
                    'risk'     => 'Low',
                    'confidence' => 'High',
                    'cwe'      => 'CWE-693',
                    'summary'  => 'The CSP permits inline script or eval, which defeats much of its XSS protection.',
                    'evidence' => 'Content-Security-Policy: ' . substr($h['content-security-policy'], 0, 300),
                    'solution' => 'Remove \'unsafe-inline\'/\'unsafe-eval\' and move inline code to external files with nonces or hashes.',
                    'reference'=> 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP',
                    'url'      => $url,
                    'port'     => $port,
                ]), true);
            }
        }

        // Version / technology disclosure
        if (!empty($h['server']) && preg_match('/[\d]+\.[\d]+/', $h['server'])) {
            $emit(vs_alert([
                'rule'     => 'server-version',
                'name'     => 'Server Version Information Disclosure',
                'risk'     => 'Low',
                'confidence' => 'High',
                'cwe'      => 'CWE-200',
                'summary'  => 'Exact web-server version is advertised, which lets attackers match known exploits.',
                'evidence' => 'Server: ' . $h['server'],
                'solution' => 'Suppress version tokens (e.g. ServerTokens Prod for Apache, server_tokens off for nginx).',
                'reference'=> 'https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration',
                'url'      => $url,
                'port'     => $port,
            ]));
        }
        if (!empty($h['x-powered-by'])) {
            $emit(vs_alert([
                'rule'     => 'x-powered-by',
                'name'     => 'Application Technology Disclosure (X-Powered-By)',
                'risk'     => 'Low',
                'confidence' => 'High',
                'cwe'      => 'CWE-200',
                'summary'  => 'The application stack and sometimes its version are disclosed in an HTTP header.',
                'evidence' => 'X-Powered-By: ' . $h['x-powered-by'],
                'solution' => 'Remove the X-Powered-By header (expose_php=Off, app.disable("x-powered-by"), etc.).',
                'reference'=> 'https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration',
                'url'      => $url,
                'port'     => $port,
            ]), true);
        }

        // CORS policy
        if (isset($h['access-control-allow-origin'])) {
            $acao = trim($h['access-control-allow-origin']);
            $acac = strtolower(trim($h['access-control-allow-credentials'] ?? 'false')) === 'true';
            if ($acao === '*' && $acac) {
                $emit(vs_alert([
                    'rule'     => 'cors-wildcard-credentials',
                    'name'     => 'CORS Wildcard With Credentials',
                    'risk'     => 'High',
                    'confidence' => 'High',
                    'cwe'      => 'CWE-942',
                    'summary'  => 'Any origin is allowed while credentials are enabled, so any website can read authenticated responses.',
                    'evidence' => 'Access-Control-Allow-Origin: *; Access-Control-Allow-Credentials: true',
                    'solution' => 'Return an explicit allow-list of trusted origins and never combine "*" with credentials.',
                    'reference'=> 'https://portswigger.net/web-security/cors',
                    'url'      => $url,
                    'port'     => $port,
                ]), true);
            } elseif ($acao === '*') {
                $emit(vs_alert([
                    'rule'     => 'cors-wildcard',
                    'name'     => 'Permissive Cross-Origin Resource Sharing',
                    'risk'     => 'Medium',
                    'confidence' => 'Medium',
                    'cwe'      => 'CWE-942',
                    'summary'  => 'The API allows reads from any origin; if it serves sensitive data, an attacker site can exfiltrate it.',
                    'evidence' => 'Access-Control-Allow-Origin: *',
                    'solution' => 'Restrict Access-Control-Allow-Origin to known front-end origins.',
                    'reference'=> 'https://portswigger.net/web-security/cors',
                    'url'      => $url,
                    'port'     => $port,
                ]), true);
            }
        }

        // Cookies
        foreach (vs_parse_cookies($raw) as $name => $attrs) {
            if ($name === '') {
                continue;
            }
            if ($isHttps && empty($attrs['secure'])) {
                $emit(vs_alert([
                    'rule'     => 'cookie-secure',
                    'name'     => 'Cookie Without Secure Flag',
                    'risk'     => 'Medium',
                    'confidence' => 'High',
                    'cwe'      => 'CWE-614',
                    'summary'  => 'A cookie is sent over plain HTTP, exposing it to network interception.',
                    'evidence' => 'Set-Cookie: ' . $name . ' lacks the Secure attribute.',
                    'solution' => 'Add the Secure attribute to every cookie, especially session cookies.',
                    'reference'=> 'https://owasp.org/www-project-secure-headers/',
                    'url'      => $url,
                    'port'     => $port,
                ]), true);
            }
            if (empty($attrs['httponly'])) {
                $emit(vs_alert([
                    'rule'     => 'cookie-httponly',
                    'name'     => 'Cookie Without HttpOnly Flag',
                    'risk'     => 'Low',
                    'confidence' => 'High',
                    'cwe'      => 'CWE-1004',
                    'summary'  => 'Client-side JavaScript can read this cookie, so any XSS can steal the session.',
                    'evidence' => 'Set-Cookie: ' . $name . ' lacks the HttpOnly attribute.',
                    'solution' => 'Add HttpOnly to session and authentication cookies.',
                    'reference'=> 'https://owasp.org/www-project-secure-headers/',
                    'url'      => $url,
                    'port'     => $port,
                ]), true);
            }
            if ($attrs['samesite'] === '') {
                $emit(vs_alert([
                    'rule'     => 'cookie-samesite',
                    'name'     => 'Cookie Without SameSite Attribute',
                    'risk'     => 'Low',
                    'confidence' => 'High',
                    'cwe'      => 'CWE-1275',
                    'summary'  => 'Without SameSite, the cookie is sent on cross-site requests, weakening CSRF defences.',
                    'evidence' => 'Set-Cookie: ' . $name . ' lacks SameSite.',
                    'solution' => 'Set SameSite=Lax (or Strict for sensitive cookies).',
                    'reference'=> 'https://owasp.org/www-project-secure-headers/',
                    'url'      => $url,
                    'port'     => $port,
                ]), true);
            }
        }

        // Directory listing
        if (preg_match('/<title>\s*Index of \/?/i', $page['body'] ?? '')) {
            $emit(vs_alert([
                'rule'     => 'directory-listing',
                'name'     => 'Directory Browsing Enabled',
                'risk'     => 'Medium',
                'confidence' => 'High',
                'cwe'      => 'CWE-548',
                'summary'  => 'The server returns an auto-generated directory index, exposing files that were not meant to be listed.',
                'evidence' => 'Response title is "Index of ..." at ' . $url,
                'solution' => 'Disable directory indexes (Options -Indexes, autoindex off) and review the exposed directory.',
                'reference'=> 'https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration',
                'url'      => $url,
                'port'     => $port,
            ]));
        }

        // Mixed content on HTTPS pages
        if ($isHttps && preg_match_all('/(?:src|href)\s*=\s*["\'](http:\/\/[^"\']+)["\']/i', $page['body'] ?? '', $mm)) {
            $sample = array_slice(array_values(array_unique($mm[1])), 0, 5);
            $emit(vs_alert([
                'rule'     => 'mixed-content',
                'name'     => 'Secure Page Loads Mixed Content',
                'risk'     => 'Low',
                'confidence' => 'High',
                'cwe'      => 'CWE-319',
                'summary'  => 'An HTTPS page loads resources over insecure HTTP, which can be tampered with in transit.',
                'evidence' => 'Insecure resources: ' . implode(', ', array_map(fn($u) => substr($u, 0, 90), $sample)),
                'solution' => 'Load all sub-resources over HTTPS and add upgrade-insecure-requests to the CSP.',
                'reference'=> 'https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content',
                'url'      => $url,
                'port'     => $port,
            ]));
        }

        // External scripts without Subresource Integrity
        if (preg_match_all('/<script[^>]+src=["\'](https?:\/\/[^"\']+)["\'][^>]*>/i', $page['body'] ?? '', $sm, PREG_SET_ORDER)) {
            $noSRI = [];
            foreach ($sm as $tag) {
                if (stripos($tag[0], 'integrity=') === false) {
                    $noSRI[] = $tag[1];
                }
            }
            if ($noSRI) {
                $emit(vs_alert([
                    'rule'     => 'missing-sri',
                    'name'     => 'External Script Without Subresource Integrity',
                    'risk'     => 'Low',
                    'confidence' => 'Medium',
                    'cwe'      => 'CWE-353',
                    'summary'  => 'Third-party scripts are loaded without an integrity hash, so a compromised CDN can inject code.',
                    'evidence' => 'No integrity attribute on: ' . substr(implode(', ', array_slice(array_unique($noSRI), 0, 4)), 0, 300),
                    'solution' => 'Add integrity + crossorigin attributes, or self-host critical scripts.',
                    'reference'=> 'https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity',
                    'url'      => $url,
                    'port'     => $port,
                ]));
            }
        }

        // Password autocomplete
        if (preg_match('/<input[^>]+type=["\']password["\'][^>]*>/i', $page['body'] ?? '', $pm)
            && stripos($pm[0], 'autocomplete="off"') === false
            && stripos($pm[0], 'autocomplete="new-password"') === false) {
            $emit(vs_alert([
                'rule'     => 'password-autocomplete',
                'name'     => 'Password Field Allows Autocomplete',
                'risk'     => 'Low',
                'confidence' => 'Medium',
                'cwe'      => 'CWE-522',
                'summary'  => 'Some browsers may retain or autofill the password; this is a minor credential-handling weakness.',
                'evidence' => substr($pm[0], 0, 200),
                'solution' => 'Use autocomplete="current-password" (login) or "new-password" (registration) appropriately.',
                'reference'=> 'https://owasp.org/www-community/vulnerabilities/Password_Field_Autocomplete',
                'url'      => $url,
                'port'     => $port,
            ]));
        }

        // Error / stack trace disclosure
        $bodySample = substr($page['body'] ?? '', 0, 20000);
        if (preg_match('/(Fatal error:|Warning: \w+\(|Uncaught \w*Exception|Stack trace:|SQLSTATE\[|Traceback \(most recent call last\)|Notice: Undefined (?:variable|index))/i', $bodySample, $em)) {
            $emit(vs_alert([
                'rule'     => 'error-disclosure',
                'name'     => 'Application Error / Stack Trace Disclosure',
                'risk'     => 'Medium',
                'confidence' => 'Medium',
                'cwe'      => 'CWE-209',
                'summary'  => 'Detailed error output leaks file paths, queries or stack frames useful for exploitation.',
                'evidence' => 'Matched "' . substr($em[0], 0, 120) . '" in the response body.',
                'solution' => 'Disable display_errors / debug mode in production and return generic error pages.',
                'reference'=> 'https://owasp.org/www-community/Improper_Error_Handling',
                'url'      => $url,
                'port'     => $port,
            ]));
        }

        // Sensitive HTML comments
        $suspicious = [];
        foreach (($page['comments'] ?? []) as $comment) {
            if (preg_match('/\b(password|passwd|secret|api[_ -]?key|token|todo|fixme|hack|internal|debug|admin|database|username|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+)\b/i', $comment)) {
                $suspicious[] = $comment;
            }
        }
        if ($suspicious) {
            $emit(vs_alert([
                'rule'     => 'sensitive-comment',
                'name'     => 'Potentially Sensitive Information in HTML Comments',
                'risk'     => 'Low',
                'confidence' => 'Medium',
                'cwe'      => 'CWE-200',
                'summary'  => 'HTML comments contain hints about credentials, internal infrastructure or unfinished features.',
                'evidence' => substr(implode(' | ', array_slice($suspicious, 0, 3)), 0, 400),
                'solution' => 'Remove developer comments from production output.',
                'reference'=> 'https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url',
                'url'      => $url,
                'port'     => $port,
            ]));
        }

        // Insecure form submission (no TLS)
        if ($isHttps) {
            foreach (($page['forms'] ?? []) as $form) {
                if (str_starts_with(strtolower($form['action'] ?? ''), 'http://')) {
                    $emit(vs_alert([
                        'rule'     => 'insecure-form-action',
                        'name'     => 'Form Submits Over Insecure HTTP',
                        'risk'     => 'Medium',
                        'confidence' => 'High',
                        'cwe'      => 'CWE-319',
                        'summary'  => 'Form data, potentially including credentials, is posted over cleartext HTTP.',
                        'evidence' => 'form action="' . $form['action'] . '" on ' . $url,
                        'solution' => 'Post the form over HTTPS.',
                        'reference'=> 'https://owasp.org/www-community/vulnerabilities/Insufficient_Transport_Layer_Protection',
                        'url'      => $url,
                        'port'     => $port,
                    ]));
                }
            }
        }

        // CSRF token hints on sensitive forms (evidence only — confirmed in active scan)
        foreach (($page['forms'] ?? []) as $form) {
            if (($form['sensitive'] ?? false) && !($form['has_token'] ?? false) && strtoupper($form['method'] ?? 'GET') === 'POST') {
                $emit(vs_alert([
                    'rule'     => 'csrf-token-missing',
                    'name'     => 'Sensitive Form Without CSRF Token',
                    'risk'     => 'Medium',
                    'confidence' => 'Medium',
                    'cwe'      => 'CWE-352',
                    'summary'  => 'A login/credential form has no anti-CSRF token field. Verify whether the session is protected by another mechanism.',
                    'evidence' => 'POST form to ' . ($form['action'] ?? $url) . ' with no csrf/xsrf/authenticity/token input.',
                    'solution' => 'Add a per-session, unpredictable anti-CSRF token and validate it server-side.',
                    'reference'=> 'https://owasp.org/www-community/attacks/csrf',
                    'url'      => $url,
                    'port'     => $port,
                ]));
            }
        }
    }

    // --- Technology version / EOL checks --------------------------------
    foreach (($spider['technologies'] ?? []) as $tech) {
        $name = strtolower($tech['name'] ?? '');
        $ver  = (string)($tech['version'] ?? '');
        if ($ver === '') {
            continue;
        }
        $outdated = false;
        if ($name === 'jquery' && version_compare($ver, '3.5.0', '<')) {
            $outdated = true;
            $why = 'jQuery < 3.5.0 is affected by CVE-2020-11022 / CVE-2020-11023 (XSS via htmlPrefilter).';
        } elseif ($name === 'bootstrap' && version_compare($ver, '3.4.1', '<')) {
            $outdated = true;
            $why = 'Bootstrap < 3.4.1 is affected by XSS issues (CVE-2019-8331).';
        } elseif ($name === 'php' && version_compare($ver, '8.0', '<')) {
            $outdated = true;
            $why = 'PHP < 8.0 is end-of-life and no longer receives security fixes.';
        }
        if ($outdated) {
            $emit(vs_alert([
                'rule'     => 'outdated-component',
                'name'     => 'Outdated Third-Party Component (' . $tech['name'] . ' ' . $ver . ')',
                'risk'     => 'Medium',
                'confidence' => 'Medium',
                'cwe'      => 'CWE-1104',
                'summary'  => $why,
                'evidence' => $tech['name'] . ' ' . $ver . ' detected via ' . ($tech['evidence'] ?? 'page fingerprint'),
                'solution' => 'Upgrade the component to a supported release.',
                'reference'=> 'https://owasp.org/www-project-top-ten/2017/A9_2017-Using_Components_with_Known_Vulnerabilities',
                'url'      => $base,
                'port'     => $port,
            ]), true);
        }
    }

    // --- Exposed sensitive files / paths (from the directory fuzzer) -----
    $criticalPaths = [
        '.env' => ['Environment File Exposure', 'Critical', 'CWE-538', 'Environment files often contain database passwords, API keys and signing secrets.'],
        '.git/config' => ['Git Repository Exposure', 'Critical', 'CWE-538', 'Exposed .git metadata allows full source-code reconstruction.'],
        '.git/HEAD' => ['Git Repository Exposure', 'High', 'CWE-538', 'Exposed .git metadata allows full source-code reconstruction.'],
        'dump.sql' => ['Database Dump Exposure', 'Critical', 'CWE-538', 'A SQL dump exposes schema and live data, including credentials hashes.'],
        'db.sqlite3' => ['Database File Exposure', 'Critical', 'CWE-538', 'The raw database file can be downloaded directly.'],
        'backup.zip' => ['Backup Archive Exposure', 'High', 'CWE-538', 'Backup archives often contain full source code and configuration.'],
        'backup.tar.gz' => ['Backup Archive Exposure', 'High', 'CWE-538', 'Backup archives often contain full source code and configuration.'],
        'wp-config.php' => ['WordPress Configuration Exposure', 'High', 'CWE-538', 'WP-CLI configuration contains database credentials and salts.'],
        'config.php' => ['Configuration File Exposure', 'Medium', 'CWE-538', 'Configuration files may disclose credentials or internal hostnames.'],
        'database.yml' => ['Database Configuration Exposure', 'High', 'CWE-538', 'Rails database configuration with credentials is readable.'],
        '.htpasswd' => ['Password File Exposure', 'High', 'CWE-538', 'Hashed credentials for HTTP authentication are readable.'],
        '.DS_Store' => ['Metadata File Exposure', 'Low', 'CWE-538', 'macOS metadata reveals file and directory names.'],
        'server-status' => ['Server Status Page Exposure', 'Medium', 'CWE-200', 'Apache server-status reveals internal requests and client IPs.'],
        'phpinfo.php' => ['phpinfo() Exposure', 'Medium', 'CWE-200', 'phpinfo() reveals paths, modules and configuration details.'],
        'info.php' => ['phpinfo() Exposure', 'Medium', 'CWE-200', 'phpinfo() reveals paths, modules and configuration details.'],
        '.svn/entries' => ['SVN Repository Exposure', 'Medium', 'CWE-538', 'Subversion metadata may allow source reconstruction.'],
        'composer.json' => ['Dependency Manifest Exposure', 'Low', 'CWE-200', 'Dependency versions help attackers pick matching exploits.'],
        'package.json' => ['Dependency Manifest Exposure', 'Low', 'CWE-200', 'Dependency versions help attackers pick matching exploits.'],
    ];
    foreach (($ctx['fuzz']['hits'] ?? []) as $hit) {
        $path = ltrim((string)($hit['path'] ?? ''), '/');
        $status = (int)($hit['status'] ?? 0);
        $match = null;
        foreach ($criticalPaths as $needle => $meta) {
            if (strcasecmp($path, $needle) === 0 || str_ends_with(strtolower($path), '/' . strtolower($needle))) {
                $match = $meta;
                break;
            }
        }
        if ($match === null) {
            if (preg_match('/\.(?:sql|bak|old|zip|tar\.gz|7z|rar|env|ini|log)$/i', $path) && $status === 200) {
                $match = ['Sensitive File Exposure', 'High', 'CWE-538', 'A backup or configuration artifact is directly downloadable.'];
            } elseif ($status === 401 || $status === 403) {
                continue;
            } else {
                continue;
            }
        }
        [$name, $risk, $cwe, $why] = $match;
        $emit(vs_alert([
            'rule'     => 'exposed-path-' . $path,
            'name'     => $name,
            'risk'     => $risk,
            'confidence' => $status === 200 ? 'High' : 'Medium',
            'cwe'      => $cwe,
            'summary'  => $why,
            'evidence' => 'HTTP ' . $status . ' for /' . $path . ' (' . (int)($hit['length'] ?? 0) . ' bytes)',
            'solution' => 'Remove the file from the webroot, block direct access and rotate any exposed secrets.',
            'reference'=> 'https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration',
            'url'      => rtrim($base, '/') . '/' . $path,
            'port'     => $port,
            'source'   => 'Passive Scanner / Dir Fuzzer',
        ]));
    }

    // --- ZAP-parity body/header sweep (disclosure & hygiene rules) -------
    $b64LongRuns = [];
    $emails = [];
    $privIps = [];
    $serialized = [];
    $unprotectedBlank = [];
    $dangerousJs = [];
    $charsetMismatch = false;
    foreach ($pages as $page) {
        $url  = $page['final_url'] ?? $page['url'];
        $body = (string)($page['body'] ?? '');
        $h    = $page['headers'];
        $len  = strlen($body);
        if ($len === 0) {
            continue;
        }

        // 10094 — Base64 Disclosure: long runs decoded + heuristically named
        if ($len > 20
            && preg_match_all('/["\'\s>=(^]([A-Za-z0-9+\/]{96,}={0,2})["\'\s<)]/i', $body, $b64m, PREG_SET_ORDER)
            && count($b64m) <= 12) {
            foreach ($b64m as $hit) {
                $dec = @base64_decode($hit[1], true);
                if ($dec === false || !preg_match('/^[\x20-\x7e]{16,4096}$/', $dec)) {
                    continue;
                }
                $head = substr($dec, 0, 60);
                try {
                    $decoded = json_decode($dec, true, 2);
                    $kind = is_array($decoded) ? 'structured JSON dataset' : 'text';
                } catch (Throwable $e) {
                    $kind = 'text';
                }
                if (preg_match('/^(PK\x03\x04|\xff\xd8|\x1f\x8b|\x89PNG)/', $dec)) {
                    $kind = 'embedded binary object';
                }
                $protocol = 'unknown';
                if (preg_match('/^https?:\/\//i', $dec)) {
                    $protocol = 'URL payload';
                }
                $b64LongRuns[$url] = $head . ' — ' . $kind . ($protocol !== 'unknown' ? ' / ' . $protocol : '');
                break;
            }
        }

        // Timestamp disclosure (10096): long epoch second-milliseconds runs
        if (preg_match('/[\'"(:](1[6-9]\d{8}|2\d{8})[\'")\s,]/', $body, $tsm)) {
            $emit(vs_alert([
                'rule'        => 'timestamp-disclosure',
                'name'        => 'Timestamp Disclosure (Unix Epoch)',
                'risk'        => 'Low',
                'confidence'  => 'Low',
                'cwe'         => 'CWE-200',
                'summary'     => 'The page contains Unix-style timestamps that can reveal caching behaviour, deployment times or backend processing order.',
                'evidence'    => 'Epoch value ' . $tsm[1] . ' found in page at ' . $url . '.',
                'solution'    => 'Avoid exposing precision timestamps in client-facing HTML; round or remove them.',
                'reference'   => 'https://www.zaproxy.org/docs/alerts/10096/',
                'url'         => $url,
                'port'        => $port,
                'source'      => 'Passive Scanner',
            ]));
        }

        // 10062/PII — email addresses + internal IPs in bodies
        preg_match_all('/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,8}/', $body, $em);
        foreach (array_slice($em[0], 0, 3) as $addr) {
            if (!preg_match('/example\.|@\w{2,3}\.schema|sentry\.io|noreply@localhost/i', $addr)) {
                $emails[$addr][$url] = true;
            }
        }
        preg_match_all('/\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/', $body, $ipm);
        foreach (array_slice($ipm[0], 0, 3) as $ip) {
            $privIps[$ip][$url] = true;
        }

        // 90002 — Java serialization / PHP object-injection markers
        if ((bool)preg_match('/rO0AB[A-Za-z0-9+\/=]{12,}/', $body) || (bool)preg_match('/O:\d+:"[A-Za-z_\x7f-\xff][\w\x7f-\xff]*":\d+:\{/', $body)) {
            $which = preg_match('/rO0AB/', $body) ? 'Java serialized object data (rO0AB)' : 'PHP serialized object string';
            $serialized[] = $which . ' at ' . $url;
        }

        // 10108 — target="_blank" without rel=noopener
        if (preg_match_all('/<a[^>]*target=["\']_blank["\'][^>]*>/i', $body, $abm) && count($abm[0]) <= 40) {
            foreach ($abm[0] as $tag) {
                if (!preg_match('/rel=["\']([^"\']*noopener[^"\']*|[^"\']*noreferrer[^"\']*)["\']/i', $tag)) {
                    $unprotectedBlank[$url] = ($unprotectedBlank[$url] ?? 0) + 1;
                    break;
                }
            }
        }

        // 10110 — dangerous JS sinks rendered in page scripts
        $jsSignals = [];
        if (preg_match_all('/\beval\s*\(/', $body, $m2) && count($m2[0]) <= 10) {
            $jsSignals[] = 'eval()';
        }
        if (preg_match_all('/\bdocument\.write\s*\(/', $body, $m3) && count($m3[0]) <= 10) {
            $jsSignals[] = 'document.write()';
        }
        if ($jsSignals) {
            $dangerousJs[$url] = implode(', ', $jsSignals);
        }

        // 90011 — charset mismatch: header vs meta
        $hdrCharset = strtolower((string)($h['content-type'] ?? ''));
        if (preg_match('/charset=([a-z0-9--]).*/', $hdrCharset, $hc1) && preg_match('/<meta[^>]*charset=["\']?([\w-]+)/i', $body, $hc2)) {
            if ($hc1[1] !== strtolower($hc2[1])) {
                $charsetMismatch = true;
            }
        }

        // 10044 — Big redirect response
        $loc = (string)($h['location'] ?? '');
        if ($loc !== '' && $len > 5120) {
            $emit(vs_alert([
                'rule'        => 'big-redirect',
                'name'        => 'Large Redirect Response (Information Leakage)',
                'risk'        => 'Low',
                'confidence'  => 'Low',
                'cwe'         => 'CWE-200',
                'summary'     => 'A 3xx redirect carries a response body larger than 5 KB that could contain internal error details or sensitive content if rendered in some user agents.',
                'evidence'    => 'Redirect to ' . substr($loc, 0, 160) . ' with ' . $len . ' bytes of body content at ' . $url . '.',
                'solution'    => 'Send minimal bodies with redirects.',
                'reference'   => 'https://www.zaproxy.org/docs/alerts/10044/',
                'url'         => $url,
                'port'        => $port,
                'source'      => 'Passive Scanner',
            ]));
        }

        // 10041/42 — secure→insecure form action
        if ($isHttps && preg_match_all('/<form[^>]*action=["\']([^"\']*)["\']/i', $body, $fm)) {
            foreach ($fm[1] as $fAction) {
                if (preg_match('#^http://#i', $fAction) || str_starts_with(trim($fAction), '//') && !str_starts_with($fAction, '//')) {
                    // explicit http:// form target from an https page
                    $emit(vs_alert([
                        'rule'        => 'downgrade-form',
                        'name'        => 'HTTPS Page Contains Form Posting to HTTP',
                        'risk'        => 'Medium',
                        'confidence'  => 'High',
                        'cwe'         => 'CWE-319',
                        'summary'     => 'A form on this HTTPS page posts to a plaintext HTTP URL; submitted data will be transmitted unencrypted.',
                        'evidence'    => 'Form action ' . substr($fAction, 0, 200) . ' at ' . $url . '.',
                        'solution'    => 'Use relative HTTPS actions everywhere.',
                        'reference'   => 'https://www.zaproxy.org/docs/alerts/10041/',
                        'url'         => $url,
                        'port'        => $port,
                        'source'      => 'Passive Scanner',
                    ]));
                    break;
                }
            }
        }

        // 10049/50 — cacheability flags on authenticated-looking pages
        if (isset($h['set-cookie']) && (empty($h['cache-control']) || stripos((string)$h['cache-control'], 'no-store') === false)
            && empty($h['pragma']) === false) {
            // only flag if no explicit no-store and a session-ish cookie is set
            if (empty($h['cache-control']) || (stripos((string)$h['cache-control'], 'no-store') === false && stripos((string)$h['cache-control'], 'private') === false)) {
                $emit(vs_alert([
                    'rule'        => 'cacheable-with-cookies',
                    'name'        => 'Cacheable Response With Session Cookies',
                    'risk'        => 'Low',
                    'confidence'  => 'Low',
                    'cwe'         => 'CWE-524',
                    'summary'     => 'A response bearing cookies does not send no-store/private, so it may be stored by intermediaries in shared caches.',
                    'evidence'    => 'Cache-Control: ' . substr((string)($h['cache-control'] ?? 'absent'), 0, 80) . ' at ' . $url . '.',
                    'solution'    => 'Send "Cache-Control: no-store" on session-bearing responses.',
                    'reference'   => 'https://www.zaproxy.org/docs/alerts/10049/',
                    'url'         => $url,
                    'port'        => $port,
                    'source'      => 'Passive Scanner',
                ]));
            }
        }

        // 10039/52/56 — debug/backend header leaks
        foreach ([['x-backend-server', 'X-Backend-Server', 'Medium'],
                  ['x-chrome-logger-data', 'X-ChromeLogger-Data', 'Medium'],
                  ['x-debug-token', 'X-Debug-Token', 'Low']] as [$hdr2, $pretty, $r2]) {
            if (!empty($h[$hdr2])) {
                $emit(vs_alert([
                    'rule'        => 'header-' . $hdr2,
                    'name'        => $pretty . ' Header Discloses Internal Information',
                    'risk'        => $r2,
                    'confidence'  => 'High',
                    'cwe'         => 'CWE-200',
                    'summary'     => 'The response leaks internal infrastructure details via the ' . $pretty . ' header.',
                    'evidence'    => $pretty . ': ' . substr((string)$h[$hdr2], 0, 140) . ' at ' . $url . '.',
                    'solution'    => 'Strip internal headers at the edge before responses leave the network.',
                    'reference'   => 'https://www.zaproxy.org/docs/alerts/10039/',
                    'url'         => $url,
                    'port'        => $port,
                    'source'      => 'Passive Scanner',
                ]));
            }
        }
    }

    if ($b64LongRuns) {
        [$u, $head] = [array_key_first($b64LongRuns), reset($b64LongRuns)];
        $emit(vs_alert([
            'rule'        => 'base64-disclosure',
            'name'        => 'Base64 Disclosure',
            'risk'        => 'Info',
            'confidence'  => 'Medium',
            'cwe'         => 'CWE-200',
            'summary'     => 'Base64 data was embedded inline and decodes to meaningful content; it can reveal datasets, configuration or identifiers.',
            'evidence'    => 'Decoded to: ' . substr((string)$head, 0, 120) . ' at ' . $u . '.',
            'solution'    => 'Check whether the encoded payload is sensitive; avoid embedding raw encoded blobs in HTML.',
            'reference'   => 'https://www.zaproxy.org/docs/alerts/10094/',
            'url'         => $u,
            'port'        => $port,
            'source'      => 'Passive Scanner',
        ]));
    }
    if ($emails) {
        $list = [];
        foreach ($emails as $addr => $urls) {
            $list[] = $addr . ' on ' . count($urls) . ' page(s)';
        }
        $emit(vs_alert([
            'rule'        => 'pii-disclosure',
            'name'        => 'Personal Data (E-mail Addresses) Disclosed',
            'risk'        => 'Info',
            'confidence'  => 'Medium',
            'cwe'         => 'CWE-359',
            'summary'     => 'E-mail addresses appear in page bodies and may constitute personally identifiable data exposure.',
            'evidence'    => substr(implode('; ', $list), 0, 240),
            'solution'    => 'Minimise PII in client-facing HTML; consider contact forms or hashed contact identifiers.',
            'reference'   => 'https://www.zaproxy.org/docs/alerts/10062/',
            'url'         => $base,
            'port'        => $port,
            'source'      => 'Passive Scanner',
        ]));
    }
    if ($privIps) {
        $list = [];
        foreach ($privIps as $ip => $urls) {
            $list[] = $ip . ' (' . count($urls) . ' page(s))';
        }
        $emit(vs_alert([
            'rule'        => 'private-ip-disclosure',
            'name'        => 'Private IP Address Disclosure',
            'risk'        => 'Low',
            'confidence'  => 'Medium',
            'cwe'         => 'CWE-200',
            'summary'     => 'Page content references RFC1918/private network addresses, which helps attackers map the internal topology.',
            'evidence'    => substr(implode('; ', $list), 0, 240),
            'solution'    => 'Replace internal IPs with logical names in public content.',
            'reference'   => 'https://www.zaproxy.org/docs/alerts/2/',
            'url'         => $base,
            'port'        => $port,
            'source'      => 'Passive Scanner',
        ]));
    }
    if ($serialized) {
        $emit(vs_alert([
            'rule'        => 'deserialization-marker',
            'name'        => 'Serialized Object Data Exposed',
            'risk'        => 'Medium',
            'confidence'  => 'Medium',
            'cwe'         => 'CWE-502',
            'summary'     => 'Serialized objects appear in responses, indicating a deserialization sink; crafted payloads may trigger code execution.',
            'evidence'    => substr(implode('; ', $serialized), 0, 240),
            'solution'    => 'Do not serialize user-controllable state; if unavoidable, sign-and-encrypt with version-critical allow-lists.',
            'reference'   => 'https://www.zaproxy.org/docs/alerts/90002/',
            'url'         => $base,
            'port'        => $port,
            'source'      => 'Passive Scanner',
        ]));
    }
    if ($unprotectedBlank) {
        [$u, $count] = [array_key_first($unprotectedBlank), reset($unprotectedBlank)];
        $emit(vs_alert([
            'rule'        => 'unprotected-blank',
            'name'        => 'target="_blank" Without rel=noopener',
            'risk'        => 'Info',
            'confidence'  => 'Low',
            'cwe'         => 'CWE-1022',
            'summary'     => 'Links opened in a new context without noopener keep a window.opener handle, enabling cross-origin tab-nabbing where supported.',
            'evidence'    => $count . ' unprotected target=\"_blank\" link(s) at ' . $u . '.',
            'solution'    => 'Add rel="noopener noreferrer" to externally-targeted links.',
            'reference'   => 'https://www.zaproxy.org/docs/alerts/10108/',
            'url'         => $u,
            'port'        => $port,
            'source'      => 'Passive Scanner',
        ]));
    }
    if ($dangerousJs) {
        [$u, $which] = [array_key_first($dangerousJs), reset($dangerousJs)];
        $emit(vs_alert([
            'rule'        => 'dangerous-js',
            'name'        => 'Dangerous JavaScript Sinks in Page Script',
            'risk'        => 'Info',
            'confidence'  => 'Low',
            'cwe'         => 'CWE-79',
            'summary'     => 'The page uses JavaScript functions that weaken output-encoding guarantees and can amplify XSS impact.',
            'evidence'    => $which . ' used at ' . $u . '.',
            'solution'    => 'Prefer safe DOM APIs (textContent, createElement) over string-based sinks.',
            'reference'   => 'https://www.zaproxy.org/docs/alerts/10110/',
            'url'         => $u,
            'port'        => $port,
            'source'      => 'Passive Scanner',
        ]));
    }
    if ($charsetMismatch) {
        $emit(vs_alert([
            'rule'        => 'charset-mismatch',
            'name'        => 'Character Set Mismatch',
            'risk'        => 'Low',
            'confidence'  => 'Medium',
            'cwe'         => 'CWE-116',
            'summary'     => 'The Content-Type charset disagrees with the page meta charset; encodings can be abused for filter-evasion attacks.',
            'evidence'    => 'Header and meta charset disagree on at least one scanned page.',
            'solution'    => 'Set one canonical charset server-side and document it consistently.',
            'reference'   => 'https://www.zaproxy.org/docs/alerts/90011/',
            'url'         => $base,
            'port'        => $port,
            'source'      => 'Passive Scanner',
        ]));
    }

    // --- robots.txt / sitemap path disclosure --------------------------
    if (!empty($spider['disallow'])) {
        $emit(vs_alert([
            'rule'     => 'robots-disclosure',
            'name'     => 'robots.txt Discloses Internal Paths',
            'risk'     => 'Info',
            'confidence' => 'High',
            'cwe'      => 'CWE-200',
            'summary'  => 'robots.txt lists paths that should not be indexed, effectively advertising them to attackers.',
            'evidence' => 'Disallow entries: ' . substr(implode(', ', array_slice($spider['disallow'], 0, 12)), 0, 400),
            'solution' => 'Do not rely on robots.txt for secrecy; enforce access control and remove sensitive paths from the listing.',
            'reference'=> 'https://owasp.org/www-community/attacks/Forced_browsing',
            'url'      => rtrim($base, '/') . '/robots.txt',
            'port'     => $port,
        ]));
    }

    // --- Aggregate ------------------------------------------------------
    $counts = ['Critical' => 0, 'High' => 0, 'Medium' => 0, 'Low' => 0, 'Info' => 0];
    foreach ($alerts as $a) {
        $counts[$a['severity']] = ($counts[$a['severity']] ?? 0) + 1;
    }

    return [
        'alerts'      => $alerts,
        'summary'     => [
            'total'    => count($alerts),
            'critical' => $counts['Critical'],
            'high'     => $counts['High'],
            'medium'   => $counts['Medium'],
            'low'      => $counts['Low'],
            'info'     => $counts['Info'],
        ],
        'rules_run'   => 40,
        'duration_ms' => (int)((microtime(true) - $started) * 1000),
    ];
}
