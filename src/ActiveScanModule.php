<?php
/**
 * VulnScope Pro — Active scanner (ZAP active-scan rules equivalent).
 *
 * Drives payloads against the parameters and forms discovered by the spider.
 * Every rule is bounded by a request budget and a wall-clock deadline so a
 * deep scan stays predictable even on large applications.
 *
 * Covered classes:
 *   SQL injection (error-based + boolean differential), reflected XSS,
 *   LFI / path traversal, open redirect, CRLF header injection, SSTI,
 *   time-based command injection, IDOR, HTTP methods / TRACE, backup files.
 */
declare(strict_types=1);

/** One HTTP request for active testing (no redirect following). */
function vs_active_http(string $url, string $method = 'GET', array $post = [], string $cookie = '', array $extra_headers = []): array
{
    $started = microtime(true);
    $ch = curl_init($url);
    if ($ch === false) {
        return ['code' => 0, 'headers' => [], 'raw' => '', 'body' => '', 'ms' => 0];
    }
    curl_setopt_array($ch, vs_curl_defaults());
    $hh = [];
    foreach ($extra_headers as $k => $v) {
        if (is_string($k) && preg_match('/^[A-Za-z0-9-]+$/', $k)) {
            $hh[] = $k . ': ' . substr((string)$v, 0, 400);
        }
    }
    curl_setopt_array($ch, [
        CURLOPT_HEADER         => true,
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_TIMEOUT_MS     => 10000,
        CURLOPT_COOKIE         => $cookie,
        CURLOPT_HTTPHEADER     => $hh,
    ]);
    $verb = strtoupper($method);
    if ($verb === 'POST') {
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($post));
    } elseif ($verb !== 'GET') {
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $verb);
    }
    $raw  = curl_exec($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $hsize = (int)curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    curl_close($ch);

    if (!is_string($raw)) {
        $raw = '';
    }
    $rawHeaders = $hsize > 0 ? substr($raw, 0, $hsize) : '';
    vs_log_request($verb, $url, $code, $hsize > 0 ? strlen(substr($raw, $hsize)) : strlen($raw), (int)((microtime(true) - $started) * 1000), 'active', 'active-scan');
    return [
        'code'    => $code,
        'headers' => vs_header_map($rawHeaders),
        'raw'     => $rawHeaders,
        'body'    => $hsize > 0 ? substr($raw, $hsize) : $raw,
        'ms'      => (int)((microtime(true) - $started) * 1000),
    ];
}

/** Normalised similarity 0..1 between two response bodies (bounded sample). */
function vs_body_similarity(string $a, string $b): float
{
    $a = substr($a, 0, 12000);
    $b = substr($b, 0, 12000);
    if ($a === '' && $b === '') {
        return 1.0;
    }
    if ($a === '' || $b === '') {
        return 0.0;
    }
    similar_text($a, $b, $pct);
    return $pct / 100;
}

/** Build an absolute URL with one query parameter replaced. */
function vs_url_set_param(string $url, string $param, string $payload): string
{
    $parts = parse_url($url);
    $query = [];
    if (!empty($parts['query'])) {
        parse_str($parts['query'], $query);
    }
    $query[$param] = $payload;
    $authority = ($parts['host'] ?? '') . (isset($parts['port']) ? ':' . $parts['port'] : '');
    return ($parts['scheme'] ?? 'http') . '://' . $authority . ($parts['path'] ?? '/')
        . '?' . http_build_query($query);
}

/** Does this parameter name look numeric / object-reference like? */
function vs_is_id_param(string $name): bool
{
    return (bool)preg_match('/^(id|uid|user|user_?id|account|order|invoice|item|file|doc|record|pid|profile|customer|booking|ticket)$/i', $name);
}

/**
 * Build active-scan targets from spider parameters and forms.
 * Each target: url, method, names[], post (default form values).
 */
function vs_active_targets(array $spider, string $base, int $maxTargets = 30): array
{
    $targets = [];
    $seen = [];
    $add = function (string $url, string $method, array $names, array $post = []) use (&$targets, &$seen): void {
        $url = trim($url);
        if ($url === '' || !preg_match('#^https?://#i', $url)) {
            return;
        }
        $names = array_values(array_filter(array_unique($names)));
        if (!$names) {
            return;
        }
        $key = strtoupper($method) . ' ' . $url . ' ' . implode(',', $names);
        if (isset($seen[$key])) {
            return;
        }
        $seen[$key] = true;
        $targets[] = ['url' => $url, 'method' => strtoupper($method) ?: 'GET', 'names' => $names, 'post' => $post];
    };

    foreach (($spider['parameters'] ?? []) as $p) {
        $add((string)$p['url'], (string)($p['method'] ?? 'GET'), (array)($p['names'] ?? []));
    }
    foreach (($spider['forms'] ?? []) as $form) {
        // Never fuzz state-changing / credential forms over POST: active tests
        // could lock accounts, transfer data or delete records. GET forms and
        // non-sensitive POST forms remain in scope.
        $method = strtoupper((string)($form['method'] ?? 'GET'));
        $action = (string)($form['action'] ?? '');
        $isSensitive = (bool)($form['sensitive'] ?? false)
            || preg_match('/(logout|signout|delete|remove|destroy|transfer|payment|checkout|register|password|reset|upload|revoke)/i', $action);
        if ($method === 'POST' && $isSensitive) {
            continue;
        }

        $post = [];
        $names = [];
        foreach (($form['inputs'] ?? []) as $input) {
            if (in_array(strtolower($input['type']), ['submit', 'button', 'image', 'reset', 'file', 'password'], true)) {
                continue;
            }
            $names[] = $input['name'];
            $post[$input['name']] = $input['value'] !== '' ? $input['value'] : '1';
        }
        if (!$names) {
            continue;
        }
        $add($action, $method, $names, $post);
    }

    // Synthetic parameter probing on the landing page (ZAP-style forced browse
    // of common parameters when the app exposes none).
    if (!$targets) {
        $add(rtrim($base, '/') . '/?id=1', 'GET', ['id']);
        $add(rtrim($base, '/') . '/?q=test', 'GET', ['q']);
        $add(rtrim($base, '/') . '/?page=1', 'GET', ['page']);
    }

    // Prefer parameterised pages, then HTML pages.
    usort($targets, fn($a, $b) => count($b['names']) <=> count($a['names']));
    return array_slice($targets, 0, $maxTargets);
}

/**
 * Run the active scanner.
 *
 * $ctx: cookie, port, max_requests (140), max_seconds (75), aggressive (bool)
 */
function vs_active_scan(array $spider, string $base, array $ctx = []): array
{
    $started   = microtime(true);
    $cookie    = vs_sanitize_cookie((string)($ctx['cookie'] ?? ''));
    $port      = (string)($ctx['port'] ?? '');
    $budget    = max(20, (int)($ctx['max_requests'] ?? 140));
    $deadline  = $started + max(10, (float)($ctx['max_seconds'] ?? 75));
    $aggressive = (bool)($ctx['aggressive'] ?? true);

    // Policy gating (ZAP scan-policy parity): groups can disable rule classes.
    $policyGroups = (array)($ctx['policy'] ?? []);
    $groupOn = static function (string $group) use ($policyGroups): bool {
        return ($policyGroups[$group] ?? 'default') !== 'off';
    };

    $targets = vs_active_targets($spider, $base, 24);
    $alerts  = [];
    $seen    = [];
    $tests   = 0;
    $requests = 0;

    $emit = function (array $a) use (&$alerts, &$seen, $port): void {
        $key = ($a['rule'] ?? '') . '|' . ($a['url'] ?? '') . '|' . ($a['param'] ?? '') . '|' . substr((string)($a['payload'] ?? ''), 0, 40);
        if (isset($seen[$key])) {
            return;
        }
        $seen[$key] = true;
        $a['port'] = $a['port'] ?? $port;
        $a['affected_service'] = $a['affected_service'] ?? ($a['url'] ?? '');
        $alerts[] = vs_alert($a);
    };

    $canRun = function () use (&$requests, $budget, $deadline): bool {
        return $requests < $budget && microtime(true) < $deadline;
    };

    $sig = function (string $body, string $marker): bool {
        return $body !== '' && strpos($body, $marker) !== false;
    };

    $sqlError = function (string $body): bool {
        return vs_sqli_error_in_body($body);
    };

    $lfiHit = function (string $body): bool {
        return (bool)preg_match('/root:[x*!]?:[0-9:]+:[0-9:]+:[^:]*:\/root:\/bin\/(?:ba)?sh/i', $body)
            || (bool)preg_match('/\[fonts\]\s*(?:\r?\n|$)/i', $body)
            || (bool)preg_match('/\[extensions\]\s*(?:\r?\n|$)/i', $body);
    };

    /* ---------------- Host-level checks (once, not per parameter) ------- */
    $root = rtrim($base, '/') . '/';
    if ($canRun() && $groupOn('server')) {
        $opt = vs_active_http($root, 'OPTIONS', [], $cookie);
        $requests++;
        $tests++;
        if ($opt['code'] > 0) {
            $allow = $opt['headers']['allow'] ?? '';
            $dangerous = [];
            foreach (['TRACE', 'PUT', 'DELETE', 'PATCH', 'CONNECT'] as $m) {
                if ($allow && stripos($allow, $m) !== false) {
                    $dangerous[] = $m;
                }
            }
            if ($dangerous) {
                $emit([
                    'rule'     => 'http-methods',
                    'name'     => 'Risky HTTP Methods Enabled',
                    'type'     => 'active',
                    'risk'     => in_array('PUT', $dangerous, true) || in_array('DELETE', $dangerous, true) ? 'Medium' : 'Low',
                    'confidence' => 'Medium',
                    'cwe'      => 'CWE-650',
                    'summary'  => 'The server advertises HTTP methods that allow state changes or protocol debugging.',
                    'evidence' => 'Allow: ' . substr($allow, 0, 200),
                    'solution' => 'Disable unused methods at the web server or reverse proxy.',
                    'reference'=> 'https://owasp.org/www-project-web-security-testing-guide/',
                    'url'      => $root,
                    'method'   => 'OPTIONS',
                    'source'   => 'Active Scanner',
                ]);
            }
        }

        // TRACE / XST
        $trace = vs_active_http($root, 'TRACE', [], $cookie);
        $requests++;
        $tests++;
        if ($trace['code'] === 200 && stripos($trace['body'], 'TRACE /') !== false) {
            $emit([
                'rule'     => 'trace-enabled',
                'name'     => 'HTTP TRACE Method Enabled (Cross-Site Tracing)',
                'type'     => 'active',
                'risk'     => 'Low',
                'confidence' => 'High',
                'cwe'      => 'CWE-693',
                'summary'  => 'TRACE echoes the request, which can assist cross-site tracing and cookie theft in legacy clients.',
                'evidence' => 'TRACE ' . $root . ' returned 200 with the request echoed.',
                'solution' => 'Disable TRACE (TraceEnable off in Apache, deny in nginx).',
                'reference'=> 'https://owasp.org/www-community/attacks/Cross_Site_Tracing',
                'url'      => $root,
                'method'   => 'TRACE',
                'source'   => 'Active Scanner',
            ]);
        }

        // Server header returned after a malformed Host (host header routing hint)
        $badHost = vs_active_http($root, 'GET', [], $cookie);
        $requests++;
        $tests++;
        if ($badHost['code'] > 0 && !empty($badHost['headers']['server'])) {
            // informational only; already covered passively
        }
    }

    /* ---------------- Backup / source artifact probing ------------------ */
    $backupChecked = 0;
    $pagePaths = [];
    foreach (($spider['pages'] ?? []) as $p) {
        $path = (string)parse_url($p['final_url'] ?? $p['url'], PHP_URL_PATH);
        if ($path !== '' && $path !== '/' && !vs_is_static_asset($path)) {
            $pagePaths[$path] = true;
        }
    }
    foreach (array_slice(array_keys($pagePaths), 0, 4) as $path) {
        foreach (['.bak', '.old', '.orig', '~', '.swp'] as $ext) {
            if (!$groupOn('endpoints') || !$canRun() || $backupChecked >= 6) {
                break 2;
            }
            $url = rtrim($base, '/') . $path . $ext;
            $res = vs_active_http($url, 'GET', [], $cookie);
            $requests++;
            $tests++;
            $backupChecked++;
            if ($res['code'] === 200 && strlen(trim($res['body'])) > 0) {
                $emit([
                    'rule'     => 'backup-file',
                    'name'     => 'Backup or Source Artifact Exposed',
                    'type'     => 'active',
                    'risk'     => 'High',
                    'confidence' => 'High',
                    'cwe'      => 'CWE-538',
                    'summary'  => 'An editor/backup copy of an application file is downloadable and may disclose source or secrets.',
                    'evidence' => 'HTTP 200 for ' . $url . ' (' . strlen($res['body']) . ' bytes)',
                    'solution' => 'Remove backup artifacts from the webroot and block such extensions at the server.',
                    'reference'=> 'https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration',
                    'url'      => $url,
                    'method'   => 'GET',
                    'source'   => 'Active Scanner',
                ]);
            }
        }
    }

    /* ---------------- Advanced host-level probes (ZAP ruleset parity) --- */

    // --- Dev-ops / debug endpoints (ZAP 40028/40042/40029/40034) ---------
    $devEndpoints = [
        ['/elmah.axd',        'ELMAH error log',          'High',   'CWE-215'],
        ['/actuator/env',     'Spring Actuator environment endpoint', 'High', 'CWE-200'],
        ['/actuator/heapdump','Spring Actuator heap dump',  'High',   'CWE-200'],
        ['/trace.axd',        'ASP.NET trace log',          'Medium', 'CWE-215'],
        ['/debug/vars',       'Go pprof / expvar endpoint', 'Medium', 'CWE-200'],
        ['/.git/HEAD',        'Git repository exposed',     'High',   'CWE-538'],
        ['/swagger.json',     'Swagger / OpenAPI definition', 'Medium', 'CWE-1059'],
        ['/.well-known/security.txt', 'security.txt (informational)', 'Info', 'CWE-693'],
    ];
    $devTried = 0;
    if ($groupOn('endpoints')) {
    foreach ($devEndpoints as [$ep, $epName, $epRisk, $epCwe]) {
        if (!$canRun() || $devTried >= 6) {
            break;
        }
        $res = vs_active_http($root . ltrim($ep, '/'), 'GET', [], $cookie);
        $requests++;
        $tests++;
        $devTried++;
        $isSecurityTxt = $epRisk === 'Info';
        $hitBody = $res['code'] === 200 && strlen($res['body']) > 10
            && !(stripos($res['body'], '<!DOCTYPE') !== false && stripos($res['body'], '404') !== false && strlen($res['body']) < 800);
        if ($hitBody) {
            $emit([
                'rule'     => 'endpoint-' . substr(md5($ep), 0, 6),
                'name'     => ($isSecurityTxt ? '' : 'Exposed ') . $epName . ' available',
                'type'     => 'active',
                'risk'     => $epRisk,
                'confidence' => $isSecurityTxt ? 'High' : 'Medium',
                'cwe'      => $epCwe,
                'summary'  => $isSecurityTxt
                    ? 'A security.txt file is published, which provides a contact path for vulnerability reports.'
                    : 'A developer/maintenance endpoint is server-controlled and returns an unknown (non-cached 404-supporting) body to unauthenticated callers; it often discloses source, environment variables, dependency versions or full error traces.',
                'evidence' => 'HTTP 200 for ' . $root . ltrim($ep, '/') . ' — ' . strlen($res['body']) . ' bytes, first bytes: ' . substr(trim($res['body']), 0, 120),
                'solution' => $isSecurityTxt
                    ? 'Keep the security.txt file available and up to date (RFC 9116).'
                    : 'Disable the debug endpoint in production and require authentication for such maintenance routes.',
                'reference'=> 'https://www.zaproxy.org/docs/alerts/',
                'url'      => $root . ltrim($ep, '/'),
                'method'   => 'GET',
                'source'   => 'Active Scanner',
            ]);
        }
    }
    } // dev endpoints enabled

    // --- 403-bypass heuristics on spidered pages (ZAP 40038) -------------
    foreach (array_slice($targets, 0, 6) as $t403) {
        if (!$canRun() || !$groupOn('server')) {
            break;
        }
        $u = $t403['url'];
        $r0 = vs_active_http($u, $t403['method'], $t403['post'], $cookie);
        $requests++;
        if ($r0['code'] === 403) {
            foreach ([
                'X-Forwarded-For: 127.0.0.1',
                'X-Original-URL: ' . $u,
                'X-Rewrite-URL: ' . $u,
            ] as $hdr) {
                $extra = explode(': ', $hdr, 2);
                $rh = vs_active_http($u, 'GET', [], $cookie, [$extra[0] => $extra[1]]);
                $requests++;
                $tests++;
                if ($rh['code'] === 200 && strlen($rh['body']) > 100) {
                    $emit([
                        'rule'     => '403-bypass',
                        'name'     => 'Potential Access-Control Bypass (403 evasion)',
                        'type'     => 'active',
                        'risk'     => 'Medium',
                        'confidence' => 'Low',
                        'cwe'      => 'CWE-862',
                        'summary'  => 'A spoofed proxy/original-URL header turned a 403 into a 200, which suggests an access control enforced only at the front-end.',
                        'evidence' => $extra[0] . ': ' . $extra[1] . ' → HTTP 200 (' . strlen($rh['body']) . ' bytes) after HTTP 403 without it.',
                        'solution' => 'Enforce authorization in application code, not only at proxies/WAFs; validate headers handling.',
                        'reference'=> 'https://www.zaproxy.org/docs/alerts/40038/',
                        'url'      => $u,
                        'method'   => 'GET',
                        'payload'  => $hdr,
                        'source'   => 'Active Scanner',
                    ]);
                    break;
                }
            }
        }
    }

    // --- Log4Shell-style JNDI sink probe (ZAP 40043) ----------------------
    if ($aggressive && $canRun() && $groupOn('injection')) {
        $jndiNonce = 'vs' . substr(md5((string)$started), 0, 8);
        $jndiPayload = '${jndi:ldap://' . $jndiNonce . '.jndi-oob.invalid/a}';
        $r = vs_active_http($root, 'GET', [], $cookie, [
            'X-Api-Version' => $jndiPayload,
            'User-Agent'    => 'VSProbe/1.0 ' . $jndiPayload,
            'Referer'       => 'https://example.invalid/ref ' . $jndiPayload,
            'X-Forwarded-Server' => $jndiNonce . '.jndi-oob.invalid',
        ]);
        $requests++;
        $tests++;
        if (strpos($r['body'], $jndiPayload) !== false || strpos($r['raw'], $jndiNonce) !== false) {
            $emit([
                'rule'     => 'jndi-reflected',
                'name'     => 'JNDI Payload Reflected (Log4Shell-Class Sink Reachable)',
                'type'     => 'active',
                'risk'     => 'Medium',
                'confidence' => 'Low',
                'cwe'      => 'CWE-917',
                'summary'  => 'A ${jndi:…} expression in a request header reached a component that echoes header values unexpanded. Confirm logging-based exploitation with your own DNS callback infrastructure before raising severity.',
                'evidence' => 'Nonce ' . $jndiNonce . ' reflected with the unexpanded JNDI expression.',
                'solution' => 'Patch log4j-core ≥ 2.17, strip ${…} from all header sinks, restrict egress from the application host.',
                'reference'=> 'https://www.zaproxy.org/docs/alerts/40043/',
                'url'      => $root,
                'method'   => 'GET',
                'source'   => 'Active Scanner',
            ]);
        }
    }

    /* ---------------- Light SSRF/XXE stage on original bodies ------------ */

    // Synthetic OOB nonce absent; only react on unambiguous evidence.
    $ssrfMarkers = static function (string $body): bool {
        return (bool)preg_match('/ami-[a-f0-9]{8}|latest\/meta-data|metadata\.google\.internal|X-aws-ec2-metadata|169\.254\.169\.254/i', $body);
    };

    /* ---------------- Parameter injection rules ------------------------- */
    $marker = 'vs' . substr(md5((string)microtime(true)), 0, 6);

    foreach ($targets as $target) {
        if (!$canRun()) {
            break;
        }
        $url    = $target['url'];
        $method = $target['method'];
        $names  = array_slice($target['names'], 0, 4);
        $post   = $target['post'];

        $baseRes = vs_active_http($url, $method, $post, $cookie);
        $requests++;
        $tests++;
        $baseBody = $baseRes['body'];
        $baseLen  = strlen($baseBody);
        $baseCode = $baseRes['code'];
        $baseMs   = $baseRes['ms'];

        foreach ($names as $param) {
            if (!$canRun()) {
                break;
            }

            /** Send one injected request, preserving form fields for POST. */
            $probe = function (string $payload) use ($url, $method, $post, $param, $cookie, &$requests): array {
                if ($method === 'POST') {
                    $fields = $post;
                    $fields[$param] = $payload;
                    $r = vs_active_http($url, 'POST', $fields, $cookie);
                } else {
                    $r = vs_active_http(vs_url_set_param($url, $param, $payload), 'GET', [], $cookie);
                }
                $requests++;
                return $r;
            };

            // --- SQL injection: error-based --------------------------------
            $errorPayloads = ["'", "\"", "')", "1' AND '1'='1"];
            foreach ($errorPayloads as $payload) {
                if (!$canRun() || !$groupOn('sqli')) {
                    break;
                }
                $r = $probe($payload);
                $tests++;
                if ($sqlError($r['body']) && !$sqlError($baseBody)) {
                    $emit([
                        'rule'     => 'sqli-error',
                        'name'     => 'SQL Injection (Error-Based)',
                        'type'     => 'active',
                        'risk'     => 'High',
                        'confidence' => 'High',
                        'cwe'      => 'CWE-89',
                        'summary'  => 'Injecting a quote produced a database error, indicating the parameter is concatenated into a SQL query.',
                        'evidence' => vs_sqli_evidence($r['body']) . ' | param: ' . $param,
                        'solution' => 'Use parameterised queries / prepared statements and validate input types.',
                        'reference'=> 'https://owasp.org/www-community/attacks/SQL_Injection',
                        'url'      => $url,
                        'param'    => $param,
                        'payload'  => $payload,
                        'method'   => $method,
                        'source'   => 'Active Scanner',
                    ]);
                    break;
                }
            }

            // --- SQL injection: boolean differential -----------------------
            if ($aggressive && $groupOn('sqli') && $canRun()) {
                $trueRes  = $probe("' AND '1'='1");
                $falseRes = $probe("' AND '1'='2");
                $tests += 2;
                if ($trueRes['code'] === $baseCode && $falseRes['code'] === $baseCode && $baseLen > 0) {
                    $simTrue  = vs_body_similarity($trueRes['body'], $baseBody);
                    $simFalse = vs_body_similarity($falseRes['body'], $baseBody);
                    if ($simTrue > 0.90 && $simFalse < 0.75) {
                        $emit([
                            'rule'     => 'sqli-boolean',
                            'name'     => 'SQL Injection (Boolean Differential)',
                            'type'     => 'active',
                            'risk'     => 'High',
                            'confidence' => 'Medium',
                            'cwe'      => 'CWE-89',
                            'summary'  => 'A true SQL condition reproduced the baseline page while a false condition changed it, which is a strong blind-injection signal.',
                            'evidence' => sprintf('similarity true=%.0f%% false=%.0f%% (param %s)', $simTrue * 100, $simFalse * 100, $param),
                            'solution' => 'Use parameterised queries and reject unexpected input.',
                            'reference'=> 'https://owasp.org/www-community/attacks/Blind_SQL_Injection',
                            'url'      => $url,
                            'param'    => $param,
                            'payload'  => "' AND '1'='2",
                            'method'   => $method,
                            'source'   => 'Active Scanner',
                        ]);
                    }
                }
            }

            // --- Reflected XSS ---------------------------------------------
            if ($groupOn('xss') && $canRun()) {
                $xssMarkers = ['<' . $marker . '>', '"><' . $marker . '>'];
                foreach ($xssMarkers as $payload) {
                    $r = $probe($payload);
                    $tests++;
                    $ctype = $r['headers']['content-type'] ?? '';
                    if ($sig($r['body'], '<' . $marker . '>') && ($ctype === '' || stripos($ctype, 'html') !== false)) {
                        $emit([
                            'rule'     => 'xss-reflected',
                            'name'     => 'Reflected Cross-Site Scripting (XSS)',
                            'type'     => 'active',
                            'risk'     => 'High',
                            'confidence' => 'Medium',
                            'cwe'      => 'CWE-79',
                            'summary'  => 'The parameter value is echoed into the HTML response without encoding, so script markup executes in the victim browser.',
                            'evidence' => 'Payload <' . $marker . '> reflected literally in the response body (param ' . $param . ').',
                            'solution' => 'Context-aware output encoding and a restrictive CSP; validate input server-side.',
                            'reference'=> 'https://owasp.org/www-community/attacks/xss/',
                            'url'      => $url,
                            'param'    => $param,
                            'payload'  => $payload,
                            'method'   => $method,
                            'source'   => 'Active Scanner',
                        ]);
                        break;
                    }
                }
            }

            // --- LFI / path traversal -------------------------------------
            if ($groupOn('lfi') && $canRun()) {
                foreach (['../../../../../../etc/passwd', '....//....//....//....//etc/passwd', '..\\..\\..\\..\\windows\\win.ini'] as $payload) {
                    $r = $probe($payload);
                    $tests++;
                    if ($lfiHit($r['body'])) {
                        $emit([
                            'rule'     => 'lfi',
                            'name'     => 'Local File Inclusion / Path Traversal',
                            'type'     => 'active',
                            'risk'     => 'Critical',
                            'confidence' => 'High',
                            'cwe'      => 'CWE-22',
                            'summary'  => 'A traversal payload returned a system file, so the parameter controls a file path.',
                            'evidence' => 'System file signature returned for payload ' . $payload . ' (param ' . $param . ').',
                            'solution' => 'Avoid user-controlled file paths; resolve against a fixed base and allow-list filenames.',
                            'reference'=> 'https://owasp.org/www-community/attacks/Path_Traversal',
                            'url'      => $url,
                            'param'    => $param,
                            'payload'  => $payload,
                            'method'   => $method,
                            'source'   => 'Active Scanner',
                        ]);
                        break;
                    }
                }
            }

            // --- Open redirect --------------------------------------------
            if ($groupOn('redirect') && $canRun()) {
                foreach (['https://example.org/vs-redirect', '//example.org/vs-redirect'] as $payload) {
                    $r = $probe($payload);
                    $tests++;
                    $loc = $r['headers']['location'] ?? '';
                    if (in_array($r['code'], [301, 302, 303, 307, 308], true) && stripos($loc, 'example.org') !== false) {
                        $emit([
                            'rule'     => 'open-redirect',
                            'name'     => 'Open Redirect',
                            'type'     => 'active',
                            'risk'     => 'Medium',
                            'confidence' => 'High',
                            'cwe'      => 'CWE-601',
                            'summary'  => 'The parameter controls the redirect destination, enabling phishing links that start on the trusted domain.',
                            'evidence' => 'HTTP ' . $r['code'] . ' Location: ' . substr($loc, 0, 200),
                            'solution' => 'Only redirect to a fixed allow-list or to relative paths validated server-side.',
                            'reference'=> 'https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet',
                            'url'      => $url,
                            'param'    => $param,
                            'payload'  => $payload,
                            'method'   => $method,
                            'source'   => 'Active Scanner',
                        ]);
                        break;
                    }
                }
            }

            // --- CRLF header injection ------------------------------------
            if ($groupOn('redirect') && $canRun()) {
                $crlfPayload = '%0d%0aX-VS-Injected: ' . $marker;
                $r = $probe($crlfPayload);
                $tests++;
                if (isset($r['headers']['x-vs-injected']) || stripos($r['raw'], 'X-VS-Injected: ' . $marker) !== false) {
                    $emit([
                        'rule'     => 'crlf-injection',
                        'name'     => 'HTTP Header Injection (CRLF)',
                        'type'     => 'active',
                        'risk'     => 'High',
                        'confidence' => 'High',
                        'cwe'      => 'CWE-113',
                        'summary'  => 'Encoded CR/LF characters in the parameter created an attacker-controlled response header.',
                        'evidence' => 'Injected header X-VS-Injected: ' . $marker . ' appeared in the response.',
                        'solution' => 'Reject control characters in header-bound input and use framework header APIs.',
                        'reference'=> 'https://owasp.org/www-community/attacks/HTTP_Response_Splitting',
                        'url'      => $url,
                        'param'    => $param,
                        'payload'  => $crlfPayload,
                        'method'   => $method,
                        'source'   => 'Active Scanner',
                    ]);
                }
            }

            // --- Server-side template injection ---------------------------
            if ($groupOn('injection') && $canRun()) {
                $sstiMarkers = ['{{7*7}}' . $marker => '49' . $marker, '${7*7}' . $marker => '49' . $marker, '<%= 7*7 %>' . $marker => '49' . $marker];
                foreach ($sstiMarkers as $payload => $expected) {
                    $r = $probe($payload);
                    $tests++;
                    if ($sig($r['body'], $expected) && !$sig($baseBody, $expected)) {
                        $emit([
                            'rule'     => 'ssti',
                            'name'     => 'Server-Side Template Injection',
                            'type'     => 'active',
                            'risk'     => 'Critical',
                            'confidence' => 'Medium',
                            'cwe'      => 'CWE-94',
                            'summary'  => 'Template expression syntax was evaluated by the server, which can lead to remote code execution.',
                            'evidence' => 'Payload ' . $payload . ' evaluated to ' . $expected . ' (param ' . $param . ').',
                            'solution' => 'Do not build templates from user input; use sandboxed template engines and allow-list variables.',
                            'reference'=> 'https://portswigger.net/web-security/server-side-template-injection',
                            'url'      => $url,
                            'param'    => $param,
                            'payload'  => $payload,
                            'method'   => $method,
                            'source'   => 'Active Scanner',
                        ]);
                        break;
                    }
                }
            }

            // --- Time-based command injection -----------------------------
            if ($aggressive && $groupOn('injection') && $canRun() && $baseMs < 4000) {
                foreach (['; sleep 4', '| sleep 4', '`sleep 4`'] as $payload) {
                    $r = $probe($payload);
                    $tests++;
                    if ($r['ms'] >= $baseMs + 3500 && $r['code'] > 0) {
                        $confirm = $probe('; sleep 4');
                        $requests++;
                        $tests++;
                        if ($confirm['ms'] >= $baseMs + 3500) {
                            $emit([
                                'rule'     => 'command-injection',
                                'name'     => 'OS Command Injection (Time-Based)',
                                'type'     => 'active',
                                'risk'     => 'Critical',
                                'confidence' => 'Medium',
                                'cwe'      => 'CWE-78',
                                'summary'  => 'The parameter is passed to a shell: an injected sleep delayed the response reproducibly.',
                                'evidence' => sprintf('baseline %dms vs injected %dms / %dms', $baseMs, $r['ms'], $confirm['ms']),
                                'solution' => 'Avoid shell invocation; use argument-array APIs and strict allow-lists.',
                                'reference'=> 'https://owasp.org/www-community/attacks/Command_Injection',
                                'url'      => $url,
                                'param'    => $param,
                                'payload'  => $payload,
                                'method'   => $method,
                                'source'   => 'Active Scanner',
                            ]);
                        }
                        break;
                    }
                }
            }

            // --- SSRF + cloud metadata (ZAP 40046 / 90034) ------------------
            if ($canRun() && $groupOn('ssrf') && ($aggressive || preg_match('/url|path|host|source|dest|target|proxy|fetch|load|ref|site|feed/i', $param))) {
                $ssrfPayloads = [
                    'http://169.254.169.254/latest/meta-data/',
                    'http://169.254.169.254/openstack/',
                    'http://metadata.google.internal/computeMetadata/v1/',
                    'file:///etc/hostname',
                ];
                foreach ($ssrfPayloads as $payload) {
                    $r = $probe($payload);
                    $tests++;
                    if ($ssrfMarkers($r['body'])) {
                        preg_match('/ami-[a-f0-9]{8}|latest\/meta-data|metadata\.google\.internal/i', $r['body'], $__m);
                        $emit([
                            'rule'     => 'ssrf-metadata',
                            'name'     => 'Server-Side Request Forgery (Cloud Metadata Probe)',
                            'type'     => 'active',
                            'risk'     => 'Critical',
                            'confidence' => 'High',
                            'cwe'      => 'CWE-918',
                            'summary'  => 'The parameter made the server fetch an internal cloud metadata endpoint and its response leaked instance details.',
                            'evidence' => 'Metadata marker ' . ($__m[0] ?? 'matched') . ' returned for payload ' . $payload . ' (param ' . $param . ').',
                            'solution' => 'Never let user input build arbitrary URLs; allow-list destination hosts and block link-local ranges at the egress firewall.',
                            'reference'=> 'https://owasp.org/www-community/attacks/Server_Side_Request_Forgery',
                            'url'      => $url,
                            'param'    => $param,
                            'payload'  => $payload,
                            'method'   => $method,
                            'source'   => 'Active Scanner',
                        ]);
                        break;
                    }
                }
            }

            // --- XXE (XML external entity) probe (ZAP 90023) ----------------
            if ($canRun() && $groupOn('xxe') && preg_match('/xml|data|payload|doc|file|input|content/i', $param)) {
                $xxePayload = '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY vsx "' . $marker . '">]><x>&vsx;</x>';
                $r = $probe($xxePayload);
                $tests++;
                $xmlParserError = (bool)preg_match('/simplexml|xmlParse|SAX|lxml|etree|expat|XML error|doctype not allowed|INTERNAL_ENTITY/i', $r['body']) && !$sqlError($r['body']);
                if ($sig($r['body'], $marker) && !($baseBody !== '' && strpos($baseBody, $marker) !== false)) {
                    $emit([
                        'rule'     => 'xxe',
                        'name'     => 'XML External Entity Injection (XXE)',
                        'type'     => 'active',
                        'risk'     => 'High',
                        'confidence' => 'Medium',
                        'cwe'      => 'CWE-611',
                        'summary'  => 'An internal XML entity defined in the DOCTYPE was expanded by the parser: external entities resolve, which can read files or reach internal hosts.',
                        'evidence' => 'Entity marker ' . $marker . ' reflected after entity expansion (param ' . $param . ').',
                        'solution' => 'Disable DTDs/external entities (libxml2 2.9+, javax.xml.catalog,DocumentsBuilderFactory hardening), or parse with a schema-validated parser.',
                        'reference'=> 'https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing',
                        'url'      => $url,
                        'param'    => $param,
                        'payload'  => $xxePayload,
                        'method'   => $method,
                        'source'   => 'Active Scanner',
                    ]);
                } elseif ($xmlParserError) {
                    $emit([
                        'rule'     => 'xml-native',
                        'name'     => 'XML Parser Accepts Document-Type Definitions',
                        'type'     => 'active',
                        'risk'     => 'Medium',
                        'confidence' => 'Low',
                        'cwe'      => 'CWE-611',
                        'summary'  => 'A DOCTYPE-bearing document reached the XML parser and produced parser-specific errors, so DTDs are not globally disabled.',
                        'evidence' => 'Parser diagnostics after DOCTYPE payload on param ' . $param . '.',
                        'solution' => 'Reject DOCTYPE declarations at the parser level before any further processing.',
                        'reference'=> 'https://www.zaproxy.org/docs/alerts/90023/',
                        'url'      => $url,
                        'param'    => $param,
                        'payload'  => $xxePayload,
                        'method'   => $method,
                        'source'   => 'Active Scanner',
                    ]);
                }
            }

            // --- NoSQL / MongoDB injection (ZAP 40033) ----------------------
            if ($canRun() && $aggressive && $groupOn('nosql')) {
                $nosqlPayloads = ['{"$ne": null}', '{"$regex": "^v"}', '1[$ne]=1', '{"$gt":""}'];
                $nosqlErr = static function (string $body): bool {
                    return (bool)preg_match('/MongoError|BSONError|mongo.*error|not.*primary|BSONUnexpected|\$regex.*error/i', $body);
                };
                foreach ($nosqlPayloads as $payload) {
                    $r = $probe($payload);
                    $tests++;
                    if ($nosqlErr($r['body']) && !$nosqlErr($baseBody)) {
                        $emit([
                            'rule'     => 'nosql-injection',
                            'name'     => 'NoSQL Injection (MongoDB Operators)',
                            'type'     => 'active',
                            'risk'     => 'High',
                            'confidence' => 'High',
                            'cwe'      => 'CWE-943',
                            'summary'  => 'MongoDB operator syntax reached the query layer and generated engine errors; operator injection into authentication or query filters is likely.',
                            'evidence' => 'MongoDB error markers returned for payload ' . $payload . ' (param ' . $param . ').',
                            'solution' => 'Parse and type-cast user input strictly; never pass raw dicts into query builders; disable unindexed filters.',
                            'reference'=> 'https://www.zaproxy.org/docs/alerts/40033/',
                            'url'      => $url,
                            'param'    => $param,
                            'payload'  => $payload,
                            'method'   => $method,
                            'source'   => 'Active Scanner',
                        ]);
                        break;
                    }
                }
            }

            // --- LDAP injection (ZAP 40015) ---------------------------------
            if ($canRun() && $aggressive && $groupOn('injection')) {
                $ldapPayload = ')(uid=*))(|(uid=*';
                $r = $probe($ldapPayload);
                $tests++;
                $ldapErr = static fn(string $b): bool => (bool)preg_match('/ldap_|LdapException|DirectoryServices|invalid DN|partial results/i', $b);
                if ($ldapErr($r['body']) && !$ldapErr($baseBody)) {
                    $emit([
                        'rule'     => 'ldap-injection',
                        'name'     => 'LDAP Injection',
                        'type'     => 'active',
                        'risk'     => 'High',
                        'confidence' => 'Medium',
                        'cwe'      => 'CWE-90',
                        'summary'  => 'LDAP filter metacharacters changed the server response, indicating the parameter is concatenated into an LDAP search filter.',
                        'evidence' => 'Directory-service error markers for payload ' . $ldapPayload . ' (param ' . $param . ').',
                        'solution' => 'Escape LDAP filter special characters with framework escaping (e.g. LdapEncoder) and prefer parameterised bind/search.',
                        'reference'=> 'https://owasp.org/www-community/attacks/LDAP_Injection',
                        'url'      => $url,
                        'param'    => $param,
                        'payload'  => $ldapPayload,
                        'method'   => $method,
                        'source'   => 'Active Scanner',
                    ]);
                }
            }

            // --- Expression Language / EL variants (ZAP 90025 + XSTI) -------
            if ($groupOn('injection') && $canRun()) {
                foreach (['#{7*7}' => '#49', '%{7*7}' => '49'] as $payload => $expected) {
                    $r = $probe($payload);
                    $tests++;
                    if ($sig($r['body'], $expected) && !$sig($baseBody, $expected)) {
                        $emit([
                            'rule'     => 'el-injection',
                            'name'     => 'Expression Language Injection',
                            'type'     => 'active',
                            'risk'     => 'Critical',
                            'confidence' => 'Medium',
                            'cwe'      => 'CWE-917',
                            'summary'  => 'A Java/JSP Expression Language expression was evaluated server-side, which can escalate to RCE via classloader gadgets.',
                            'evidence' => 'Payload ' . $payload . ' evaluated to ' . $expected . ' (param ' . $param . ').',
                            'solution' => 'Upgrade EL sandboxes, disallow arbitrary expression evaluation on user input.',
                            'reference'=> 'https://www.zaproxy.org/docs/alerts/90025/',
                            'url'      => $url,
                            'param'    => $param,
                            'payload'  => $payload,
                            'method'   => $method,
                            'source'   => 'Active Scanner',
                        ]);
                        break;
                    }
                }
            }

            // --- JWT handling checks (ZAP 40036) ----------------------------
            if ($canRun() && $groupOn('jwt') && preg_match('/token|jwt|auth|session/i', $param)) {
                $findJwt = static function (string $hay): ?string {
                    if (preg_match('/\b(ey[A-Za-z0-9_-]{10,}\.[eyA-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,})\b/', $hay, $m)) {
                        return $m[1];
                    }
                    return null;
                };
                $jwt = $findJwt((string)($post[$param] ?? '')) ?: $findJwt($baseBody);
                if ($jwt) {
                    $parts = explode('.', $jwt);
                    $newParts = $parts;
                    // alg:none unsigned re-sign: header alg none, original payload, empty sig
                    $b64 = static function (string $v): string {
                        return rtrim(strtr(base64_encode($v), '+/', '-_'), '=');
                    };
                    $b64d = static function (string $v): ?string {
                        $pad = strlen($v) % 4 ? str_repeat('=', 4 - strlen($v) % 4) : '';
                        $d = base64_decode(strtr($v . $pad, '-_', '+/'), true);
                        return $d === false ? null : $d;
                    };
                    $h = $b64d($parts[0]) ?: '{}';
                    $hdr = json_decode($h, true) ?: [];
                    if (isset($hdr['alg']) && strtolower((string)$hdr['alg']) !== 'none') {
                        $hdr['alg'] = 'none';
                        $newParts[0] = $b64((string)json_encode($hdr));
                        if (is_array($parts) && count($parts) === 3) {
                            $forged = $newParts[0] . '.' . $parts[1] . '.';
                            $r = $probe($forged);
                            $tests++;
                            if ($r['code'] === $baseCode && ($r['code'] < 400) && !preg_match('/invalid|unauthor|forbidden|token/i', $r['body'])) {
                                $emit([
                                    'rule'     => 'jwt-none',
                                    'name'     => 'JWT Accepts Unsigned "alg": "none" Tokens',
                                    'type'     => 'active',
                                    'risk'     => 'Critical',
                                    'confidence' => 'Medium',
                                    'cwe'      => 'CWE-347',
                                    'summary'  => 'A token re-signed with alg:none was accepted, meaning the signature is not verified and any valid format token would be accepted.',
                                    'evidence' => 'Forged alg:none token produced HTTP ' . $r['code'] . ' with no rejection signature (param ' . $param . ').',
                                    'solution' => 'Pin the algorithm server-side and reject non-allow-listed alg headers; enforce signature verification before trust.',
                                    'reference'=> 'https://www.zaproxy.org/docs/alerts/40036/',
                                    'url'      => $url,
                                    'param'    => $param,
                                    'method'   => $method,
                                    'source'   => 'Active Scanner',
                                ]);
                            }
                        }
                    }
                    $claims = json_decode($b64d($parts[1]) ?? '{}', true) ?: [];
                    $weak = [];
                    if (!isset($claims['exp'])) $weak[] = 'no exp claim';
                    if (!isset($claims['aud'])) $weak[] = 'no aud claim';
                    if (!isset($claims['iss'])) $weak[] = 'no iss claim';
                    if (isset($hdr['kid']) && preg_match('#\.\./|[\\/]#', (string)$hdr['kid'])) $weak[] = 'path-bearing kid';
                    if ($weak) {
                        $emit([
                            'rule'     => 'jwt-weak-claims',
                            'name'     => 'JWT With Missing / Weak Claims',
                            'type'     => 'active',
                            'risk'     => 'Medium',
                            'confidence' => 'High',
                            'cwe'      => 'CWE-287',
                            'summary'  => 'The bearer token lacks standard validation-relevant claims, which weakens replay protection and audience binding.',
                            'evidence' => implode('; ', $weak) . ' (param ' . $param . ').',
                            'solution' => 'Require exp/aud/iss and short TTLs; validate kid against a fixed key directory.',
                            'reference'=> 'https://datatracker.ietf.org/doc/html/rfc8725',
                            'url'      => $url,
                            'param'    => $param,
                            'method'   => $method,
                            'source'   => 'Active Scanner',
                        ]);
                    }
                }
            }

            // --- IDOR: sequential numeric neighbours ---------------------
            if ($canRun() && $groupOn('session') && vs_is_id_param($param)) {
                $q = [];
                if ($method === 'GET') {
                    parse_str((string)parse_url($url, PHP_URL_QUERY), $q);
                } else {
                    $q = $post;
                }
                $orig = (int)($q[$param] ?? 0);
                if ($orig > 0) {
                    $baseFp = md5($baseBody);
                    foreach ([$orig + 1, $orig - 1, 1] as $try) {
                        if ($try < 1 || $try === $orig || !$canRun()) {
                            continue;
                        }
                        $r = $probe((string)$try);
                        $tests++;
                        if ($r['code'] === $baseCode && strlen($r['body']) > 200
                            && md5($r['body']) !== $baseFp
                            && vs_body_similarity($r['body'], $baseBody) < 0.92) {
                            $emit([
                                'rule'     => 'idor',
                                'name'     => 'Possible Insecure Direct Object Reference (IDOR)',
                                'type'     => 'active',
                                'risk'     => 'High',
                                'confidence' => 'Low',
                                'cwe'      => 'CWE-639',
                                'summary'  => 'Changing the object identifier returned a different record without an access error. Verify authorisation manually.',
                                'evidence' => 'id=' . $orig . ' → id=' . $try . ' returned a distinct HTTP ' . $r['code'] . ' page (' . strlen($r['body']) . ' bytes).',
                                'solution' => 'Enforce object-level authorization using the authenticated user and server-side ownership checks.',
                                'reference'=> 'https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control',
                                'url'      => $url,
                                'param'    => $param,
                                'payload'  => (string)$try,
                                'method'   => $method,
                                'source'   => 'Active Scanner',
                            ]);
                            break;
                        }
                    }
                }
            }
        }
    }

    return [
        'alerts'      => $alerts,
        'tests_run'   => $tests,
        'requests'    => $requests,
        'targets'     => count($targets),
        'budget'      => $budget,
        'duration_ms' => (int)((microtime(true) - $started) * 1000),
        'summary'     => [
            'total'    => count($alerts),
            'critical' => count(array_filter($alerts, fn($a) => $a['severity'] === 'Critical')),
            'high'     => count(array_filter($alerts, fn($a) => $a['severity'] === 'High')),
            'medium'   => count(array_filter($alerts, fn($a) => $a['severity'] === 'Medium')),
            'low'      => count(array_filter($alerts, fn($a) => $a['severity'] === 'Low')),
            'info'     => count(array_filter($alerts, fn($a) => $a['severity'] === 'Info')),
        ],
    ];
}
