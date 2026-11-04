<?php
/**
 * VulnScope Pro — Module 3: active payload scanner
 * (SQLi / XSS / LFI / Open Redirect / CSRF / IDOR heuristics).
 */
declare(strict_types=1);


/** Quick TLS handshake probe: does <host>:<port> speak TLS? */
function vs_tls_probe(string $host, int $port, int $timeout = 4): bool {
    $fp = @fsockopen('ssl://' . $host, $port, $errno, $errstr, $timeout);
    if ($fp) { fclose($fp); return true; }
    return false;
}


/** Extract a named header value from a raw header block. */
function vs_extract_header(string $raw_headers, string $name): string {
    if (preg_match('/^' . preg_quote($name, '/') . ':\s*([^\r\n]+)/mi', $raw_headers, $m)) {
        return trim($m[1]);
    }
    return '';
}


/** SQLi heuristic: scan body for common DB error signatures. */
function vs_sqli_error_in_body(string $body): bool {
    $sigs = [
        'you have an error in your sql syntax', 'warning: mysql',
        'unclosed quotation mark', 'quoted string not properly terminated',
        'mysql_fetch_', 'pg_query', 'postgresql query failed', 'psql:',
        'sql syntax', 'syntax error at or near', 'ora-[0-9]{5}',
        'odbc.*driver', 'jdbc.*exception',
    ];
    foreach ($sigs as $sig) {
        if (@preg_match('/' . $sig . '/i', $body)) { return true; }
    }
    return false;
}


/** Human-readable SQLi evidence string. */
function vs_sqli_evidence(string $body): string {
    foreach (['SQL syntax', 'mysql_fetch_array', 'PostgreSQL query', 'Warning: mysql', 'Unclosed quotation mark', 'ORA-'] as $sig) {
        if (stripos($body, $sig) !== false) { return "DB error signature: {$sig}"; }
    }
    return 'DB error signature match';
}


/**
 * Resolve a possibly-relative URL against the scan base (fragment stripped).
 * Needed because form actions / hrefs collected from page markup are often
 * relative ("/login", "search.php"), which parse_url() cannot handle alone.
 */
function vs_resolve_url(string $base, string $rel): string {
    $rel = trim($rel);
    $rel = preg_replace('/#.*$/', '', $rel);
    if ($rel === '') { return $base; }
    if (preg_match('#^https?://#i', $rel)) { return $rel; }
    $p = parse_url($base);
    $scheme = $p['scheme'] ?? 'http';
    $host   = $p['host'] ?? '';
    $port   = isset($p['port']) ? ':' . $p['port'] : '';
    if ($host === '') { return $rel; }
    if (str_starts_with($rel, '//')) { return $scheme . ':' . $rel; }
    $path = $p['path'] ?? '/';
    if ($rel[0] === '?') { return $scheme . '://' . $host . $port . $path . $rel; }
    if ($rel[0] === '/') { return $scheme . '://' . $host . $port . $rel; }
    $dir = preg_replace('#/[^/]*$#', '/', $path);
    return $scheme . '://' . $host . $port . $dir . $rel;
}


/** Inject a payload into the first query param of a URL; null if no params. */
function vs_inject_param(string $url, string $payload): ?string {
    $parts = parse_url($url);
    if (empty($parts['host']) || empty($parts['query'])) { return null; }
    parse_str($parts['query'], $params);
    if (!$params) { return null; }
    $first = array_key_first($params);
    $params[$first] = $payload;
    $authority = $parts['host'] . (isset($parts['port']) ? ':' . $parts['port'] : '');
    return ($parts['scheme'] ?? 'http') . '://' . $authority . ($parts['path'] ?? '/') . '?' . http_build_query($params);
}


/** Verdict logic shared by the injection tests. Returns [vulnerable, evidence]. */
function vs_detect(string $type, int $code, string $body, string $headers): array {
    switch ($type) {
        case 'sqli':
        case 'sqli2':
            if (vs_sqli_error_in_body($body)) { return [true, vs_sqli_evidence($body)]; }
            return [false, ''];
        case 'xss':
            if (strpos($body, '"><xsstester>') !== false) { return [true, 'Unencoded payload echoed in response body.']; }
            return [false, ''];
        case 'lfi':
            if (preg_match('/root:[x*!]?:[0-9:]+:[0-9:]+:[^:]*:\/root:\/bin\/(ba)?sh/i', $body)) { return [true, 'passwd-file structure present in body.']; }
            return [false, ''];
        case 'redirect':
            $loc = vs_extract_header($headers, 'Location');
            if (in_array($code, [301, 302], true) && $loc && stripos($loc, 'google.com') !== false) { return [true, 'Redirects to ' . $loc]; }
            return [false, ''];
    }
    return [false, ''];
}


/**
 * MODULE 3 — Active payload scanner (thread-safe injection tester).
 * SQLi / XSS / LFI / Open Redirect / CSRF / IDOR against discovered GET inputs,
 * with synthetic parameter probing when the target exposes none.
 */
function vs_module3_payloads(string $host, int $port, bool $tls, array $probe_paths = [], string $cookie = ''): array {
    $scheme = $tls ? 'https' : 'http';
    $base   = "{$scheme}://{$host}:{$port}";
    $tests  = [];
    $cookie_hdr = vs_sanitize_cookie($cookie);
    $base_host  = strtolower(parse_url($base, PHP_URL_HOST) ?: $host);

    /** Hardened GET, no redirect-follow, returns [status, body, headers, final_url]. */
    $http = function (string $url) use ($base, $cookie_hdr): array {
        $ch = curl_init($url);
        curl_setopt_array($ch, vs_curl_defaults());
        curl_setopt_array($ch, [
            CURLOPT_HEADER         => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_TIMEOUT_MS     => 9000,
            CURLOPT_COOKIE         => $cookie_hdr,
        ]);
        $raw = curl_exec($ch);
        $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $furl = (string)curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
        curl_close($ch);
        if (!is_string($raw)) { return [$code, '', '', $furl]; }
        $sep = strpos($raw, "\r\n\r\n");
        return [$code, $sep !== false ? substr($raw, $sep + 4) : $raw, substr($raw, 0, $sep ?: 0), $furl];
    };

    /** Baseline fetch for the fingerprint cache + session seeding. */
    $bl0 = $http($base . '/');
    $fp  = static fn(string $b): int => crc32($b);
    $cache = [$fp($bl0[1])];

    /** Grab candidate GET param URLs from a page's links + forms (same-host only). */
    $collect = function (string $url) use ($http): array {
        [$code, $body] = $http($url);
        $cands = [];
        if ($code < 200 || $code >= 400 || !$body) { return $cands; }
        // query-string links
        if (preg_match_all('/href=["\']([^"\']+\?[^"\']+)["\']/i', $body, $m)) {
            foreach ($m[1] as $u) { $cands[] = html_entity_decode($u, ENT_QUOTES); }
        }
        // GET form actions (real input surface on live apps)
        if (preg_match_all('/<form[^>]+action=["\']([^"\']*)["\'][^>]*>/is', $body, $fm)) {
            foreach ($fm[1] as $act) { $cands[] = html_entity_decode($act, ENT_QUOTES); }
        }
        // bare ?a=b&c=d URLs anywhere in the markup
        if (preg_match_all('/[?&][a-zA-Z_][a-zA-Z0-9_]*=[^"\'\s>]+/', $body, $qm)) {
            $cands = array_merge($cands, $qm[0]);
        }
        return array_slice(array_values(array_unique($cands)), 0, 8);
    };

    $payloads = [
        'sqli'     => "'",
        'sqli2'    => "' OR '1'='1",
        'xss'      => '"><xsstester>',
        'lfi'      => '../../../../etc/passwd',
        'redirect' => 'https://google.com',
    ];

    // Synthetic params probed when the page exposes no parameterised URLs.
    $synth = [
        'id'       => ['sqli', 'idor'],
        'page'     => ['sqli', 'lfi'],
        'q'        => ['sqli', 'xss'],
        'search'   => ['sqli', 'xss'],
        'file'     => ['lfi'],
        'path'     => ['lfi'],
        'url'      => ['redirect'],
        'next'     => ['redirect'],
        'redirect' => ['redirect'],
        'cat'      => ['sqli'],
        'user'     => ['sqli', 'idor'],
    ];

    $deadline = microtime(true) + 60.0;

    /** Append/replace one query param on a candidate URL. */
    $build = function (string $url, string $param, string $payload): string {
        $u = parse_url($url);
        $query = [];
        if (!empty($u['query'])) { parse_str($u['query'], $query); }
        $query[$param] = $payload;
        $authority = ($u['host'] ?? '') . (isset($u['port']) ? ':' . $u['port'] : '');
        return ($u['scheme'] ?? 'http') . '://' . $authority . ($u['path'] ?? '/') . '?' . http_build_query($query);
    };

    /** Record one test result with class metadata. */
    $record = function (string $type, string $url, string $payload, bool $vuln, string $evidence, int $code) use (&$tests): void {
        $meta = [
            'sqli'     => ['SQL Injection',      'High',   'CWE-89'],
            'sqli2'    => ['SQL Injection',      'High',   'CWE-89'],
            'xss'      => ['Cross-Site Scripting', 'Medium', 'CWE-79'],
            'lfi'      => ['Local File Inclusion', 'Critical', 'CWE-98'],
            'redirect' => ['Open Redirect',      'Medium', 'CWE-601'],
            'idor'     => ['IDOR',               'High',   'CWE-639'],
            'csrf'     => ['CSRF',               'Medium', 'CWE-352'],
        ][$type] ?? [$type, 'Medium', ''];
        $tests[] = [
            'type' => $type, 'label' => $meta[0],
            'severity' => $meta[1], 'cwe' => $meta[2],
            'url' => $url, 'payload' => $payload,
            'vulnerable' => $vuln, 'evidence' => $evidence, 'status' => $code,
        ];
    };

    $scanUrl = function (string $url0) use ($http, $collect, $payloads, $build, $record, $synth, $deadline, &$cache, $fp, $cookie_hdr, $base_host): void {
        [$code0, $body0] = $http($url0);
        if ($code0 < 200 || $code0 >= 400 || !$body0) { return; }

        // --- CSRF heuristic: password/submit forms with no token field ---
        if (preg_match_all('/<form[^>]*>(.*?)<\/form>/is', $body0, $forms)) {
            foreach ($forms[1] as $fi => $inner) {
                $sensitive = (bool)preg_match('/type=["\'](?:password|email|submit)["\']/i', $inner);
                $hasToken  = (bool)preg_match('/name=["\'][^"\']*(token|csrf|authenticity|nonce|_token|xsrf)[^"\']*["\']/i', $inner);
                if ($sensitive && !$hasToken) {
                    $record('csrf', $url0, '(form analysis)', true, 'Sensitive form #' . ($fi + 1) . ' has no CSRF token field — verify session-binding manually.', $code0);
                }
            }
        }

        $cands = $collect($url0);
        if (!$cands) {
            // --- Synthetic param probing (common on static/landing pages) ---
            foreach ($synth as $param => $types) {
                if (microtime(true) > $deadline) { return; }
            foreach ($types as $type) {
                // IDOR is fingerprint-based (no injection payload): a neighbor
                // id must return a DISTINCT 200 page, not the base template.
                if ($type === 'idor') {
                    $turl = $build($url0, $param, '2');
                    [$code, $body] = $http($turl);
                    $nf = $fp($body);
                    if ($code === 200 && strlen($body) > 200 && !in_array($nf, $cache, true) && $nf !== $fp($body0)) {
                        $cache[] = $nf;
                        $record('idor', $turl, '2', true, "Neighbor id=2 returned distinct HTTP 200 page — verify object-level authorization.", $code);
                    }
                    continue;
                }
                // Defensive: every non-IDOR type must have a payload entry.
                $payload = $payloads[$type] ?? null;
                if ($payload === null) { continue; }
                $turl = $build($url0, $param, $payload);
                [$code, $body, $hdrs] = $http($turl);
                [$vuln, $evidence] = vs_detect($type, $code, $body, $hdrs);
                $record($type, $turl, $payload, $vuln, $evidence, $code);
            }
            }
            return;
        }

        foreach (array_slice($cands, 0, 6) as $cu) {
            if (microtime(true) > $deadline) { return; }
            // Resolve relative hrefs/form-actions against the scan URL, then
            // enforce same-host (skips CDN/ads/social links).
            $cu = vs_resolve_url($url0, $cu);
            $cu_host = strtolower((string)parse_url($cu, PHP_URL_HOST));
            if ($cu_host === '' || $cu_host !== $base_host) { continue; }
            if (strpos($cu, '?') === false) {
                $cu .= '?id=1';
            }
            foreach ($payloads as $type => $payload) {
                $turl = vs_inject_param($cu, $payload);
                if ($turl === null) { continue; }
                [$code, $body, $hdrs] = $http($turl);
                [$vuln, $evidence] = vs_detect($type, $code, $body, $hdrs);
                $record($type, $turl, $payload, $vuln, $evidence, $code);
            }
            // --- IDOR heuristic: sequential numeric ids return distinct 200 pages ---
            if (preg_match('/[?&](id|user|uid|account|order)=(\d+)/i', $cu, $m)) {
                $orig = (int)$m[2];
                [$oc, $ob] = $http($cu);
                $obFp = $fp($ob);
                foreach ([1, $orig - 1, $orig + 1] as $try) {
                    if ($try < 1 || $try === $orig) { continue; }
                    $turl = $build($cu, strtolower($m[1]), (string)$try);
                    [$code, $body] = $http($turl);
                    $nf = $fp($body);
                    if ($code === 200 && strlen($body) > 200 && !in_array($nf, $cache, true) && $nf !== $obFp) {
                        $cache[] = $nf;
                        $record('idor', $turl, (string)$try, true, "Sequential id={$try} returned distinct HTTP 200 page — verify object-level authorization.", $code);
                        break;
                    }
                }
            }
        }
    };

    foreach (($probe_paths ?: ['/']) as $pp) {
        if (microtime(true) > $deadline) { break; }
        $scanUrl($base . '/' . ltrim($pp, '/'));
    }
    return ['base_url' => $base, 'tests_run' => count($tests), 'vulnerabilities' => $tests, 'cookie_used' => $cookie_hdr !== ''];
}

