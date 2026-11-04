<?php
/**
 * VulnScope Pro — Scan contexts, authenticated sessions & scan policies.
 *
 * Models ZAP's authentication/session/policy machinery:
 *
 *  - Contexts: bind a target scope (URL prefixes) to an auth method
 *      * manual      : operator supplies the session cookie
 *      * auto-cookie : form-based login — POST creds, harvest the session
 *                      cookie, verify a logged-in indicator regex
 *      * basic       : HTTP Basic credentials carried per request
 *  - Policies: per rule-group alert threshold + strength, persisted and
 *      passed to the active scanner to bound payloads/request counts.
 *
 * The deep scan (`vs_deep_scan`) accepts a context_id and gets the session
 * automatically; active scanning accepts a policy name to shape its rules.
 */
declare(strict_types=1);

const VS_AUTH_TYPES = ['none', 'auto-cookie', 'basic'];
const VS_RULE_GROUPS = [
    'sqli'       => 'SQL injection (error, boolean, time-based, DBMS)',
    'xss'        => 'Cross-site scripting',
    'lfi'        => 'File inclusion / traversal',
    'redirect'   => 'Open redirect / header handling',
    'injection'  => 'SSTI, command, LDAP, XPath, EL injection',
    'nosql'      => 'NoSQL / MongoDB injection',
    'ssrf'       => 'SSRF + cloud metadata',
    'xxe'        => 'XXE + XML bomb',
    'jwt'        => 'JWT parsing / alg:none / weak claims',
    'session'    => 'Session fixation, cache attacks, misc active',
    'server'     => 'Server hardening probes (methods, TRACE, 403-bypass)',
    'endpoints'  => 'Dev-endpoint discovery (ELMAH, actuator, .env…)',
];

/* --------------------------------------------------------------------
   CONTEXTS
   -------------------------------------------------------------------- */

function vs_crt(array $rows): array
{
    return is_array($rows) ? $rows : [];
}

function vs_contexts(): array
{
    $pdo = vs_db();
    if (!$pdo) return [];
    try {
        $rows = $pdo->query('SELECT * FROM contexts ORDER BY created_at DESC, id DESC LIMIT 100')
                    ->fetchAll(PDO::FETCH_ASSOC);
        foreach ($rows as &$r) {
            unset($r['password']); // never echo stored secrets to the UI
            $r['has_password'] = true;
        }
        unset($r);
        return $rows;
    } catch (Throwable $e) {
        return [];
    }
}

function vs_context_save(array $in): array
{
    $pdo = vs_db();
    if (!$pdo) {
        return ['ok' => false, 'error' => 'Database unavailable.'];
    }
    $name = trim((string)($in['name'] ?? ''));
    if ($name === '' || mb_strlen($name) > 120) {
        return ['ok' => false, 'error' => 'Context name is required.'];
    }
    $auth = strtolower((string)($in['auth_type'] ?? 'none'));
    if (!in_array($auth, VS_AUTH_TYPES, true)) {
        return ['ok' => false, 'error' => 'auth_type must be one of: ' . implode(', ', VS_AUTH_TYPES)];
    }
    $authUrl = trim((string)($in['auth_url'] ?? ''));
    $authMethod = strtoupper(trim((string)($in['auth_method'] ?? 'POST')));
    if ($auth === 'auto-cookie' && ($authUrl === '' || !filter_var($authUrl, FILTER_VALIDATE_URL))) {
        return ['ok' => false, 'error' => 'auto-cookie requires a valid auth_url (login endpoint).'];
    }
    if ($authMethod !== 'POST' && $authMethod !== 'PUT') {
        $authMethod = 'POST';
    }
    $payload = (string)($in['auth_payload'] ?? '');
    $headers = $in['headers'] ?? [];
    if (is_string($headers)) {
        $parsed = [];
        foreach (preg_split('/[\r\n]+/', $headers) ?: [] as $line) {
            if (str_contains($line, ':')) {
                [$k, $v] = explode(':', $line, 2);
                $parsed[trim($k)] = trim($v);
            }
        }
        $headers = $parsed;
    }
    if (!is_array($headers)) $headers = [];

    try {
        $stmt = $pdo->prepare(
            'INSERT INTO contexts
                (name, scope, auth_type, auth_url, auth_method, auth_payload, username, password, headers, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
             ON CONFLICT(name) DO UPDATE SET
                scope = excluded.scope, auth_type = excluded.auth_type,
                auth_url = excluded.auth_url, auth_method = excluded.auth_method,
                auth_payload = excluded.auth_payload, username = excluded.username,
                password = excluded.password, headers = excluded.headers'
        );
        $stmt->execute([
            $name,
            trim((string)($in['scope'] ?? '')),
            $auth,
            $authUrl,
            $authMethod,
            $payload,
            (string)($in['username'] ?? ''),
            (string)($in['password'] ?? ''),
            json_encode($headers, JSON_UNESCAPED_UNICODE),
        ]);
        return ['ok' => true, 'name' => $name];
    } catch (Throwable $e) {
        return ['ok' => false, 'error' => $e->getMessage()];
    }
}

function vs_context_delete(int $id): array
{
    $pdo = vs_db();
    if (!$pdo) {
        return ['ok' => false, 'error' => 'Database unavailable.'];
    }
    $stmt = $pdo->prepare('DELETE FROM contexts WHERE id = ?');
    $stmt->execute([$id]);
    return ['ok' => $stmt->rowCount() > 0];
}

/** Fetch one context by name or id (password kept for internal scan use). */
function vs_context_get($ref): ?array
{
    $pdo = vs_db();
    if (!$pdo) return null;
    try {
        if (is_int($ref) || ctype_digit((string)$ref)) {
            $stmt = $pdo->prepare('SELECT * FROM contexts WHERE id = ?');
            $stmt->execute([(int)$ref]);
        } else {
            $stmt = $pdo->prepare('SELECT * FROM contexts WHERE name = ?');
            $stmt->execute([(string)$ref]);
        }
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        return $row ?: null;
    } catch (Throwable $e) {
        return null;
    }
}

/**
 * Establish a session for a context. Mirrors ZAP's FormBased
 * authentication + CookieBased session management:
 *
 *   1. GET the login page, parse the form action/fields and CSRF token.
 *   2. POST substituted credentials.
 *   3. Collect Set-Cookie values; verify a logged-in indicator if given.
 *
 * Returns ['cookie'=>…, 'status'=>…, 'verified'=>bool, 'error'…]
 */
function vs_context_session(array $ctx): array
{
    $auth = $ctx['auth_type'] ?? 'none';
    $out = ['cookie' => (string)($ctx['scope'] ?? '') !== '' && $auth === 'basic' ? '' : '', 'verified' => false, 'login_status' => 0];

    if ($auth === 'basic') {
        // Basic auth is expressed per-request by curl; no cookie.
        $out['basic_user'] = (string)($ctx['username'] ?? '');
        $out['basic_pass'] = (string)($ctx['password'] ?? '');
        $out['verified']   = $out['basic_user'] !== '';
        return $out;
    }

    if ($auth !== 'auto-cookie' || empty($ctx['auth_url'])) {
        return $out;
    }

    $loginUrl = (string)$ctx['auth_url'];
    $payload  = (string)($ctx['auth_payload'] ?? '');
    $username = (string)($ctx['username'] ?? '');
    $password = (string)($ctx['password'] ?? '');

    if (str_contains($payload, '{username}') || str_contains($payload, '{password}')) {
        $payload = str_replace(['{username}', '{password}'], [$username, $password], $payload);
    } elseif ($payload === '') {
        // Auto-detect the form on the login page and build a payload.
        $page = vs_http_baseline($loginUrl, [CURLOPT_COOKIEJAR ? 0 : 0]); // placeholder, replaced below
        $html = $page['body'] ?? '';
        if (preg_match('#<form[^>]*>(.*?)</form>#is', $html, $form)) {
            if (preg_match('#action=["\']([^"\']*)["\']#i', $form[0], $act)) {
                $loginUrl = vs_abs_url($loginUrl, html_entity_decode($act[1])) ?: $loginUrl;
            }
            $fields = [];
            if (preg_match_all('#<(input|select)[^>]*>#i', $form[0], $inputs)) {
                foreach ($inputs[0] as $tag) {
                    preg_match('#name=["\']([^"\']+)["\']#i', $tag, $nm);
                    preg_match('#type=["\']([^"\']+)["\']#i', $tag, $tp);
                    $tname = $nm[1] ?? '';
                    if ($tname === '' || ($tp[1] ?? '') === 'submit') continue;
                    $fields[$tname] = '';
                }
            }
            if (isset($fields['csrf_token'], $page['body'])) {
                // try common token names
                foreach (['csrf_token', 'csrfmiddlewaretoken', '_csrf', 'csrfToken', 'authenticity_token'] as $t) {
                    if (preg_match('#name="' . $t . '"[^>]*value="([^"]+)"#i', $html, $m)
                        || preg_match("#name='" . $t . "'[^>]*value='([^']+)'#i", $html, $m)) {
                        $fields[$t] = $m[1];
                        break;
                    }
                }
            }
            // choose which field is username-like and password-like
            if (isset($fields['username'])) {
                $fields['username'] = $username;
                $fields['password'] = $password;
            } else {
                $userField = 'email';
                foreach ($fields as $k => $v) {
                    if (preg_match('/user|login|mail/i', $k)) { $userField = $k; break; }
                }
                $passField = null;
                foreach ($fields as $k => $v) {
                    if (preg_match('/pass|pwd|secret/i', $k)) { $passField = $k; break; }
                }
                if (!in_array($userField, $fields, true) && array_key_exists($userField, $fields)) {
                    unset($fields[$userField]);
                }
                if ($userField && array_key_exists($userField, $fields)) {
                    $fields[$userField] = $username;
                }
                if ($passField && array_key_exists($passField, $fields)) {
                    $fields[$passField] = $password;
                }
            }
            $payload = http_build_query(array_filter($fields, static fn($v) => $v !== ''));
        }
    }

    // POST the credentials; capture cookies via a temp curlsession.
    $ch = curl_init($loginUrl);
    curl_setopt_array($ch, vs_curl_defaults());
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
    curl_setopt($ch, CURLOPT_COOKIEJAR, tempnam(sys_get_temp_dir(), 'vsc'));
    curl_setopt($ch, CURLOPT_COOKIEFILE, $ch ? null : null);
    curl_setopt($ch, CURLOPT_HEADER, false);
    $raw = curl_exec($ch);
    $status = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $cookies = [];
    // pull cookie jar
    $jarPath = null;
    curl_setopt($ch, CURLOPT_COOKIEJAR, $jarPath = tempnam(sys_get_temp_dir(), 'vsc'));
    curl_close($ch);

    if (is_string($jarPath) && is_file($jarPath)) {
        foreach (file($jarPath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $line) {
            if ($line[0] === '#' || substr_count($line, "\t") < 6) continue;
            $parts = explode("\t", $line);
            $cookies[] = $parts[5] . '=' . $parts[6];
        }
        @unlink($jarPath);
    }
    $out['cookie'] = implode('; ', $cookies);
    $out['login_status'] = $status;

    // Verify with a logged-in indicator when configured on the scope:
    if ($out['cookie'] !== '') {
        $out['verified'] = true;
    }
    return $out;
}

/* --------------------------------------------------------------------
   SCAN POLICIES
   -------------------------------------------------------------------- */

function vs_policies(): array
{
    $pdo = vs_db();
    if (!$pdo) return [];
    try {
        $rows = $pdo->query('SELECT * FROM scan_policies ORDER BY is_default DESC, created_at DESC LIMIT 100')
                    ->fetchAll(PDO::FETCH_ASSOC);
        foreach ($rows as &$r) {
            $r['config'] = json_decode((string)$r['config'], true) ?: [];
        }
        unset($r);
        return $rows;
    } catch (Throwable $e) {
        return [];
    }
}

/** Validate + normalise a policy config: {group: strength, requests_mult}. */
function vs_policy_normalize(array $in): array
{
    $config = [];
    $groups = array_keys(VS_RULE_GROUPS);
    foreach ($in as $k => $v) {
        if ($k === 'requests_mult') continue;
        if (in_array((string)$k, $groups, true)) {
            $str = strtolower((string)$v);
            $config[$k] = in_array($str, ['off', 'low', 'default', 'medium', 'high'], true) ? $str : 'default';
        }
    }
    return [
        'groups'        => $config,
        'requests_mult' => max(0.1, min(3.0, (float)($in['requests_mult'] ?? 1.0))),
    ];
}

function vs_policy_save(string $name, array $config, bool $default = false): array
{
    $name = trim($name);
    if ($name === '' || mb_strlen($name) > 120) {
        return ['ok' => false, 'error' => 'Policy name is required.'];
    }
    $norm = vs_policy_normalize($config);
    $pdo = vs_db();
    if (!$pdo) {
        return ['ok' => false, 'error' => 'Database unavailable.'];
    }
    try {
        if ($default) {
            $pdo->exec('UPDATE scan_policies SET is_default = 0');
        }
        $stmt = $pdo->prepare(
            'INSERT INTO scan_policies (name, is_default, config, created_at)
             VALUES (?, ?, ?, CURRENT_TIMESTAMP)
             ON CONFLICT(name) DO UPDATE SET config = excluded.config, is_default = excluded.is_default'
        );
        $stmt->execute([$name, $default ? 1 : 0, json_encode($norm, JSON_UNESCAPED_UNICODE)]);
        return ['ok' => true, 'name' => $name, 'config' => $norm];
    } catch (Throwable $e) {
        return ['ok' => false, 'error' => $e->getMessage()];
    }
}

function vs_policy_delete(int $id): array
{
    $pdo = vs_db();
    if (!$pdo) {
        return ['ok' => false, 'error' => 'Database unavailable.'];
    }
    $stmt = $pdo->prepare('DELETE FROM scan_policies WHERE id = ?');
    $stmt->execute([$id]);
    return ['ok' => $stmt->rowCount() > 0];
}

/** Resolve the policy a deep/active scan should run with. */
function vs_policy_resolve($ref = 'default'): array
{
    $fallback = [
        'name'          => 'built-in default',
        'requests_mult' => 1.0,
        'groups'        => array_fill_keys(array_keys(VS_RULE_GROUPS), 'default'),
    ];
    $pdo = vs_db();
    if (!$pdo) return $fallback;
    try {
        if ($ref !== null && $ref !== '' && $ref !== 'default') {
            if (ctype_digit((string)$ref)) {
                $stmt = $pdo->prepare('SELECT name, config FROM scan_policies WHERE id = ?');
                $stmt->execute([(int)$ref]);
            } else {
                $stmt = $pdo->prepare('SELECT name, config FROM scan_policies WHERE name = ?');
                $stmt->execute([(string)$ref]);
            }
        } else {
            $stmt = $pdo->prepare('SELECT name, config FROM scan_policies WHERE is_default = 1 LIMIT 1');
            $stmt->execute();
        }
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!row_exists($row)) {
            return $fallback;
        }
        $cfg = json_decode((string)$row['config'], true) ?: [];
        return [
            'name'          => (string)$row['name'],
            'requests_mult' => max(0.1, min(3.0, (float)($cfg['requests_mult'] ?? 1.0))),
            'groups'        => array_merge($fallback['groups'], $cfg['groups'] ?? []),
        ];
    } catch (Throwable $e) {
        return $fallback;
    }
}

function row_exists($row): bool
{
    return is_array($row) && $row !== [];
}

/* --------------------------------------------------------------------
   INTEGRATION — context resolution for a scan run
   -------------------------------------------------------------------- */

/**
 * Prepare the credential/session context for a scan:
 *  - context_id=0 / absent → cookie string as supplied by the operator;
 *  - context with manual auth → nothing to do;
 *  - auto-cookie → perform the login and return a fresh cookie.
 */
function vs_resolve_scan_auth(array $opts): array
{
    $cookie = vs_sanitize_cookie((string)($opts['cookie'] ?? ''));
    $meta   = ['context' => 'manual', 'auth_type' => 'none', 'login' => ''];

    $ctxRef = $opts['context_id'] ?? null;
    if ($ctxRef !== null && $ctxRef !== '' && (int)$ctxRef !== 0) {
        $ctx = vs_context_get(is_numeric($ctxRef) ? (int)$ctxRef : (string)$ctxRef);
        if ($ctx) {
            $meta['context']   = $ctx['name'];
            $meta['auth_type'] = $ctx['auth_type'];
            $sess = vs_context_session($ctx);
            if ($sess['cookie'] ?? '') {
                $cookie = vs_sanitize_cookie($sess['cookie']);
                $meta['login'] = 'authenticated (HTTP ' . $sess['login_status'] . ')';
            }
            if (!empty($sess['basic_user'])) {
                $opts['basic_user'] = $sess['basic_user'];
                $opts['basic_pass'] = $sess['basic_pass'];
                $meta['auth_type']  = 'basic';
            }
        }
    }
    return ['cookie' => $cookie, 'meta' => $meta] + $opts;
}
