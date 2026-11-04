<?php
/**
 * VulnScope Pro — HTTP proxy layer (ZAP parity).
 *
 * Two capabilities:
 *
 *  1. History / Site map: every request the scan engine makes is logged to
 *     SQLite (method, URL, status, size, latency) so the operator can browse
 *     the scan's traffic like ZAP's History tab, grouped per host.
 *
 *  2. Manual request composer ("Replay"): hand-craft an arbitrary request
 *     against an authorised context (respects the same scope validation the
 *     scanner enforces) and inspect the raw request/response pair.
 *
 * Request logging is a no-op when SQLite is unavailable — scanning never
 * depends on it.
 */
declare(strict_types=1);

/** Log one exchange performed by the scan engine (called from the HTTP layer). */
function vs_log_request(
    string $method,
    string $url,
    int $status,
    int $size,
    int $ms,
    string $session = '',
    string $entry_type = 'scan'
): void {
    $pdo = function_exists('vs_db') ? vs_db() : null;
    if (!$pdo) return;
    try {
        $host = strtolower(parse_url($url, PHP_URL_HOST) ?: '');
        $stmt = $pdo->prepare(
            'INSERT INTO http_history (method, url, host, status, size, ms, session, entry_type, ts)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)'
        );
        $stmt->execute([strtoupper($method), $url, $host, $status, $size, $ms, $session, $entry_type]);
    } catch (Throwable $e) {
        // History is best-effort.
    }
}

/** Recent history, newest first; optional host/message filters. */
function vs_history(array $filters = [], int $limit = 150): array
{
    $pdo = vs_db();
    if (!$pdo) return [];
    try {
        $sql  = 'SELECT id, ts, method, url, host, status, size, ms, entry_type FROM http_history';
        $cond = [];
        $args = [];
        if (!empty($filters['host'])) {
            $cond[] = 'host = ?';
            $args[] = strtolower((string)$filters['host']);
        }
        if (!empty($filters['type'])) {
            $cond[] = 'entry_type = ?';
            $args[] = (string)$filters['type'];
        }
        if (!empty($filters['status'])) {
            $cond[] = 'status LIKE ?';
            $args[] = substr((string)$filters['status'], 0, 1) . '%';
        }
        if (!empty($filters['q'])) {
            $cond[] = '(url LIKE ?)';
            $args[] = '%' . $filters['q'] . '%';
        }
        if ($cond) {
            $sql .= ' WHERE ' . implode(' AND ', $cond);
        }
        $sql .= ' ORDER BY id DESC LIMIT ?';
        $args[] = max(1, min(1000, $limit));
        $stmt = $pdo->prepare($sql);
        $stmt->execute($args);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    } catch (Throwable $e) {
        return [];
    }
}

/** Distinct hosts seen by the scanner (site-map roots). */
function vs_history_hosts(): array
{
    $pdo = vs_db();
    if (!$pdo) return [];
    try {
        $rows = $pdo->query(
            'SELECT host, COUNT(*) AS requests, MAX(ts) AS latest, MIN(status) AS min_status,
                    SUM(CASE WHEN status < 400 THEN 1 ELSE 0 END) AS reachable
             FROM http_history WHERE host != "" GROUP BY host ORDER BY requests DESC LIMIT 100'
        )->fetchAll(PDO::FETCH_ASSOC);
        return $rows;
    } catch (Throwable $e) {
        return [];
    }
}

/** Trim history to keep the DB bounded. */
function vs_history_purge(int $keep = 5000): void
{
    $pdo = vs_db();
    if (!$pdo) return;
    try {
        $pdo->exec("DELETE FROM http_history WHERE id NOT IN
            (SELECT id FROM http_history ORDER BY id DESC LIMIT " . max(100, min(20000, $keep)) . ")");
    } catch (Throwable $e) {
    }
}

/**
 * Manual request composer.
 * Sends one request; returns a full request/response transcript (no HTML
 * parsing, no follow of oversized bodies — capped).
 */
function vs_compose_request(array $spec): array
{
    $method = strtoupper((string)($spec['method'] ?? 'GET'));
    if (!preg_match('/^[A-Z]{1,10}$/', $method)) {
        return ['ok' => false, 'error' => 'Invalid HTTP method.'];
    }
    $url = trim((string)($spec['url'] ?? ''));
    if ($url === '' || !filter_var($url, FILTER_VALIDATE_URL)) {
        return ['ok' => false, 'error' => 'A valid absolute URL is required.'];
    }
    // Respect scanner scope: external targets allowed; internal blocked
    // unless ALLOW_INTERNAL_SCAN is explicitly on.
    $host = (string)parse_url($url, PHP_URL_HOST);
    $iP = filter_var(gethostbyname($host), FILTER_VALIDATE_IP);
    $internal = $iP && !filter_var($iP, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
    if ($internal && !ALLOW_INTERNAL_SCAN) {
        return ['ok' => false, 'error' => 'Blocked: internal network target (set ALLOW_INTERNAL_SCAN to allow lab use).'];
    }

    $headers = [];
    if (is_array($spec['headers'] ?? null)) {
        foreach ($spec['headers'] as $k => $v) {
            $k = trim((string)$k);
            if ($k === '' || strlen($k) > 80 || preg_match('/[^A-Za-z0-9-]/', $k)) continue;
            $headers[] = $k . ': ' . substr(trim((string)$v), 0, 500);
        }
    }
    $body = (string)($spec['body'] ?? '');
    $fh   = [];
    foreach ($headers as $h) {
        $fh[] = $h;
        if (strncmp(strtolower($h), 'content-type:', 13) === 0) $fh['ct'] = $h;
    }

    $ch = curl_init($url);
    $opts = vs_curl_defaults();
    $opts[CURLOPT_CUSTOMREQUEST] = $method;
    curl_setopt_array($ch, $opts);
    curl_setopt($ch, CURLOPT_HEADER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, $fh);
    if ($body !== '' && $method !== 'GET' && $method !== 'HEAD') {
        curl_setopt($ch, CURLOPT_POSTFIELDS, substr($body, 0, 50000));
    }
    if (($spec['timeout'] ?? 0)) {
        curl_setopt($ch, CURLOPT_TIMEOUT_MS, max(500, min(20000, (int)$spec['timeout'])));
    }
    $raw = curl_exec($ch);
    if ($raw === false) {
        $err = curl_error($ch);
        curl_close($ch);
        return ['ok' => false, 'error' => 'cURL: ' . $err];
    }
    $code   = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $headerSize = (int)curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    $finalUrl = (string)curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
    $ms   = (int)round(curl_getinfo($ch, CURLINFO_TOTAL_TIME_T) / 1000);
    curl_close($ch);

    $raw = (string)$raw;
    $respHead = substr($raw, 0, $headerSize);
    $respBody = substr($raw, $headerSize);
    if (strlen($respBody) > 60000) {
        $respBody = substr($respBody, 0, 60000) . "\n…[truncated]";
    }

    // Build a replayable request transcript.
    $scheme = parse_url($url, PHP_URL_SCHEME) ?: 'http';
    $path   = parse_url($url, PHP_URL_PATH) ?: '/';
    if (($q = parse_url($url, PHP_URL_QUERY))) $path .= '?' . $q;
    $reqHead = "$method $path HTTP/1.1\r\nHost: $host\r\n" . implode("\r\n", $headers);
    $reqTranscript = $reqHead . ($body !== '' ? "\r\n\r\n" . $body : '');

    vs_log_request($method, $finalUrl ?: $url, $code, strlen($respBody), $ms, 'manual', 'replay');

    return [
        'ok'       => true,
        'status'   => $code,
        'ms'       => $ms,
        'final_url'=> $finalUrl,
        'sent'     => $reqTranscript,
        'headers'  => $respHead,
        'body'     => $respBody,
        'size'     => strlen($respBody),
    ];
}
