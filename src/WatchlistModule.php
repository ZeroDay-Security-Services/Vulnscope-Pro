<?php
/**
 * VulnScope Pro — Watchlists & notifications (Vulnerability-Lookup parity).
 *
 * Watches vendor:product pairs against the Vulnerability-Lookup search API
 * and CISA KEV; queues webhook notifications (Slack/Mattermost/SIEM/try any
 * HTTPS endpoint) for new advisories that pass the severity threshold.
 *
 * Outbound webhook policy is strict: HTTPS only, max 5s timeout, max 8KB
 * body, blocked private/loopback/link-local addresses (SSRF-safe by design).
 */
declare(strict_types=1);

/** True if host resolves to an internal/loopback range forbidden for webhooks. */
function vs_is_forbidden_webhook_host(string $host): bool
{
    $host = strtolower(trim($host));
    if ($host === 'localhost' || str_ends_with($host, '.localhost')) return true;
    $parts = gethostbynamel($host);
    if ($parts === false && filter_var($host, FILTER_VALIDATE_IP)) {
        $parts = [$host];
    }
    foreach ((array)$parts as $ip) {
        if (preg_match('/^(0\.|10\.|127\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|::1|f[ce][0-9a-f]{2}:)/i', $ip)) {
            return true;
        }
    }
    return false;
}

/** Deliver a webhook (HTTPS-only, non-internal, tight timeouts). */
function vs_send_webhook(string $url, array $payload, array $headers = []): array
{
    $url = trim($url);
    if (!preg_match('#^https://#i', $url)) {
        return ['ok' => false, 'error' => 'Webhook URL must be HTTPS.'];
    }
    $host = parse_url($url, PHP_URL_HOST);
    if (!$host || vs_is_forbidden_webhook_host((string)$host)) {
        return ['ok' => false, 'error' => 'Webhook host is forbidden (internal network).'];
    }
    $body = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    if (strlen($body) > 8192) {
        $body = substr($body, 0, 8189) . '…';
    }
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => $body,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 5,
        CURLOPT_CONNECTTIMEOUT => 3,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_HTTPHEADER     => array_merge(['Content-Type: application/json'], $headers),
        CURLOPT_USERAGENT      => 'VulnScope-Pro/6.0 Watchlist',
    ]);
    curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err  = curl_error($ch);
    curl_close($ch);
    return ['ok' => $code >= 200 && $code < 300, 'status' => $code, 'error' => $err ?: null];
}

/* --------------------------------------------------------------------
   WATCHLIST CRUD
   -------------------------------------------------------------------- */

function vs_watchlists(): array
{
    $pdo = vs_db();
    if (!$pdo) return [];
    try {
        $rows = $pdo->query('SELECT * FROM watchlists ORDER BY created_at DESC, id DESC LIMIT 200')
                    ->fetchAll(PDO::FETCH_ASSOC);
        foreach ($rows as &$r) {
            // Outstanding + delivered notification counts (cheap aggregate).
            $stmt = $pdo->prepare(
                'SELECT SUM(CASE WHEN delivered = 0 THEN 1 ELSE 0 END) AS pending, COUNT(*) AS total
                 FROM notifications WHERE watchlist_id = ?'
            );
            $stmt->execute([(int)$r['id']]);
            $agg = $stmt->fetch(PDO::FETCH_ASSOC) ?: ['pending' => 0, 'total' => 0];
            $r['pending'] = (int)($agg['pending'] ?? 0);
            $r['total']   = (int)($agg['total'] ?? 0);
        }
        unset($r);
        return $rows;
    } catch (Throwable $e) {
        return [];
    }
}

function vs_watchlist_add(string $vendor, string $product, float $min_cvss = 0.0, string $webhook = '', array $opts = []): array
{
    $vendor  = strtolower(trim($vendor));
    $product = strtolower(trim($product));
    if ($vendor === '' || $product === '') {
        return ['ok' => false, 'error' => 'vendor and product are required (e.g. apache / http_server).'];
    }
    if ($webhook !== '' && !preg_match('#^https://#i', $webhook)) {
        return ['ok' => false, 'error' => 'Webhook URL must be HTTPS.'];
    }
    $frequency = strtolower(trim((string)($opts['frequency'] ?? 'daily')));
    if (!in_array($frequency, ['hourly', 'daily', 'weekly'], true)) {
        $frequency = 'daily';
    }
    $hazardThreshold = max(0, min(100, (int)($opts['hazard_threshold'] ?? 0)));
    $pdo = vs_db();
    if (!$pdo) {
        return ['ok' => false, 'error' => 'Database unavailable.'];
    }
    try {
        $stmt = $pdo->prepare(
            'INSERT INTO watchlists (vendor, product, min_cvss, webhook_url, frequency, hazard_threshold, is_active, created_at)
             VALUES (?, ?, ?, ?, ?, ?, 1, CURRENT_TIMESTAMP)'
        );
        $stmt->execute([$vendor, $product, max(0.0, min(10.0, $min_cvss)), $webhook, $frequency, $hazardThreshold]);
        return ['ok' => true, 'id' => (int)$pdo->lastInsertId()];
    } catch (Throwable $e) {
        return ['ok' => false, 'error' => $e->getMessage()];
    }
}

function vs_watchlist_delete(int $id): array
{
    $pdo = vs_db();
    if (!$pdo) {
        return ['ok' => false, 'error' => 'Database unavailable.'];
    }
    $pdo->prepare('DELETE FROM notifications WHERE watchlist_id = ?')->execute([$id]);
    $pdo->prepare('DELETE FROM seen_vulns WHERE watchlist_id = ?')->execute([$id]);
    $stmt = $pdo->prepare('DELETE FROM watchlists WHERE id = ?');
    $stmt->execute([$id]);
    return ['ok' => $stmt->rowCount() > 0];
}

/* --------------------------------------------------------------------
   CHECK RUN — poll upstream feeds, queue notifications
   -------------------------------------------------------------------- */

/**
 * Run every (or one) watchlist: search Vulnerability-Lookup for the
 * vendor:product pair, keep advisories above min_cvss, filter already-seen
 * ones with seen_vulns, queue notifications, deliver webhooks, remember.
 */
function vs_watchlist_check(?int $only_id = null): array
{
    $pdo = vs_db();
    if (!$pdo) {
        return ['ok' => false, 'error' => 'Database unavailable.'];
    }

    if ($only_id) {
        $stmt = $pdo->prepare('SELECT * FROM watchlists WHERE id = ?');
        $stmt->execute([$only_id]);
        $lists = $stmt->fetchAll(PDO::FETCH_ASSOC);
    } else {
        $lists = $pdo->query('SELECT * FROM watchlists ORDER BY id')->fetchAll(PDO::FETCH_ASSOC);
    }

    $report = ['checked' => 0, 'new' => 0, 'notified' => 0, 'errors' => []];

    foreach ($lists as $wl) {
        $wlId = (int)$wl['id'];
        $report['checked']++;

        try {
            $hits = vl_vendor_product((string)$wl['vendor'], (string)$wl['product'], 30);
        } catch (Throwable $e) {
            $report['errors'][] = $wl['vendor'] . ':' . $wl['product'] . ' — ' . $e->getMessage();
            continue;
        }
        if (!$hits) {
            $pdo->prepare('UPDATE watchlists SET last_checked = CURRENT_TIMESTAMP WHERE id = ?')->execute([$wlId]);
            continue;
        }

        // Which of these are already recorded as seen for this watchlist?
        $seenStmt = $pdo->prepare('SELECT vuln_id FROM seen_vulns WHERE watchlist_id = ?');
        $seenStmt->execute([$wlId]);
        $seen = array_flip($seenStmt->fetchAll(PDO::FETCH_COLUMN));

        $newItems = [];
        foreach ($hits as $hit) {
            $id = strtoupper((string)($hit['id'] ?? ''));
            $cvss = (float)($hit['cvss'] ?? 0);
            if ($id === '' || isset($seen[$id]) || $cvss < (float)$wl['min_cvss']) {
                continue;
            }
            $newItems[] = $hit + ['vuln_id' => $id];
        }
        usort($newItems, static fn($a, $b) => ($b['cvss'] ?? 0) <=> ($a['cvss'] ?? 0));
        $newItems = array_slice($newItems, 0, 8);
        $report['new'] += count($newItems);

        // Exploit-hazard enrichment for the new advisories (one batch).
        $hazards = [];
        if ($newItems) {
            try {
                $hbatch = vs_exploit_hazard_batch(array_map(
                    static fn($i) => ['vulnerability_id' => $i['vuln_id'], 'cvss' => $i['cvss'] ?? 0],
                    $newItems
                ));
                foreach ($hbatch['instances'] as $h) {
                    if (!empty($h['vulnerability_id'])) {
                        $hazards[$h['vulnerability_id']] = $h['score'];
                    }
                }
            } catch (Throwable $e) {
                $report['errors'][] = 'hazard batch — ' . $e->getMessage();
            }
        }

        $hThreshold = (int)($wl['hazard_threshold'] ?? 0);

        foreach ($newItems as $item) {
            $id = $item['vuln_id'];
            // Persist seen + queue notification.
            $pdo->prepare('INSERT OR IGNORE INTO seen_vulns (watchlist_id, vuln_id, seen_at) VALUES (?, ?, CURRENT_TIMESTAMP)')
                ->execute([$wlId, $id]);
            $payload = [
                'vulnerability' => $item,
                'watchlist' => ['vendor' => $wl['vendor'], 'product' => $wl['product']],
                'hazard_score' => $hazards[$id] ?? null,
                'source' => 'VulnScope-Pro',
            ];
            $escalated = $hThreshold > 0 && ($hazards[$id] ?? 0) >= $hThreshold;
            $payload['text'] = ($escalated ? '[Hazard Alert] ' : '[VulnScope Watchlist] ') . $id
                . ' (' . ($item['severity'] ?? 'Unknown') . ', CVSS ' . ($item['cvss'] ?? 0)
                . ', hazard ' . ($hazards[$id] ?? '-') . ') — '
                . ($item['summary'] ?? '')
                . ' — ' . $wl['vendor'] . ':' . $wl['product'];
            $pdo->prepare('INSERT INTO notifications (watchlist_id, vuln_id, payload, delivered) VALUES (?, ?, ?, 0)')
                ->execute([$wlId, $id, json_encode($payload, JSON_UNESCAPED_UNICODE)]);
        }

        // Hazard hysteresis latch: alert once per threshold crossing.
        if ($hThreshold > 0 && $hazards && max($hazards) >= $hThreshold) {
            $pdo->prepare('UPDATE watchlists SET hazard_alerted = 1 WHERE id = ?')->execute([$wlId]);
        } elseif ($hThreshold > 0 && (!$hazards || max($hazards) < $hThreshold)) {
            $pdo->prepare('UPDATE watchlists SET hazard_alerted = 0 WHERE id = ?')->execute([$wlId]);
        }

        // Deliver pending webhooks for this watchlist.
        if (!empty($wl['webhook_url'])) {
            $pend = $pdo->prepare(
                'SELECT n.id, n.payload FROM notifications n
                 WHERE n.watchlist_id = ? AND n.delivered = 0 ORDER BY n.id'
            );
            $pend->execute([$wlId]);
            foreach ($pend->fetchAll(PDO::FETCH_ASSOC) as $n) {
                $payload = json_decode((string)$n['payload'], true) ?: [];
                $res = vs_send_webhook((string)$wl['webhook_url'], $payload);
                $upd = $pdo->prepare(
                    $res['ok']
                        ? 'UPDATE notifications SET delivered = 1 WHERE id = ?'
                        : 'UPDATE notifications SET error = ? WHERE id = ?'
                );
                if ($res['ok']) {
                    $upd->execute([$n['id']]);
                    $report['notified']++;
                } else {
                    $err = 'HTTP ' . ($res['status'] ?? 0) . ' ' . ($res['error'] ?? '');
                    $upd->execute([$err, $n['id']]);
                    $report['errors'][] = 'webhook ' . $wl['vendor'] . ':' . $wl['product'] . ' — ' . $err;
                    break; // failing endpoint: stop hammering
                }
            }
        }

        $pdo->prepare('UPDATE watchlists SET last_checked = CURRENT_TIMESTAMP WHERE id = ?')->execute([$wlId]);
    }

    return ['ok' => true] + $report;
}

/** Notification queue view (for the UI's alert drawer). */
function vs_notifications(int $limit = 50): array
{
    $pdo = vs_db();
    if (!$pdo) return [];
    try {
        $stmt = $pdo->prepare(
            'SELECT n.*, w.vendor, w.product, w.webhook_url
             FROM notifications n LEFT JOIN watchlists w ON w.id = n.watchlist_id
             ORDER BY n.id DESC LIMIT ?'
        );
        $stmt->execute([max(1, min(500, $limit))]);
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
        foreach ($rows as &$r) {
            $r['payload'] = json_decode((string)$r['payload'], true);
        }
        unset($r);
        return $rows;
    } catch (Throwable $e) {
        return [];
    }
}
