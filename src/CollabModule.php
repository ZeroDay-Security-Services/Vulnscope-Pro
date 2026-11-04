<?php
/**
 * VulnScope Pro — Collaborative CVD layer (Vulnerability-Lookup parity).
 *
 * Ports Vulnerability-Lookup's analyst workflow into the scanner:
 *   - Sightings: record how a vulnerability was observed on a target
 *     (seen, exploited, not-exploited, confirmed, not-confirmed,
 *      patched, not-patched).
 *   - Comments: analyst notes attached to any advisory ID.
 *   - Bundles: group related advisories into a tracked case with a
 *     description (mirrors VL bundles for MISP-style correlation).
 *
 * Everything is stored locally in SQLite so the platform stays fully
 * functional without a self-hosted Vulnerability-Lookup instance, while
 * remote intel still comes from the public CIRCL API through
 * src/VulnLookupClient.php.
 */
declare(strict_types=1);

const VS_SIGHTING_KINDS = [
    'seen', 'exploited', 'not-exploited', 'confirmed',
    'not-confirmed', 'patched', 'not-patched',
];

/** Guard shared by every collab endpoint. */
function vs_collab_available(): bool
{
    $pdo = vs_db();
    return $pdo !== null;
}

/* --------------------------------------------------------------------
   SIGHTINGS
   -------------------------------------------------------------------- */

/** Validate + normalise a sighting kind token. */
function vs_sighting_kind(string $kind): ?string
{
    $kind = strtolower(trim($kind));
    if (in_array($kind, VS_SIGHTING_KINDS, true)) {
        return $kind;
    }
    if ($kind === 'notexploited') return 'not-exploited';
    if ($kind === 'notconfirmed') return 'not-confirmed';
    if ($kind === 'notpatched')   return 'not-patched';
    return null;
}

/**
 * Record a sighting (locally, and mirror it to a self-hosted
 * Vulnerability-Lookup instance when VULNLOOKUP_SIGHTINGS_URL is set).
 */
function vs_record_sighting(string $vuln_id, string $kind, string $target = '', string $author = '', string $note = ''): array
{
    $vuln_id = strtoupper(trim($vuln_id));
    if (!preg_match('/^(CVE|GHSA|GCVE)-[A-Z0-9-]+$/i', $vuln_id)) {
        return ['ok' => false, 'error' => 'vuln_id must be a CVE, GHSA or GCVE identifier.'];
    }
    $kind = vs_sighting_kind($kind);
    if ($kind === null) {
        return ['ok' => false, 'error' => 'kind must be one of: ' . implode(', ', VS_SIGHTING_KINDS)];
    }

    $pdo = vs_db();
    $stored = false;
    if ($pdo) {
        try {
            $stmt = $pdo->prepare(
                'INSERT INTO sightings (vuln_id, kind, target, author, note, timestamp)
                 VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)'
            );
            $stmt->execute([$vuln_id, $kind, $target, $author ?: 'analyst', $note]);
            $stored = true;
        } catch (Throwable $e) {
            return ['ok' => false, 'error' => 'Storage failed: ' . $e->getMessage()];
        }
    }

    // Optional mirror write to a self-hosted Vulnerability-Lookup instance.
    $mirror = '';
    if (defined('VULNLOOKUP_SIGHTINGS_URL') || getenv('VULNLOOKUP_SIGHTINGS_URL')) {
        $url = getenv('VULNLOOKUP_SIGHTINGS_URL');
        $token = getenv('VULNLOOKUP_SIGHTINGS_TOKEN');
        if ($url) {
            $ch = curl_init($url);
            curl_setopt_array($ch, [
                CURLOPT_POST           => true,
                CURLOPT_POSTFIELDS     => json_encode([
                    'vulnerability_id'   => $vuln_id,
                    'sighting_type'      => str_contains($kind, '-') ? str_replace('-', '_', $kind) : $kind,
                    'source'             => 'VulnScope-Pro',
                    'description'        => trim($note . ($target ? ' — on ' . $target : '')),
                    'created_at'         => date('c'),
                ]),
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT        => 6,
                CURLOPT_HTTPHEADER     => array_merge(
                    ['Content-Type: application/json'],
                    $token ? ['Authorization: Bearer ' . $token] : []
                ),
            ]);
            curl_exec($ch);
            $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);
            $mirror = $code >= 200 && $code < 300 ? 'mirrored' : 'mirror-failed(' . $code . ')';
        }
    }

    return ['ok' => true, 'kind' => $kind, 'stored' => $stored, 'mirror' => $mirror];
}

/** CSV of recorded sightings, newest first. */
function vs_list_sightings(string $vuln_id = '', int $limit = 200): array
{
    $pdo = vs_db();
    if (!$pdo) return [];
    try {
        if ($vuln_id !== '') {
            $stmt = $pdo->prepare('SELECT * FROM sightings WHERE vuln_id = ? ORDER BY id DESC LIMIT ?');
            $stmt->execute([strtoupper($vuln_id), max(1, min(1000, $limit))]);
        } else {
            $stmt = $pdo->prepare('SELECT * FROM sightings ORDER BY id DESC LIMIT ?');
            $stmt->execute([max(1, min(1000, $limit))]);
        }
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    } catch (Throwable $e) {
        return [];
    }
}

/** Sighting summary for one vulnerability: count per kind. */
function vs_sighting_summary(string $vuln_id): array
{
    $summary = [];
    foreach (vs_list_sightings($vuln_id, 500) as $s) {
        $summary[$s['kind']] = ($summary[$s['kind']] ?? 0) + 1;
    }
    return $summary;
}

/* --------------------------------------------------------------------
   COMMENTS
   -------------------------------------------------------------------- */

function vs_add_comment(string $vuln_id, string $body, string $author = '', string $severity_vote = ''): array
{
    $vuln_id = strtoupper(trim($vuln_id));
    $body = trim($body);
    if (!preg_match('/^(CVE|GHSA|GCVE)-[A-Z0-9-]+$/i', $vuln_id)) {
        return ['ok' => false, 'error' => 'vuln_id must be a CVE, GHSA or GCVE identifier.'];
    }
    if ($body === '') {
        return ['ok' => false, 'error' => 'Comment body is required.'];
    }
    if (mb_strlen($body) > 8000) {
        $body = mb_substr($body, 0, 8000);
    }
    $pdo = vs_db();
    if (!$pdo) {
        return ['ok' => false, 'error' => 'Database unavailable — commentary cannot be stored.'];
    }
    try {
        $stmt = $pdo->prepare(
            'INSERT INTO comments (vuln_id, author, body, severity_vote, timestamp)
             VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)'
        );
        $stmt->execute([$vuln_id, $author ?: 'analyst', $body, $severity_vote !== '' ? $severity_vote : null]);
    } catch (Throwable $e) {
        return ['ok' => false, 'error' => 'Storage failed: ' . $e->getMessage()];
    }
    return ['ok' => true];
}

/** Comment feed for one advisory or across all. */
function vs_list_comments(string $vuln_id = '', int $limit = 200): array
{
    $pdo = vs_db();
    if (!$pdo) return [];
    try {
        if ($vuln_id !== '') {
            $stmt = $pdo->prepare('SELECT * FROM comments WHERE vuln_id = ? ORDER BY id DESC LIMIT ?');
            $stmt->execute([strtoupper($vuln_id), max(1, min(1000, $limit))]);
        } else {
            $stmt = $pdo->prepare('SELECT * FROM comments ORDER BY id DESC LIMIT ?');
            $stmt->execute([max(1, min(1000, $limit))]);
        }
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    } catch (Throwable $e) {
        return [];
    }
}

/* --------------------------------------------------------------------
   BUNDLES
   -------------------------------------------------------------------- */

/** Normalise an array of IDs into clean CVE/GHSA/GCVE tokens. */
function vs_bundle_ids($raw): array
{
    $ids = [];
    if (is_string($raw)) {
        $raw = preg_split('/[\s,;]+/', $raw) ?: [];
    }
    if (!is_array($raw)) {
        return [];
    }
    foreach ($raw as $id) {
        if (!is_string($id)) continue;
        foreach (preg_split('/[\s,;]+/', strtoupper(trim($id))) ?: [] as $one) {
            if (preg_match('/^(CVE|GHSA|GCVE)-[A-Z0-9-]+$/i', $one, $m)) {
                $ids[] = strtoupper($m[0]);
            }
        }
    }
    return array_values(array_unique($ids));
}

function vs_create_bundle(string $name, string $description, $vuln_ids): array
{
    $name = trim($name);
    if ($name === '' || mb_strlen($name) > 200) {
        return ['ok' => false, 'error' => 'Bundle name is required (max 200 chars).'];
    }
    $ids_json = json_encode(vs_bundle_ids($vuln_ids), JSON_UNESCAPED_UNICODE);
    $pdo = vs_db();
    if (!$pdo) {
        return ['ok' => false, 'error' => 'Database unavailable — bundles cannot be stored.'];
    }
    try {
        $stmt = $pdo->prepare(
            'INSERT INTO bundles (name, description, vuln_ids, created_at, updated_at)
             VALUES (?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)'
        );
        $stmt->execute([$name, trim($description), $ids_json]);
        return ['ok' => true, 'id' => (int)$pdo->lastInsertId()];
    } catch (Throwable $e) {
        return ['ok' => false, 'error' => 'Storage failed: ' . $e->getMessage()];
    }
}

function vs_list_bundles(): array
{
    $pdo = vs_db();
    if (!$pdo) return [];
    try {
        $rows = $pdo->query('SELECT * FROM bundles ORDER BY updated_at DESC, id DESC LIMIT 200')
                    ->fetchAll(PDO::FETCH_ASSOC);
        foreach ($rows as &$r) {
            $r['vuln_ids'] = json_decode((string)$r['vuln_ids'], true) ?: [];
            $r['count']    = is_array($r['vuln_ids']) ? count($r['vuln_ids']) : 0;
        }
        unset($r);
        return $rows;
    } catch (Throwable $e) {
        return [];
    }
}

/** Add/remove vulnerabilities from an existing bundle. */
function vs_bundle_modify(int $bundle_id, ?array $add, ?array $remove, ?string $description = null): array
{
    $pdo = vs_db();
    if (!$pdo) {
        return ['ok' => false, 'error' => 'Database unavailable.'];
    }
    try {
        $stmt = $pdo->prepare('SELECT vuln_ids, description FROM bundles WHERE id = ?');
        $stmt->execute([$bundle_id]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$row) {
            return ['ok' => false, 'error' => 'Bundle not found.'];
        }
        $ids = vs_bundle_ids($row['vuln_ids']);
        if ($add !== null) {
            $ids = array_values(array_unique(array_merge($ids, vs_bundle_ids($add))));
        }
        if ($remove !== null) {
            $ids = array_values(array_diff($ids, vs_bundle_ids($remove)));
        }
        $stmt = $pdo->prepare(
            'UPDATE bundles SET vuln_ids = ?, updated_at = CURRENT_TIMESTAMP,
                description = COALESCE(?, description) WHERE id = ?'
        );
        $stmt->execute([json_encode($ids), $description, $bundle_id]);
        return ['ok' => true, 'vuln_ids' => $ids];
    } catch (Throwable $e) {
        return ['ok' => false, 'error' => $e->getMessage()];
    }
}

function vs_delete_bundle(int $bundle_id): array
{
    $pdo = vs_db();
    if (!$pdo) {
        return ['ok' => false, 'error' => 'Database unavailable.'];
    }
    $stmt = $pdo->prepare('DELETE FROM bundles WHERE id = ?');
    $stmt->execute([$bundle_id]);
    return ['ok' => $stmt->rowCount() > 0];
}

/**
 * Full case view for a bundle: local annotations plus live VL metadata
 * for every advisory in it (expensive — capped).
 */
function vs_bundle_detail(int $bundle_id, bool $with_meta = true): array
{
    foreach (vs_list_bundles() as $b) {
        if ((int)$b['id'] === $bundle_id) {
            $detail = $b;
            if ($with_meta && count($detail['vuln_ids']) <= 12) {
                $metas = [];
                foreach ($detail['vuln_ids'] as $id) {
                    $rec = null;
                    try {
                        $rec = vl_lookup_cve($id);
                    } catch (Throwable $e) {
                    }
                    $metas[$id] = $rec ? [
                        'cvss'     => $rec['cvss'],
                        'severity' => $rec['severity'],
                        'cwe'      => implode(', ', $rec['cwe']),
                        'is_kev'   => $rec['is_kev'] ?? false,
                        'epss'     => $rec['epss_score'] ?? null,
                    ] : null;
                }
                $detail['meta'] = $metas;
            }
            return $detail;
        }
    }
    return [];
}

/* --------------------------------------------------------------------
   ACTIVITY MERGE — sightings + comments in one timeline
   -------------------------------------------------------------------- */

function vs_collab_timeline(string $vuln_id = '', int $limit = 60): array
{
    $events = [];
    foreach (vs_list_sightings($vuln_id, $limit) as $s) {
        $events[] = [
            'ts'   => $s['timestamp'],
            'type' => 'sighting',
            'kind' => $s['kind'],
            'vuln' => $s['vuln_id'],
            'author' => $s['author'],
            'note' => $s['note'],
            'target' => $s['target'],
        ];
    }
    foreach (vs_list_comments($vuln_id, $limit) as $c) {
        $events[] = [
            'ts'   => $c['timestamp'],
            'type' => 'comment',
            'vuln' => $c['vuln_id'],
            'author' => $c['author'],
            'note' => $c['body'],
            'score' => $c['severity_vote'],
        ];
    }
    usort($events, static fn($a, $b) => strcmp($b['ts'], $a['ts']));
    return array_slice($events, 0, $limit);
}
