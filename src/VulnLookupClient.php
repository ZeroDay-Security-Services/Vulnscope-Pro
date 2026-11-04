<?php
/**
 * VulnScope Pro — Vulnerability-Lookup (CIRCL) intelligence client.
 *
 * Ports the useful surface of vulnerability-lookup into the scanner:
 *   - unified CVE records (NVD / CIRCL / VulnLookup / GCVE shapes normalised)
 *   - vendor/product search
 *   - EPSS likelihood + CISA KEV status
 *   - CWE / CAPEC classification metadata
 *
 * Every remote call is cached in SQLite (intel_cache) so repeated scans and
 * the UI's intel lookup stay fast and upstream-friendly.
 */
declare(strict_types=1);

function vl_base(): string
{
    $base = getenv('VULNLOOKUP_API_BASE');
    return rtrim($base ?: 'https://vulnerability.circl.lu/api', '/');
}

/** Read-through cache row. Returns null on miss / DB unavailable. */
function vl_cache_read(string $key): ?array
{
    $pdo = function_exists('vs_db') ? vs_db() : null;
    if (!$pdo) {
        return null;
    }
    try {
        $stmt = $pdo->prepare('SELECT payload, cached_at FROM intel_cache WHERE cache_key = ?');
        $stmt->execute([$key]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$row) {
            return null;
        }
        $data = json_decode((string)$row['payload'], true);
        return is_array($data) ? ['data' => $data, 'cached_at' => (int)$row['cached_at']] : null;
    } catch (Throwable $e) {
        return null;
    }
}

function vl_cache_write(string $key, array $data): void
{
    $pdo = function_exists('vs_db') ? vs_db() : null;
    if (!$pdo) {
        return;
    }
    try {
        $stmt = $pdo->prepare('INSERT OR REPLACE INTO intel_cache (cache_key, payload, cached_at) VALUES (?, ?, ?)');
        $stmt->execute([$key, json_encode($data, JSON_UNESCAPED_UNICODE), time()]);
    } catch (Throwable $e) {
        // Cache is best-effort by design.
    }
}

/**
 * Cached GET against the Vulnerability-Lookup API.
 * Returns decoded JSON or null. Never throws.
 */
function vl_get(string $path, int $ttl = 86400, int $timeout = 10): ?array
{
    $key = 'vl:' . $path;
    $hit = vl_cache_read($key);
    if ($hit && (time() - $hit['cached_at']) < $ttl) {
        return $hit['data'];
    }

    $data = safe_curl(vl_base() . '/' . ltrim($path, '/'), ['Accept: application/json'], null, $timeout);
    if (is_array($data)) {
        vl_cache_write($key, $data);
        return $data;
    }
    // Stale cache beats no data when upstream is down.
    return $hit['data'] ?? null;
}

/** First non-empty value from a list of dotted paths. */
function vl_pick(array $src, array $paths, $default = null)
{
    foreach ($paths as $path) {
        $cur = $src;
        $ok = true;
        foreach (explode('.', $path) as $seg) {
            if (is_array($cur) && array_key_exists($seg, $cur)) {
                $cur = $cur[$seg];
            } else {
                $ok = false;
                break;
            }
        }
        if ($ok && $cur !== null && $cur !== '' && $cur !== []) {
            return $cur;
        }
    }
    return $default;
}

/** Collapse string|array|object into a flat list of strings. */
function vl_flat_list($value, array $keys = ['value', 'description', 'name', 'url', 'id']): array
{
    $out = [];
    $walk = function ($v) use (&$walk, &$out, $keys) {
        if (is_string($v) || is_int($v) || is_float($v)) {
            $s = trim((string)$v);
            if ($s !== '') {
                $out[] = $s;
            }
            return;
        }
        if (!is_array($v)) {
            return;
        }
        foreach ($keys as $k) {
            if (isset($v[$k]) && (is_string($v[$k]) || is_int($v[$k]))) {
                $s = trim((string)$v[$k]);
                if ($s !== '') {
                    $out[] = $s;
                }
                return;
            }
        }
        foreach ($v as $item) {
            $walk($item);
        }
    };
    $walk($value);
    return array_values(array_unique($out));
}

/** Recursively locate the first CVSS base score in a record tree. */
function vl_find_cvss($node, int $depth = 0): array
{
    if ($depth > 8 || !is_array($node)) {
        return [0.0, ''];
    }
    if (isset($node['baseScore']) && is_numeric($node['baseScore']) && (float)$node['baseScore'] > 0) {
        return [
            (float)$node['baseScore'],
            (string)($node['vectorString'] ?? $node['vector'] ?? ''),
        ];
    }
    foreach ($node as $value) {
        if (is_array($value)) {
            [$score, $vector] = vl_find_cvss($value, $depth + 1);
            if ($score > 0) {
                return [$score, $vector];
            }
        }
    }
    return [0.0, ''];
}

/** Extract the best CVSS score from any of the supported record shapes. */
function vl_cvss(array $rec): array
{
    $direct = vl_pick($rec, ['cvss', 'cvss_score', 'cvssV3', 'metrics.cvssV31.data.score']);
    if (is_numeric($direct)) {
        return [(float)$direct, (string)vl_pick($rec, ['cvss-vector', 'vector', 'metrics.cvssV31.data.vector'], '')];
    }

    // CVE 5.0 (containers.cna.metrics), CVE 4.0 (impact) and legacy shapes.
    foreach (['metrics', 'cvss_list', 'impact', 'containers'] as $field) {
        if (empty($rec[$field]) || !is_array($rec[$field])) {
            continue;
        }
        [$score, $vector] = vl_find_cvss($rec[$field]);
        if ($score > 0) {
            return [$score, $vector];
        }
    }
    return [0.0, ''];
}

/** Normalise one Vulnerability-Lookup record into the scanner's schema. */
function vl_normalize(array $rec, string $fallback_id = ''): array
{
    $id = (string)vl_pick($rec, ['id', 'cve_id', 'cveMetadata.cveId', 'vulnId'], $fallback_id);
    [$cvss, $vector] = vl_cvss($rec);

    $summary = (string)vl_pick($rec, [
        'summary', 'details', 'description', 'containers.cna.descriptions.0.value',
    ], 'No description available.');

    $cwe = [];
    foreach (['cwe', 'cwes', 'containers.cna.problemTypes', 'weaknesses'] as $path) {
        $val = vl_pick($rec, [$path]);
        if ($val) {
            foreach (vl_flat_list($val) as $entry) {
                if (preg_match('/CWE-\d+/i', $entry, $m)) {
                    $cwe[] = strtoupper($m[0]);
                }
            }
        }
    }
    $cwe = array_values(array_unique($cwe));

    $refs = [];
    $rawRefs = vl_pick($rec, ['references', 'containers.cna.references'], []);
    if (is_array($rawRefs)) {
        foreach ($rawRefs as $r) {
            if (is_string($r)) {
                $refs[] = $r;
            } elseif (is_array($r) && !empty($r['url'])) {
                $refs[] = (string)$r['url'];
            }
        }
    }
    $refs = array_slice(array_values(array_unique($refs)), 0, 12);

    $sources = [];
    $rawSources = $rec['sources'] ?? [];
    if (is_array($rawSources)) {
        foreach ($rawSources as $s) {
            if (is_string($s)) {
                $sources[] = $s;
            } elseif (is_array($s)) {
                $sources[] = (string)($s['name'] ?? $s['id'] ?? '');
            }
        }
    }
    $sources = array_values(array_unique(array_filter($sources)));

    $cpes = [];
    foreach (['cpe', 'cpes', 'vulnerable_configuration', 'containers.cna.affected'] as $path) {
        $val = vl_pick($rec, [$path]);
        if ($val) {
            $cpes = array_slice(array_values(array_unique(vl_flat_list($val, ['criteria', 'cpeName', 'cpe']))), 0, 25);
            break;
        }
    }

    $aliases = vl_flat_list($rec['aliases'] ?? [], ['alias', 'id', 'value']);

    return [
        'id'          => strtoupper($id),
        'title'       => (string)vl_pick($rec, ['title', 'containers.cna.title'], ''),
        'summary'     => trim(preg_replace('/\s+/', ' ', $summary)),
        'cvss'        => $cvss,
        'vector'      => $vector,
        'severity'    => classify_severity($cvss),
        'cwe'         => $cwe,
        'cwe_list'    => $cwe,
        'capec'       => vl_flat_list($rec['capec'] ?? [], ['id', 'capecId', 'value']),
        'cpes'        => $cpes,
        'references'  => $refs,
        'sources'     => $sources,
        'aliases'     => $aliases,
        'published'   => substr((string)vl_pick($rec, ['published', 'Published', 'cveMetadata.datePublished', 'created_at'], ''), 0, 10),
        'modified'    => substr((string)vl_pick($rec, ['modified', 'updated', 'cveMetadata.dateUpdated'], ''), 0, 10),
        'exploited'   => !empty($rec['exploited']) || !empty($rec['is_exploited']),
    ];
}

/** Full CVE record: VulnLookup + EPSS + KEV + local CWE description. */
function vl_lookup_cve(string $cve_id): ?array
{
    $cve_id = strtoupper(trim($cve_id));
    if (!preg_match('/^(CVE|GHSA|GCVE)-[A-Z0-9-]+$/i', $cve_id)) {
        return null;
    }

    $raw = vl_get('vulnerability/' . rawurlencode($cve_id), 43200);
    $record = is_array($raw) ? vl_normalize($raw, $cve_id) : [
        'id'         => $cve_id,
        'title'      => '',
        'summary'    => 'No local or upstream record available.',
        'cvss'       => 0.0,
        'vector'     => '',
        'severity'   => 'Unknown',
        'cwe'        => [],
        'cwe_list'   => [],
        'capec'      => [],
        'cpes'       => [],
        'references' => [],
        'sources'    => [],
        'aliases'    => [],
        'published'  => '',
        'modified'   => '',
        'exploited'  => false,
    ];

    // EPSS (FIRST.org) — authoritative exploit-likelihood signal.
    $epss = query_epss([$cve_id])[$cve_id] ?? null;
    if ($epss) {
        $record['epss_score'] = $epss['score'];
        $record['epss_percentile'] = $epss['percentile'];
    }

    // CISA KEV — confirmed in-the-wild exploitation.
    $kev = query_kev();
    if (isset($kev[$cve_id])) {
        $record['is_kev'] = true;
        $record['kev_date_added'] = $kev[$cve_id]['dateAdded'] ?? '';
        $record['kev_ransomware'] = $kev[$cve_id]['ransomwareUse'] ?? 'Unknown';
    } else {
        $record['is_kev'] = $record['exploited'];
    }

    if (!empty($record['cwe'])) {
        $record['cwe_details'] = array_map('vl_cwe_info', array_slice($record['cwe'], 0, 5));
    }
    $record['risk_notes'] = vl_risk_notes($record);
    return $record;
}

/** Vendor/product CVE search (Vulnerability-Lookup backend). */
function vl_vendor_product(string $vendor, string $product, int $limit = 20): array
{
    $vendor = preg_replace('/[^a-zA-Z0-9._-]/', '', trim($vendor));
    $product = preg_replace('/[^a-zA-Z0-9._-]/', '', trim($product));
    if ($vendor === '' || $product === '') {
        return [];
    }

    $data = vl_get(
        'vulnerability/search/' . rawurlencode($vendor) . '/' . rawurlencode($product) . '?per_page=' . max(1, min(50, $limit)),
        21600
    );
    if (!is_array($data)) {
        return [];
    }
    $items = $data['results'] ?? (isset($data[0]) ? $data : []);
    if (!is_array($items)) {
        return [];
    }

    $out = [];
    foreach (array_slice($items, 0, $limit) as $item) {
        if (!is_array($item)) {
            continue;
        }
        $rec = vl_normalize($item);
        if ($rec['id'] !== '') {
            $out[$rec['id']] = [
                'id'       => $rec['id'],
                'summary'  => $rec['summary'],
                'cvss'     => $rec['cvss'],
                'severity' => $rec['severity'],
                'cwe'      => implode(', ', $rec['cwe']),
                'published'=> $rec['published'],
                'source'   => 'Vulnerability-Lookup',
            ];
        }
    }
    return array_values($out);
}

/** Latest vulnerabilities (feeds the dashboard intel ticker). */
function vl_latest(int $limit = 10): array
{
    $data = vl_get('vulnerability/last/' . max(1, min(30, $limit)), 900);
    if (!is_array($data)) {
        return [];
    }
    $items = $data['results'] ?? (isset($data[0]) ? $data : []);
    $out = [];
    foreach (array_slice($items, 0, $limit) as $item) {
        if (is_array($item)) {
            $rec = vl_normalize($item);
            if ($rec['id'] !== '') {
                $out[] = $rec;
            }
        }
    }
    return $out;
}

/** Recent advisories filtered by VL feeder source (nvd, github, pysec, cvelistv5, csaf_cisa…). */
function vl_recent_by_source(string $source = '', int $limit = 20, string $since = ''): array
{
    $limit = max(1, min(50, $limit));
    $source = preg_replace('/[^a-z0-9_-]/i', '', $source);
    if ($source !== '') {
        $path = 'vulnerability/last/' . $limit . '/' . $source . '';
    } else {
        $path = 'vulnerability/last/' . $limit;
    }
    $data = vl_get($path, 900);
    if (!is_array($data)) {
        return [];
    }
    $items = $data['results'] ?? (isset($data[0]) ? $data : []);
    $out = [];
    foreach (array_slice($items, 0, $limit) as $item) {
        if (!is_array($item)) continue;
        $rec = vl_normalize($item);
        if ($rec['id'] === '') continue;
        if ($since !== '' && ($rec['published'] ?? '') < $since) continue;
        // Feeder provenance for the feed UI.
        $rec['feeder'] = $source !== '' ? $source : 'recent';
        $out[] = $rec;
    }
    return $out;
}

/** VEX (Vulnerability Exploitability eXchange) statements attached to an advisory. */
function vl_vex_statements(string $vuln_id): array
{
    if (!preg_match('/^(CVE|GHSA|GCVE)-[A-Z0-9-]+$/i', $vuln_id)) {
        return [];
    }
    $data = vl_get('vex/' . rawurlencode(strtoupper($vuln_id)), 21600);
    if (!is_array($data)) {
        return [];
    }
    $out = [];
    foreach ((is_array($data) ? $data : []) as $i => $vex) {
        if (!is_array($vex)) continue;
        $out[] = [
            'source'    => (string)($vex['source'] ?? $i),
            'status'    => (string)($vex['status'] ?? ''),
            'product'   => (string)($vex['product'] ?? ''),
            'statement' => (string)($vex['statement'] ?? ($vex['detail'] ?? '')),
            'justification' => (string)($vex['justification'] ?? ''),
            'url'       => (string)($vex['vulnerability_url'] ?? ''),
        ];
        if (count($out) >= 8) break;
    }
    return $out;
}

/** Vendor browse (VL parity for the browse page). */
function vl_vendors(string $q = ''): array
{
    $path = 'browse/vendors' . ($q !== '' ? '?q=' . rawurlencode($q) : '');
    $data = vl_get($path, 21600);
    if (!is_array($data)) return [];
    $out = [];
    foreach ($data as $v) {
        if (is_string($v)) {
            $out[] = $v;
        } elseif (is_array($v) && !empty($v['name'])) {
            $out[] = (string)$v['name'];
        }
    }
    return array_slice($out, 0, 200);
}

/** Public stats for the dashboard (most-sighted advisories this week). */
function vl_top_sightings(int $limit = 10): array
{
    $data = vl_get('stats/vulnerability/most_sighted/?output=json', 3600);
    if (!is_array($data)) return [];
    $list = $data['data'] ?? (isset($data[0]) ? $data : []);
    $out = [];
    foreach (array_slice(is_array($list) ? $list : [], 0, $limit) as $row) {
        if (!is_array($row)) continue;
        $id = (string)($row['vulnerability_id'] ?? ($row['vulnerability'] ?? ($row['id'] ?? '')));
        $cnt = (int)($row['sightings'] ?? ($row['count'] ?? 0));
        if (preg_match('/^CVE-\d{4}-\d+$/i', $id)) {
            $out[] = ['id' => strtoupper($id), 'sightings' => $cnt];
        }
    }
    return $out;
}

/** Local CWE knowledge base for the weakness classes this scanner detects. */
function vl_cwe_catalog(): array
{
    static $cat = null;
    if ($cat !== null) {
        return $cat;
    }
    $cat = [
        'CWE-16'   => ['Configuration', 'Weaknesses that stem from software or system configuration.'],
        'CWE-22'   => ['Path Traversal', 'The product uses externally supplied paths to access files outside restricted directories.'],
        'CWE-77'   => ['Command Injection', 'Untrusted input is used to build an OS command.'],
        'CWE-78'   => ['OS Command Injection', 'The product constructs OS commands from externally influenced input.'],
        'CWE-79'   => ['Cross-site Scripting (XSS)', 'Neutralisation of user-controllable input is missing before it is placed in a web page.'],
        'CWE-89'   => ['SQL Injection', 'The product constructs SQL queries from externally influenced input without neutralisation.'],
        'CWE-94'   => ['Code Injection', 'The product constructs code segments from externally influenced input.'],
        'CWE-98'   => ['PHP File Inclusion', 'PHP include/require statements are influenced by user input.'],
        'CWE-200'  => ['Information Exposure', 'The product exposes sensitive information to an unauthorised actor.'],
        'CWE-209'  => ['Error Message Information Leak', 'An error message contains sensitive debugging information.'],
        'CWE-284'  => ['Improper Access Control', 'Access control is not enforced as intended.'],
        'CWE-287'  => ['Improper Authentication', 'The product does not correctly verify identities.'],
        'CWE-319'  => ['Cleartext Transmission of Sensitive Information', 'Sensitive data is transmitted without encryption.'],
        'CWE-352'  => ['Cross-Site Request Forgery (CSRF)', 'The application cannot verify that a request was intentionally sent by the user.'],
        'CWE-353'  => ['Missing Support for Integrity Check', 'The integrity of a resource cannot be validated.'],
        'CWE-548'  => ['Exposure of Directory Listing', 'A directory index exposes file names and metadata.'],
        'CWE-601'  => ['Open Redirect', 'A URL parameter allows redirects to attacker-controlled destinations.'],
        'CWE-614'  => ['Sensitive Cookie Without Secure Attribute', 'A cookie is transmitted over cleartext channels.'],
        'CWE-639'  => ['Authorization Bypass Through User-Controlled Key (IDOR)', 'The product uses an externally controlled key to access records.'],
        'CWE-693'  => ['Protection Mechanism Failure', 'A required protection mechanism is missing or weak.'],
        'CWE-798'  => ['Use of Hard-coded Credentials', 'Credentials are embedded in the product.'],
        'CWE-942'  => ['Permissive Cross-domain Policy', 'A cross-domain policy allows untrusted domains to interact with the product.'],
        'CWE-1004' => ['Sensitive Cookie Without HttpOnly Flag', 'Scripts can read a sensitive cookie.'],
        'CWE-1021' => ['Improper Restriction of Rendered UI Layers (Clickjacking)', 'The web UI can be embedded by untrusted origins.'],
        'CWE-1104' => ['Use of Unmaintained Third-party Components', 'A dependency is outdated or no longer supported.'],
        'CWE-1275' => ['Sensitive Cookie with Insecure SameSite Attribute', 'A cookie without a restrictive SameSite value enables cross-site sending.'],
    ];
    return $cat;
}

function vl_cwe_info(string $cwe_id): array
{
    $id = strtoupper(trim($cwe_id));
    if (strpos($id, 'CWE-') !== 0) {
        $id = 'CWE-' . $id;
    }
    $cat = vl_cwe_catalog();
    $local = $cat[$id] ?? null;
    return [
        'id'          => $id,
        'name'        => $local[0] ?? $id,
        'description' => $local[1] ?? 'See the MITRE CWE definition for details.',
        'url'         => 'https://cwe.mitre.org/data/definitions/' . (int)substr($id, 4) . '.html',
    ];
}

/** Human-readable risk notes used by the UI and reports. */
function vl_risk_notes(array $rec): array
{
    $notes = [];
    if (!empty($rec['is_kev'])) {
        $notes[] = 'Listed in CISA KEV — known to be exploited in the wild' .
            (!empty($rec['kev_date_added']) ? ' since ' . $rec['kev_date_added'] : '') . '.';
    }
    if (isset($rec['epss_score']) && (float)$rec['epss_score'] >= 0.1) {
        $notes[] = 'EPSS exploit probability is ' . round((float)$rec['epss_score'] * 100, 2) . '%.';
    }
    if (($rec['severity'] ?? '') === 'Critical') {
        $notes[] = 'Critical CVSS score — prioritise immediate patching or isolation.';
    }
    if (empty($rec['cpes'] ?? [])) {
        $notes[] = 'No CPE configuration mapping was returned; confirm affected versions manually.';
    }
    return $notes;
}

/**
 * Enrich scanner findings with Vulnerability-Lookup / EPSS / KEV metadata.
 * Capped so a large CVE result set never turns into hundreds of API calls.
 */
function vl_enrich_findings(array &$findings, int $max_remote = 8): void
{
    $budget = $max_remote;
    foreach ($findings as &$f) {
        $id = strtoupper((string)($f['id'] ?? ''));
        if (!preg_match('/^CVE-\d{4}-\d+$/', $id)) {
            continue;
        }
        if ($budget > 0) {
            $budget--;
            $detail = vl_lookup_cve($id);
            if ($detail) {
                if (empty($f['cwe']) && !empty($detail['cwe'])) {
                    $f['cwe'] = implode(', ', $detail['cwe']);
                }
                if (($f['cvss'] ?? 0) == 0 && $detail['cvss'] > 0) {
                    $f['cvss'] = $detail['cvss'];
                    $f['severity'] = $detail['severity'];
                }
                if (!empty($detail['references'])) {
                    $f['references'] = $detail['references'];
                }
                if (!empty($detail['cpes'])) {
                    $f['cpes'] = $detail['cpes'];
                }
                $f['vl_sources'] = $detail['sources'];
                if (!empty($detail['risk_notes'])) {
                    $f['risk_notes'] = $detail['risk_notes'];
                }
                $f['is_kev'] = !empty($detail['is_kev']);
                if (isset($detail['epss_score'])) {
                    $f['epss_score'] = $detail['epss_score'];
                    $f['epss_percentile'] = $detail['epss_percentile'];
                }
            }
        }
        if (!isset($f['epss_score'])) {
            $epss = query_epss([$id]);
            if (isset($epss[$id])) {
                $f['epss_score'] = $epss[$id]['score'];
                $f['epss_percentile'] = $epss[$id]['percentile'];
            }
        }
    }
    unset($f);
}

/** Status block for the dashboard's intel-source widget. */
function vl_status(): array
{
    return [
        'vulnerability_lookup' => 'configured (public CIRCL API)',
        'epss'                 => 'configured (FIRST.org)',
        'cisa_kev'             => 'configured (CISA feed, 24h cache)',
    ];
}
