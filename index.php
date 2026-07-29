<?php
declare(strict_types=1);

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

/**
 * VulnScope Pro — Enterprise Intelligence Engine v5.0
 * Multi-source CVE correlation: NVD v2, Shodan, Censys v2, CIRCL CVE Search
 */

defined('DB_PATH')            or define('DB_PATH', 'vulnscope_v2.sqlite');
defined('SCAN_TOKEN')         or define('SCAN_TOKEN', 'SECURE_SCAN_TOKEN_2024');
defined('ALLOW_INTERNAL_SCAN') or define('ALLOW_INTERNAL_SCAN', true);

// API keys — loaded from environment variables (set in Render dashboard or .env)
defined('NVD_API_KEY')      or define('NVD_API_KEY',      getenv('NVD_API_KEY')      ?: '');
defined('SHODAN_API_KEY')   or define('SHODAN_API_KEY',   getenv('SHODAN_API_KEY')   ?: '');
defined('CENSYS_API_TOKEN') or define('CENSYS_API_TOKEN', getenv('CENSYS_API_TOKEN') ?: '');
defined('OPENCVE_USER')     or define('OPENCVE_USER',     getenv('OPENCVE_USER')     ?: '');
defined('OPENCVE_PASS')     or define('OPENCVE_PASS',     getenv('OPENCVE_PASS')     ?: '');

define('CIRCL_API_BASE',  'https://cve.circl.lu/api/');
define('NVD_API_BASE',    'https://services.nvd.nist.gov/rest/json/cves/2.0');
define('OPENCVE_API_BASE','https://app.opencve.io/api/v2/');

error_reporting(E_ALL);
ini_set('display_errors', 0);
set_time_limit(300);

/* =========================================================
   DATABASE
   ========================================================= */
$db = null;
if (extension_loaded('pdo_sqlite')) {
    try {
        $db = new PDO('sqlite:' . DB_PATH);
        $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $db->exec("CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT, ip_address TEXT, risk_score INTEGER,
            nmap_output TEXT, intelligence_data TEXT,
            vulnerabilities TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )");
        // 30-minute scan result cache to make repeat scans instant
        $db->exec("CREATE TABLE IF NOT EXISTS scan_cache (
            ip_key TEXT PRIMARY KEY,
            response_json TEXT,
            cached_at INTEGER
        )");
    } catch (Exception $e) {
        error_log('DB init: ' . $e->getMessage());
    }
}


/* =========================================================
   HTTP HELPERS — Sequential & Parallel
   ========================================================= */
function safe_curl($url, $headers = [], $post_data = null, $timeout = 12) {
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => $timeout,
        CURLOPT_CONNECTTIMEOUT => 5,
        CURLOPT_USERAGENT      => 'VulnScope-Pro/5.0 (Security Research)',
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_HTTPHEADER     => array_merge(['Accept: application/json'], $headers),
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS      => 2,
    ]);
    if ($post_data !== null) {
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $post_data);
    }
    $response = curl_exec($ch);
    $code     = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err      = curl_error($ch);
    curl_close($ch);
    if ($err || $code >= 400 || !$response) {
        error_log("safe_curl [$code] $url — $err");
        return null;
    }
    return json_decode($response, true);
}

/**
 * Execute multiple HTTP requests in PARALLEL using curl_multi.
 * @param array $requests  Array of ['url'=>..., 'headers'=>[], 'userpwd'=>null, 'timeout'=>12]
 * @return array           Decoded JSON results in same order; null on failure.
 */
function safe_curl_multi(array $requests): array {
    $mh      = curl_multi_init();
    $handles = [];

    foreach ($requests as $i => $req) {
        $ch = curl_init($req['url']);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => $req['timeout'] ?? 12,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_USERAGENT      => 'VulnScope-Pro/5.0 (Security Research)',
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS      => 2,
            CURLOPT_HTTPHEADER     => array_merge(['Accept: application/json'], $req['headers'] ?? []),
        ]);
        if (!empty($req['userpwd'])) {
            curl_setopt($ch, CURLOPT_USERPWD, $req['userpwd']);
            curl_setopt($ch, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
        }
        curl_multi_add_handle($mh, $ch);
        $handles[$i] = $ch;
    }

    // Execute all in parallel
    $running = null;
    do {
        $status = curl_multi_exec($mh, $running);
        if ($running) curl_multi_select($mh, 0.5);
    } while ($running && $status === CURLM_OK);

    $results = [];
    foreach ($handles as $i => $ch) {
        $body = curl_multi_getcontent($ch);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_multi_remove_handle($mh, $ch);
        curl_close($ch);
        $results[$i] = ($code < 400 && $body) ? json_decode($body, true) : null;
    }
    curl_multi_close($mh);
    return $results;
}

/* =========================================================
   UTILITY FUNCTIONS
   ========================================================= */
function get_api_status() {
    return [
        'nvd'     => NVD_API_KEY      ? 'configured' : 'missing',
        'shodan'  => SHODAN_API_KEY   ? 'configured' : 'missing',
        'censys'  => CENSYS_API_TOKEN ? 'configured' : 'missing',
        'opencve' => (OPENCVE_USER && OPENCVE_PASS) ? 'configured' : 'missing',
    ];
}

function classify_severity($cvss) {
    $v = (float)$cvss;
    if ($v >= 9.0) return 'Critical';
    if ($v >= 7.0) return 'High';
    if ($v >= 4.0) return 'Medium';
    if ($v >  0.0) return 'Low';
    return 'Info';
}

/**
 * Advanced risk scoring — produces realistic varied scores.
 *
 * Algorithm:
 * 1. Base weighted score from severity buckets
 * 2. Attack surface multiplier (open ports count)
 * 3. Criticality bonus for cascading criticals
 * 4. Diversity penalty (many different severity levels = harder to patch)
 * 5. Final normalisation to 0-100 range with realistic distribution
 */
function calculate_risk_score(array $findings, int $open_ports_count = 0): int {
    if (empty($findings)) return 0;

    // Step 1: Weighted severity base
    $weights = ['Critical' => 12, 'High' => 7, 'Medium' => 3, 'Low' => 1, 'Info' => 0, 'Unknown' => 2];
    $counts  = ['Critical' => 0, 'High' => 0, 'Medium' => 0, 'Low' => 0, 'Info' => 0, 'Unknown' => 0];
    $cvss_sum = 0;
    foreach ($findings as $f) {
        $sev = $f['severity'] ?? 'Info';
        $counts[$sev] = ($counts[$sev] ?? 0) + 1;
        $cvss_sum += (float)($f['cvss'] ?? 0);
    }

    $base = 0;
    foreach ($counts as $sev => $cnt) {
        $base += ($weights[$sev] ?? 0) * $cnt;
    }

    // Step 2: Average CVSS contribution (max +20 pts)
    $avg_cvss   = count($findings) > 0 ? $cvss_sum / count($findings) : 0;
    $cvss_bonus = min(20, round($avg_cvss * 2.2));

    // Step 3: Attack surface multiplier — more open ports = wider exposure
    // 0-5 ports: 1.0x, 6-10: 1.15x, 11-20: 1.25x, 21+: 1.35x
    if ($open_ports_count <= 5)       $surface = 1.0;
    elseif ($open_ports_count <= 10)  $surface = 1.15;
    elseif ($open_ports_count <= 20)  $surface = 1.25;
    else                              $surface = 1.35;

    // Step 4: Criticality cascade bonus — multiple criticals amplify each other
    $crit_bonus = 0;
    if ($counts['Critical'] >= 3)     $crit_bonus = 15;
    elseif ($counts['Critical'] >= 1) $crit_bonus = 8;
    elseif ($counts['High'] >= 5)     $crit_bonus = 5;

    // Step 5: Diversity bonus (mix of severities = complex attack surface)
    $sev_types = count(array_filter($counts));
    $diversity = $sev_types >= 4 ? 5 : ($sev_types >= 3 ? 3 : 0);

    // Step 6: CISA KEV bonus — findings with confirmed real-world exploitation
    // are a materially bigger risk than CVSS alone captures.
    $kev_count = 0;
    foreach ($findings as $f) {
        if (!empty($f['is_kev'])) $kev_count++;
    }
    $kev_bonus = min(25, $kev_count * 9);

    // Combine
    $raw = ($base + $cvss_bonus + $crit_bonus + $diversity + $kev_bonus) * $surface;

    // Step 7: Normalise to 0–100 with a logarithmic curve so:
    // — small vulns (~5 findings) score 20–40
    // — medium (~20-30 findings) score 50–70
    // — large (50+ findings) score 75–95
    // — truly catastrophic (100+ criticals) score 95-100
    // Raw scores typically land 10–400+; map to 0-100
    $normalised = round(100 * (1 - exp(-$raw / 120)));

    // Hard floor/ceiling
    return (int) max(1, min(100, $normalised));
}

/* =========================================================
   INTELLIGENCE SOURCE: FIRST.org EPSS (Exploit Prediction Scoring System)
   Free, keyless API. Batches up to 90 CVEs per request.
   ========================================================= */
function query_epss(array $cve_ids): array {
    $cve_ids = array_values(array_unique(array_filter($cve_ids)));
    if (empty($cve_ids)) return [];
    $out = [];
    foreach (array_chunk($cve_ids, 90) as $chunk) {
        $url  = 'https://api.first.org/data/v1/epss?cve=' . implode(',', array_map('urlencode', $chunk));
        $data = safe_curl($url, [], null, 10);
        if ($data && !empty($data['data']) && is_array($data['data'])) {
            foreach ($data['data'] as $row) {
                if (empty($row['cve'])) continue;
                $out[$row['cve']] = [
                    'score'      => (float)($row['epss'] ?? 0),
                    'percentile' => (float)($row['percentile'] ?? 0),
                ];
            }
        }
    }
    return $out;
}

/* =========================================================
   INTELLIGENCE SOURCE: CISA Known Exploited Vulnerabilities (KEV)
   Cached to disk for 24h since the catalog only updates a few
   times a week — keeps repeat scans fast and avoids rate limits.
   ========================================================= */
function query_kev(): array {
    static $mem_cache = null;
    if ($mem_cache !== null) return $mem_cache;

    $cache_file = sys_get_temp_dir() . '/vulnscope_kev_catalog.json';
    if (is_file($cache_file) && (time() - filemtime($cache_file)) < 86400) {
        $cached = json_decode((string)@file_get_contents($cache_file), true);
        if (is_array($cached)) { $mem_cache = $cached; return $mem_cache; }
    }

    $data = safe_curl('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', [], null, 10);
    $set  = [];
    if ($data && !empty($data['vulnerabilities']) && is_array($data['vulnerabilities'])) {
        foreach ($data['vulnerabilities'] as $v) {
            if (empty($v['cveID'])) continue;
            $set[$v['cveID']] = [
                'dateAdded'     => $v['dateAdded'] ?? '',
                'ransomwareUse' => $v['knownRansomwareCampaignUse'] ?? 'Unknown',
            ];
        }
        @file_put_contents($cache_file, json_encode($set));
    } elseif (is_file($cache_file)) {
        // Live fetch failed (network/rate-limit) — fall back to stale cache rather than nothing.
        $cached = json_decode((string)@file_get_contents($cache_file), true);
        if (is_array($cached)) $set = $cached;
    }

    $mem_cache = $set;
    return $mem_cache;
}

/**
 * Cross-references every CVE finding against EPSS exploit-likelihood
 * scores and the CISA KEV catalog, mutating $findings in place.
 * This is the correlation layer that turns raw CVE hits into
 * triage-ready intelligence.
 */
function enrich_findings_intel(array &$findings): void {
    $cve_ids = [];
    foreach ($findings as $f) {
        if (!empty($f['id']) && preg_match('/^CVE-\d{4}-\d+$/', $f['id'])) {
            $cve_ids[] = $f['id'];
        }
    }
    if (empty($cve_ids)) return;

    $epss = query_epss($cve_ids);
    $kev  = query_kev();

    foreach ($findings as &$f) {
        $id = $f['id'] ?? '';
        if (isset($epss[$id])) {
            $f['epss_score']      = $epss[$id]['score'];
            $f['epss_percentile'] = $epss[$id]['percentile'];
        }
        if (isset($kev[$id])) {
            $f['is_kev']         = true;
            $f['kev_date_added'] = $kev[$id]['dateAdded'];
            $f['kev_ransomware'] = $kev[$id]['ransomwareUse'];
            // A KEV-listed finding is being exploited right now — never let it read as Low/Info.
            if (($f['severity'] ?? '') !== 'Critical' && (float)($f['cvss'] ?? 0) < 9.0) {
                $f['severity'] = 'High';
            }
        } else {
            $f['is_kev'] = false;
        }
    }
    unset($f);
}

function normalize_product(string $product): string {
    $product = str_replace(['_', '-', '/'], ' ', $product);
    // Remove generic suffixes that pollute keyword searches
    $strip = ['httpd', 'server', 'service', 'daemon', 'proxy', 'd', 'nd'];
    $words = explode(' ', strtolower(trim($product)));
    $words = array_filter($words, fn($w) => strlen($w) > 1 && !in_array($w, $strip));
    return implode(' ', $words);
}

/* =========================================================
   INTELLIGENCE SOURCE: NVD v2
   ========================================================= */
function query_nvd(string $keyword, int $limit = 30): array {
    if (!NVD_API_KEY || strlen(trim($keyword)) < 2) return [];

    $headers = ['apiKey: ' . NVD_API_KEY];
    $results = [];
    $seen    = [];

    // Single keyword search (removed duplicate exactMatch call — saves 50% NVD time)
    $url1 = NVD_API_BASE . '?keywordSearch=' . urlencode($keyword) . '&resultsPerPage=' . $limit;
    $res1 = safe_curl($url1, $headers, null, 12);

    foreach ([$res1] as $res) {
        if (!isset($res['vulnerabilities'])) continue;
        foreach ($res['vulnerabilities'] as $v) {
            $cve = $v['cve'];
            $id  = $cve['id'] ?? '';
            if (!$id || isset($seen[$id])) continue;
            $seen[$id] = true;

            // Extract best available CVSS score (prefer v3.1 > v3.0 > v2)
            $score = 0;
            $vector = '';
            if (!empty($cve['metrics']['cvssMetricV31'])) {
                $m = $cve['metrics']['cvssMetricV31'][0];
                $score  = $m['cvssData']['baseScore'] ?? 0;
                $vector = $m['cvssData']['vectorString'] ?? '';
            } elseif (!empty($cve['metrics']['cvssMetricV30'])) {
                $m = $cve['metrics']['cvssMetricV30'][0];
                $score  = $m['cvssData']['baseScore'] ?? 0;
                $vector = $m['cvssData']['vectorString'] ?? '';
            } elseif (!empty($cve['metrics']['cvssMetricV2'])) {
                $m = $cve['metrics']['cvssMetricV2'][0];
                $score  = $m['cvssData']['baseScore'] ?? 0;
                $vector = $m['cvssData']['vectorString'] ?? '';
            }

            // Description — prefer English
            $desc = 'No description available.';
            foreach (($cve['descriptions'] ?? []) as $d) {
                if ($d['lang'] === 'en') { $desc = $d['value']; break; }
            }

            // Published date
            $published = substr($cve['published'] ?? '', 0, 10);

            // CWE
            $cwe = '';
            foreach (($cve['weaknesses'] ?? []) as $w) {
                $cwe = $w['description'][0]['value'] ?? '';
                if ($cwe) break;
            }

            $results[] = [
                'id'       => $id,
                'cvss'     => (float)$score,
                'severity' => classify_severity($score),
                'summary'  => $desc,
                'source'   => 'NVD',
                'vector'   => $vector,
                'cwe'      => $cwe,
                'published'=> $published,
            ];
        }
    }
    return $results;
}

/* =========================================================
   INTELLIGENCE SOURCE: CIRCL CVE Search
   ========================================================= */
function query_circl(string $keyword, int $limit = 20): array {
    $keyword = trim($keyword);
    if (strlen($keyword) < 2) return [];

    // CIRCL search endpoint
    $url = CIRCL_API_BASE . 'search/' . urlencode($keyword);
    $res = safe_curl($url, [], null, 15);

    $results = [];
    $seen    = [];

    if (!is_array($res)) return [];

    // CIRCL can return array directly or nested
    $items = isset($res[0]) ? $res : ($res['results'] ?? []);

    foreach (array_slice($items, 0, $limit) as $cve) {
        $id = $cve['id'] ?? ($cve['cve_id'] ?? '');
        if (!$id || isset($seen[$id])) continue;
        $seen[$id] = true;

        $score = (float)($cve['cvss'] ?? $cve['cvss_score'] ?? 0);
        $results[] = [
            'id'        => $id,
            'cvss'      => $score,
            'severity'  => classify_severity($score),
            'summary'   => $cve['summary'] ?? $cve['description'] ?? 'No summary.',
            'source'    => 'CIRCL',
            'vector'    => $cve['cvss-vector'] ?? '',
            'cwe'       => $cve['cwe'] ?? '',
            'published' => substr($cve['Published'] ?? $cve['published'] ?? '', 0, 10),
        ];
    }
    return $results;
}


function query_opencve(string $keyword, int $limit = 30): array {
    if (!OPENCVE_USER || !OPENCVE_PASS) return [];
    $keyword = trim($keyword);
    if (strlen($keyword) < 2) return [];

    // OpenCVE CVE search endpoint
    $url = OPENCVE_API_BASE . 'cves?search=' . urlencode($keyword) . '&limit=' . $limit;
    $ch  = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 20,
        CURLOPT_CONNECTTIMEOUT => 8,
        CURLOPT_USERAGENT      => 'VulnScope-Pro/5.0 (Security Research)',
        CURLOPT_USERPWD        => OPENCVE_USER . ':' . OPENCVE_PASS,
        CURLOPT_HTTPAUTH       => CURLAUTH_BASIC,
        CURLOPT_HTTPHEADER     => ['Accept: application/json'],
        CURLOPT_SSL_VERIFYPEER => true,
    ]);
    $response = curl_exec($ch);
    $code     = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($code >= 400 || !$response) return [];
    $data = json_decode($response, true);

    $results = [];
    $seen    = [];
    $items = $data['results'] ?? $data;
    if (!is_array($items)) return [];

    foreach (array_slice($items, 0, $limit) as $item) {
        $id = $item['cve_id'] ?? $item['id'] ?? '';
        if (!$id || isset($seen[$id])) continue;
        $seen[$id] = true;

        
        $score  = 0;
        $vector = '';
        $metrics = $item['metrics'] ?? [];
        foreach (['cvssV31', 'cvssV30', 'cvssV2'] as $mk) {
            if (!empty($metrics[$mk]['data']['score'])) {
                $score  = (float)$metrics[$mk]['data']['score'];
                $vector = $metrics[$mk]['data']['vector'] ?? '';
                break;
            }
        }
        if ($score === 0 && isset($item['cvss'])) {
            $score = (float)$item['cvss'];
        }

        $desc = '';
        if (!empty($item['description'])) {
            if (is_string($item['description'])) {
                $desc = $item['description'];
            } elseif (is_array($item['description'])) {
                foreach ($item['description'] as $d) {
                    if (($d['lang'] ?? '') === 'en') { $desc = $d['value']; break; }
                }
                if (!$desc && isset($item['description'][0])) {
                    $desc = $item['description'][0]['value'] ?? '';
                }
            }
        }
        if (!$desc) $desc = 'No description available.';

        $results[] = [
            'id'        => $id,
            'cvss'      => $score,
            'severity'  => classify_severity($score),
            'summary'   => $desc,
            'source'    => 'OpenCVE',
            'vector'    => $vector,
            'cwe'       => $item['cwe'] ?? '',
            'published' => substr($item['created_at'] ?? $item['published'] ?? '', 0, 10),
        ];
    }
    return $results;
}


function enrich_cve_from_circl(string $cve_id): array {
    $url = CIRCL_API_BASE . 'cve/' . urlencode($cve_id);
    $res = safe_curl($url, [], null, 10);
    if (!$res || !isset($res['id'])) return [];

    $score = (float)($res['cvss'] ?? $res['cvss_score'] ?? 0);
    return [
        'id'        => $res['id'],
        'cvss'      => $score,
        'severity'  => classify_severity($score),
        'summary'   => $res['summary'] ?? $res['description'] ?? 'No summary.',
        'source'    => 'Shodan/CIRCL',
        'vector'    => $res['cvss-vector'] ?? '',
        'cwe'       => $res['cwe'] ?? '',
        'published' => substr($res['Published'] ?? '', 0, 10),
    ];
}


function query_shodan(string $ip): array {
    $empty = ['vulns' => [], 'ports' => [], 'intel' => null];
    if (!SHODAN_API_KEY) return $empty;

    $url = 'https://api.shodan.io/shodan/host/' . urlencode($ip) . '?key=' . SHODAN_API_KEY;
    $res = safe_curl($url, [], null, 20);

    if (!$res || isset($res['error'])) return $empty;

    $vulns = [];
    foreach (array_keys($res['vulns'] ?? []) as $cve_id) {
        $shodan_cvss = $res['vulns'][$cve_id]['cvss'] ?? 0;

        if ($shodan_cvss > 0) {
            $vulns[] = [
                'id'       => $cve_id,
                'cvss'     => (float)$shodan_cvss,
                'severity' => classify_severity($shodan_cvss),
                'summary'  => $res['vulns'][$cve_id]['summary'] ?? 'Observed by Shodan internet scanners.',
                'source'   => 'Shodan',
                'vector'   => '',
                'cwe'      => '',
                'published'=> '',
            ];
        } else {
            $enriched = enrich_cve_from_circl($cve_id);
            if ($enriched) {
                $vulns[] = $enriched;
            } else {
                $vulns[] = [
                    'id'       => $cve_id,
                    'cvss'     => 0,
                    'severity' => 'Unknown',
                    'summary'  => 'Observed by Shodan. CVSS data pending enrichment.',
                    'source'   => 'Shodan',
                    'vector'   => '',
                    'cwe'      => '',
                    'published'=> '',
                ];
            }
        }
    }

    $shodan_ports = array_map('strval', $res['ports'] ?? []);

    return [
        'vulns'  => $vulns,
        'ports'  => $shodan_ports,
        'intel'  => [
            'org'          => $res['org']      ?? null,
            'isp'          => $res['isp']      ?? null,
            'country'      => $res['country']  ?? null,
            'asn'          => $res['asn']      ?? null,
            'hostnames'    => $res['hostnames'] ?? [],
            'tags'         => $res['tags']     ?? [],
            'last_update'  => $res['last_update'] ?? null,
        ],
    ];
}


function query_censys(string $ip): array {
    if (!CENSYS_API_TOKEN) return ['error' => 'not_configured'];

    $url     = 'https://search.censys.io/api/v2/hosts/' . urlencode($ip);
    $headers = [
        'Authorization: Bearer ' . CENSYS_API_TOKEN,
        'Content-Type: application/json',
    ];
    $res = safe_curl($url, $headers, null, 20);

    if (!$res || isset($res['error'])) {
        return ['error' => 'api_failure'];
    }
    return $res;
}


function extract_censys_services(array $censys): array {
    $services = [];
    $result   = $censys['result'] ?? [];
    foreach (($result['services'] ?? []) as $svc) {
        $port    = (string)($svc['port'] ?? '');
        $name    = strtolower($svc['service_name'] ?? $svc['transport_protocol'] ?? '');
        $product = $svc['software'][0]['product'] ?? $svc['banner'] ?? '';
        $version = $svc['software'][0]['version'] ?? '';
        if ($port) {
            $services[] = [
                'port'    => $port,
                'service' => $name,
                'product' => is_string($product) ? substr($product, 0, 60) : '',
                'version' => is_string($version) ? substr($version, 0, 40) : '',
            ];
        }
    }
    return $services;
}


function php_socket_scan(string $host, string $ip): string {
    $port_map = [
        21   => ['ftp',          'vsftpd'],
        22   => ['ssh',          'OpenSSH'],
        23   => ['telnet',       'Linux telnetd'],
        25   => ['smtp',         'Postfix smtpd'],
        53   => ['domain',       'ISC BIND'],
        80   => ['http',         'Apache httpd'],
        110  => ['pop3',         'Dovecot pop3d'],
        111  => ['rpcbind',      'rpcbind'],
        135  => ['msrpc',        'Microsoft RPC'],
        139  => ['netbios-ssn',  'Samba smbd'],
        143  => ['imap',         'Dovecot imapd'],
        443  => ['https',        'Apache httpd'],
        445  => ['microsoft-ds', 'Samba smbd'],
        465  => ['smtps',        'Postfix smtpd'],
        587  => ['submission',   'Postfix smtpd'],
        993  => ['imaps',        'Dovecot imapd'],
        995  => ['pop3s',        'Dovecot pop3d'],
        1433 => ['ms-sql-s',    'Microsoft SQL Server'],
        1521 => ['oracle',       'Oracle TNS listener'],
        2375 => ['docker',       'Docker API (unauthenticated)'],
        3000 => ['http',         'Node.js Express'],
        3306 => ['mysql',        'MySQL'],
        3389 => ['ms-wbt-server','Microsoft RDP'],
        5432 => ['postgresql',   'PostgreSQL'],
        5900 => ['vnc',          'RealVNC'],
        5985 => ['wsman',        'Windows WinRM'],
        6379 => ['redis',        'Redis'],
        8080 => ['http-proxy',   'Apache Tomcat'],
        8443 => ['https-alt',    'Apache Tomcat'],
        8888 => ['http',         'Jupyter Notebook'],
        9000 => ['http',         'PHP-FPM'],
        9200 => ['http',         'Elasticsearch'],
        27017=> ['mongodb',      'MongoDB'],
    ];

    $sockets = [];
    foreach ($port_map as $port => $info) {
        $ctx = stream_context_create(['socket' => ['so_reuseaddr' => true]]);
        $sock = @stream_socket_client(
            "tcp://{$ip}:{$port}",
            $errno, $errstr, 1.2,
            STREAM_CLIENT_ASYNC_CONNECT | STREAM_CLIENT_CONNECT,
            $ctx
        );
        if ($sock !== false) {
            stream_set_blocking($sock, false);
            $sockets[$port] = $sock;
        }
    }

    
    $open_ports = [];
    if (!empty($sockets)) {
        $read  = null;
        $write = array_values($sockets);
        $excpt = null;
        $ready = @stream_select($read, $write, $excpt, 1, 500000);
        if ($ready) {
            
            $port_by_sock = array_flip(array_map('intval', array_keys($sockets)));
            foreach ($write as $ws) {
                foreach ($sockets as $port => $sock) {
                    if ($sock === $ws) { $open_ports[$port] = true; break; }
                }
            }
        }
    }

    $banner_ports = [21, 22, 25, 110, 143, 3306];
    $xml_ports = '';
    foreach ($port_map as $port => [$svcname, $product]) {
        if (!isset($open_ports[$port])) {
            if (isset($sockets[$port])) fclose($sockets[$port]);
            continue;
        }
        $sock    = $sockets[$port];
        $version = '';
        if (in_array($port, $banner_ports) && $sock) {
            stream_set_blocking($sock, true);
            stream_set_timeout($sock, 1);
            $banner = @fgets($sock, 256);
            if ($banner) {
                $version = htmlspecialchars(
                    substr(trim(preg_replace('/[^\x20-\x7E]/', '', $banner)), 0, 80),
                    ENT_XML1
                );
            }
        }
        if ($sock) fclose($sock);

        $p_safe  = htmlspecialchars($product, ENT_XML1);
        $xml_ports .= "<port protocol=\"tcp\" portid=\"{$port}\">"
            . "<state state=\"open\" reason=\"syn-ack\"/>"
            . "<service name=\"{$svcname}\" product=\"{$p_safe}\" version=\"{$version}\" method=\"probed\"/>"
            . "</port>\n";
    }

    return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        . "<nmaprun scanner=\"php-socket-fallback\" args=\"php_socket_scan\" version=\"5.0\" xmloutputversion=\"1.04\">\n"
        . "<host><status state=\"up\" reason=\"user-set\"/>"
        . "<address addr=\"{$ip}\" addrtype=\"ipv4\"/>"
        . "<ports>{$xml_ports}</ports></host>\n"
        . "</nmaprun>";
}



function port_to_products(int $port): array {
    $map = [
        21    => ['ftp',              'vsftpd',                     ['vsftpd', 'ProFTPD', 'FileZilla Server']],
        22    => ['ssh',              'OpenSSH',                    ['OpenSSH', 'Dropbear SSH']],
        23    => ['telnet',           'telnet',                     ['telnet', 'telnetd']],
        25    => ['smtp',             'Postfix',                    ['Postfix', 'Sendmail', 'Exim']],
        53    => ['dns',              'BIND',                       ['ISC BIND', 'dnsmasq', 'PowerDNS']],
        80    => ['http',             'Apache httpd',               ['Apache', 'Nginx', 'IIS', 'Lighttpd']],
        110   => ['pop3',             'Dovecot',                    ['Dovecot', 'Courier', 'qmail']],
        111   => ['rpcbind',          'rpcbind',                    ['rpcbind', 'portmap']],
        135   => ['msrpc',            'Microsoft RPC',              ['Microsoft RPC', 'DCOM']],
        139   => ['netbios',          'Samba',                      ['Samba', 'Windows SMB']],
        143   => ['imap',             'Dovecot',                    ['Dovecot IMAP', 'Cyrus IMAP']],
        443   => ['https',            'OpenSSL',                    ['Apache', 'Nginx', 'OpenSSL', 'IIS']],
        445   => ['smb',              'Samba',                      ['Samba', 'Microsoft SMB', 'EternalBlue']],
        465   => ['smtps',            'Postfix',                    ['Postfix', 'Exim SMTP']],
        514   => ['syslog',           'rsyslog',                    ['rsyslog', 'syslog']],
        587   => ['smtp',             'Postfix',                    ['Postfix submission', 'Exim']],
        631   => ['ipp',              'CUPS',                       ['CUPS', 'IPP printer']],
        993   => ['imaps',            'Dovecot',                    ['Dovecot IMAP', 'OpenSSL']],
        995   => ['pop3s',            'Dovecot',                    ['Dovecot POP3', 'OpenSSL']],
        1433  => ['mssql',            'Microsoft SQL Server',       ['Microsoft SQL Server', 'MSSQL']],
        1521  => ['oracle',           'Oracle Database',            ['Oracle TNS', 'Oracle Database']],
        2049  => ['nfs',              'NFS',                        ['NFS', 'rpc.nfsd']],
        2375  => ['docker',           'Docker API',                 ['Docker', 'containerd']],
        2376  => ['docker-tls',       'Docker API TLS',             ['Docker TLS', 'Docker daemon']],
        3000  => ['http',             'Node.js',                    ['Node.js', 'Express.js', 'Grafana']],
        3306  => ['mysql',            'MySQL',                      ['MySQL', 'MariaDB', 'Percona']],
        3389  => ['rdp',              'Microsoft RDP',              ['Microsoft RDP', 'Windows Remote Desktop']],
        4848  => ['glassfish',        'GlassFish',                  ['GlassFish', 'Payara']],
        5432  => ['postgresql',       'PostgreSQL',                 ['PostgreSQL', 'pg_hba']],
        5601  => ['kibana',           'Kibana',                     ['Kibana', 'Elasticsearch']],
        5900  => ['vnc',              'RealVNC',                    ['VNC', 'LibVNCServer', 'TigerVNC']],
        5985  => ['winrm',            'WinRM',                      ['WinRM', 'Windows WinRM', 'PowerShell remoting']],
        6379  => ['redis',            'Redis',                      ['Redis', 'redis-server']],
        6443  => ['kubernetes',       'Kubernetes API',             ['Kubernetes', 'k8s apiserver']],
        7001  => ['weblogic',         'Oracle WebLogic',            ['WebLogic', 'Oracle WebLogic']],
        8008  => ['http',             'HTTP alternative',           ['Apache', 'Nginx']],
        8080  => ['http',             'Apache Tomcat',              ['Apache Tomcat', 'Jetty', 'JBoss']],
        8081  => ['http',             'HTTP service',               ['Nginx', 'Squid proxy']],
        8443  => ['https',            'Apache Tomcat TLS',          ['Apache Tomcat', 'JBoss', 'WildFly']],
        8888  => ['http',             'Jupyter Notebook',           ['Jupyter', 'Python HTTP']],
        9000  => ['http',             'PHP-FPM',                    ['PHP-FPM', 'SonarQube', 'Portainer']],
        9090  => ['http',             'Prometheus',                 ['Prometheus', 'Cockpit']],
        9200  => ['elasticsearch',    'Elasticsearch',              ['Elasticsearch', 'OpenSearch']],
        9300  => ['elasticsearch',    'Elasticsearch cluster',      ['Elasticsearch']],
        10250 => ['kubelet',          'Kubernetes Kubelet',         ['Kubernetes kubelet']],
        11211 => ['memcached',        'Memcached',                  ['Memcached']],
        15672 => ['rabbitmq',         'RabbitMQ Management',        ['RabbitMQ', 'AMQP']],
        27017 => ['mongodb',          'MongoDB',                    ['MongoDB', 'mongodbserver']],
        27018 => ['mongodb',          'MongoDB shard',              ['MongoDB']],
        50070 => ['hadoop',           'Hadoop HDFS',                ['Hadoop', 'HDFS']],
    ];
    return $map[$port] ?? ['unknown', 'unknown', []];
}

function run_nmap(string $target): string {
    $bin = trim((string)shell_exec('which nmap 2>/dev/null || where nmap 2>NUL'));
    $bin = trim(explode("\n", $bin)[0]);

    if (!empty($bin) && @file_exists($bin)) {
        $safe = escapeshellarg($target);
        $out = shell_exec("{$bin} -sV --version-intensity 5 -T4 --max-retries 1 --host-timeout 15m -oX - {$safe} 2>&1");
        if ($out && strpos($out, '<nmaprun') !== false) return $out;

        $out2 = shell_exec("{$bin} -sV --version-intensity 3 -T4 -oX - {$safe} 2>&1");
        if ($out2 && strpos($out2, '<nmaprun') !== false) return $out2;
    }

    $ip = filter_var($target, FILTER_VALIDATE_IP)
        ? $target
        : @gethostbyname($target);

    if ($ip === $target && !filter_var($target, FILTER_VALIDATE_IP)) {
        throw new Exception("DNS resolution failed for: {$target}");
    }
    return php_socket_scan($target, $ip);
}


function validate_target(string $target): array|false {
    $target = trim($target);
    if (empty($target)) return false;

    $host = preg_replace('#^https?://#', '', $target);
    $host = explode('/', $host)[0];
    
    $port_specified = null;
    if (strpos($host, ':') !== false) {
        $parts = explode(':', $host);
        $host  = $parts[0];
        $port_specified = (int)$parts[1];
    }

    if (!preg_match('/^[a-zA-Z0-9.\-]+$/', $host)) return false;

    $ip = gethostbyname($host);
    if (!filter_var($ip, FILTER_VALIDATE_IP)) return false;

    if (!ALLOW_INTERNAL_SCAN) {
        $private = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8'];
        foreach ($private as $range) {
            [$subnet, $mask] = explode('/', $range);
            if ((ip2long($ip) & ~((1 << (32 - $mask)) - 1)) === ip2long($subnet)) return false;
        }
    }
    return ['host' => $host, 'ip' => $ip];
}


if (isset($_GET['action'])) {
    header('Content-Type: application/json');
    header('X-Content-Type-Options: nosniff');

    $token = $_SERVER['HTTP_X_VULNSCOPE_TOKEN'] ?? '';
    if ($token !== SCAN_TOKEN) {
        http_response_code(401);
        echo json_encode(['success' => false, 'message' => 'Unauthorized.']);
        exit;
    }

    if ($_GET['action'] === 'scan') {
        try {
            $target_raw = trim($_POST['target'] ?? '');
            $validation = validate_target($target_raw);
            if (!$validation) throw new Exception('Invalid or unreachable target. Check the hostname/IP.');

            $host = $validation['host'];
            $ip   = $validation['ip'];

            $cache_ttl = 1800;
            if ($db) {
                try {
                    $cs = $db->prepare('SELECT response_json, cached_at FROM scan_cache WHERE ip_key = ?');
                    $cs->execute([$ip]);
                    $crow = $cs->fetch(PDO::FETCH_ASSOC);
                    if ($crow && (time() - (int)$crow['cached_at'] < $cache_ttl)) {
                        $cached = json_decode($crow['response_json'], true);
                        if ($cached) {
                            $cached['cached'] = true;
                            $cached['cached_at'] = date('Y-m-d H:i:s', (int)$crow['cached_at']);
                            echo json_encode($cached, JSON_UNESCAPED_UNICODE);
                            exit;
                        }
                    }
                } catch (Exception $e) { /* cache miss — proceed with full scan */ }
            }

            $nmap_xml   = run_nmap($host);
            $xml        = @simplexml_load_string($nmap_xml);
            $findings   = [];
            $open_ports = [];
            $nse_findings = [];

            $add_finding = function(array $hit, string $port_id, string $service_label) use (&$findings) {
                $hit['affected_service'] = $hit['affected_service'] ?? $service_label;
                $hit['port']             = $hit['port'] ?? $port_id;
                $id = $hit['id'];
                if (!isset($findings[$id])) {
                    $findings[$id] = $hit;
                } else {
                    $src = $hit['source'] ?? '';
                    if ($src && !str_contains($findings[$id]['source'] ?? '', $src)) {
                        $findings[$id]['source'] .= ' / ' . $src;
                    }
                    if (($findings[$id]['cvss'] ?? 0) == 0 && ($hit['cvss'] ?? 0) > 0) {
                        $findings[$id]['cvss']     = $hit['cvss'];
                        $findings[$id]['severity'] = $hit['severity'];
                    }
                }
            };

            $all_kw_map = [];
            if ($xml && isset($xml->host->ports->port)) {
                foreach ($xml->host->ports->port as $p) {
                    $state = (string)($p->state['state'] ?? '');
                    if ($state !== 'open' && $state !== 'open|filtered') continue;

                    $svc      = $p->service;
                    $svc_name = (string)($svc['name']    ?? '');
                    $product  = (string)($svc['product'] ?? '');
                    $version  = (string)($svc['version'] ?? '');
                    $port_id  = (string)($p['portid']    ?? '');
                    $port_int = (int)$port_id;

                    $inferred_products = [];
                    if (empty($product) || in_array(strtolower($svc_name), ['tcpwrapped', 'unknown', ''])) {
                        [$inf_svc, $inf_prod, $inf_keywords] = port_to_products($port_int);
                        if ($inf_prod !== 'unknown') {
                            if (empty($product)) $product  = $inf_prod;
                            if (empty($svc_name)) $svc_name = $inf_svc;
                            $inferred_products = $inf_keywords;
                        }
                    }

                    $open_ports[] = [
                        'port'    => $port_id,
                        'service' => $svc_name ?: 'unknown',
                        'product' => $product,
                        'version' => $version,
                    ];

                    $keywords = [];
                    if ($product && !in_array(strtolower($product), ['tcpwrapped', 'unknown'])) {
                        $norm = normalize_product($product);
                        if ($norm) {
                            $keywords[] = $norm;
                            if ($version) $keywords[] = $norm . ' ' . $version;
                        }
                    }
                    foreach ($inferred_products as $kw) {
                        $normalized = normalize_product($kw);
                        if ($normalized) $keywords[] = $normalized;
                    }
                    if ($svc_name && !in_array(strtolower($svc_name), ['tcpwrapped','unknown','http','https','ssl'])) {
                        $keywords[] = $svc_name;
                    }

                    $keywords = array_unique(array_filter($keywords));
                    $service_label = trim("$product $version") ?: "Port $port_id";

                    $was_inferred = !empty($inferred_products);
                    if ($was_inferred) {
                        $keywords = array_slice($keywords, 0, 1);
                    } else {
                        $keywords = array_slice($keywords, 0, 3);
                    }

                    foreach ($keywords as $kw) {
                        if (strlen(trim($kw)) >= 2) {
                            $all_kw_map[$kw][] = ['port_id' => $port_id, 'service_label' => $service_label];
                        }
                    }
                    foreach ($p->script as $script) {
                        $script_id  = strtolower((string)($script['id'] ?? ''));
                        $script_out = trim((string)($script['output'] ?? ''));

                        if (preg_match_all('/CVE-\d{4}-\d+/i', $script_out, $cve_matches)) {
                            foreach ($cve_matches[0] as $cve_id) {
                                $cve_id = strtoupper($cve_id);
                                if (isset($findings[$cve_id])) continue;
                                $enriched = enrich_cve_from_circl($cve_id);
                                if (!$enriched) {
                                    $enriched = [
                                        'id'        => $cve_id,
                                        'cvss'      => 7.0,
                                        'severity'  => 'High',
                                        'summary'   => 'Detected by Nmap NSE vuln script: ' . $script_id,
                                        'source'    => 'Nmap NSE',
                                        'vector'    => '',
                                        'cwe'       => '',
                                        'published' => '',
                                    ];
                                } else {
                                    $enriched['source'] = 'Nmap NSE / CIRCL';
                                }
                                $add_finding($enriched, $port_id, $service_label);
                            }
                        }

                        $known_critical = [
                            'smb-vuln-ms17-010'  => ['MS17-010 (EternalBlue)', 9.8],
                            'smb-vuln-ms08-067'  => ['MS08-067 Netapi RCE',   10.0],
                            'ssl-heartbleed'     => ['CVE-2014-0160 Heartbleed', 7.5],
                            'ssl-drown'          => ['CVE-2016-0800 DROWN',   5.9],
                            'ssl-poodle'         => ['CVE-2014-3566 POODLE',  3.4],
                            'smb-vuln-conficker'  => ['MS08-067 Conficker',   10.0],
                            'http-shellshock'    => ['CVE-2014-6271 Shellshock', 9.8],
                            'ftp-anon'           => ['Anonymous FTP Access',   5.0],
                        ];
                        if (isset($known_critical[$script_id]) && str_contains(strtolower($script_out), 'vulnerable')) {
                            [$vuln_name, $cvss_score] = $known_critical[$script_id];
                            $fake_id = 'NSE-' . strtoupper(str_replace(['-', '_'], '', $script_id));
                            if (!isset($findings[$fake_id])) {
                                $findings[$fake_id] = [
                                    'id'              => $fake_id,
                                    'cvss'            => $cvss_score,
                                    'severity'        => classify_severity($cvss_score),
                                    'summary'         => $vuln_name . ' — ' . substr($script_out, 0, 200),
                                    'source'          => 'Nmap NSE',
                                    'vector'          => '',
                                    'cwe'             => '',
                                    'published'       => '',
                                    'affected_service'=> $service_label,
                                    'port'            => $port_id,
                                ];
                            }
                        }
                    }
                }
            }

            if (!empty($all_kw_map)) {
                $unique_kws = array_keys($all_kw_map);
                $requests   = [];
                $req_meta   = [];

                foreach ($unique_kws as $kw) {
                    $kw_enc = urlencode($kw);
                    if (NVD_API_KEY) {
                        $req_meta[] = ['source' => 'nvd', 'kw' => $kw];
                        $requests[] = [
                            'url'     => NVD_API_BASE . '?keywordSearch=' . $kw_enc . '&resultsPerPage=25',
                            'headers' => ['apiKey: ' . NVD_API_KEY],
                            'timeout' => 12,
                        ];
                    }
                    $req_meta[] = ['source' => 'circl', 'kw' => $kw];
                    $requests[] = [
                        'url'     => CIRCL_API_BASE . 'search/' . $kw_enc,
                        'headers' => [],
                        'timeout' => 10,
                    ];
                    // OpenCVE request
                    if (OPENCVE_USER && OPENCVE_PASS) {
                        $req_meta[] = ['source' => 'opencve', 'kw' => $kw];
                        $requests[] = [
                            'url'     => OPENCVE_API_BASE . 'cves?search=' . $kw_enc . '&limit=20',
                            'headers' => ['Accept: application/json'],
                            'userpwd' => OPENCVE_USER . ':' . OPENCVE_PASS,
                            'timeout' => 12,
                        ];
                    }
                }

                $responses = safe_curl_multi($requests);

                foreach ($responses as $i => $data) {
                    if (!$data || !is_array($data)) continue;
                    $meta = $req_meta[$i];
                    $kw   = $meta['kw'];
                    $src  = $meta['source'];

                    $hits = [];
                    if ($src === 'nvd') {
                        foreach ($data['vulnerabilities'] ?? [] as $v) {
                            $cve   = $v['cve'] ?? [];
                            $id    = $cve['id'] ?? '';
                            if (!$id) continue;
                            $score = 0; $vector = '';
                            foreach (['cvssMetricV31','cvssMetricV30','cvssMetricV2'] as $mk) {
                                if (!empty($cve['metrics'][$mk])) {
                                    $m = $cve['metrics'][$mk][0];
                                    $score  = $m['cvssData']['baseScore'] ?? 0;
                                    $vector = $m['cvssData']['vectorString'] ?? '';
                                    break;
                                }
                            }
                            $desc = 'No description.';
                            foreach ($cve['descriptions'] ?? [] as $d) {
                                if ($d['lang'] === 'en') { $desc = $d['value']; break; }
                            }
                            $cwe = '';
                            foreach ($cve['weaknesses'] ?? [] as $w) {
                                $cwe = $w['description'][0]['value'] ?? ''; if ($cwe) break;
                            }
                            $hits[] = [
                                'id' => $id, 'cvss' => (float)$score,
                                'severity' => classify_severity($score), 'summary' => $desc,
                                'source' => 'NVD', 'vector' => $vector, 'cwe' => $cwe,
                                'published' => substr($cve['published'] ?? '', 0, 10),
                            ];
                        }
                    } elseif ($src === 'circl') {
                        $items = isset($data[0]) ? $data : ($data['results'] ?? []);
                        foreach (array_slice($items, 0, 15) as $cve) {
                            $id = $cve['id'] ?? ($cve['cve_id'] ?? '');
                            if (!$id) continue;
                            $score = (float)($cve['cvss'] ?? $cve['cvss_score'] ?? 0);
                            $hits[] = [
                                'id' => $id, 'cvss' => $score,
                                'severity' => classify_severity($score),
                                'summary' => $cve['summary'] ?? $cve['description'] ?? 'No summary.',
                                'source' => 'CIRCL', 'vector' => $cve['cvss-vector'] ?? '',
                                'cwe' => $cve['cwe'] ?? '',
                                'published' => substr($cve['Published'] ?? $cve['published'] ?? '', 0, 10),
                            ];
                        }
                    } elseif ($src === 'opencve') {
                        $items = $data['results'] ?? $data;
                        if (!is_array($items)) continue;
                        foreach (array_slice($items, 0, 20) as $item) {
                            $id = $item['cve_id'] ?? $item['id'] ?? '';
                            if (!$id) continue;
                            $score = 0; $vector = '';
                            foreach (['cvssV31','cvssV30','cvssV2'] as $mk) {
                                if (!empty($item['metrics'][$mk]['data']['score'])) {
                                    $score  = (float)$item['metrics'][$mk]['data']['score'];
                                    $vector = $item['metrics'][$mk]['data']['vector'] ?? '';
                                    break;
                                }
                            }
                            if (!$score && isset($item['cvss'])) $score = (float)$item['cvss'];
                            $desc = '';
                            if (!empty($item['description'])) {
                                if (is_string($item['description'])) $desc = $item['description'];
                                elseif (is_array($item['description'])) {
                                    foreach ($item['description'] as $d) {
                                        if (($d['lang']??'') === 'en') { $desc = $d['value']; break; }
                                    }
                                    if (!$desc) $desc = $item['description'][0]['value'] ?? '';
                                }
                            }
                            $hits[] = [
                                'id' => $id, 'cvss' => $score,
                                'severity' => classify_severity($score),
                                'summary' => $desc ?: 'No description.',
                                'source' => 'OpenCVE', 'vector' => $vector,
                                'cwe' => $item['cwe'] ?? '',
                                'published' => substr($item['created_at'] ?? $item['published'] ?? '', 0, 10),
                            ];
                        }
                    }

                    foreach ($hits as $hit) {
                        foreach ($all_kw_map[$kw] as $ctx) {
                            $add_finding($hit, $ctx['port_id'], $ctx['service_label']);
                        }
                    }
                }
            }

            $shodan_data = query_shodan($ip);
            foreach ($shodan_data['vulns'] as $hit) {
                if (!isset($findings[$hit['id']])) {
                    $hit['port']            = $hit['port'] ?? 'External';
                    $hit['affected_service']= $hit['affected_service'] ?? 'Internet-facing exposure (Shodan)';
                    $findings[$hit['id']]   = $hit;
                } else {
                    if (!str_contains($findings[$hit['id']]['source'], 'Shodan'))
                        $findings[$hit['id']]['source'] .= ' / Shodan';
                    if ($findings[$hit['id']]['cvss'] == 0 && $hit['cvss'] > 0) {
                        $findings[$hit['id']]['cvss']     = $hit['cvss'];
                        $findings[$hit['id']]['severity'] = $hit['severity'];
                    }
                }
            }

            // Merge Shodan-observed ports (those our scanner missed)
            $existing_ports = array_column($open_ports, 'port');
            foreach ($shodan_data['ports'] as $sp) {
                if (!in_array($sp, $existing_ports)) {
                    $open_ports[] = [
                        'port'    => $sp,
                        'service' => 'unknown',
                        'product' => 'Observed by Shodan',
                        'version' => '',
                    ];
                }
            }

            $censys_data = query_censys($ip);
            if ($censys_data && !isset($censys_data['error'])) {
                foreach (extract_censys_services($censys_data) as $csvc) {
                    $port_id = $csvc['port'];
                    $product = $csvc['product'];
                    $version = $csvc['version'];

                    $found = false;
                    foreach ($open_ports as &$op) {
                        if ($op['port'] === $port_id) {
                            if (empty($op['product']) && $product) $op['product'] = $product;
                            if (empty($op['version']) && $version) $op['version'] = $version;
                            $found = true; break;
                        }
                    }
                    unset($op);
                    if (!$found && $port_id) {
                        $open_ports[] = ['port' => $port_id, 'service' => $csvc['service'], 'product' => $product, 'version' => $version];
                    }

                    // Query CVEs for Censys-detected products
                    if ($product) {
                        $norm = normalize_product($product);
                        foreach (query_nvd($norm . ' ' . $version, 20) as $hit) {
                            $hit['affected_service'] = "$product $version";
                            $hit['port']             = $port_id;
                            if (!isset($findings[$hit['id']])) $findings[$hit['id']] = $hit;
                        }
                        foreach (query_circl($norm, 10) as $hit) {
                            $hit['affected_service'] = "$product $version";
                            $hit['port']             = $port_id;
                            if (!isset($findings[$hit['id']])) $findings[$hit['id']] = $hit;
                        }
                    }
                }
            }

            $findings = array_values($findings);
            enrich_findings_intel($findings);

            usort($findings, function ($a, $b) {
                $order = ['Critical' => 5, 'High' => 4, 'Medium' => 3, 'Low' => 2, 'Info' => 1, 'Unknown' => 0];
                $sa = $order[$a['severity']] ?? 0;
                $sb = $order[$b['severity']] ?? 0;
                if ($sa !== $sb) return $sb - $sa;
                return $b['cvss'] <=> $a['cvss'];
            });
            $dist = ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0, 'info' => 0];
            foreach ($findings as $f) {
                $l = strtolower($f['severity'] ?? 'info');
                if (!isset($dist[$l])) $l = 'info';
                $dist[$l]++;
            }

            $risk_score = calculate_risk_score($findings, count($open_ports));

            $response = [
                'success'              => true,
                'findings'             => $findings,
                'api_status'           => get_api_status(),
                'summary'              => [
                    'target'           => $host,
                    'ip'               => $ip,
                    'risk_score'       => $risk_score,
                    'open_ports_count' => count($open_ports),
                    'total_findings'   => count($findings),
                    'shodan_intel'     => $shodan_data['intel'] ?? null,
                ],
                'severity_distribution'=> $dist,
                'debug_info'           => [
                    'ports'            => $open_ports,
                    'censys'           => isset($censys_data['error']) ? null : $censys_data,
                    'scan_engine'      => str_contains($nmap_xml, 'php-socket-fallback') ? 'PHP Socket' : 'Nmap',
                ],
            ];

            /* ---- 7. Persist to DB & cache ---- */
            if ($db) {
                try {
                    $stmt = $db->prepare(
                        'INSERT INTO scans (target, ip_address, risk_score, nmap_output, intelligence_data, vulnerabilities)
                         VALUES (?, ?, ?, ?, ?, ?)'
                    );
                    $stmt->execute([
                        $host, $ip, $risk_score,
                        substr($nmap_xml, 0, 65535),
                        json_encode($response['debug_info']),
                        json_encode($findings),
                    ]);
                    // Write to scan cache (REPLACE = upsert)
                    $cstmt = $db->prepare(
                        'INSERT OR REPLACE INTO scan_cache (ip_key, response_json, cached_at) VALUES (?, ?, ?)'
                    );
                    $cstmt->execute([$ip, json_encode($response, JSON_UNESCAPED_UNICODE), time()]);
                } catch (Exception $e) {
                    error_log('DB insert: ' . $e->getMessage());
                }
            }

            echo json_encode($response, JSON_UNESCAPED_UNICODE);


        } catch (Exception $e) {
            http_response_code(500);
            echo json_encode(['success' => false, 'message' => $e->getMessage()]);
        }
        exit;
    }
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VulnScope Pro &mdash; Enterprise Vulnerability Intelligence</title>
<meta name="description" content="Enterprise vulnerability intelligence platform. Multi-source CVE correlation: NVD, Shodan, Censys, CIRCL.">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
:root{
  --bg-root:#020408;--bg-card:rgba(10,18,30,0.92);
  --accent:#06b6d4;--accent2:#3b82f6;
  --accent-glow:rgba(6,182,212,0.12);--accent-border:rgba(6,182,212,0.22);
  --danger:#ef4444;--danger-dim:rgba(239,68,68,0.08);--danger-border:rgba(239,68,68,0.28);
  --warn:#f97316;--warn-dim:rgba(249,115,22,0.08);
  --med:#eab308;--med-dim:rgba(234,179,8,0.08);
  --low:#22d3ee;--low-dim:rgba(34,211,238,0.06);
  --info:#64748b;--info-dim:rgba(100,116,139,0.06);
  --t1:#e2e8f0;--t2:#94a3b8;--t3:#475569;--t4:#1e293b;
  --border:rgba(30,41,59,0.8);--border2:rgba(51,65,85,0.9);
  --r8:8px;--r12:12px;--r16:16px;--r24:24px;
  --sidebar:260px;--topbar:60px;
  --ease:all 0.22s cubic-bezier(.4,0,.2,1);
  --font:"Inter",system-ui,sans-serif;
  --mono:"JetBrains Mono","Courier New",monospace;
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{background:var(--bg-root);color:var(--t1);font-family:var(--font);overflow-x:hidden;min-height:100vh}
::-webkit-scrollbar{width:4px;height:4px}::-webkit-scrollbar-track{background:transparent}::-webkit-scrollbar-thumb{background:#1e293b;border-radius:99px}
#bgc{position:fixed;inset:0;z-index:0;pointer-events:none;opacity:.3}
#shell{position:relative;z-index:1;display:flex;min-height:100vh}
#sb{width:var(--sidebar);flex-shrink:0;background:rgba(4,8,18,0.97);border-right:1px solid var(--border);display:flex;flex-direction:column;position:fixed;top:0;left:0;height:100vh;z-index:200;backdrop-filter:blur(20px);transition:transform .3s ease;overflow:hidden}
.sb-logo{padding:20px 16px 18px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:10px}
.sb-logo-ico{width:36px;height:36px;border-radius:8px;background:linear-gradient(135deg,var(--accent),var(--accent2));display:flex;align-items:center;justify-content:center;font-size:16px;color:#fff;flex-shrink:0;box-shadow:0 0 14px rgba(6,182,212,.35)}
.sb-logo-txt h2{font-size:13px;font-weight:800;letter-spacing:.04em;text-transform:uppercase}
.sb-logo-txt h2 span{color:var(--accent)}
.sb-logo-txt p{font-size:9px;color:var(--t3);font-family:var(--mono);letter-spacing:.1em;margin-top:1px}
.sb-nav{flex:1;padding:12px 10px;overflow-y:auto}
.nav-lbl{font-size:9px;font-weight:700;color:var(--t4);letter-spacing:.15em;text-transform:uppercase;padding:10px 8px 5px}
.nav-a{display:flex;align-items:center;gap:10px;padding:9px 12px;border-radius:var(--r8);color:var(--t2);font-size:13px;font-weight:500;cursor:pointer;transition:var(--ease);border:1px solid transparent;margin-bottom:2px;text-decoration:none}
.nav-a:hover,.nav-a.active{background:var(--accent-glow);border-color:var(--accent-border);color:var(--accent)}
.nav-a i{width:15px;text-align:center;font-size:12px}
.sb-apis{padding:14px;border-top:1px solid var(--border)}
.sb-api-lbl{font-size:9px;font-weight:700;color:var(--t4);letter-spacing:.14em;text-transform:uppercase;margin-bottom:8px}
.sb-api-row{display:flex;align-items:center;justify-content:space-between;padding:5px 0;border-bottom:1px solid rgba(30,41,59,.4)}
.sb-api-row:last-child{border:none}
.sb-api-name{font-family:var(--mono);font-size:10px;color:var(--t2);text-transform:uppercase;display:flex;align-items:center;gap:6px}
.dot{width:6px;height:6px;border-radius:50%;flex-shrink:0}
.dot-on{background:#22c55e;box-shadow:0 0 5px #22c55e;animation:dpulse 2s infinite}
.dot-off{background:#ef4444}
@keyframes dpulse{0%,100%{opacity:1}50%{opacity:.35}}
.api-badge{font-family:var(--mono);font-size:9px;font-weight:700;padding:2px 6px;border-radius:4px;text-transform:uppercase;letter-spacing:.04em}
.api-badge.on{background:rgba(34,197,94,.1);color:#22c55e;border:1px solid rgba(34,197,94,.2)}
.api-badge.off{background:rgba(239,68,68,.1);color:#ef4444;border:1px solid rgba(239,68,68,.2)}
.sb-footer{padding:10px 14px;border-top:1px solid var(--border);font-size:9px;color:var(--t4);text-align:center;font-family:var(--mono);line-height:1.6}
#main{margin-left:var(--sidebar);flex:1;display:flex;flex-direction:column;min-height:100vh}
#topbar{height:var(--topbar);border-bottom:1px solid var(--border);background:rgba(4,8,18,.85);backdrop-filter:blur(20px);display:flex;align-items:center;justify-content:space-between;padding:0 24px;position:sticky;top:0;z-index:100}
.tb-left{display:flex;align-items:center;gap:12px}
.tb-bread{display:flex;align-items:center;gap:6px;font-size:12px;color:var(--t3)}
.tb-bread .cr-active{color:var(--t1);font-weight:600}
.tb-bread i{font-size:8px}
.tb-right{display:flex;align-items:center;gap:10px}
.tb-pill{display:flex;align-items:center;gap:5px;font-size:10px;font-family:var(--mono);color:var(--t3);background:rgba(255,255,255,.03);border:1px solid var(--border);padding:4px 10px;border-radius:var(--r8)}
.ldot{width:5px;height:5px;border-radius:50%;background:#22c55e;animation:dpulse 2s infinite;display:inline-block}
#sbtoggle{display:none;background:none;border:1px solid var(--border);color:var(--t2);padding:7px 10px;border-radius:var(--r8);cursor:pointer;transition:var(--ease);font-size:13px}
#sbtoggle:hover{border-color:var(--accent-border);color:var(--accent)}
#pg{flex:1;padding:24px}
.scan-panel{background:var(--bg-card);border:1px solid var(--border2);border-radius:var(--r24);padding:28px 32px;margin-bottom:24px;position:relative;overflow:hidden;backdrop-filter:blur(16px)}
.scan-panel::before{content:"";position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,var(--accent),var(--accent2),transparent);opacity:.55}
.scan-ph{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;margin-bottom:22px;flex-wrap:wrap}
.scan-ph h1{font-size:18px;font-weight:800;letter-spacing:-.01em;margin-bottom:4px}
.scan-ph p{font-size:11px;color:var(--t3);font-family:var(--mono);letter-spacing:.04em}
.eng-badge{display:flex;align-items:center;gap:7px;background:rgba(6,182,212,.05);border:1px solid var(--accent-border);border-radius:var(--r12);padding:7px 13px;font-size:10px;font-family:var(--mono);color:var(--accent);text-transform:uppercase;letter-spacing:.07em;white-space:nowrap;flex-shrink:0}
.scan-row{display:flex;gap:10px;align-items:stretch}
.inp-wrap{position:relative;flex:1}
.inp-ico{position:absolute;left:15px;top:50%;transform:translateY(-50%);color:var(--t3);font-size:13px;pointer-events:none}
#target{width:100%;background:rgba(4,8,18,.9);border:1px solid var(--border2);border-radius:var(--r12);padding:14px 16px 14px 44px;font-family:var(--mono);font-size:13px;color:var(--t1);outline:none;transition:var(--ease);letter-spacing:.02em}
#target::placeholder{color:var(--t4)}
#target:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(6,182,212,.07)}
#btn{background:linear-gradient(135deg,var(--accent),var(--accent2));color:#fff;border:none;border-radius:var(--r12);padding:14px 26px;font-family:var(--font);font-size:13px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;cursor:pointer;transition:var(--ease);display:flex;align-items:center;gap:8px;white-space:nowrap;flex-shrink:0}
#btn:hover{transform:translateY(-1px);box-shadow:0 8px 24px rgba(6,182,212,.3)}
#btn:disabled{opacity:.4;cursor:not-allowed;transform:none;box-shadow:none}
#loader{display:none;margin-top:18px;padding:14px 18px;background:rgba(6,182,212,.04);border:1px solid var(--accent-border);border-radius:var(--r12);align-items:center;gap:14px}
#loader.show{display:flex}
.ld-spin{width:30px;height:30px;border:2px solid var(--accent-border);border-top-color:var(--accent);border-radius:50%;animation:spin .8s linear infinite;flex-shrink:0}
@keyframes spin{to{transform:rotate(360deg)}}
.ld-bar-wrap{flex:1}
.ld-txt{font-size:11px;font-family:var(--mono);color:var(--accent);letter-spacing:.03em;margin-bottom:7px}
.ld-track{height:2px;background:rgba(6,182,212,.1);border-radius:99px;overflow:hidden}
.ld-fill{height:100%;width:0;background:linear-gradient(90deg,var(--accent),var(--accent2));border-radius:99px;animation:ldsweep 2s ease-in-out infinite}
@keyframes ldsweep{0%{width:0;margin-left:0}50%{width:60%;margin-left:15%}100%{width:0;margin-left:100%}}
#results{display:none;animation:fadeup .35s ease}
#results.show{display:block}
@keyframes fadeup{from{opacity:0;transform:translateY(14px)}to{opacity:1;transform:translateY(0)}}
.res-hdr{display:flex;align-items:center;justify-content:space-between;margin-bottom:18px;flex-wrap:wrap;gap:10px}
.res-hdr-left{display:flex;align-items:center;gap:14px;flex-wrap:wrap}
.res-hdr-title{font-size:11px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:var(--t3);display:flex;align-items:center;gap:8px}
.res-hdr-title::before{content:"";width:3px;height:14px;background:linear-gradient(var(--accent),var(--accent2));border-radius:2px;flex-shrink:0;display:inline-block}
.exp-btn{display:flex;align-items:center;gap:6px;padding:7px 13px;background:transparent;border:1px solid var(--border2);border-radius:var(--r8);color:var(--t2);font-size:11px;font-weight:600;cursor:pointer;transition:var(--ease)}
.exp-btn:hover{border-color:var(--accent-border);color:var(--accent);background:var(--accent-glow)}
.risk-badge{display:inline-flex;align-items:center;gap:6px;font-family:var(--mono);font-size:10px;font-weight:700;padding:4px 10px;border-radius:6px;text-transform:uppercase;letter-spacing:.08em}
.risk-badge.r-critical{background:rgba(239,68,68,.12);color:var(--danger);border:1px solid var(--danger-border)}
.risk-badge.r-high{background:rgba(249,115,22,.1);color:var(--warn);border:1px solid rgba(249,115,22,.25)}
.risk-badge.r-medium{background:rgba(234,179,8,.1);color:var(--med);border:1px solid rgba(234,179,8,.25)}
.risk-badge.r-low{background:rgba(34,211,238,.08);color:var(--low);border:1px solid rgba(34,211,238,.2)}
.risk-badge.r-info{background:rgba(100,116,139,.08);color:var(--info);border:1px solid var(--border)}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:18px}
.sc{background:var(--bg-card);border:1px solid var(--border);border-radius:var(--r16);padding:18px 20px;backdrop-filter:blur(12px);position:relative;overflow:hidden;transition:var(--ease)}
.sc::after{content:"";position:absolute;bottom:0;left:0;right:0;height:2px;opacity:0;transition:var(--ease)}
.sc:hover{transform:translateY(-2px);border-color:var(--border2)}
.sc:hover::after{opacity:1}
.sc.risk::after{background:linear-gradient(90deg,var(--danger),var(--warn))}
.sc.finds::after{background:linear-gradient(90deg,var(--accent),var(--accent2))}
.sc.ports::after{background:linear-gradient(90deg,#a855f7,var(--accent2))}
.sc.ip::after{background:linear-gradient(90deg,var(--med),var(--warn))}
.sc-lbl{font-size:9px;font-weight:700;letter-spacing:.15em;text-transform:uppercase;color:var(--t4);margin-bottom:10px}
.sc-val{font-size:32px;font-weight:900;line-height:1;margin-bottom:8px;font-variant-numeric:tabular-nums}
.sc.risk .sc-val{color:var(--danger)}.sc.finds .sc-val{color:var(--accent)}.sc.ports .sc-val{color:#a855f7}
.sc.ip .sc-val{font-size:13px;padding-top:4px;color:var(--med);font-family:var(--mono)}
.sc-meta{font-size:10px;color:var(--t3);font-family:var(--mono)}
.sc-sub{font-size:9px;font-family:var(--mono);color:var(--t4);margin-top:4px}
.risk-trk{height:4px;background:rgba(255,255,255,.05);border-radius:99px;overflow:hidden;margin:8px 0 6px}
#riskBar{height:100%;background:linear-gradient(90deg,var(--med),var(--warn),var(--danger));border-radius:99px;width:0%;transition:width 1.4s cubic-bezier(.4,0,.2,1)}
.res-body{display:grid;grid-template-columns:300px 1fr;gap:16px;margin-bottom:16px}
.panel{background:var(--bg-card);border:1px solid var(--border);border-radius:var(--r16);backdrop-filter:blur(12px);overflow:hidden}
.panel-hdr{padding:14px 18px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px}
.panel-title{font-size:10px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:var(--t2);display:flex;align-items:center;gap:7px}
.panel-title i{color:var(--accent);font-size:11px}
.panel-body{padding:18px}
#severityBars{display:flex;flex-direction:column;gap:12px}
.sev-row .sev-hdr{display:flex;justify-content:space-between;align-items:center;margin-bottom:5px}
.sev-name{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.09em}
.sev-right{display:flex;align-items:center;gap:5px}
.sev-pct{font-size:10px;color:var(--t3);font-family:var(--mono)}
.sev-cnt{font-size:9px;font-weight:700;font-family:var(--mono);padding:1px 5px;border-radius:4px}
.sev-trk{height:5px;background:rgba(255,255,255,.04);border-radius:99px;overflow:hidden}
.progress-bar{height:100%;border-radius:99px;width:0;transition:width .9s cubic-bezier(.4,0,.2,1)}
.sev-Critical .sev-name{color:var(--danger)}.sev-Critical .sev-cnt{background:var(--danger-dim);color:var(--danger)}.bar-Critical{background:linear-gradient(90deg,#dc2626,var(--danger))}
.sev-High .sev-name{color:var(--warn)}.sev-High .sev-cnt{background:var(--warn-dim);color:var(--warn)}.bar-High{background:linear-gradient(90deg,#ea580c,var(--warn))}
.sev-Medium .sev-name{color:var(--med)}.sev-Medium .sev-cnt{background:var(--med-dim);color:var(--med)}.bar-Medium{background:linear-gradient(90deg,#ca8a04,var(--med))}
.sev-Low .sev-name{color:var(--low)}.sev-Low .sev-cnt{background:var(--low-dim);color:var(--low)}.bar-Low{background:linear-gradient(90deg,#0891b2,var(--low))}
.sev-Info .sev-name{color:var(--info)}.sev-Info .sev-cnt{background:var(--info-dim);color:var(--info)}.bar-Info{background:#475569}
#apiStatusDisplay{display:flex;flex-direction:column;gap:7px}
.vf-wrap{display:flex;gap:5px;flex-wrap:wrap}
.fb{font-size:9px;font-weight:700;font-family:var(--mono);letter-spacing:.07em;text-transform:uppercase;padding:3px 9px;border-radius:6px;border:1px solid var(--border2);background:transparent;color:var(--t3);cursor:pointer;transition:var(--ease)}
.fb:hover,.fb.active{background:var(--accent-glow);border-color:var(--accent-border);color:var(--accent)}
.fb.fc.active{background:var(--danger-dim);border-color:var(--danger-border);color:var(--danger)}
.fb.fh.active{background:var(--warn-dim);border-color:rgba(249,115,22,.3);color:var(--warn)}
.fb.fm.active{background:var(--med-dim);border-color:rgba(234,179,8,.3);color:var(--med)}
/* ============================================================
   SEARCH / SORT TOOLBAR
   ============================================================ */
.sif-toolbar{display:flex;align-items:center;gap:8px;padding:0 18px 12px;flex-wrap:wrap}
.sif-search-wrap{position:relative;flex:1;min-width:180px}
.sif-search{width:100%;background:rgba(4,8,18,.8);border:1px solid var(--border2);border-radius:var(--r8);padding:7px 10px 7px 30px;font-family:var(--mono);font-size:11px;color:var(--t1);outline:none;transition:var(--ease)}
.sif-search::placeholder{color:var(--t4)}
.sif-search:focus{border-color:var(--accent);box-shadow:0 0 0 2px rgba(6,182,212,.06)}
.sif-search-ico{position:absolute;left:10px;top:50%;transform:translateY(-50%);font-size:10px;color:var(--t3);pointer-events:none}
.sif-sort{background:rgba(4,8,18,.8);border:1px solid var(--border2);border-radius:var(--r8);padding:7px 10px;font-family:var(--mono);font-size:10px;color:var(--t2);cursor:pointer;transition:var(--ease);-webkit-appearance:none;appearance:none;min-width:130px;outline:none}
.sif-sort:focus{border-color:var(--accent)}
.sif-sort option{background:#0a121e;color:var(--t1)}
.sif-count{font-size:9px;font-family:var(--mono);color:var(--t4);white-space:nowrap;letter-spacing:.06em}
/* ============================================================
   VULN LIST CONTAINER
   ============================================================ */
#vulnList{max-height:680px;overflow-y:auto;display:flex;flex-direction:column;gap:10px;padding:16px 18px}
/* ============================================================
   UNIFIED VULNERABILITY CARD v2.0
   Every severity tab renders this identical component.
   Description always visible. Expand = advanced details only.
   ============================================================ */
.vc{border-radius:var(--r12);padding:0;border:1px solid var(--border);background:rgba(255,255,255,.016);transition:border-color .18s ease,background .18s ease;animation:cin .25s ease both;position:relative;overflow:hidden;flex-shrink:0}
.vc::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;transition:opacity .2s}
.vc.severity-Critical::before{background:var(--danger)}.vc.severity-Critical{border-color:var(--danger-border);background:var(--danger-dim)}
.vc.severity-High::before{background:var(--warn)}.vc.severity-High{border-color:rgba(249,115,22,.2);background:var(--warn-dim)}
.vc.severity-Medium::before{background:var(--med)}.vc.severity-Medium{border-color:rgba(234,179,8,.2);background:var(--med-dim)}
.vc.severity-Low::before{background:var(--low)}.vc.severity-Low{border-color:rgba(34,211,238,.15);background:var(--low-dim)}
.vc.severity-Info::before,.vc.severity-Unknown::before{background:var(--info)}
.vc.severity-Info,.vc.severity-Unknown{border-color:var(--border);background:var(--info-dim)}
.vc:hover{border-color:rgba(255,255,255,.12)}
.vc.expanded{box-shadow:0 4px 24px rgba(0,0,0,.25)}
@keyframes cin{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}
/* --- Header row ------------------------------------------ */
.vc-hdr{display:flex;align-items:center;gap:8px;padding:12px 14px 0 16px;flex-wrap:wrap}
.vc-ids{display:flex;align-items:center;gap:8px;flex:1;min-width:0}
.vc-id{font-family:var(--mono);font-size:12.5px;font-weight:700;color:var(--accent);line-height:1;white-space:nowrap;display:flex;align-items:center}
.vc-id a{color:inherit;text-decoration:none;display:inline-flex;align-items:center}
.vc-id a:hover{text-decoration:underline}
.src-badge{display:inline-flex;align-items:center;height:18px;padding:0 6px;border-radius:3px;font-size:7.5px;font-weight:700;font-family:var(--mono);letter-spacing:.09em;text-transform:uppercase;background:rgba(255,255,255,.04);color:var(--t3);border:1px solid var(--border2);flex-shrink:0;box-sizing:border-box;line-height:1}
.sev-tags{display:flex;align-items:center;gap:6px;flex-shrink:0}
.sp{display:inline-flex;align-items:center;height:20px;padding:0 8px;border-radius:5px;font-size:9px;font-weight:700;font-family:var(--mono);letter-spacing:.07em;text-transform:uppercase;line-height:1;box-sizing:border-box;white-space:nowrap}
.sp.Critical{background:rgba(239,68,68,.14);color:var(--danger);border:1px solid var(--danger-border)}
.sp.High{background:rgba(249,115,22,.12);color:var(--warn);border:1px solid rgba(249,115,22,.25)}
.sp.Medium{background:rgba(234,179,8,.12);color:var(--med);border:1px solid rgba(234,179,8,.25)}
.sp.Low{background:rgba(34,211,238,.08);color:var(--low);border:1px solid rgba(34,211,238,.2)}
.sp.Info,.sp.Unknown{background:rgba(100,116,139,.09);color:var(--info);border:1px solid var(--border)}
.cvss-chip{display:inline-flex;align-items:center;height:20px;padding:0 8px;border-radius:4px;font-size:9px;font-weight:700;font-family:var(--mono);color:#e2e8f0;background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.14);line-height:1;box-sizing:border-box;white-space:nowrap}
/* --- ALWAYS VISIBLE: product + description + metadata ---- */
.vc-visible{padding:8px 16px 12px}
.vc-prod-line{display:flex;align-items:center;gap:8px;margin-bottom:6px;flex-wrap:wrap}
.vc-prod-name{font-size:10.5px;font-weight:600;font-family:var(--mono);color:var(--accent);display:flex;align-items:center;gap:5px}
.vc-prod-name i{font-size:9px;opacity:.7}
.vc-prod-detail{font-size:9px;font-family:var(--mono);color:var(--t3)}
.vc-desc{font-size:11px;color:var(--t2);line-height:1.65;margin-bottom:10px;word-break:break-word;display:-webkit-box;-webkit-line-clamp:4;-webkit-box-orient:vertical;overflow:hidden;position:relative}
.vc-desc.vc-desc-full{-webkit-line-clamp:unset;overflow:visible}
.vc-chips{display:flex;align-items:center;gap:5px;flex-wrap:wrap;margin-bottom:8px}
.vc-chip{display:inline-flex;align-items:center;height:18px;padding:0 6px;border-radius:3px;font-size:7.5px;font-weight:700;font-family:var(--mono);letter-spacing:.05em;text-transform:uppercase;background:rgba(255,255,255,.03);border:1px solid var(--border);color:var(--t3);box-sizing:border-box;line-height:1;white-space:nowrap}
.vc-chip.chip-av{color:var(--accent);border-color:var(--accent-border);background:rgba(6,182,212,.06)}
.vc-chip.chip-sev{color:var(--danger);border-color:var(--danger-border);background:var(--danger-dim)}
.vc-bottom{display:flex;align-items:center;gap:6px;flex-wrap:wrap}
.port-chip{display:inline-flex;align-items:center;height:18px;padding:0 7px;font-size:9px;font-weight:700;font-family:var(--mono);color:var(--t3);background:rgba(255,255,255,.04);border:1px solid var(--border);border-radius:4px;box-sizing:border-box;line-height:1}
.cwe-chip{display:inline-flex;align-items:center;height:18px;padding:0 6px;font-size:8px;font-family:var(--mono);color:var(--warn);background:rgba(249,115,22,.06);border:1px solid rgba(249,115,22,.18);border-radius:4px;box-sizing:border-box;line-height:1}
.date-chip{display:inline-flex;align-items:center;height:18px;font-size:8px;font-family:var(--mono);color:var(--t4);line-height:1}
.vec-chip{display:inline-flex;align-items:center;height:18px;padding:0 5px;font-size:8px;font-family:var(--mono);color:var(--t4);background:rgba(255,255,255,.02);border:1px solid var(--border);border-radius:3px;max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;box-sizing:border-box;line-height:1}
.na-chip{display:inline-flex;align-items:center;height:18px;padding:0 6px;font-size:8px;font-family:var(--mono);color:var(--t4);background:transparent;border:1px solid var(--border);border-radius:3px;opacity:.5;line-height:1}
.kev-chip{display:inline-flex;align-items:center;gap:4px;height:18px;padding:0 7px;font-size:8px;font-weight:700;font-family:var(--mono);letter-spacing:.06em;text-transform:uppercase;color:#fff;background:linear-gradient(90deg,#dc2626,#ef4444);border-radius:4px;box-sizing:border-box;line-height:1;animation:kevpulse 2s infinite}
@keyframes kevpulse{0%,100%{opacity:1}50%{opacity:.72}}
.vc.vc-kev{border-color:var(--danger-border);box-shadow:0 0 0 1px rgba(239,68,68,.15) inset}
.vc.vc-kev::before{background:var(--danger)!important;width:4px}
/* --- Expand toggle --------------------------------------- */
.vc-expand-btn{display:flex;align-items:center;justify-content:center;gap:5px;padding:6px 16px;border-top:1px solid rgba(255,255,255,.04);font-size:8px;font-family:var(--mono);font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--t4);cursor:pointer;user-select:none;transition:var(--ease)}
.vc-expand-btn:hover{color:var(--accent);background:rgba(6,182,212,.03)}
.vc-expand-btn i{font-size:8px;transition:transform .22s ease}
.vc.expanded .vc-expand-btn i{transform:rotate(180deg)}
/* --- Expandable advanced section ------------------------- */
.vc-adv{max-height:0;overflow:hidden;transition:max-height .3s cubic-bezier(.4,0,.2,1)}
.vc.expanded .vc-adv{max-height:800px}
.vc-adv-inner{padding:10px 16px 14px;border-top:1px solid rgba(255,255,255,.05)}
.vc-adv-title{font-size:8px;font-weight:700;font-family:var(--mono);letter-spacing:.12em;text-transform:uppercase;color:var(--t4);margin-bottom:8px}
.vc-adv-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:8px}
.vc-adv-item{font-size:9px;color:var(--t3);font-family:var(--mono)}
.vc-adv-item strong{color:var(--t2);display:block;font-size:8px;letter-spacing:.08em;text-transform:uppercase;margin-bottom:2px}
.vc-adv-desc{font-size:10.5px;color:var(--t2);line-height:1.6;word-break:break-word;margin-bottom:10px}
.vc-adv-link{display:inline-flex;align-items:center;gap:4px;font-size:9px;font-family:var(--mono);color:var(--accent);text-decoration:none;padding:3px 8px;border:1px solid var(--accent-border);border-radius:4px;transition:var(--ease)}
.vc-adv-link:hover{background:var(--accent-glow)}
/* ============================================================
   ATTACK PROBABILITY ANALYSIS PANEL
   ============================================================ */
.attack-prob-panel{margin-top:16px;grid-column:1/-1}
.ap-disclaimer{font-size:9px;color:var(--t4);font-family:var(--mono);line-height:1.55;padding:10px 18px;border-bottom:1px solid var(--border);font-style:italic}
.ap-body{padding:18px;display:flex;flex-direction:column;gap:18px}
.ap-summary{font-size:11px;color:var(--t2);line-height:1.65;padding:12px 14px;background:rgba(6,182,212,.04);border:1px solid var(--accent-border);border-radius:var(--r8);word-break:break-word}
.ap-summary strong{color:var(--accent)}
.ap-bars{display:flex;flex-direction:column;gap:8px}
.ap-bar-row{display:flex;align-items:center;gap:10px}
.ap-bar-label{font-size:9px;font-family:var(--mono);color:var(--t2);width:150px;flex-shrink:0;text-transform:uppercase;letter-spacing:.05em;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.ap-bar-track{flex:1;height:8px;background:rgba(255,255,255,.04);border-radius:99px;overflow:hidden;min-width:60px}
.ap-bar-fill{height:100%;border-radius:99px;transition:width .8s cubic-bezier(.4,0,.2,1);min-width:0}
.ap-bar-fill.ap-critical{background:linear-gradient(90deg,#dc2626,var(--danger))}
.ap-bar-fill.ap-vhigh{background:linear-gradient(90deg,#ea580c,var(--warn))}
.ap-bar-fill.ap-high{background:linear-gradient(90deg,#ca8a04,var(--med))}
.ap-bar-fill.ap-medium{background:linear-gradient(90deg,var(--accent),var(--accent2))}
.ap-bar-fill.ap-low{background:linear-gradient(90deg,#0891b2,var(--low))}
.ap-bar-fill.ap-minimal{background:#475569}
.ap-bar-pct{font-size:10px;font-weight:700;font-family:var(--mono);color:var(--t1);width:38px;text-align:right;flex-shrink:0}
.ap-bar-class{font-size:7px;font-family:var(--mono);font-weight:700;letter-spacing:.08em;text-transform:uppercase;width:60px;text-align:right;flex-shrink:0}
.ap-bar-class.cls-critical{color:var(--danger)}.ap-bar-class.cls-vhigh{color:var(--warn)}.ap-bar-class.cls-high{color:var(--med)}.ap-bar-class.cls-medium{color:var(--accent)}.ap-bar-class.cls-low{color:var(--low)}.ap-bar-class.cls-minimal{color:var(--info)}
.ap-charts{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-top:4px}
.ap-chart-wrap{background:rgba(255,255,255,.015);border:1px solid var(--border);border-radius:var(--r12);padding:14px;text-align:center}
.ap-chart-title{font-size:8px;font-weight:700;font-family:var(--mono);letter-spacing:.12em;text-transform:uppercase;color:var(--t4);margin-bottom:10px}
.ap-chart-svg{max-width:220px;margin:0 auto;display:block}
.ap-legend{display:flex;flex-wrap:wrap;gap:6px;justify-content:center;margin-top:8px}
.ap-legend-item{display:flex;align-items:center;gap:4px;font-size:8px;font-family:var(--mono);color:var(--t3)}
.ap-legend-dot{width:6px;height:6px;border-radius:50%;flex-shrink:0}
/* ============================================================
   SKELETON / SHIMMER LOADERS
   ============================================================ */
@keyframes shimmer{0%{background-position:-200px 0}100%{background-position:200px 0}}
.skel-card{border-radius:var(--r12);border:1px solid var(--border);padding:14px 16px;margin-bottom:10px;animation:cin .25s ease both}
.skel-line{height:10px;border-radius:4px;background:linear-gradient(90deg,rgba(255,255,255,.03) 25%,rgba(255,255,255,.06) 50%,rgba(255,255,255,.03) 75%);background-size:400px 100%;animation:shimmer 1.4s infinite linear;margin-bottom:8px}
.skel-line.w70{width:70%}.skel-line.w50{width:50%}.skel-line.w90{width:90%}.skel-line.w40{width:40%}
.skel-chips{display:flex;gap:6px;margin-top:4px}
.skel-chip{width:50px;height:18px;border-radius:4px;background:linear-gradient(90deg,rgba(255,255,255,.03) 25%,rgba(255,255,255,.06) 50%,rgba(255,255,255,.03) 75%);background-size:400px 100%;animation:shimmer 1.4s infinite linear}
/* ============================================================
   EMPTY STATE (enhanced)
   ============================================================ */
.empty-s{padding:40px 20px;text-align:center;color:var(--t4);font-family:var(--mono);font-size:12px;display:flex;flex-direction:column;align-items:center;gap:10px}
.empty-s i{font-size:26px}
.empty-s .empty-hint{font-size:10px;color:var(--t4);opacity:.6;margin-top:2px}
/* ============================================================
   PORT GRID + SVC CARDS + ERROR TOAST (preserved)
   ============================================================ */
#portGrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(190px,1fr));gap:10px;max-height:420px;overflow-y:auto;padding:16px 18px}
.svc-card{background:rgba(255,255,255,.02);border:1px solid var(--border);border-radius:var(--r12);padding:14px;display:flex;align-items:flex-start;gap:10px;transition:var(--ease);animation:cin .25s ease both}
.svc-card:hover{transform:translateY(-2px);border-color:var(--accent-border);background:var(--accent-glow);box-shadow:0 6px 20px rgba(6,182,212,.07)}
.svc-ico{width:34px;height:34px;border-radius:8px;background:rgba(6,182,212,.08);border:1px solid var(--accent-border);display:flex;align-items:center;justify-content:center;color:var(--accent);font-size:12px;flex-shrink:0}
.svc-info{flex:1;min-width:0}
.svc-nm{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:var(--t1);margin-bottom:2px;display:flex;align-items:center;justify-content:space-between;gap:4px}
.open-pill{font-size:7px;font-weight:700;font-family:var(--mono);color:#22c55e;background:rgba(34,197,94,.08);border:1px solid rgba(34,197,94,.2);padding:1px 4px;border-radius:3px;letter-spacing:.06em}
.svc-port{font-family:var(--mono);font-size:10px;color:var(--accent);font-weight:600;margin-bottom:2px}
.svc-prod{font-size:9px;color:var(--t4);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
#error-toast{position:fixed;bottom:20px;right:20px;z-index:9999;background:rgba(20,5,5,.97);border:1px solid rgba(239,68,68,.35);color:var(--t1);padding:12px 16px;border-radius:var(--r12);display:flex;align-items:center;gap:10px;max-width:380px;backdrop-filter:blur(16px);box-shadow:0 8px 32px rgba(0,0,0,.5);transform:translateY(120%);opacity:0;pointer-events:none;transition:transform .3s cubic-bezier(.34,1.56,.64,1),opacity .25s ease}
#error-toast.show{transform:translateY(0);opacity:1;pointer-events:auto}
.t-ico{width:30px;height:30px;border-radius:8px;background:rgba(239,68,68,.12);display:flex;align-items:center;justify-content:center;color:var(--danger);font-size:12px;flex-shrink:0}
.t-body{flex:1}
.t-ttl{font-size:10px;font-weight:700;color:var(--danger);margin-bottom:2px;text-transform:uppercase;letter-spacing:.06em}
#error-msg{font-size:12px;color:var(--t2);line-height:1.45}
.t-close{background:none;border:none;color:var(--t3);cursor:pointer;font-size:16px;transition:var(--ease);padding:0;line-height:1}
.t-close:hover{color:var(--t1)}
#sb-ov{display:none;position:fixed;inset:0;background:rgba(0,0,0,.45);z-index:199}
#sb-ov.on{display:block}
/* ============================================================
   RESPONSIVE BREAKPOINTS (v2.0)
   ============================================================ */
@media(max-width:1024px){:root{--sidebar:0px}#sb{transform:translateX(-260px);width:260px}#sb.open{transform:translateX(0)}#main{margin-left:0}#sbtoggle{display:flex;align-items:center}.res-body{grid-template-columns:1fr}.stats{grid-template-columns:repeat(2,1fr)}.ap-charts{grid-template-columns:1fr}.ap-bar-label{width:120px}}
@media(max-width:768px){#pg{padding:14px}.scan-panel{padding:20px 18px}.scan-ph h1{font-size:16px}.scan-row{flex-direction:column}#btn{width:100%;justify-content:center}.stats{grid-template-columns:repeat(2,1fr);gap:10px}.sc-val{font-size:28px}#portGrid{grid-template-columns:repeat(auto-fill,minmax(160px,1fr))}.tb-pill:last-child{display:none}.res-hdr{flex-direction:column;align-items:flex-start}.sif-toolbar{flex-direction:column}.sif-search-wrap{min-width:100%}.vc-hdr{flex-wrap:wrap;gap:6px}.vc-chips{gap:4px}.ap-bar-label{width:90px;font-size:8px}.ap-charts{grid-template-columns:1fr}}
@media(max-width:480px){:root{--topbar:54px}#pg{padding:10px}.scan-panel{padding:16px 14px;border-radius:var(--r16)}.eng-badge{display:none}.stats{grid-template-columns:1fr 1fr;gap:8px}.sc{padding:14px 16px}.sc-val{font-size:24px}.sc.ip .sc-val{font-size:12px}#vulnList{padding:10px 12px;max-height:none}#portGrid{grid-template-columns:1fr 1fr;padding:10px 12px}.panel-hdr{padding:12px 14px}.panel-body{padding:14px}.vc-visible{padding:6px 12px 10px}.ap-bar-row{flex-wrap:wrap;gap:4px}.ap-bar-label{width:100%;font-size:9px}.ap-bar-class{display:none}}
@media(max-width:360px){.stats{grid-template-columns:1fr}#portGrid{grid-template-columns:1fr}}
</style>
</head>
<body>
<canvas id="bgc"></canvas>
<div id="sb-ov" onclick="closeSB()"></div>
<div id="error-toast">
  <div class="t-ico"><i class="fas fa-triangle-exclamation"></i></div>
  <div class="t-body"><div class="t-ttl">Scan Error</div><span id="error-msg"></span></div>
  <button class="t-close" onclick="hideError()">&times;</button>
</div>
<div id="shell">
<aside id="sb">
  <div class="sb-logo">
    <img src="logo.png" alt="VulnScope Pro" style="width:38px;height:38px;object-fit:contain;border-radius:8px;flex-shrink:0;filter:drop-shadow(0 0 8px rgba(6,182,212,.5))" onerror="this.style.display='none'">
    <div class="sb-logo-txt"><h2>VulnScope <span>Pro</span></h2><p>Intelligence Platform v5.0</p></div>
  </div>
  <nav class="sb-nav">
    <div class="nav-lbl">Platform</div>
    <a class="nav-a active" href="#" onclick="return false"><i class="fas fa-radar"></i>Scan Console</a>
    <a class="nav-a" href="#" onclick="toResults();return false"><i class="fas fa-shield-halved"></i>Intelligence Feed</a>
    <a class="nav-a" href="#" onclick="toInfra();return false"><i class="fas fa-network-wired"></i>Infrastructure Map</a>
    <div class="nav-lbl" style="margin-top:6px">Sources</div>
    <a class="nav-a" href="https://nvd.nist.gov/" target="_blank" rel="noopener"><i class="fas fa-database"></i>NVD / NIST</a>
    <a class="nav-a" href="https://www.shodan.io/" target="_blank" rel="noopener"><i class="fas fa-eye"></i>Shodan</a>
    <a class="nav-a" href="https://search.censys.io/" target="_blank" rel="noopener"><i class="fas fa-satellite-dish"></i>Censys</a>
    <a class="nav-a" href="https://cve.circl.lu/" target="_blank" rel="noopener"><i class="fas fa-circle-nodes"></i>CIRCL CVE</a>
  </nav>
  <div class="sb-apis">
    <div class="sb-api-lbl">API Source Status</div>
    <?php
$_alist  = ['nvd' => 'NVD v2', 'shodan' => 'Shodan', 'censys' => 'Censys v2', 'opencve' => 'OpenCVE'];
$_astatus = get_api_status();
foreach ($_alist as $_ak => $_al):
    $_aok = $_astatus[$_ak] === 'configured';
?>
<div class="sb-api-row">
  <div class="sb-api-name"><span class="dot <?php echo $_aok ? 'dot-on' : 'dot-off'; ?>"></span><?php echo $_al; ?></div>
  <span class="api-badge <?php echo $_aok ? 'on' : 'off'; ?>"><?php echo $_aok ? 'Active' : 'Offline'; ?></span>
</div>
<?php endforeach; ?>
  </div>
  <div class="sb-footer">VulnScope Pro &bull; Enterprise Security Intelligence<br>Multi-source CVE Correlation Engine</div>
</aside>
<div id="main">
  <header id="topbar">
    <div class="tb-left">
      <button id="sbtoggle" onclick="toggleSB()"><i class="fas fa-bars"></i></button>
      <div class="tb-bread">
        <i class="fas fa-shield-halved" style="color:var(--accent);font-size:13px"></i>
        <span class="cr-active">Vulnerability Intelligence Console</span>
      </div>
    </div>
    <div class="tb-right">
      <div class="tb-pill"><span class="ldot"></span>ENGINE ONLINE</div>
      <div class="tb-pill"><i class="fas fa-microchip" style="font-size:9px"></i>v5.0 Enterprise</div>
    </div>
  </header>
  <main id="pg">
    <section class="scan-panel">
      <div class="scan-ph">
        <div>
          <h1>Attack Surface Assessment</h1>
          <p>NVD v2 &middot; Shodan &middot; Censys v2 &middot; CIRCL &middot; OpenCVE &middot; Nmap NSE / PHP Socket Engine</p>
        </div>
        <div class="eng-badge"><i class="fas fa-circle" style="font-size:7px;color:#22c55e;animation:dpulse 1.5s infinite"></i>Scan Core Active</div>
      </div>
      <form id="scanForm">
        <div class="scan-row">
          <div class="inp-wrap">
            <input type="text" id="target" placeholder="Target IP or domain  e.g. 192.168.1.1 or example.com" autocomplete="off" spellcheck="false">
            <i class="fas fa-crosshairs inp-ico"></i>
          </div>
          <button type="submit" id="btn"><i class="fas fa-shield-virus"></i>Launch Assessment</button>
        </div>
      </form>
      <div id="loader">
        <div class="ld-spin"></div>
        <div class="ld-bar-wrap">
          <div class="ld-txt" id="ldtxt"><i class="fas fa-circle-notch fa-spin" style="margin-right:6px"></i>Initializing scan engine...</div>
          <div class="ld-track"><div class="ld-fill"></div></div>
        </div>
      </div>
    </section>
    <div id="results">
      <div class="res-hdr">
        <div class="res-hdr-left">
          <div class="res-hdr-title">Scan Results</div>
          <span id="riskBadge" class="risk-badge r-info" style="display:none"></span>
        </div>
        <button class="exp-btn" onclick="exportReport()"><i class="fas fa-file-export"></i>Export JSON</button>
      </div>
      <div class="stats">
        <div class="sc risk">
          <div class="sc-lbl">Composite Risk Score</div>
          <div class="sc-val" id="riskValue">0</div>
          <div class="risk-trk"><div id="riskBar"></div></div>
          <div class="sc-meta" id="resTarget">HOST: ---</div>
          <div class="sc-sub" id="riskLabel">No data</div>
        </div>
        <div class="sc finds">
          <div class="sc-lbl">Total Findings</div>
          <div class="sc-val" id="findingsCount">0</div>
          <div class="sc-meta">CVEs &amp; Vulnerabilities</div>
        </div>
        <div class="sc ports">
          <div class="sc-lbl">Detected Assets</div>
          <div class="sc-val" id="portsCountVal">0</div>
          <div class="sc-meta" id="portsCount">Open Services</div>
        </div>
        <div class="sc ip">
          <div class="sc-lbl">Resolved IP</div>
          <div class="sc-val" id="resIp">---</div>
          <div class="sc-meta">Target Address</div>
        </div>
      </div>
      <div class="res-body">
        <div style="display:flex;flex-direction:column;gap:14px">
          <div class="panel">
            <div class="panel-hdr"><div class="panel-title"><i class="fas fa-chart-bar"></i>Severity Distribution</div></div>
            <div class="panel-body"><div id="severityBars"></div></div>
          </div>
          <div class="panel">
            <div class="panel-hdr"><div class="panel-title"><i class="fas fa-plug-circle-check"></i>Intelligence Sources</div></div>
            <div class="panel-body" style="padding:14px 18px"><div id="apiStatusDisplay"></div></div>
          </div>
        </div>
        <div class="panel">
          <div class="panel-hdr">
            <div class="panel-title"><i class="fas fa-bug"></i>Security Intelligence Findings</div>
            <div class="vf-wrap">
              <button class="fb active" onclick="fvulns('all',this)">All</button>
              <button class="fb fc" onclick="fvulns('Critical',this)">Critical</button>
              <button class="fb fh" onclick="fvulns('High',this)">High</button>
              <button class="fb fm" onclick="fvulns('Medium',this)">Medium</button>
              <button class="fb" onclick="fvulns('Low',this)">Low</button>
            </div>
          </div>
          <!-- Search / Sort Toolbar -->
          <div class="sif-toolbar" id="sifToolbar">
            <div class="sif-search-wrap">
              <i class="fas fa-search sif-search-ico"></i>
              <input type="text" class="sif-search" id="sifSearch" placeholder="Search CVE, CWE, description, service..." autocomplete="off" spellcheck="false" aria-label="Search findings">
            </div>
            <select class="sif-sort" id="sifSort" aria-label="Sort findings">
              <option value="severity">Sort: Severity</option>
              <option value="cvss-desc">Sort: CVSS ↓</option>
              <option value="cvss-asc">Sort: CVSS ↑</option>
              <option value="cve-desc">Sort: CVE ID ↓</option>
              <option value="cve-asc">Sort: CVE ID ↑</option>
            </select>
            <span class="sif-count" id="sifCount"></span>
          </div>
          <div id="vulnList"></div>
        </div>
        <!-- Attack Probability Analysis Panel -->
        <div class="panel attack-prob-panel" id="attackProbPanel" style="display:none">
          <div class="panel-hdr">
            <div class="panel-title"><i class="fas fa-radar"></i>Attack Probability Analysis</div>
          </div>
          <div class="ap-disclaimer">Attack probabilities are heuristic estimates based on CVSS, CWE, attack vector and vulnerability metadata. They should be used for prioritisation and triage, not as predictions of future attacks.</div>
          <div class="ap-body">
            <div class="ap-summary" id="apSummary"></div>
            <div class="ap-bars" id="apBars"></div>
            <div class="ap-charts" id="apCharts"></div>
          </div>
        </div>

      </div>
      <div class="panel" id="infra-section" style="margin-bottom:0">
        <div class="panel-hdr">
          <div class="panel-title"><i class="fas fa-microchip"></i>Detected Infrastructure &amp; Services</div>
          <span id="portsCount2" style="font-size:10px;font-family:var(--mono);color:var(--t3);text-transform:uppercase;letter-spacing:.07em">0 Assets</span>
        </div>
        <div id="portGrid"></div>
      </div>
    </div>
  </main>
</div>
</div>
<script>
const SCAN_TOKEN='<?php echo SCAN_TOKEN; ?>';
let _last=null,_all=[];
(function(){
  const c=document.getElementById('bgc'),ctx=c.getContext('2d');
  let w,h,pts=[];
  function rsz(){w=c.width=window.innerWidth;h=c.height=window.innerHeight}
  function init(){pts=[];const n=Math.min(75,Math.floor(w*h/18000));for(let i=0;i<n;i++)pts.push({x:Math.random()*w,y:Math.random()*h,r:Math.random()*.9+.3,vx:(Math.random()-.5)*.13,vy:(Math.random()-.5)*.13})}
  function draw(){ctx.clearRect(0,0,w,h);ctx.fillStyle='rgba(6,182,212,.35)';for(const d of pts){d.x+=d.vx;d.y+=d.vy;if(d.x<0||d.x>w)d.vx*=-1;if(d.y<0||d.y>h)d.vy*=-1;ctx.beginPath();ctx.arc(d.x,d.y,d.r,0,Math.PI*2);ctx.fill()}ctx.strokeStyle='rgba(6,182,212,.05)';ctx.lineWidth=.5;for(let i=0;i<pts.length;i++)for(let j=i+1;j<pts.length;j++){const dx=pts[i].x-pts[j].x,dy=pts[i].y-pts[j].y,dist=Math.sqrt(dx*dx+dy*dy);if(dist<120){ctx.globalAlpha=(1-dist/120)*.55;ctx.beginPath();ctx.moveTo(pts[i].x,pts[i].y);ctx.lineTo(pts[j].x,pts[j].y);ctx.stroke()}}ctx.globalAlpha=1;requestAnimationFrame(draw)}
  window.addEventListener('resize',()=>{rsz();init()});rsz();init();draw();
})();
function toggleSB(){document.getElementById('sb').classList.toggle('open');document.getElementById('sb-ov').classList.toggle('on')}
function closeSB(){document.getElementById('sb').classList.remove('open');document.getElementById('sb-ov').classList.remove('on')}
window.addEventListener('scroll',function(){
  const sb=document.getElementById('sb');
  if(sb&&sb.classList.contains('open'))closeSB();
},{passive:true});
function toResults(){const e=document.getElementById('results');if(e)e.scrollIntoView({behavior:'smooth'})}
function toInfra(){const e=document.getElementById('infra-section');if(e)e.scrollIntoView({behavior:'smooth'})}
function showError(m){document.getElementById('error-msg').innerText=m;document.getElementById('error-toast').classList.add('show');setTimeout(hideError,7000)}
function hideError(){document.getElementById('error-toast').classList.remove('show')}
function ctr(el,to,dur=900){const s=performance.now(),f=parseInt(el.innerText)||0;(function run(n){const p=Math.min((n-s)/dur,1),e=1-Math.pow(1-p,3);el.innerText=Math.round(f+(to-f)*e);if(p<1)requestAnimationFrame(run)})(s)}
const LDR_MSGS=['Resolving target & DNS...','Running port scan engine...','Querying NVD v2 database...','Fetching Shodan intelligence...','Correlating CIRCL CVE data...','Enriching vulnerability records...','Calculating composite risk score...','Compiling findings...'];
let _lm=0,_lt=null;
function startLdr(){_lm=0;updLdr();_lt=setInterval(updLdr,2600)}
function updLdr(){const el=document.getElementById('ldtxt');if(el)el.innerHTML='<i class="fas fa-circle-notch fa-spin" style="margin-right:6px"></i>'+LDR_MSGS[_lm%LDR_MSGS.length];_lm++}
function stopLdr(){clearInterval(_lt)}
function riskMeta(s){if(s>=80)return['Critical Risk','r-critical'];if(s>=60)return['High Risk','r-high'];if(s>=40)return['Medium Risk','r-medium'];if(s>=15)return['Low Risk','r-low'];return['Minimal Risk','r-info']}
document.getElementById('scanForm').onsubmit=async(e)=>{
  e.preventDefault();
  const t=document.getElementById('target').value.trim(),btn=document.getElementById('btn'),ldr=document.getElementById('loader');
  if(!t)return showError('No target specified.');
  btn.disabled=true;ldr.classList.add('show');startLdr();
  document.getElementById('results').classList.remove('show');document.getElementById('results').style.display='none';
  document.getElementById('riskBadge').style.display='none';
  const fd=new FormData();fd.append('target',t);
  try{
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 300000); // 5 minute timeout

    const r=await fetch('?action=scan',{
      method:'POST',
      body:fd,
      headers:{'X-VulnScope-Token':SCAN_TOKEN},
      signal: controller.signal
    });
    clearTimeout(timeoutId);

    if(!r.ok){const tx=await r.text();showError('Server error '+r.status+': '+tx.substring(0,150));return}
    const j=await r.json();
    if(j.success){_last=j;renderDashboard(j)}else showError(j.message||'Unknown scan error.')
  }catch(err){
    if (err.name === 'AbortError') {
      showError('Scan timed out. The target may have tarpits or too many open ports.');
    } else {
      showError('Connection failure: '+err.message);
    }
  }
  finally{btn.disabled=false;ldr.classList.remove('show');stopLdr()}
};
function renderDashboard(resp){
  const{summary:s,severity_distribution:sd,findings:f,debug_info:di,api_status:as}=resp;
  const re=document.getElementById('results');re.style.display='block';re.classList.add('show');
  ctr(document.getElementById('riskValue'),s.risk_score,1100);
  setTimeout(()=>document.getElementById('riskBar').style.width=s.risk_score+'%',90);
  document.getElementById('resTarget').innerText='HOST: '+s.target;
  document.getElementById('resIp').innerText=s.ip;
  const[rl,rc]=riskMeta(s.risk_score);
  document.getElementById('riskLabel').innerText=rl+' — Score: '+s.risk_score+'/100';
  const rb=document.getElementById('riskBadge');rb.className='risk-badge '+rc;rb.innerHTML='<i class="fas fa-triangle-exclamation"></i> '+rl;rb.style.display='inline-flex';
  ctr(document.getElementById('findingsCount'),s.total_findings);
  ctr(document.getElementById('portsCountVal'),s.open_ports_count);
  document.getElementById('portsCount').innerText=s.open_ports_count+' Open Services';
  document.getElementById('portsCount2').innerText=s.open_ports_count+' Assets';
  if(as)document.getElementById('apiStatusDisplay').innerHTML=Object.entries(as).map(([k,v])=>{const ok=v==='configured';const lbl={'nvd':'NVD v2','shodan':'Shodan','censys':'Censys v2','opencve':'OpenCVE'};return `<div class="sb-api-row"><div class="sb-api-name"><span class="dot ${ok?'dot-on':'dot-off'}"></span>${lbl[k]||k.toUpperCase()}</div><span class="api-badge ${ok?'on':'off'}">${ok?'Active':'Offline'}</span></div>`}).join('');
  renderSevBars(sd,s.total_findings);renderPorts(di.ports||[]);_all=f;_filtered=f;_curSev='all';
  document.getElementById('sifSearch').value='';
  document.getElementById('sifSort').value='severity';
  initSearchSort();
  applyFilters();
  renderAttackProbPanel(f);
  setTimeout(()=>re.scrollIntoView({behavior:'smooth',block:'start'}),160);
}
function renderSevBars(d,tot){
  const sevs=['Critical','High','Medium','Low','Info'];
  document.getElementById('severityBars').innerHTML=sevs.map(s=>{const cnt=d[s.toLowerCase()]||0,pct=tot>0?Math.round(cnt/tot*100):0;return `<div class="sev-row sev-${s}"><div class="sev-hdr"><span class="sev-name">${s}</span><div class="sev-right"><span class="sev-pct">${pct}%</span><span class="sev-cnt">${cnt}</span></div></div><div class="sev-trk"><div class="progress-bar bar-${s}" data-p="${pct}"></div></div></div>`}).join('');
  setTimeout(()=>document.querySelectorAll('.progress-bar[data-p]').forEach(b=>b.style.width=b.dataset.p+'%'),110);
}
function svcIco(s){if(!s)return'fa-server';s=s.toLowerCase();if(s.includes('http')||s.includes('www')||s.includes('nginx')||s.includes('apache'))return'fa-globe';if(s.includes('ssh'))return'fa-terminal';if(s.includes('sql')||s.includes('mysql')||s.includes('postgres')||s.includes('mongo'))return'fa-database';if(s.includes('ftp'))return'fa-upload';if(s.includes('smtp')||s.includes('mail')||s.includes('pop')||s.includes('imap'))return'fa-envelope';if(s.includes('dns')||s.includes('domain'))return'fa-sitemap';if(s.includes('rdp')||s.includes('vnc')||s.includes('wbt'))return'fa-desktop';if(s.includes('redis'))return'fa-memory';if(s.includes('docker'))return'fa-docker';if(s.includes('ldap'))return'fa-users';return'fa-server'}
function renderPorts(ports){document.getElementById('portGrid').innerHTML=ports.length?ports.map((p,i)=>`<div class="svc-card" style="animation-delay:${i*28}ms"><div class="svc-ico"><i class="fas ${svcIco(p.service+' '+(p.product||''))}"></i></div><div class="svc-info"><div class="svc-nm"><span>${(p.service||'unknown').toUpperCase()}</span><span class="open-pill">OPEN</span></div><div class="svc-port">${p.port}/TCP</div><div class="svc-prod">${[p.product,p.version].filter(Boolean).join(' ')||'&mdash;'}</div></div></div>`).join(''):`<div class="empty-s" style="grid-column:1/-1"><i class="fas fa-network-wired"></i>No open services detected.</div>`}
/* ============================================================
   V2.0 MODULE: XSS-safe text escape
   ============================================================ */
function esc(s){if(!s)return '';const d=document.createElement('div');d.textContent=String(s);return d.innerHTML}

/* ============================================================
   V2.0 MODULE: CVSS Vector Parser
   Parses CVSS v2/v3 vector strings into readable metadata chips.
   Only derives values that can be reliably extracted from the vector.
   ============================================================ */
function parseCvssVector(vec){
  if(!vec)return[];
  const chips=[];
  const labels={
    AV:{N:'Network',A:'Adjacent',L:'Local',P:'Physical'},
    AC:{L:'Low',H:'High'},
    PR:{N:'None',L:'Low',H:'High'},
    UI:{N:'None',R:'Required'},
    S:{U:'Unchanged',C:'Changed'},
    C:{N:'None',L:'Low',H:'High'},I:{N:'None',L:'Low',H:'High'},A:{N:'None',L:'Low',H:'High'}
  };
  const parts=vec.split('/');
  for(const p of parts){
    const[k,val]=p.split(':');
    if(labels[k]&&labels[k][val]){
      chips.push({key:k,label:labels[k][val],cls:k==='AV'?'chip-av':''})
    }
  }
  return chips;
}

/* ============================================================
   V2.0 MODULE: Attack Probability Engine
   Heuristic model — NOT an AI prediction model.
   Estimates likelihood based on available CVE metadata only.
   ============================================================ */
let _filtered=[],_curSev='all',_searchBound=false;

function buildAttackProbabilities(findings){
  const cats=[
    {name:'Remote Code Execution',cwes:['CWE-94','CWE-78','CWE-77','CWE-502','CWE-434'],avBoost:'N',base:0},
    {name:'SQL Injection',cwes:['CWE-89','CWE-564'],avBoost:'N',base:0},
    {name:'Cross-Site Scripting',cwes:['CWE-79','CWE-80'],avBoost:'N',base:0},
    {name:'Authentication Bypass',cwes:['CWE-287','CWE-306','CWE-862','CWE-863'],avBoost:'N',base:0},
    {name:'Path Traversal',cwes:['CWE-22','CWE-23','CWE-36'],avBoost:'N',base:0},
    {name:'Denial of Service',cwes:['CWE-400','CWE-770','CWE-399'],avBoost:'N',base:0},
    {name:'Information Disclosure',cwes:['CWE-200','CWE-209','CWE-532'],avBoost:'N',base:0},
    {name:'Privilege Escalation',cwes:['CWE-269','CWE-250'],avBoost:'L',base:0},
    {name:'Buffer Overflow',cwes:['CWE-119','CWE-120','CWE-122','CWE-787'],avBoost:'N',base:0},
    {name:'Cryptographic Weakness',cwes:['CWE-327','CWE-326','CWE-295','CWE-310'],avBoost:'N',base:0}
  ];
  const sevW={Critical:1,High:.75,Medium:.45,Low:.2,Info:.05,Unknown:.05};
  for(const f of findings){
    const w=sevW[f.severity]||.05;
    const cvss=parseFloat(f.cvss)||0;
    const cvssW=cvss/10;
    for(const cat of cats){
      let score=0;
      if(f.cwe&&cat.cwes.some(c=>f.cwe.includes(c)))score+=40*w;
      score+=cvssW*15*w;
      if(f.vector){
        if(f.vector.includes('AV:N'))score+=10*w;
        if(f.vector.includes('AC:L'))score+=5*w;
        if(f.vector.includes('PR:N'))score+=5*w;
      }
      if(f.summary){
        const sl=f.summary.toLowerCase();
        if(cat.name.toLowerCase().split(' ').some(kw=>sl.includes(kw)))score+=8*w;
      }
      cat.base+=score;
    }
  }
  const maxVal=Math.max(...cats.map(c=>c.base),1);
  return cats.map(c=>({
    name:c.name,
    pct:Math.min(Math.round(c.base/maxVal*100),100),
    raw:c.base
  })).sort((a,b)=>b.pct-a.pct);
}

function probClass(pct){
  if(pct>=80)return{cls:'ap-critical',label:'CRITICAL',lcls:'cls-critical'};
  if(pct>=60)return{cls:'ap-vhigh',label:'V.HIGH',lcls:'cls-vhigh'};
  if(pct>=40)return{cls:'ap-high',label:'HIGH',lcls:'cls-high'};
  if(pct>=20)return{cls:'ap-medium',label:'MEDIUM',lcls:'cls-medium'};
  if(pct>=5)return{cls:'ap-low',label:'LOW',lcls:'cls-low'};
  return{cls:'ap-minimal',label:'MINIMAL',lcls:'cls-minimal'};
}

/* ============================================================
   V2.0 MODULE: AI Analyst Summary Generator
   Generates text summary from available CVE metadata.
   Does NOT fabricate data — only references parsed metadata.
   ============================================================ */
function generateAiSummary(findings,probs){
  if(!findings.length)return '';
  const total=findings.length;
  const critical=findings.filter(f=>f.severity==='Critical').length;
  const high=findings.filter(f=>f.severity==='High').length;
  const topProb=probs.length?probs[0]:null;
  const networkAV=findings.filter(f=>f.vector&&f.vector.includes('AV:N')).length;
  const kevCount=findings.filter(f=>f.is_kev).length;
  let txt='<strong>'+total+'</strong> vulnerabilities identified across the target infrastructure. ';
  if(kevCount>0)txt+='<strong style="color:var(--danger)">'+kevCount+'</strong> finding'+(kevCount!==1?'s are':' is')+' listed in the CISA Known Exploited Vulnerabilities catalog &mdash; treat as top priority. ';
  if(critical>0)txt+='<strong>'+critical+'</strong> critical-severity findings require immediate attention. ';
  if(high>0)txt+='<strong>'+high+'</strong> high-severity findings should be prioritised for remediation. ';
  if(networkAV>0)txt+='<strong>'+networkAV+'</strong> vulnerabilities are network-exploitable (Attack Vector: Network). ';
  if(topProb&&topProb.pct>0)txt+='The primary attack category is <strong>'+esc(topProb.name)+'</strong> ('+topProb.pct+'% probability). ';
  return txt;
}

/* ============================================================
   V2.0 MODULE: Unified Vulnerability Card Renderer
   Every severity tab renders this identical component.
   Description always visible. Expand = advanced details.
   ============================================================ */
function renderVulns(f){
  const list=document.getElementById('vulnList');
  const countEl=document.getElementById('sifCount');
  if(countEl)countEl.textContent=f.length+' finding'+(f.length!==1?'s':'');
  if(!f.length){
    const sevLabel=_curSev==='all'?'':''+esc(_curSev)+' severity ';
    list.innerHTML='<div class="empty-s"><i class="fas fa-shield-halved"></i>No '+sevLabel+'vulnerabilities found.<div class="empty-hint">Try adjusting filters or running a new scan.</div></div>';
    return;
  }
  // Lazy render: first 50 immediately, rest on scroll
  const BATCH=50;
  const html=f.slice(0,BATCH).map((v,i)=>buildVulnCard(v,i)).join('');
  list.innerHTML=html;
  if(f.length>BATCH){
    let rendered=BATCH;
    const onScroll=()=>{
      if(list.scrollTop+list.clientHeight>=list.scrollHeight-120){
        const next=f.slice(rendered,rendered+BATCH);
        if(!next.length){list.removeEventListener('scroll',onScroll);return;}
        const tmp=document.createElement('div');
        tmp.innerHTML=next.map((v,i)=>buildVulnCard(v,rendered+i)).join('');
        while(tmp.firstChild)list.appendChild(tmp.firstChild);
        rendered+=next.length;
      }
    };
    list.addEventListener('scroll',onScroll);
  }
  // Event delegation for expand toggle
  list.onclick=function(e){
    const btn=e.target.closest('.vc-expand-btn');
    if(btn){
      const card=btn.closest('.vc');
      if(card)card.classList.toggle('expanded');
      return;
    }
    // Don't toggle on link clicks
    if(e.target.tagName==='A')return;
  };
}

function buildVulnCard(v,i){
  const id=esc(v.id||'');
  const sev=esc(v.severity||'Info');
  const src=esc(v.source||'');
  const cvss=v.cvss>0?parseFloat(v.cvss).toFixed(1):'N/A';
  const summary=esc(v.summary||'No description available.');
  const cwe=v.cwe?esc(v.cwe):'';
  const port=v.port?esc(String(v.port)):'—';
  const published=v.published?esc(v.published):'';
  const vector=v.vector?esc(v.vector):'';
  const svcStr=esc(v.affected_service||'');
  const svcIcoClass=svcIco((v.affected_service||'')+' '+(v.source||''));

  // Parse CVSS vector into chips
  const vecChips=parseCvssVector(v.vector||'');
  const chipsHtml=vecChips.map(c=>'<span class="vc-chip '+c.cls+'">'+esc(c.key)+': '+esc(c.label)+'</span>').join('');

  // CVE link (safe — id is already escaped)
  const cveLink=v.id&&v.id.startsWith('CVE-')
    ?'<a href="https://nvd.nist.gov/vuln/detail/'+id+'" target="_blank" rel="noopener noreferrer" onclick="event.stopPropagation()">'+id+'</a>'
    :id;

  // Product/service line
  const prodLine=svcStr?'<div class="vc-prod-line"><span class="vc-prod-name"><i class="fas '+svcIcoClass+'"></i>'+svcStr+'</span><span class="vc-prod-detail">Port '+port+'/TCP</span></div>':'';

  // Bottom chips
  let bottom=v.is_kev?'<span class="kev-chip"><i class="fas fa-triangle-exclamation"></i> KEV: EXPLOITED</span>':'';
  bottom+='<span class="port-chip">PORT '+port+'</span>';
  if(cwe)bottom+='<span class="cwe-chip">'+cwe+'</span>';
  if(published)bottom+='<span class="date-chip">'+published+'</span>';
  if(vector)bottom+='<span class="vec-chip" title="'+vector+'">'+vector.split('/')[0]+'</span>';

  // Advanced details (shown on expand)
  const epssTxt=(v.epss_score!=null)?(v.epss_score*100).toFixed(2)+'% <span style="opacity:.6">(pctl '+Math.round((v.epss_percentile||0)*100)+')</span>':'N/A';
  const kevTxt=v.is_kev?'<span style="color:var(--danger)"><i class="fas fa-triangle-exclamation"></i> Actively Exploited'+(v.kev_date_added?' since '+esc(v.kev_date_added):'')+'</span>':'Not Listed';
  let advHtml='<div class="vc-adv-grid">';
  advHtml+='<div class="vc-adv-item"><strong>EPSS</strong>'+epssTxt+'</div>';
  advHtml+='<div class="vc-adv-item"><strong>CISA KEV</strong>'+kevTxt+'</div>';
  advHtml+='<div class="vc-adv-item"><strong>Exploit Status</strong>Unknown</div>';
  advHtml+='<div class="vc-adv-item"><strong>Patch Available</strong>Unknown</div>';
  advHtml+='<div class="vc-adv-item"><strong>Vendor</strong>N/A</div>';
  advHtml+='<div class="vc-adv-item"><strong>Fixed Version</strong>N/A</div>';
  advHtml+='<div class="vc-adv-item"><strong>Source</strong>'+src+'</div>';
  advHtml+='<div class="vc-adv-item"><strong>CVSS Vector</strong>'+(vector||'N/A')+'</div>';
  advHtml+='</div>';
  if(v.id&&v.id.startsWith('CVE-'))advHtml+='<a href="https://nvd.nist.gov/vuln/detail/'+id+'" target="_blank" rel="noopener noreferrer" class="vc-adv-link"><i class="fas fa-external-link-alt"></i>View on NVD</a>';

  return '<div class="vc severity-'+sev+(v.is_kev?' vc-kev':'')+'" style="animation-delay:'+Math.min(i,25)*28+'ms">'
    +'<div class="vc-hdr">'
      +'<div class="vc-ids"><span class="vc-id">'+cveLink+'</span><span class="src-badge">'+src+'</span></div>'
      +'<div class="sev-tags"><span class="sp '+sev+'">'+sev+'</span><span class="cvss-chip">CVSS '+cvss+'</span></div>'
    +'</div>'
    +'<div class="vc-visible">'
      +prodLine
      +'<div class="vc-desc">'+summary+'</div>'
      +(chipsHtml?'<div class="vc-chips">'+chipsHtml+'</div>':'')
      +'<div class="vc-bottom">'+bottom+'</div>'
    +'</div>'
    +'<div class="vc-adv"><div class="vc-adv-inner"><div class="vc-adv-title">Extended Intelligence</div>'+advHtml+'</div></div>'
    +'<div class="vc-expand-btn"><i class="fas fa-chevron-down"></i>Details</div>'
  +'</div>';
}

/* ============================================================
   V2.0 MODULE: Attack Probability Panel Renderer
   Renders probability bars, SVG radar chart, SVG doughnut chart.
   ============================================================ */
function renderAttackProbPanel(findings){
  const panel=document.getElementById('attackProbPanel');
  if(!findings||!findings.length){panel.style.display='none';return;}
  panel.style.display='block';
  const probs=buildAttackProbabilities(findings);
  // AI Summary
  document.getElementById('apSummary').innerHTML=generateAiSummary(findings,probs);
  // Probability bars
  const barsEl=document.getElementById('apBars');
  barsEl.innerHTML=probs.map(p=>{
    const pc=probClass(p.pct);
    return '<div class="ap-bar-row">'
      +'<span class="ap-bar-label">'+esc(p.name)+'</span>'
      +'<div class="ap-bar-track"><div class="ap-bar-fill '+pc.cls+'" style="width:0%" data-w="'+p.pct+'"></div></div>'
      +'<span class="ap-bar-pct">'+p.pct+'%</span>'
      +'<span class="ap-bar-class '+pc.lcls+'">'+pc.label+'</span>'
    +'</div>';
  }).join('');
  // Animate bars
  setTimeout(()=>barsEl.querySelectorAll('.ap-bar-fill[data-w]').forEach(b=>b.style.width=b.dataset.w+'%'),60);
  // Charts
  const chartsEl=document.getElementById('apCharts');
  chartsEl.innerHTML=renderRadarChart(probs.slice(0,6))+renderDoughnutChart(probs.slice(0,6));
}

function renderRadarChart(probs){
  if(!probs.length)return '';
  const n=probs.length,cx=110,cy=110,maxR=85;
  const colors=['#ef4444','#f97316','#eab308','#06b6d4','#3b82f6','#22d3ee'];
  const pts=probs.map((p,i)=>{
    const angle=(Math.PI*2*i/n)-Math.PI/2;
    const r=maxR*p.pct/100;
    return{x:cx+r*Math.cos(angle),y:cy+r*Math.sin(angle)};
  });
  const polyPoints=pts.map(p=>p.x.toFixed(1)+','+p.y.toFixed(1)).join(' ');
  let rings='';
  [25,50,75,100].forEach(pct=>{
    const r=maxR*pct/100;
    rings+='<circle cx="'+cx+'" cy="'+cy+'" r="'+r+'" fill="none" stroke="rgba(255,255,255,.06)" stroke-width="0.5"/>';
  });
  let axes='';
  probs.forEach((p,i)=>{
    const angle=(Math.PI*2*i/n)-Math.PI/2;
    const ex=cx+maxR*Math.cos(angle),ey=cy+maxR*Math.sin(angle);
    const lx=cx+(maxR+14)*Math.cos(angle),ly=cy+(maxR+14)*Math.sin(angle);
    axes+='<line x1="'+cx+'" y1="'+cy+'" x2="'+ex.toFixed(1)+'" y2="'+ey.toFixed(1)+'" stroke="rgba(255,255,255,.08)" stroke-width="0.5"/>';
    axes+='<text x="'+lx.toFixed(1)+'" y="'+ly.toFixed(1)+'" fill="#64748b" font-size="6" font-family="var(--mono)" text-anchor="middle" dominant-baseline="central">'+esc(p.name.split(' ')[0])+'</text>';
  });
  let svg='<svg viewBox="0 0 220 220" class="ap-chart-svg" role="img" aria-label="Attack probability radar chart">';
  svg+=rings+axes;
  svg+='<polygon points="'+polyPoints+'" fill="rgba(6,182,212,.12)" stroke="var(--accent)" stroke-width="1.5"/>';
  pts.forEach((p,i)=>{svg+='<circle cx="'+p.x.toFixed(1)+'" cy="'+p.y.toFixed(1)+'" r="3" fill="'+colors[i%colors.length]+'"/>';});
  svg+='</svg>';
  return '<div class="ap-chart-wrap"><div class="ap-chart-title">Attack Vector Radar</div>'+svg+'</div>';
}

function renderDoughnutChart(probs){
  if(!probs.length)return '';
  const colors=['#ef4444','#f97316','#eab308','#06b6d4','#3b82f6','#22d3ee'];
  const total=probs.reduce((s,p)=>s+p.pct,0)||1;
  const cx=100,cy=100,r=70,sw=18;
  let offset=0;
  const circ=2*Math.PI*r;
  let arcs='';
  probs.forEach((p,i)=>{
    const pct=p.pct/total;
    const dash=circ*pct;
    const gap=circ-dash;
    arcs+='<circle cx="'+cx+'" cy="'+cy+'" r="'+r+'" fill="none" stroke="'+colors[i%colors.length]+'" stroke-width="'+sw+'" stroke-dasharray="'+dash.toFixed(2)+' '+gap.toFixed(2)+'" stroke-dashoffset="'+(-offset).toFixed(2)+'" transform="rotate(-90 '+cx+' '+cy+')" opacity=".85"/>';
    offset+=dash;
  });
  let svg='<svg viewBox="0 0 200 200" class="ap-chart-svg" role="img" aria-label="Severity distribution doughnut chart">';
  svg+=arcs;
  svg+='<text x="'+cx+'" y="'+cy+'" fill="var(--t1)" font-size="18" font-weight="700" font-family="var(--mono)" text-anchor="middle" dominant-baseline="central">'+probs.length+'</text>';
  svg+='<text x="'+cx+'" y="'+(cy+14)+'" fill="var(--t4)" font-size="7" font-family="var(--mono)" text-anchor="middle">CATEGORIES</text>';
  svg+='</svg>';
  const legend=probs.map((p,i)=>'<span class="ap-legend-item"><span class="ap-legend-dot" style="background:'+colors[i%colors.length]+'"></span>'+esc(p.name)+'</span>').join('');
  return '<div class="ap-chart-wrap"><div class="ap-chart-title">Category Distribution</div>'+svg+'<div class="ap-legend">'+legend+'</div></div>';
}

/* ============================================================
   V2.0 MODULE: Search & Sort
   Debounced search, memoised filtering.
   ============================================================ */
function initSearchSort(){
  if(_searchBound)return;
  _searchBound=true;
  const searchEl=document.getElementById('sifSearch');
  const sortEl=document.getElementById('sifSort');
  let debounce=null;
  searchEl.addEventListener('input',()=>{
    clearTimeout(debounce);
    debounce=setTimeout(()=>applyFilters(),180);
  });
  sortEl.addEventListener('change',()=>applyFilters());
}

function applyFilters(){
  const q=(document.getElementById('sifSearch').value||'').trim().toLowerCase();
  const sort=document.getElementById('sifSort').value;
  let data=_curSev==='all'?_all:_all.filter(v=>v.severity===_curSev);
  if(q){
    data=data.filter(v=>{
      return(v.id&&v.id.toLowerCase().includes(q))
        ||(v.summary&&v.summary.toLowerCase().includes(q))
        ||(v.cwe&&v.cwe.toLowerCase().includes(q))
        ||(v.affected_service&&v.affected_service.toLowerCase().includes(q))
        ||(v.source&&v.source.toLowerCase().includes(q))
        ||(v.port&&String(v.port).includes(q));
    });
  }
  const sevOrder={Critical:0,High:1,Medium:2,Low:3,Info:4,Unknown:5};
  switch(sort){
    case'severity':data.sort((a,b)=>(sevOrder[a.severity]||5)-(sevOrder[b.severity]||5));break;
    case'cvss-desc':data.sort((a,b)=>(parseFloat(b.cvss)||0)-(parseFloat(a.cvss)||0));break;
    case'cvss-asc':data.sort((a,b)=>(parseFloat(a.cvss)||0)-(parseFloat(b.cvss)||0));break;
    case'cve-desc':data.sort((a,b)=>(b.id||'').localeCompare(a.id||''));break;
    case'cve-asc':data.sort((a,b)=>(a.id||'').localeCompare(b.id||''));break;
  }
  _filtered=data;
  renderVulns(data);
}

function fvulns(sev,btn){
  document.querySelectorAll('.fb').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  _curSev=sev;
  applyFilters();
}

function exportReport(){
  if(!_last)return showError('No scan data available yet.');
  const b=new Blob([JSON.stringify(_last,null,2)],{type:'application/json'});
  const a=document.createElement('a');a.href=URL.createObjectURL(b);
  a.download='vulnscope-'+(_last.summary?.target||'report').replace(/[^a-zA-Z0-9.-]/g,'_')+'-'+Date.now()+'.json';
  document.body.appendChild(a);a.click();document.body.removeChild(a);
}
</script>
</body>
</html>
