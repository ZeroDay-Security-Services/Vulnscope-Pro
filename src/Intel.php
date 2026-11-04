<?php
/**
 * VulnScope Pro — threat-intelligence source clients.
 * NVD v2, CIRCL, OpenCVE, EPSS, CISA-KEV, Shodan, Censys + enrichment.
 */
declare(strict_types=1);

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

