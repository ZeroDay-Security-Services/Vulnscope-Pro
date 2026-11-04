<?php
/**
 * VulnScope Pro — deep-scan orchestrator and report layer.
 *
 * One call runs the complete assessment pipeline:
 *   M1 recon → spider → directory fuzz → passive scan → active scan →
 *   CVE/VulnLookup intel correlation → unified, deduplicated findings.
 *
 * Also provides exposure findings, SARIF/HTML report builders and history.
 */
declare(strict_types=1);

/** Convert a passive/active alert into the dashboard's finding schema. */
function vs_finding_from_alert(array $a): array
{
    $type = strtoupper(substr((string)($a['type'] ?? 'pas'), 0, 3));
    $id = 'VSP-' . $type . '-' . strtoupper(substr(md5(
        ($a['rule'] ?? '') . '|' . ($a['url'] ?? '') . '|' . ($a['param'] ?? '') . '|' . ($a['payload'] ?? '')
    ), 0, 10));

    $severity = $a['severity'] ?? 'Info';
    $cvss = $a['cvss'] ?? vs_risk_cvss($severity);
    $summary = $a['name'] ?? 'Security finding';
    if (!empty($a['summary'])) {
        $summary .= ' — ' . $a['summary'];
    }

    return [
        'id'               => $id,
        'cvss'             => (float)$cvss,
        'severity'         => $severity,
        'summary'          => $summary,
        'source'           => $a['source'] ?? 'Scanner',
        'vector'           => '',
        'cwe'              => $a['cwe'] ?? '',
        'published'        => '',
        'port'             => $a['port'] ?? '',
        'affected_service' => $a['affected_service'] ?? ($a['url'] ?? ''),
        'url'              => $a['url'] ?? '',
        'param'            => $a['param'] ?? '',
        'payload'          => $a['payload'] ?? '',
        'method'           => $a['method'] ?? 'GET',
        'confidence'       => $a['confidence'] ?? 'Medium',
        'rule'             => $a['rule'] ?? '',
        'evidence'         => $a['evidence'] ?? '',
        'solution'         => $a['solution'] ?? '',
        'reference'        => $a['reference'] ?? '',
        'affected_urls'    => $a['affected_urls'] ?? [],
        'affected_count'   => $a['affected_count'] ?? 1,
        'is_kev'           => false,
        'finding_type'     => $a['type'] ?? 'passive',
    ];
}

/** Risky exposed services → findings (exposure analysis). */
function vs_exposure_findings(array $ports): array
{
    $risky = [
        '21'    => ['FTP Service Exposed', 'Medium', 'CWE-284', 'FTP transmits credentials and data in cleartext and is often misconfigured for anonymous access.'],
        '23'    => ['Telnet Service Exposed', 'High', 'CWE-319', 'Telnet sends credentials in cleartext and should never face untrusted networks.'],
        '135'   => ['MS RPC Exposed', 'Medium', 'CWE-284', 'Remote RPC endpoints enlarge the Windows attack surface.'],
        '139'   => ['NetBIOS Session Service Exposed', 'Medium', 'CWE-284', 'NetBIOS/SMB legacy services expose host and share information.'],
        '445'   => ['SMB File Sharing Exposed', 'High', 'CWE-284', 'Externally reachable SMB is a primary ransomware propagation vector.'],
        '1433'  => ['Microsoft SQL Server Exposed', 'High', 'CWE-284', 'A database port reachable from the scanned range should be firewalled or authenticated strictly.'],
        '2375'  => ['Docker API Exposed (Unauthenticated)', 'Critical', 'CWE-306', 'An open Docker daemon grants full host control without authentication.'],
        '2376'  => ['Docker API TLS Exposed', 'High', 'CWE-284', 'The Docker API is reachable; verify mutual TLS and client certificates.'],
        '3306'  => ['MySQL Database Exposed', 'High', 'CWE-284', 'Direct database exposure bypasses application-level controls and rate limiting.'],
        '3389'  => ['Remote Desktop Exposed', 'High', 'CWE-284', 'RDP exposure enables brute-force and pre-auth exploitation; place behind VPN.'],
        '5432'  => ['PostgreSQL Database Exposed', 'High', 'CWE-284', 'Direct database exposure should be restricted to application hosts.'],
        '5900'  => ['VNC Service Exposed', 'High', 'CWE-284', 'VNC frequently allows weak or empty authentication when exposed.'],
        '5985'  => ['WinRM Exposed', 'Medium', 'CWE-284', 'WinRM provides remote command execution and should not be internet-accessible.'],
        '6379'  => ['Redis Exposed', 'Critical', 'CWE-306', 'Unauthenticated Redis allows arbitrary data manipulation and often RCE via config writes.'],
        '9200'  => ['Elasticsearch Exposed', 'High', 'CWE-306', 'An open Elasticsearch API commonly allows unauthenticated data reads and writes.'],
        '9300'  => ['Elasticsearch Transport Port Exposed', 'High', 'CWE-284', 'Cluster transport traffic must not be reachable from untrusted networks.'],
        '10250' => ['Kubelet API Exposed', 'Critical', 'CWE-306', 'The kubelet API can execute commands in pods when unauthenticated.'],
        '11211' => ['Memcached Exposed', 'High', 'CWE-306', 'Open memcached enables cache poisoning and amplification attacks.'],
        '15672' => ['RabbitMQ Management Exposed', 'Medium', 'CWE-284', 'Management console exposure invites credential attacks.'],
        '27017' => ['MongoDB Exposed', 'Critical', 'CWE-306', 'MongoDB defaults to no authentication; exposure frequently means full data access.'],
        '50070' => ['Hadoop HDFS Exposed', 'High', 'CWE-284', 'HDFS web endpoints can expose cluster metadata and file contents.'],
        '7001'  => ['Oracle WebLogic Exposed', 'High', 'CWE-284', 'WebLogic has a long history of pre-auth deserialization RCEs.'],
    ];

    $out = [];
    foreach ($ports as $p) {
        $port = (string)($p['port'] ?? '');
        $state = strtolower((string)($p['state'] ?? 'open'));
        if (!isset($risky[$port]) || ($state !== 'open' && $state !== 'open|filtered')) {
            continue;
        }
        [$name, $risk, $cwe, $why] = $risky[$port];
        $service = trim(($p['product'] ?? '') . ' ' . ($p['version'] ?? '')) ?: ($p['service'] ?? 'unknown');
        $out[] = [
            'id'               => 'VSP-EXP-' . $port,
            'cvss'             => vs_risk_cvss($risk),
            'severity'         => $risk,
            'summary'          => $name . ' — ' . $why,
            'source'           => 'Exposure Analysis',
            'vector'           => '',
            'cwe'              => $cwe,
            'published'        => '',
            'port'             => $port,
            'affected_service' => $service . ' on port ' . $port,
            'confidence'       => 'High',
            'evidence'         => 'Port ' . $port . '/tcp is ' . $state . ' (' . $service . ').',
            'solution'         => 'Restrict the port to trusted networks, require strong authentication and patch the service.',
            'reference'        => 'https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration',
            'url'              => '',
            'is_kev'           => false,
            'finding_type'     => 'exposure',
        ];
    }
    return $out;
}

/** Pick the most likely web port from recon output. */
function vs_pick_web_port(array $ports, ?int $forced = null): array
{
    if ($forced !== null && $forced > 0) {
        return [$forced, in_array($forced, [443, 8443, 9443], true)];
    }
    $preferred = [80, 443, 8080, 8443, 8008, 8888, 3000, 5000, 8000, 9000, 9090];
    foreach ($preferred as $candidate) {
        foreach ($ports as $p) {
            if ((string)($p['port'] ?? '') === (string)$candidate && strtolower((string)($p['state'] ?? 'open')) === 'open') {
                return [$candidate, in_array($candidate, [443, 8443], true)];
            }
        }
    }
    foreach ($ports as $p) {
        $svc = strtolower((string)($p['service'] ?? ''));
        $state = strtolower((string)($p['state'] ?? 'open'));
        if ($state === 'open' && (str_contains($svc, 'http') || str_contains($svc, 'ssl'))) {
            $port = (int)$p['port'];
            return [$port, in_array($port, [443, 8443], true)];
        }
    }
    return [80, false];
}

/** De-duplicate findings by id, then sort by severity and CVSS. */
function vs_normalize_findings(array $findings): array
{
    $byId = [];
    foreach ($findings as $f) {
        if (empty($f['id'])) {
            continue;
        }
        if (!isset($byId[$f['id']])) {
            $byId[$f['id']] = $f;
            continue;
        }
        // Keep the richer record, but merge source attribution.
        $cur = $byId[$f['id']];
        if (strlen((string)($f['summary'] ?? '')) > strlen((string)($cur['summary'] ?? ''))) {
            $byId[$f['id']] = $f;
        }
        $src = $f['source'] ?? '';
        if ($src !== '' && !str_contains((string)$byId[$f['id']]['source'], $src)) {
            $byId[$f['id']]['source'] .= ' / ' . $src;
        }
    }
    $findings = array_values($byId);

    $order = ['Critical' => 5, 'High' => 4, 'Medium' => 3, 'Low' => 2, 'Info' => 1, 'Unknown' => 0];
    usort($findings, function ($a, $b) use ($order) {
        $sa = $order[$a['severity'] ?? 'Info'] ?? 0;
        $sb = $order[$b['severity'] ?? 'Info'] ?? 0;
        if ($sa !== $sb) {
            return $sb - $sa;
        }
        return ((float)($b['cvss'] ?? 0)) <=> ((float)($a['cvss'] ?? 0));
    });
    return $findings;
}

function vs_severity_distribution(array $findings): array
{
    $dist = ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0, 'info' => 0];
    foreach ($findings as $f) {
        $key = strtolower((string)($f['severity'] ?? 'info'));
        if (!isset($dist[$key])) {
            $key = 'info';
        }
        $dist[$key]++;
    }
    return $dist;
}

/**
 * Scan profiles: the lightweight/full-coverage trade-off lives here.
 * Quick stays under ~1 minute on a small app; deep is the full assessment.
 */
function vs_scan_profiles(): array
{
    return [
        'quick' => [
            'label' => 'Quick',
            'max_pages' => 8,
            'max_depth' => 1,
            'max_requests' => 90,
            'spider_seconds' => 15,
            'active_seconds' => 30,
            'aggressive' => false,
            'skip_fuzz' => false,
            'max_js' => 3,
        ],
        'balanced' => [
            'label' => 'Balanced',
            'max_pages' => 20,
            'max_depth' => 2,
            'max_requests' => 150,
            'spider_seconds' => 28,
            'active_seconds' => 55,
            'aggressive' => true,
            'skip_fuzz' => false,
            'max_js' => 6,
        ],
        'deep' => [
            'label' => 'Deep',
            'max_pages' => 35,
            'max_depth' => 3,
            'max_requests' => 220,
            'spider_seconds' => 45,
            'active_seconds' => 90,
            'aggressive' => true,
            'skip_fuzz' => false,
            'max_js' => 10,
        ],
    ];
}

/**
 * Full deep scan.
 *
 * $opts: profile (quick|balanced|deep), cookie, port, max_pages,
 *        max_requests, aggressive, skip_recon, skip_fuzz
 */
function vs_deep_scan(string $host, string $ip, array $opts = []): array
{
    $t0 = microtime(true);

    // Resolve the scan profile, letting explicit options override it.
    $profiles = vs_scan_profiles();
    $profileName = strtolower((string)($opts['profile'] ?? 'balanced'));
    if (!isset($profiles[$profileName])) {
        $profileName = 'balanced';
    }
    $profile = $profiles[$profileName];
    unset($profile['label']);
    $opts = array_merge($profile, $opts);

    // Resolve context / policy (ZAP-style auth + rule shaping).
    try {
        $auth = vs_resolve_scan_auth($opts);
        $opts['cookie'] = $auth['cookie'];
        $authMeta       = $auth['meta'];
    } catch (Throwable $e) {
        $authMeta = ['context' => 'manual', 'auth_type' => 'none', 'login' => 'error: ' . $e->getMessage()];
    }
    try {
        $policy = vs_policy_resolve($opts['policy'] ?? 'default');
    } catch (Throwable $e) {
        $policy = ['name' => 'built-in default', 'requests_mult' => 1.0, 'groups' => []];
    }
    $cookie = vs_sanitize_cookie((string)($opts['cookie'] ?? ''));
    $stages = [];

    // ---- 1. Recon ------------------------------------------------------
    $reconStart = microtime(true);
    $recon = ($opts['skip_recon'] ?? false) ? ['ports' => [], 'errors' => [], 'host' => $host, 'ip' => $ip] : vs_module1_recon($host, $ip);
    $stages['recon'] = ['duration_ms' => (int)((microtime(true) - $reconStart) * 1000), 'ports' => count($recon['ports'] ?? [])];

    // ---- 2. Web surface ------------------------------------------------
    [$webPort, $tls] = vs_pick_web_port($recon['ports'] ?? [], isset($opts['port']) ? (int)$opts['port'] : null);
    $base = ($tls ? 'https' : 'http') . '://' . $host . ':' . $webPort;

    // ---- 3. Spider -----------------------------------------------------
    $spiderStart = microtime(true);
    $spider = vs_spider($base, [
        'max_pages'   => (int)($opts['max_pages'] ?? 20),
        'max_depth'   => (int)($opts['max_depth'] ?? 2),
        'cookie'      => $cookie,
        'max_seconds' => (float)($opts['spider_seconds'] ?? 28),
        'max_js'      => (int)($opts['max_js'] ?? 6),
    ]);
    $stages['spider'] = ['duration_ms' => (int)((microtime(true) - $spiderStart) * 1000)] + $spider['stats'];

    // ---- 4. Directory fuzz --------------------------------------------
    $fuzzStart = microtime(true);
    $fuzz = ($opts['skip_fuzz'] ?? false)
        ? ['hits' => [], 'paths_tested' => 0, 'base_url' => $base]
        : vs_module2_fuzz($host, $webPort, $tls, 20, $cookie);
    $stages['fuzz'] = ['duration_ms' => (int)((microtime(true) - $fuzzStart) * 1000), 'hits' => count($fuzz['hits'] ?? [])];

    // ---- 5. Passive scan ----------------------------------------------
    $passiveStart = microtime(true);
    $passive = vs_passive_scan($spider, ['base' => $base, 'port' => $webPort, 'fuzz' => $fuzz, 'cookie' => $cookie]);
    $stages['passive'] = ['duration_ms' => (int)((microtime(true) - $passiveStart) * 1000), 'alerts' => $passive['summary']['total'] ?? 0];

    // ---- 6. Active scan ------------------------------------------------
    $activeStart = microtime(true);
    $active = vs_active_scan($spider, $base, [
        'cookie'       => $cookie,
        'port'         => $webPort,
        'max_requests' => (int)round((int)($opts['max_requests'] ?? 140) * (float)($policy['requests_mult'] ?? 1.0)),
        'max_seconds'  => (float)($opts['active_seconds'] ?? 75),
        'aggressive'   => (bool)($opts['aggressive'] ?? true),
        'policy'       => $policy['groups'] ?? [],
    ]);
    $stages['active'] = [
        'duration_ms' => (int)((microtime(true) - $activeStart) * 1000),
        'alerts'      => $active['summary']['total'] ?? 0,
        'requests'    => $active['requests'] ?? 0,
    ];

    // ---- 7. CVE intel --------------------------------------------------
    $intelStart = microtime(true);
    $cveFindings = [];
    $enrichedPorts = $recon['ports'] ?? [];
    $intelError = null;
    try {
        [$cveFindings, $enrichedPorts] = vs_correlate_cves($recon['ports'] ?? [], $ip);
    } catch (Throwable $e) {
        $intelError = $e->getMessage();
    }
    // Vulnerability-Lookup metadata for the highest-signal CVEs.
    try {
        vl_enrich_findings($cveFindings, 6);
    } catch (Throwable $e) {
        $intelError = $intelError ?: $e->getMessage();
    }
    $stages['intel'] = ['duration_ms' => (int)((microtime(true) - $intelStart) * 1000), 'cves' => count($cveFindings)];

    // ---- 8. Merge + score ---------------------------------------------
    $findings = [];
    foreach (($passive['alerts'] ?? []) as $a) {
        $findings[] = vs_finding_from_alert($a);
    }
    foreach (($active['alerts'] ?? []) as $a) {
        $findings[] = vs_finding_from_alert($a);
    }
    foreach (vs_exposure_findings($recon['ports'] ?? []) as $f) {
        $findings[] = $f;
    }
    foreach ($cveFindings as $f) {
        $findings[] = $f;
    }
    $findings = vs_normalize_findings($findings);

    // ---- 8b. Exploit hazard (Shaffer & Voicu local model) -----------------
    $hazardStart = microtime(true);
    $findings = vs_hazard_enrich_findings($findings);
    $stages['hazard'] = ['duration_ms' => (int)((microtime(true) - $hazardStart) * 1000)];

    $dist = vs_severity_distribution($findings);
    $risk = calculate_risk_score($findings, count($enrichedPorts));
    $cvssValues = array_filter(array_map(fn($f) => (float)($f['cvss'] ?? 0), $findings), fn($v) => $v > 0);

    $response = [
        'success'    => true,
        'scan_type'  => 'deep',
        'target'     => $host,
        'ip'         => $ip,
        'started_at' => date('c', (int)$t0),
        'findings'   => $findings,
        'modules'    => [
            'recon'   => $recon,
            'spider'  => $spider,
            'fuzz'    => $fuzz,
            'passive' => $passive,
            'active'  => $active,
        ],
        'summary'    => [
            'target'         => $host,
            'ip'             => $ip,
            'risk_score'     => $risk,
            'total_findings' => count($findings),
            'open_ports_count' => count($enrichedPorts),
            'web_port'       => $webPort,
            'tls'            => $tls,
            'pages_crawled'  => count($spider['pages'] ?? []),
            'urls_discovered'=> $spider['stats']['urls_discovered'] ?? 0,
            'forms_found'    => $spider['stats']['forms_found'] ?? 0,
            'parameters'     => $spider['stats']['parameters'] ?? 0,
            'requests_sent'  => ($fuzz['paths_tested'] ?? 0) + ($active['requests'] ?? 0),
            'avg_cvss'       => $cvssValues ? round(array_sum($cvssValues) / count($cvssValues), 1) : 0,
            'max_cvss'       => $cvssValues ? round(max($cvssValues), 1) : 0,
            'confidence'     => [
                'high'   => count(array_filter($findings, fn($f) => ($f['confidence'] ?? '') === 'High')),
                'medium' => count(array_filter($findings, fn($f) => ($f['confidence'] ?? '') === 'Medium')),
                'low'    => count(array_filter($findings, fn($f) => ($f['confidence'] ?? '') === 'Low')),
            ],
            'scan_engine'    => 'Deep Scan — Recon + Spider + Fuzz + Passive + Active + Intel + Hazard',
            'scan_profile'   => $profileName,
            'auth'           => $authMeta,
            'scan_policy'    => $policy['name'] ?? 'built-in default',
            'duration_ms'    => (int)((microtime(true) - $t0) * 1000),
            'cookie_used'    => $cookie !== '',
            'intel_error'    => $intelError,
        ],
        'severity_distribution' => $dist,
        'scan_stages'  => $stages,
        'technologies' => $spider['technologies'] ?? [],
        'endpoints'    => array_slice($spider['endpoints'] ?? [], 0, 100),
        'api_status'   => array_merge(get_api_status(), ['vulnlookup' => 'public API', 'epss' => 'enabled', 'kev' => 'enabled']),
        'exported_at'  => date('c'),
    ];

    // ---- 9. Persist ----------------------------------------------------
    $pdo = vs_db();
    if ($pdo) {
        try {
            $stmt = $pdo->prepare(
                'INSERT INTO scans (target, ip_address, risk_score, nmap_output, intelligence_data, vulnerabilities)
                 VALUES (?, ?, ?, ?, ?, ?)'
            );
            $stmt->execute([
                $host,
                $ip,
                $risk,
                substr(json_encode($enrichedPorts), 0, 65535),
                json_encode([
                    'scan_type'    => 'deep',
                    'stages'       => $stages,
                    'technologies' => $spider['technologies'] ?? [],
                    'web_port'     => $webPort,
                    'base_url'     => $base,
                ]),
                json_encode($findings, JSON_UNESCAPED_UNICODE),
            ]);
        } catch (Throwable $e) {
            error_log('DB insert (deep): ' . $e->getMessage());
        }
    }

    return $response;
}

/** Recent scan history for the dashboard. */
function vs_scan_history(int $limit = 25): array
{
    $pdo = vs_db();
    if (!$pdo) {
        return [];
    }
    try {
        $stmt = $pdo->prepare('SELECT id, target, ip_address, risk_score, timestamp, intelligence_data, vulnerabilities FROM scans ORDER BY id DESC LIMIT ?');
        $stmt->bindValue(1, max(1, min(100, $limit)), PDO::PARAM_INT);
        $stmt->execute();
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
    } catch (Throwable $e) {
        return [];
    }

    $out = [];
    foreach ($rows as $row) {
        $intel = json_decode((string)$row['intelligence_data'], true) ?: [];
        $findings = json_decode((string)$row['vulnerabilities'], true) ?: [];
        $out[] = [
            'id'         => (int)$row['id'],
            'target'     => $row['target'],
            'ip'         => $row['ip_address'],
            'risk_score' => (int)$row['risk_score'],
            'timestamp'  => $row['timestamp'],
            'scan_type'  => $intel['scan_type'] ?? 'legacy',
            'findings'   => is_array($findings) ? count($findings) : 0,
            'web_port'   => $intel['web_port'] ?? null,
        ];
    }
    return $out;
}

/** Load the latest stored scan for a target (used by report exports). */
function vs_latest_scan(string $target): ?array
{
    $pdo = vs_db();
    if (!$pdo) {
        return null;
    }
    try {
        $stmt = $pdo->prepare('SELECT * FROM scans WHERE target = ? ORDER BY id DESC LIMIT 1');
        $stmt->execute([$target]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
    } catch (Throwable $e) {
        return null;
    }
    if (!$row) {
        return null;
    }
    $intel = json_decode((string)$row['intelligence_data'], true) ?: [];
    $findings = json_decode((string)$row['vulnerabilities'], true) ?: [];
    return [
        'target'     => $row['target'],
        'ip'         => $row['ip_address'],
        'risk_score' => (int)$row['risk_score'],
        'timestamp'  => $row['timestamp'],
        'scan_type'  => $intel['scan_type'] ?? 'legacy',
        'findings'   => is_array($findings) ? $findings : [],
        'ports'      => json_decode((string)$row['nmap_output'], true) ?: [],
    ];
}

/** SARIF 2.1.0 report (GitHub code-scanning / CI friendly). */
function vs_report_sarif(array $scan): array
{
    $rules = [];
    $results = [];
    $levelFor = function (string $sev): string {
        return match ($sev) {
            'Critical', 'High' => 'error',
            'Medium', 'Low' => 'warning',
            default => 'note',
        };
    };

    foreach (($scan['findings'] ?? []) as $f) {
        $ruleId = $f['rule'] ?? ('vulnscope/' . preg_replace('/[^a-z0-9-]+/i', '-', strtolower((string)($f['id'] ?? 'finding'))));
        if (!isset($rules[$ruleId])) {
            $rules[$ruleId] = [
                'id'               => $ruleId,
                'name'             => substr((string)($f['summary'] ?? $ruleId), 0, 120),
                'shortDescription' => ['text' => substr((string)($f['summary'] ?? 'Security finding'), 0, 240)],
                'helpUri'          => $f['reference'] ?? 'https://owasp.org/www-project-top-ten/',
                'properties'       => [
                    'severity' => $f['severity'] ?? 'Info',
                    'cwe'      => $f['cwe'] ?? '',
                    'confidence' => $f['confidence'] ?? '',
                ],
            ];
        }
        $loc = $f['url'] ?? '';
        if ($loc === '' && !empty($f['port'])) {
            $loc = ($scan['target'] ?? '') . ':' . $f['port'];
        }
        $message = (string)($f['summary'] ?? 'Security finding');
        if (!empty($f['evidence'])) {
            $message .= ' Evidence: ' . $f['evidence'];
        }
        $results[] = [
            'ruleId'    => $ruleId,
            'level'     => $levelFor((string)($f['severity'] ?? 'Info')),
            'message'   => ['text' => $message],
            'locations' => $loc !== '' ? [[
                'physicalLocation' => ['artifactLocation' => ['uri' => $loc]],
            ]] : [],
            'properties' => [
                'severity'   => $f['severity'] ?? 'Info',
                'cvss'       => $f['cvss'] ?? 0,
                'cwe'        => $f['cwe'] ?? '',
                'confidence' => $f['confidence'] ?? '',
                'solution'   => $f['solution'] ?? '',
                'source'     => $f['source'] ?? '',
            ],
        ];
    }

    return [
        '$schema' => 'https://json.schemastore.org/sarif-2.1.0.json',
        'version' => '2.1.0',
        'runs'    => [[
            'tool' => ['driver' => [
                'name'           => 'VulnScope Pro',
                'informationUri' => 'https://github.com/ZeroDay-Security-Services/Vulnscope-Pro',
                'version'        => '6.0',
                'rules'          => array_values($rules),
            ]],
            'results' => $results,
            'properties' => [
                'target'     => $scan['target'] ?? '',
                'riskScore'  => $scan['risk_score'] ?? 0,
                'scannedAt'  => $scan['timestamp'] ?? date('c'),
            ],
        ]],
    ];
}

/** Self-contained HTML report (printable, no external assets). */
function vs_report_html(array $scan): string
{
    $e = fn($v) => htmlspecialchars((string)$v, ENT_QUOTES, 'UTF-8');
    $findings = $scan['findings'] ?? [];
    $counts = ['Critical' => 0, 'High' => 0, 'Medium' => 0, 'Low' => 0, 'Info' => 0];
    foreach ($findings as $f) {
        $s = $f['severity'] ?? 'Info';
        $counts[$s] = ($counts[$s] ?? 0) + 1;
    }
    $risk = (int)($scan['risk_score'] ?? 0);

    $rows = '';
    foreach ($findings as $f) {
        $sev = $f['severity'] ?? 'Info';
        $rows .= '<tr class="sev-' . $e(strtolower($sev)) . '">'
            . '<td><span class="badge">' . $e($sev) . '</span></td>'
            . '<td><strong>' . $e($f['id'] ?? '') . '</strong><div class="sub">' . $e($f['cwe'] ?? '') . '</div></td>'
            . '<td>' . $e($f['summary'] ?? '') . '</td>'
            . '<td class="mono">' . $e($f['affected_service'] ?? '') . '</td>'
            . '<td class="mono">' . $e($f['confidence'] ?? '') . '</td>'
            . '<td class="mono">' . ($f['cvss'] ? number_format((float)$f['cvss'], 1) : '—') . '</td>'
            . '</tr>';
    }

    return '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
        . '<meta name="viewport" content="width=device-width,initial-scale=1">'
        . '<title>VulnScope Pro — ' . $e($scan['target'] ?? 'Report') . '</title>'
        . '<style>'
        . 'body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:0;background:#0b1220;color:#e2e8f0}'
        . '.wrap{max-width:1080px;margin:0 auto;padding:36px 24px}'
        . 'h1{font-size:22px;margin:0 0 4px}h2{font-size:14px;text-transform:uppercase;letter-spacing:.08em;color:#7dd3fc;margin:28px 0 10px}'
        . '.muted{color:#94a3b8;font-size:12px}'
        . '.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:20px 0}'
        . '.card{background:#111c30;border:1px solid #1e293b;border-radius:12px;padding:16px}'
        . '.card .v{font-size:26px;font-weight:800;margin-top:6px}'
        . '.crit{color:#ef4444}.high{color:#f97316}.med{color:#eab308}.low{color:#22d3ee}.info{color:#94a3b8}'
        . 'table{width:100%;border-collapse:collapse;font-size:12px;background:#0f1a2c;border-radius:10px;overflow:hidden}'
        . 'th{text-align:left;padding:10px;background:#152238;font-size:10px;text-transform:uppercase;letter-spacing:.08em;color:#93c5fd}'
        . 'td{padding:10px;border-top:1px solid #1e293b;vertical-align:top}'
        . '.badge{display:inline-block;padding:2px 7px;border-radius:5px;font-size:10px;font-weight:700;text-transform:uppercase}'
        . 'tr.sev-critical .badge{background:rgba(239,68,68,.16);color:#f87171}'
        . 'tr.sev-high .badge{background:rgba(249,115,22,.16);color:#fb923c}'
        . 'tr.sev-medium .badge{background:rgba(234,179,8,.16);color:#facc15}'
        . 'tr.sev-low .badge{background:rgba(34,211,238,.12);color:#67e8f9}'
        . 'tr.sev-info .badge{background:rgba(148,163,184,.14);color:#cbd5e1}'
        . '.sub{font-size:10px;color:#64748b}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11px;word-break:break-all}'
        . 'footer{margin-top:32px;font-size:10px;color:#475569}'
        . '@media print{body{background:#fff;color:#111}.card,table{background:#fff;border-color:#ddd}th{background:#eee;color:#111}td{border-color:#eee}}'
        . '</style></head><body><div class="wrap">'
        . '<h1>VulnScope Pro — Security Assessment</h1>'
        . '<div class="muted">Target: ' . $e($scan['target'] ?? '') . ' &middot; IP: ' . $e($scan['ip'] ?? '') . ' &middot; ' . $e($scan['timestamp'] ?? date('c')) . ' &middot; ' . $e($scan['scan_type'] ?? 'scan') . '</div>'
        . '<div class="cards">'
        . '<div class="card"><div class="muted">Risk Score</div><div class="v ' . ($risk >= 80 ? 'crit' : ($risk >= 60 ? 'high' : ($risk >= 40 ? 'med' : 'low'))) . '">' . $risk . '/100</div></div>'
        . '<div class="card"><div class="muted">Findings</div><div class="v">' . count($findings) . '</div></div>'
        . '<div class="card"><div class="muted">Critical</div><div class="v crit">' . $counts['Critical'] . '</div></div>'
        . '<div class="card"><div class="muted">High</div><div class="v high">' . $counts['High'] . '</div></div>'
        . '<div class="card"><div class="muted">Medium</div><div class="v med">' . $counts['Medium'] . '</div></div>'
        . '<div class="card"><div class="muted">Low / Info</div><div class="v low">' . ($counts['Low'] + $counts['Info']) . '</div></div>'
        . '</div>'
        . '<h2>Findings</h2>'
        . '<table><thead><tr><th>Severity</th><th>ID / CWE</th><th>Finding</th><th>Affected</th><th>Confidence</th><th>CVSS</th></tr></thead>'
        . '<tbody>' . ($rows ?: '<tr><td colspan="6">No findings.</td></tr>') . '</tbody></table>'
        . '<footer>Generated by VulnScope Pro. Validate findings before remediation; automated results can contain false positives.</footer>'
        . '</div></body></html>';
}
