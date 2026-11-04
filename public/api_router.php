<?php
/**
 * VulnScope Pro - JSON API router (extracted verbatim from the monolith),
 * now also include-able from public/index.php for single-URL behavior.
 * Endpoints: scan | recon | fuzz | payloads | full | export
 */
if (isset($_GET['action'])) {
    header('Content-Type: application/json');
    header('X-Content-Type-Options: nosniff');

    // The Atom feed is a public document (Vulnerability-Lookup parity);
    // every other action stays token-gated.
    $isFeed = $_GET['action'] === 'feed';

    $token = $_SERVER['HTTP_X_VULNSCOPE_TOKEN'] ?? '';
    if ($token !== SCAN_TOKEN && !$isFeed) {
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

    /* ---- action=recon — MODULE 1 standalone ---- */
    if ($_GET['action'] === 'recon') {
        try {
            $target_raw  = trim($_POST['target'] ?? '');
            $validation  = validate_target($target_raw);
            if (!$validation) throw new Exception('Invalid or unreachable target.');
            $host = $validation['host']; $ip = $validation['ip'];
            echo json_encode(['success' => true, 'recon' => vs_module1_recon($host, $ip)], JSON_UNESCAPED_UNICODE);
        } catch (Throwable $e) {
            http_response_code(500);
            echo json_encode(['success' => false, 'message' => $e->getMessage()]);
        }
        exit;
    }

    /* ---- action=fuzz — MODULE 2 standalone ---- */
    if ($_GET['action'] === 'fuzz') {
        try {
            $target_raw  = trim($_POST['target'] ?? '');
            $validation  = validate_target($target_raw);
            if (!$validation) throw new Exception('Invalid or unreachable target.');
            $host = $validation['host']; $ip = $validation['ip'];
            $port = (int)($_POST['port'] ?? 0);
            $tls  = $port === 443 || $port === 8443 || ($port === 0 && vs_tls_probe($host, 443));
            if ($port === 0) { $port = $tls ? 443 : 80; }
            $cookie = vs_sanitize_cookie(trim((string)($_POST['cookie'] ?? '')));
            echo json_encode(['success' => true, 'fuzz' => vs_module2_fuzz($host, $port, $tls, 20, $cookie)], JSON_UNESCAPED_UNICODE);
        } catch (Throwable $e) {
            http_response_code(500);
            echo json_encode(['success' => false, 'message' => $e->getMessage()]);
        }
        exit;
    }

    /* ---- action=payloads — MODULE 3 standalone ---- */
    if ($_GET['action'] === 'payloads') {
        try {
            $target_raw  = trim($_POST['target'] ?? '');
            $validation  = validate_target($target_raw);
            if (!$validation) throw new Exception('Invalid or unreachable target.');
            $host = $validation['host']; $ip = $validation['ip'];
            $port = (int)($_POST['port'] ?? 0);
            $tls  = $port === 443 || $port === 8443 || ($port === 0 && vs_tls_probe($host, 443));
            if ($port === 0) { $port = $tls ? 443 : 80; }
            $paths  = array_filter(array_map('trim', explode("\n", (string)($_POST['paths'] ?? ''))));
            $cookie = vs_sanitize_cookie(trim((string)($_POST['cookie'] ?? '')));
            echo json_encode(['success' => true, 'payload_scan' => vs_module3_payloads($host, $port, $tls, $paths, $cookie)], JSON_UNESCAPED_UNICODE);
        } catch (Throwable $e) {
            http_response_code(500);
            echo json_encode(['success' => false, 'message' => $e->getMessage()]);
        }
        exit;
    }

    /* ---- action=full — full modular pipeline (M1 -> M2 -> M3 -> M4) ---- */
    if ($_GET['action'] === 'full') {
        try {
            $t0 = microtime(true);
            $target_raw  = trim($_POST['target'] ?? '');
            $validation  = validate_target($target_raw);
            if (!$validation) throw new Exception('Invalid or unreachable target.');
            $host = $validation['host']; $ip = $validation['ip'];
            $cookie = vs_sanitize_cookie(trim((string)($_POST['cookie'] ?? '')));

            // ---- MODULE 1: recon ----
            $module1 = vs_module1_recon($host, $ip);

            // pick a web port (prefer 80/443, else first HTTP-ish open port)
            $web_port = 0; $tls = false;
            foreach ($module1['ports'] as $p) {
                if (in_array((int)$p['port'], [80, 443, 8080, 8443, 8008, 8888, 3000, 5000], true)) {
                    $web_port = (int)$p['port'];
                    $tls      = in_array($web_port, [443, 8443], true);
                    break;
                }
            }
            if ($web_port === 0) {
                $tls = vs_tls_probe($host, 443);
                $web_port = $tls ? 443 : 80;
            }

            // ---- MODULE 2: directory fuzz ----
            $module2 = vs_module2_fuzz($host, $web_port, $tls, 20, $cookie);

            // probe the paths Module 2 found (200s first)
            $probe_paths = [];
            foreach ($module2['hits'] as $h) {
                if ($h['status'] === 200) { $probe_paths[] = $h['path']; }
            }
            $probe_paths = array_slice($probe_paths, 0, 5);

            // ---- MODULE 3: payload scan ----
            $module3 = vs_module3_payloads($host, $web_port, $tls, $probe_paths, $cookie);

            // ---- CVE INTEL: correlate M1 ports against NVD/CIRCL/OpenCVE/Shodan/Censys ----
            // Fail-open: intel outages must never kill an otherwise successful scan.
            $cve_findings = [];
            $enriched_ports = [];
            $intel_error = null;
            try {
                [$cve_findings, $enriched_ports] = vs_correlate_cves($module1['ports'], $ip);
            } catch (Throwable $ie) {
                $intel_error = $ie->getMessage();
            }

            // ---- MODULE 4: export envelope (module findings + CVE intel merged) ----
            $response = vs_module4_export($module1, $module2, $module3, $host, $ip, 0);
            $byId = [];
            foreach ($response['findings'] as $f) { $byId[$f['id']] = true; }
            foreach ($cve_findings as $cf) {
                if (empty($cf['id']) || isset($byId[$cf['id']])) { continue; }
                $byId[$cf['id']] = true;
                $response['findings'][] = $cf;
            }
            $risk = calculate_risk_score($response['findings'], count($enriched_ports) ?: count($module1['ports']));
            $response['summary']['risk_score'] = $risk;
            $response['summary']['web_port'] = $web_port;
            $response['summary']['total_findings'] = count($response['findings']);
            $response['summary']['open_ports_count'] = count($enriched_ports) ?: count($module1['ports']);
            $response['summary']['scan_engine'] = 'Modular Pipeline + CVE Intel';
            $response['summary']['duration_ms'] = (int)((microtime(true) - $t0) * 1000);
            $response['summary']['cookie_used'] = $cookie !== '';
            if ($intel_error !== null) { $response['summary']['intel_error'] = $intel_error; }

            /* ---- persist ---- */
            if ($db) {
                try {
                    $stmt = $db->prepare(
                        'INSERT INTO scans (target, ip_address, risk_score, nmap_output, intelligence_data, vulnerabilities)
                         VALUES (?, ?, ?, ?, ?, ?)'
                    );
                    $stmt->execute([
                        $host, $ip, $risk,
                        json_encode($module1['ports']),
                        json_encode(['recon' => $module1, 'fuzz' => $module2, 'payloads' => $module3]),
                        json_encode($response['findings']),
                    ]);
                } catch (Exception $e) { error_log('DB insert (full): ' . $e->getMessage()); }
            }

            echo json_encode($response, JSON_UNESCAPED_UNICODE);
        } catch (Throwable $e) {
            http_response_code(500);
            echo json_encode(['success' => false, 'message' => $e->getMessage()]);
        }
        exit;
    }

    /* ---- action=export — MODULE 4 raw envelope for last stored pipeline run ---- */
    if ($_GET['action'] === 'export') {
        try {
            if (!$db) throw new Exception('Database unavailable.');
            $stmt = $db->prepare('SELECT intelligence_data, vulnerabilities, target, ip_address, risk_score FROM scans WHERE target = ? ORDER BY id DESC LIMIT 1');
            $stmt->execute([trim($_GET['target'] ?? '')]);
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            if (!$row) throw new Exception('No stored scan for this target.');
            echo json_encode([
                'success'       => true,
                'target'        => $row['target'],
                'ip'            => $row['ip_address'],
                'risk_score'    => (int)$row['risk_score'],
                'intelligence'  => json_decode($row['intelligence_data'], true),
                'findings'      => json_decode($row['vulnerabilities'], true),
                'exported_at'   => date('c'),
            ], JSON_UNESCAPED_UNICODE);
        } catch (Throwable $e) {
            http_response_code(500);
            echo json_encode(['success' => false, 'message' => $e->getMessage()]);
        }
        exit;
    }

    /* =========================================================
       ADVANCED SCANNER ACTIONS
       deep | spider | passive | active | cve | history | report
       ========================================================= */

    /* ---- action=deep — full advanced assessment ---- */
    if ($_GET['action'] === 'deep') {
        try {
            $target_raw = trim($_POST['target'] ?? '');
            $validation = validate_target($target_raw);
            if (!$validation) throw new Exception('Invalid or unreachable target.');

            $opts = [
                'profile' => (string)($_POST['profile'] ?? $_GET['profile'] ?? 'balanced'),
                'cookie'  => trim((string)($_POST['cookie'] ?? '')),
                'port'    => (int)($_POST['port'] ?? 0) ?: ($validation['port'] ?? null),
            ];
            if (isset($_POST['max_pages']))    { $opts['max_pages'] = (int)$_POST['max_pages']; }
            if (isset($_POST['max_requests'])) { $opts['max_requests'] = (int)$_POST['max_requests']; }
            if (isset($_POST['safe']))         { $opts['aggressive'] = $_POST['safe'] !== '1'; }
            if (isset($_POST['skip_fuzz']))    { $opts['skip_fuzz'] = $_POST['skip_fuzz'] === '1'; }
            if (!empty($_POST['context_id']))  { $opts['context_id'] = trim((string)$_POST['context_id']); }
            if (!empty($_POST['policy']))      { $opts['policy'] = trim((string)$_POST['policy']); }

            echo json_encode(vs_deep_scan($validation['host'], $validation['ip'], $opts), JSON_UNESCAPED_UNICODE);
        } catch (Throwable $e) {
            http_response_code(500);
            echo json_encode(['success' => false, 'message' => $e->getMessage()]);
        }
        exit;
    }

    /* ---- action=spider — crawl only ---- */
    if ($_GET['action'] === 'spider') {
        try {
            $validation = validate_target(trim($_POST['target'] ?? ''));
            if (!$validation) throw new Exception('Invalid or unreachable target.');
            $host = $validation['host'];
            $port = (int)($_POST['port'] ?? 0) ?: (int)($validation['port'] ?? 0);
            $tls  = $port ? in_array($port, [443, 8443, 9443], true) : vs_tls_probe($host, 443);
            if (!$port) { $port = $tls ? 443 : 80; }
            $base = ($tls ? 'https' : 'http') . '://' . $host . ':' . $port;

            $spider = vs_spider($base, [
                'max_pages' => (int)($_POST['max_pages'] ?? 25),
                'max_depth' => (int)($_POST['max_depth'] ?? 2),
                'cookie'    => vs_sanitize_cookie(trim((string)($_POST['cookie'] ?? ''))),
            ]);
            echo json_encode(['success' => true, 'base_url' => $base, 'web_port' => $port, 'tls' => $tls, 'spider' => $spider], JSON_UNESCAPED_UNICODE);
        } catch (Throwable $e) {
            http_response_code(500);
            echo json_encode(['success' => false, 'message' => $e->getMessage()]);
        }
        exit;
    }

    /* ---- action=passive | active — crawl, then one rule engine ---- */
    if ($_GET['action'] === 'passive' || $_GET['action'] === 'active') {
        try {
            $validation = validate_target(trim($_POST['target'] ?? ''));
            if (!$validation) throw new Exception('Invalid or unreachable target.');
            $host = $validation['host'];
            $port = (int)($_POST['port'] ?? 0) ?: (int)($validation['port'] ?? 0);
            $tls  = $port ? in_array($port, [443, 8443, 9443], true) : vs_tls_probe($host, 443);
            if (!$port) { $port = $tls ? 443 : 80; }
            $base   = ($tls ? 'https' : 'http') . '://' . $host . ':' . $port;
            $cookie = vs_sanitize_cookie(trim((string)($_POST['cookie'] ?? '')));

            $spider = vs_spider($base, [
                'max_pages' => (int)($_POST['max_pages'] ?? 15),
                'max_depth' => 2,
                'cookie'    => $cookie,
            ]);

            if ($_GET['action'] === 'passive') {
                $fuzz = vs_module2_fuzz($host, $port, $tls, 20, $cookie);
                $result = vs_passive_scan($spider, ['base' => $base, 'port' => $port, 'fuzz' => $fuzz, 'cookie' => $cookie]);
                $findings = array_map('vs_finding_from_alert', $result['alerts']);
                echo json_encode([
                    'success'   => true,
                    'scan_type' => 'passive',
                    'target'    => $host,
                    'ip'        => $validation['ip'],
                    'base_url'  => $base,
                    'web_port'  => $port,
                    'spider'    => ['stats' => $spider['stats'], 'technologies' => $spider['technologies']],
                    'fuzz'      => ['hits' => $fuzz['hits']],
                    'passive'   => $result,
                    'findings'  => $findings,
                    'summary'   => ['target' => $host, 'ip' => $validation['ip'], 'risk_score' => calculate_risk_score($findings, 0), 'total_findings' => count($findings), 'scan_engine' => 'Passive Rules'],
                ], JSON_UNESCAPED_UNICODE);
            } else {
                $result = vs_active_scan($spider, $base, [
                    'cookie'       => $cookie,
                    'port'         => $port,
                    'max_requests' => (int)($_POST['max_requests'] ?? 120),
                    'aggressive'   => !isset($_POST['safe']) || $_POST['safe'] !== '1',
                ]);
                $findings = array_map('vs_finding_from_alert', $result['alerts']);
                echo json_encode([
                    'success'   => true,
                    'scan_type' => 'active',
                    'target'    => $host,
                    'ip'        => $validation['ip'],
                    'base_url'  => $base,
                    'web_port'  => $port,
                    'spider'    => ['stats' => $spider['stats'], 'technologies' => $spider['technologies']],
                    'active'    => $result,
                    'findings'  => $findings,
                    'summary'   => ['target' => $host, 'ip' => $validation['ip'], 'risk_score' => calculate_risk_score($findings, 0), 'total_findings' => count($findings), 'scan_engine' => 'Active Rules'],
                ], JSON_UNESCAPED_UNICODE);
            }
        } catch (Throwable $e) {
            http_response_code(500);
            echo json_encode(['success' => false, 'message' => $e->getMessage()]);
        }
        exit;
    }

    /* ---- action=cve — Vulnerability-Lookup intel ---- */
    if ($_GET['action'] === 'cve' || $_GET['action'] === 'intel') {
        try {
            $q      = trim((string)($_POST['q'] ?? $_GET['q'] ?? ''));
            $vendor = trim((string)($_POST['vendor'] ?? $_GET['vendor'] ?? ''));
            $product= trim((string)($_POST['product'] ?? $_GET['product'] ?? ''));
            $mode   = 'search';
            $result = [];

            if ($vendor !== '' && $product !== '') {
                $mode = 'vendor_product';
                $result = vl_vendor_product($vendor, $product, 30);
            } elseif ($q !== '' && preg_match('/^(?:CVE|GHSA|GCVE)-[A-Z0-9-]+$/i', $q)) {
                $mode = 'cve';
                $result = [vl_lookup_cve($q)];
            } elseif (strlen($q) >= 2) {
                $nvd    = query_nvd($q, 20);
                $circl  = query_circl($q, 20);
                $merged = [];
                foreach (array_merge($nvd, $circl) as $hit) {
                    $id = $hit['id'] ?? '';
                    if ($id !== '' && !isset($merged[$id])) { $merged[$id] = $hit; }
                }
                $result = array_values($merged);
            } else {
                throw new Exception('Provide a CVE ID, a keyword, or vendor + product.');
            }

            echo json_encode([
                'success'  => true,
                'mode'     => $mode,
                'query'    => $q !== '' ? $q : ($vendor . ' ' . $product),
                'results'  => array_values(array_filter($result)),
                'intel'    => vl_status(),
            ], JSON_UNESCAPED_UNICODE);
        } catch (Throwable $e) {
            http_response_code(400);
            echo json_encode(['success' => false, 'message' => $e->getMessage()]);
        }
        exit;
    }

    /* ---- action=history — recent scans ---- */
    if ($_GET['action'] === 'history') {
        echo json_encode(['success' => true, 'history' => vs_scan_history(30)], JSON_UNESCAPED_UNICODE);
        exit;
    }

    /* ---- action=report — SARIF / HTML / JSON from the latest stored scan ---- */
    if ($_GET['action'] === 'report') {
        try {
            $target = trim((string)($_POST['target'] ?? $_GET['target'] ?? ''));
            if ($target === '') throw new Exception('A target is required.');
            $scan = vs_latest_scan($target);
            if (!$scan) throw new Exception('No stored scan found for that target.');

            $format = strtolower((string)($_GET['format'] ?? 'json'));
            if ($format === 'html') {
                header('Content-Type: text/html; charset=utf-8');
                echo vs_report_html($scan);
            } elseif ($format === 'sarif') {
                header('Content-Disposition: attachment; filename="vulnscope-' . preg_replace('/[^a-zA-Z0-9._-]/', '_', $target) . '.sarif.json"');
                echo json_encode(vs_report_sarif($scan), JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
            } else {
                echo json_encode(['success' => true] + $scan, JSON_UNESCAPED_UNICODE);
            }
        } catch (Throwable $e) {
            http_response_code(400);
            echo json_encode(['success' => false, 'message' => $e->getMessage()]);
        }
        exit;
    }

    /* =================================================================
       COLLABORATIVE CVD LAYER (Vulnerability-Lookup parity)
       ================================================================= */

    /* ---- action=sight — sightings (GET list / POST create + as one-word and split forms) ---- */
    if ($_GET['action'] === 'sight' || $_GET['action'] === 'sightings') {
        try {
            if ($_SERVER['REQUEST_METHOD'] === 'POST') {
                $res = vs_record_sighting(
                    (string)($_POST['vuln_id'] ?? ''),
                    (string)($_POST['kind'] ?? 'seen'),
                    (string)($_POST['target'] ?? ''),
                    (string)($_POST['author'] ?? ''),
                    (string)($_POST['note'] ?? '')
                );
                if (!$res['ok']) {
                    http_response_code(400);
                    echo json_encode(['success' => false, 'message' => $res['error']]);
                } else {
                    echo json_encode([
                        'success'   => true,
                        'message'   => 'Sighting recorded (' . $res['kind'] . ').',
                        'mirror'    => $res['mirror'] ?? '',
                        'sightings' => vs_list_sightings((string)($_POST['vuln_id'] ?? ''), 60),
                    ]);
                }
            } else {
                $vuln = trim((string)($_GET['vuln_id'] ?? ''));
                echo json_encode([
                    'success'   => true,
                    'kinds'     => VS_SIGHTING_KINDS,
                    'vuln_id'   => $vuln,
                    'summary'   => $vuln !== '' ? vs_sighting_summary($vuln) : null,
                    'sightings' => vs_list_sightings($vuln, 300),
                ]);
            }
        } catch (Throwable $e) {
            http_response_code(500);
            echo json_encode(['success' => false, 'message' => $e->getMessage()]);
        }
        exit;
    }

    /* ---- action=comments — analyst notes ---- */
    if ($_GET['action'] === 'comments') {
        try {
            if ($_SERVER['REQUEST_METHOD'] === 'POST') {
                $res = vs_add_comment(
                    (string)($_POST['vuln_id'] ?? ''),
                    (string)($_POST['body'] ?? ''),
                    (string)($_POST['author'] ?? ''),
                    (string)($_POST['severity_vote'] ?? '')
                );
                if (!$res['ok']) {
                    http_response_code(400);
                    echo json_encode(['success' => false, 'message' => $res['error']]);
                } else {
                    echo json_encode([
                        'success'  => true,
                        'message'  => 'Comment saved.',
                        'comments' => vs_list_comments((string)($_POST['vuln_id'] ?? ''), 60),
                    ]);
                }
            } else {
                $vuln = trim((string)($_GET['vuln_id'] ?? ''));
                echo json_encode([
                    'success'  => true,
                    'vuln_id'  => $vuln,
                    'comments' => vs_list_comments($vuln, 300),
                    'timeline' => vs_collab_timeline($vuln, 80),
                ]);
            }
        } catch (Throwable $e) {
            http_response_code(500);
            echo json_encode(['success' => false, 'message' => $e->getMessage()]);
        }
        exit;
    }

    /* ---- action=bundles — tracked case groups ---- */
    if ($_GET['action'] === 'bundles') {
        try {
            if ($_SERVER['REQUEST_METHOD'] === 'POST') {
                $do = (string)($_POST['do'] ?? $_GET['do'] ?? 'create');
                if ($do === 'create') {
                    $res = vs_create_bundle(
                        (string)($_POST['name'] ?? ''),
                        (string)($_POST['description'] ?? ''),
                        $_POST['vuln_ids'] ?? []
                    );
                } elseif ($do === 'add' || $do === 'remove') {
                    $res = vs_bundle_modify(
                        (int)($_POST['id'] ?? 0),
                        $do === 'add' ? (array)($_POST['vuln_ids'] ?? []) : null,
                        $do === 'remove' ? (array)($_POST['vuln_ids'] ?? []) : null,
                        isset($_POST['description']) ? (string)$_POST['description'] : null
                    );
                } elseif ($do === 'delete') {
                    $res = vs_delete_bundle((int)($_POST['id'] ?? 0));
                } else {
                    throw new Exception('Unknown bundles action.');
                }
                if (!$res['ok']) {
                    http_response_code(400);
                    echo json_encode(['success' => false, 'message' => $res['error'] ?? 'Operation failed.']);
                } else {
                    echo json_encode(['success' => true, 'result' => $res, 'bundles' => vs_list_bundles()]);
                }
            } else {
                $id = (int)($_GET['id'] ?? 0);
                if ($id > 0) {
                    echo json_encode(['success' => true, 'bundle' => vs_bundle_detail($id, true)]);
                } else {
                    echo json_encode(['success' => true, 'bundles' => vs_list_bundles()]);
                }
            }
        } catch (Throwable $e) {
            http_response_code(500);
            echo json_encode(['success' => false, 'message' => $e->getMessage()]);
        }
        exit;
    }

    /* =================================================================
       WATCHLISTS + NOTIFICATIONS (Notification-model parity)
       ================================================================= */

    if ($_GET['action'] === 'watchlists') {
        try {
            $do = (string)($_POST['do'] ?? $_GET['do'] ?? '');
            if ($do === 'add') {
                $res = vs_watchlist_add(
                    (string)($_POST['vendor'] ?? ''),
                    (string)($_POST['product'] ?? ''),
                    (float)($_POST['min_cvss'] ?? 0),
                    (string)($_POST['webhook_url'] ?? ''),
                    [
                        'frequency'        => (string)($_POST['frequency'] ?? 'daily'),
                        'hazard_threshold' => (int)($_POST['hazard_threshold'] ?? 0),
                    ]
                );
                if (!$res['ok']) {
                    http_response_code(400);
                    echo json_encode(['success' => false, 'message' => $res['error']]);
                } else {
                    echo json_encode(['success' => true, 'id' => $res['id'], 'message' => 'Watchlist added.']);
                }
            } elseif ($do === 'delete') {
                $res = vs_watchlist_delete((int)($_POST['id'] ?? 0));
                echo json_encode(['success' => (bool)$res['ok'], 'message' => $res['ok'] ? 'Removed.' : 'Not found.']);
            } elseif ($do === 'check') {
                $res = vs_watchlist_check(isset($_POST['id']) ? (int)$_POST['id'] : null);
                if (!$res['ok']) {
                    throw new Exception((string)($res['error'] ?? 'check failed'));
                }
                echo json_encode([
                    'success'  => true,
                    'checked'  => $res['checked'],
                    'new'      => $res['new'],
                    'notified' => $res['notified'],
                    'errors'   => $res['errors'],
                    'watchlists' => vs_watchlists(),
                ], JSON_UNESCAPED_UNICODE);
            } else {
                echo json_encode([
                    'success'      => true,
                    'watchlists'   => vs_watchlists(),
                    'notifications'=> vs_notifications(40),
                    'pending'      => count(array_filter(
                        array_map(static fn($w) => $w['pending'] ?? 0, vs_watchlists()), fn($c) => $c > 0
                    )),
                ], JSON_UNESCAPED_UNICODE);
            }
        } catch (Throwable $e) {
            http_response_code(500);
            echo json_encode(['success' => false, 'message' => $e->getMessage()]);
        }
        exit;
    }

    if ($_GET['action'] === 'notifications') {
        echo json_encode([
            'success'       => true,
            'notifications' => vs_notifications((int)($_GET['limit'] ?? 60)),
        ], JSON_UNESCAPED_UNICODE);
        exit;
    }

    /* =================================================================
       EXPLOIT HAZARD (local Shaffer–Voicu model, single + batch)
       ================================================================= */

    if ($_GET['action'] === 'hazard') {
        try {
            if ($_SERVER['REQUEST_METHOD'] === 'POST') {
                $raw = file_get_contents('php://input');
                $body = json_decode($raw ?: '[]', true) ?: [];
                $instances = $body['instances'] ?? null;
                if (is_array($instances)) {
                    $out = vs_exploit_hazard_batch(
                        array_slice($instances, 0, 64),
                        (array)($body['parameters'] ?? []),
                        (int)($body['horizon_days'] ?? 30)
                    );
                } else {
                    $inst = $body ?: [];
                    if (!empty($_POST['vuln_id'])) {
                        $inst['vulnerability_id'] = (string)$_POST['vuln_id'];
                        $inst['cvss'] = (float)($_POST['cvss'] ?? 0);
                    }
                    if (!$inst) {
                        throw new Exception('Provide instances[] as JSON, or vuln_id/cvss parameters.');
                    }
                    $out = vs_exploit_hazard($inst);
                }
                echo json_encode(['success' => true] + (is_array($out) && isset($out['instances']) ? $out : ['instance' => $out]), JSON_UNESCAPED_UNICODE);
            } else {
                $vuln = strtoupper(trim((string)($_GET['vuln_id'] ?? '')));
                if (!preg_match('/^(CVE|GHSA|GCVE)-[A-Z0-9-]+$/i', $vuln)) {
                    throw new Exception('vuln_id (CVE/GHSA/GCVE) is required.');
                }
                $rec = ['vulnerability_id' => $vuln];
                if (($_GET['cvss'] ?? '') !== '') $rec['cvss'] = (float)$_GET['cvss'];
                if (($_GET['vector'] ?? '') !== '') $rec['vector'] = (string)$_GET['vector'];
                if (($_GET['published'] ?? '') !== '') $rec['published'] = (string)$_GET['published'];
                $out = vs_exploit_hazard($rec);
                echo json_encode(['success' => true, 'instance' => $out], JSON_UNESCAPED_UNICODE);
            }
        } catch (Throwable $e) {
            http_response_code(400);
            echo json_encode(['success' => false, 'message' => $e->getMessage()]);
        }
        exit;
    }

    /* =================================================================
       RECENT INTELLIGENCE FEED + top sightings (browse VL feeders)
       ================================================================= */

    if ($_GET['action'] === 'recent') {
        try {
            $source = trim((string)($_GET['source'] ?? ''));
            $limit  = (int)($_GET['limit'] ?? 24);
            $items  = vl_recent_by_source($source, $limit);
            $top    = [];
            try {
                $top = vl_top_sightings(10);
            } catch (Throwable $e) { /* stats may not be exposed */ }
            echo json_encode([
                'success'    => true,
                'source'     => $source ?: 'all',
                'sources'    => [
                    'cvelistv5'  => 'CVE List v5 (CVE Project)',
                    'github'     => 'GitHub Advisory Database',
                    'nvd'        => 'NVD (API 2.0 mirror)',
                    'pysec'      => 'PySec advisory database',
                    'gsd'        => 'Global Security Database',
                    'csaf_cisa'  => 'CISA advisories (CSAF)',
                    'certfr_avis'=> 'CERT-FR advisories',
                    'jvndb'      => 'JVN iPedia (Japan)',
                    'tailscale'  => 'Tailscale advisories',
                ],
                'recent'     => array_slice($items, 0, $limit),
                'most_sighted'=> $top,
                'intel'      => vl_status(),
            ], JSON_UNESCAPED_UNICODE);
        } catch (Throwable $e) {
            http_response_code(500);
            echo json_encode(['success' => false, 'message' => $e->getMessage()]);
        }
        exit;
    }

    /* ---- action=feed — Atom feed of local sightings/bundles + recent KEV/intel ---- */
    if ($_GET['action'] === 'feed') {
        header('Content-Type: application/atom+xml; charset=utf-8');
        $now = date(DATE_ATOM);
        $entries = [];
        foreach (vs_collab_timeline('', 25) as $ev) {
            $entries[] = [
                'title' => ($ev['type'] === 'sighting' ? '[Sighting ' . $ev['kind'] . '] ' : '[Comment] ') . $ev['vuln'],
                'link'  => vl_base() . '/vuln/' . rawurlencode($ev['vuln']),
                'date'  => (string)$ev['ts'],
                'body'  => trim((string)($ev['note'] ?? '')) . ($ev['target'] ? ' — on ' . $ev['target'] : ''),
            ];
        }
        foreach (array_slice(vl_latest(10), 0, 10) as $rec) {
            $entries[] = [
                'title' => '[New advisory] ' . $rec['id'] . ' (' . $rec['severity'] . ' ' . $rec['cvss'] . ')',
                'link'  => vl_base() . '/vuln/' . rawurlencode($rec['id']),
                'date'  => $rec['published'] !== '' ? substr($rec['published'], 0, 10) : $now,
                'body'  => mb_substr($rec['summary'], 0, 280),
            ];
        }
        echo '<?xml version="1.0" encoding="utf-8"?>' . "\n";
        echo '<feed xmlns="http://www.w3.org/2005/Atom"><title>VulnScope Pro — local advisories feed</title>';
        echo '<id>https://vulnscope.local/feed</id><updated>' . $now . '</updated>';
        $esc = static fn($s) => htmlspecialchars((string)$s, ENT_QUOTES | ENT_XML1, 'UTF-8');
        foreach (array_slice($entries, 0, 35) as $e) {
            echo '<entry><title>' . $esc($e['title']) . '</title><id>' . $esc($e['title'] . $e['date']) . '</id>';
            echo '<link rel="alternate" href="' . $esc($e['link']) . '"/><updated>' . $esc((string)$e['date']) . '</updated>';
            echo '<content type="text">' . $esc($e['body']) . '</content></entry>';
        }
        echo '</feed>';
        exit;
    }

    /* =================================================================
       HTTP PROXY HISTORY + REPLAY (ZAP parity)
       ================================================================= */

    if ($_GET['action'] === 'proxy') {
        try {
            $do = (string)($_POST['do'] ?? $_GET['do'] ?? '');
            if ($do === 'replay' || $_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['url'])) {
                $res = vs_compose_request([
                    'method'  => (string)($_POST['method'] ?? 'GET'),
                    'url'     => (string)($_POST['url'] ?? ''),
                    'headers' => is_array($_POST['headers'] ?? null) ? $_POST['headers'] : [],
                    'body'    => (string)($_POST['body'] ?? ''),
                    'timeout' => (int)($_POST['timeout'] ?? 10000),
                ]);
                if (!$res['ok']) {
                    http_response_code(400);
                    echo json_encode(['success' => false, 'message' => $res['error']]);
                } else {
                    echo json_encode(['success' => true, 'response' => $res], JSON_UNESCAPED_UNICODE);
                }
            } elseif ($do === 'purge') {
                vs_history_purge(5000);
                echo json_encode(['success' => true, 'message' => 'History trimmed to latest 5000 entries.']);
            } else {
                if (mt_rand(1, 20) === 7) {
                    vs_history_purge(5000);
                }
                $filters = [];
                foreach (['host', 'type', 'status', 'q'] as $f) {
                    if (isset($_GET[$f]) && $_GET[$f] !== '') {
                        $filters[$f] = trim((string)$_GET[$f]);
                    }
                }
                echo json_encode([
                    'success' => true,
                    'filters' => $filters,
                    'entries' => vs_history($filters, (int)($_GET['limit'] ?? 150)),
                    'hosts'   => vs_history_hosts(),
                ], JSON_UNESCAPED_UNICODE);
            }
        } catch (Throwable $e) {
            http_response_code(500);
            echo json_encode(['success' => false, 'message' => $e->getMessage()]);
        }
        exit;
    }

    /* =================================================================
       SCAN CONTEXTS (auth) + POLICIES
       ================================================================= */

    if ($_GET['action'] === 'contexts') {
        try {
            $do = (string)($_POST['do'] ?? '');
            if ($do === 'save') {
                $res = vs_context_save($_POST);
                if (!$res['ok']) {
                    throw new Exception((string)$res['error']);
                }
                echo json_encode(['success' => true, 'message' => 'Context saved.', 'contexts' => vs_contexts()]);
            } elseif ($do === 'delete') {
                $res = vs_context_delete((int)($_POST['id'] ?? 0));
                echo json_encode(['success' => (bool)$res['ok'], 'message' => $res['ok'] ? 'Deleted.' : 'Not found.']);
            } elseif ($do === 'test') {
                $ctx = vs_context_get((int)($_POST['id'] ?? 0));
                if (!$ctx) {
                    throw new Exception('Context not found.');
                }
                $sess = vs_context_session($ctx);
                echo json_encode([
                    'success'   => !empty($sess['cookie']) || !empty($sess['basic_user'] ?? ''),
                    'login_status' => $sess['login_status'] ?? 0,
                    'auth_type' => $ctx['auth_type'],
                    'detail'    => !empty($sess['cookie']) ? 'Session cookie captured for context.' : 'No cookie captured — check auth_url/credentials.',
                ]);
            } else {
                echo json_encode(['success' => true, 'auth_types' => VS_AUTH_TYPES, 'contexts' => vs_contexts()]);
            }
        } catch (Throwable $e) {
            http_response_code(400);
            echo json_encode(['success' => false, 'message' => $e->getMessage()]);
        }
        exit;
    }

    if ($_GET['action'] === 'policies') {
        try {
            $do = (string)($_POST['do'] ?? '');
            if ($do === 'save') {
                $res = vs_policy_save(
                    (string)($_POST['name'] ?? ''),
                    is_array($_POST['config'] ?? null) ? $_POST['config'] : [],
                    (($_POST['default'] ?? '') === '1')
                );
                if (!$res['ok']) {
                    throw new Exception((string)$res['error']);
                }
                echo json_encode(['success' => true, 'message' => 'Policy saved.', 'policies' => vs_policies()]);
            } elseif ($do === 'delete') {
                $res = vs_policy_delete((int)($_POST['id'] ?? 0));
                echo json_encode(['success' => (bool)$res['ok'], 'message' => $res['ok'] ? 'Deleted.' : 'Not found.']);
            } else {
                echo json_encode([
                    'success' => true,
                    'groups'  => VS_RULE_GROUPS,
                    'policies'=> vs_policies(),
                ]);
            }
        } catch (Throwable $e) {
            http_response_code(400);
            echo json_encode(['success' => false, 'message' => $e->getMessage()]);
        }
        exit;
    }

    /* ---- action=stats — platform KPIs ---- */
    if ($_GET['action'] === 'stats') {
        $pdo = vs_db();
        $s = [
            'scans'        => 0,
            'targets'      => 0,
            'findings'     => 0,
            'criticals'    => 0,
            'sightings'    => 0,
            'comments'     => 0,
            'bundles'      => 0,
            'watchlists'   => 0,
            'proxy_entries'=> 0,
            'contexts'     => 0,
            'policies'     => 0,
        ];
        if ($pdo) {
            try {
                $s['scans']      = (int)$pdo->query('SELECT COUNT(*) FROM scans')->fetchColumn();
                $s['targets']    = (int)$pdo->query('SELECT COUNT(DISTINCT target) FROM scans')->fetchColumn();
                $s['sightings']  = (int)$pdo->query('SELECT COUNT(*) FROM sightings')->fetchColumn();
                $s['comments']   = (int)$pdo->query('SELECT COUNT(*) FROM comments')->fetchColumn();
                $s['bundles']    = (int)$pdo->query('SELECT COUNT(*) FROM bundles')->fetchColumn();
                $s['watchlists'] = (int)$pdo->query('SELECT COUNT(*) FROM watchlists')->fetchColumn();
                $s['proxy_entries'] = (int)$pdo->query('SELECT COUNT(*) FROM http_history')->fetchColumn();
                $s['contexts']   = (int)$pdo->query('SELECT COUNT(*) FROM contexts')->fetchColumn();
                $s['policies']   = (int)$pdo->query('SELECT COUNT(*) FROM scan_policies')->fetchColumn();
                $rows = $pdo->query('SELECT vulnerabilities FROM scans ORDER BY id DESC LIMIT 40')->fetchAll(PDO::FETCH_COLUMN);
                foreach ($rows as $j) {
                    $f = json_decode((string)$j, true) ?: [];
                    $s['findings'] += count($f);
                    foreach ($f as $fi) {
                        if (($fi['severity'] ?? '') === 'Critical') $s['criticals']++;
                    }
                }
            } catch (Throwable $e) { /* fresh DB: zeros */ }
        }
        echo json_encode(['success' => true, 'stats' => $s]);
        exit;
    }
}

