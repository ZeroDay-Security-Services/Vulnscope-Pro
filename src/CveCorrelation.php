<?php
/**
 * VulnScope Pro — CVE correlation engine.
 * Turns open service fingerprints into CVE findings via intel feeds.
 */
declare(strict_types=1);




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


/**
 * CVE correlation core (shared with the legacy engine): turns an open-port
 * list into real CVE findings via NVD/CIRCL/OpenCVE keyword lookups + Shodan.
 * Returns [findings (flat), open_ports (enriched with Shodan/Censys intel)].
 */
function vs_correlate_cves(array $module1_ports, string $ip): array {
    $findings   = [];
    $open_ports = [];
    foreach ($module1_ports as $p) {
        if (($p['state'] ?? '') !== 'open' && ($p['state'] ?? '') !== 'open|filtered') { continue; }
        $open_ports[] = $p;
    }
    if (!$open_ports) { return [[], []]; }

    $add_finding = function (array $hit, string $port_id, string $service_label) use (&$findings): void {
        $hit['affected_service'] = $hit['affected_service'] ?? $service_label;
        $hit['port']             = $hit['port'] ?? $port_id;
        $id = $hit['id'];
        if (!isset($findings[$id])) { $findings[$id] = $hit; return; }
        $src = $hit['source'] ?? '';
        if ($src && !str_contains($findings[$id]['source'] ?? '', $src)) { $findings[$id]['source'] .= ' / ' . $src; }
        if (($findings[$id]['cvss'] ?? 0) == 0 && ($hit['cvss'] ?? 0) > 0) {
            $findings[$id]['cvss']     = $hit['cvss'];
            $findings[$id]['severity'] = $hit['severity'];
        }
    };

    $all_kw_map = [];
    foreach ($open_ports as $p) {
        $port_id  = (string)($p['port'] ?? '');
        $svc_name = (string)($p['service'] ?? '');
        $product  = (string)($p['product'] ?? '');
        $version  = (string)($p['version'] ?? '');
        $port_int = (int)$port_id;

        $inferred = [];
        if (empty($product) || in_array(strtolower($svc_name), ['tcpwrapped', 'unknown', ''], true)) {
            [$inf_svc, $inf_prod, $inf_kw] = port_to_products($port_int);
            if ($inf_prod !== 'unknown') {
                if (empty($product))  { $product  = $inf_prod; }
                if (empty($svc_name)) { $svc_name = $inf_svc; }
                $inferred = $inf_kw;
            }
        }

        $keywords = [];
        if ($product && !in_array(strtolower($product), ['tcpwrapped', 'unknown'], true)) {
            $norm = normalize_product($product);
            if ($norm) {
                $keywords[] = $norm;
                if ($version) { $keywords[] = $norm . ' ' . $version; }
            }
        }
        foreach ($inferred as $kw) {
            $normalized = normalize_product($kw);
            if ($normalized) { $keywords[] = $normalized; }
        }
        if ($svc_name && !in_array(strtolower($svc_name), ['tcpwrapped', 'unknown', 'http', 'https', 'ssl'], true)) {
            $keywords[] = $svc_name;
        }
        $keywords = array_unique(array_filter($keywords));
        $service_label = trim("$product $version") ?: "Port $port_id";

        $keywords = empty($inferred) ? array_slice($keywords, 0, 3) : array_slice($keywords, 0, 1);
        foreach ($keywords as $kw) {
            if (strlen(trim($kw)) >= 2) { $all_kw_map[$kw][] = ['port_id' => $port_id, 'service_label' => $service_label]; }
        }
    }

    // Cap API fan-out: 8 keywords ≈ 16-24 upstream requests per scan.
    $all_kw_map = array_slice($all_kw_map, 0, 8, true);

    if ($all_kw_map) {
        $requests = [];
        $req_meta = [];
        foreach (array_keys($all_kw_map) as $kw) {
            $kw_enc = urlencode($kw);
            if (NVD_API_KEY) {
                $req_meta[] = ['source' => 'nvd', 'kw' => $kw];
                $requests[] = ['url' => NVD_API_BASE . '?keywordSearch=' . $kw_enc . '&resultsPerPage=25', 'headers' => ['apiKey: ' . NVD_API_KEY], 'timeout' => 12];
            }
            $req_meta[] = ['source' => 'circl', 'kw' => $kw];
            $requests[] = ['url' => CIRCL_API_BASE . 'search/' . $kw_enc, 'headers' => [], 'timeout' => 10];
            if (OPENCVE_USER && OPENCVE_PASS) {
                $req_meta[] = ['source' => 'opencve', 'kw' => $kw];
                $requests[] = ['url' => OPENCVE_API_BASE . 'cves?search=' . $kw_enc . '&limit=20', 'headers' => ['Accept: application/json'], 'userpwd' => OPENCVE_USER . ':' . OPENCVE_PASS, 'timeout' => 12];
            }
        }

        foreach (safe_curl_multi($requests) as $i => $data) {
            if (!$data || !is_array($data)) { continue; }
            $meta = $req_meta[$i];
            $kw   = $meta['kw'];
            $src  = $meta['source'];
            $hits = [];
            if ($src === 'nvd') {
                foreach ($data['vulnerabilities'] ?? [] as $v) {
                    $cve = $v['cve'] ?? [];
                    $id  = $cve['id'] ?? '';
                    if (!$id) { continue; }
                    $score = 0; $vector = '';
                    foreach (['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'] as $mk) {
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
                        $cwe = $w['description'][0]['value'] ?? ''; if ($cwe) { break; }
                    }
                    $hits[] = ['id' => $id, 'cvss' => (float)$score, 'severity' => classify_severity($score), 'summary' => $desc, 'source' => 'NVD', 'vector' => $vector, 'cwe' => $cwe, 'published' => substr($cve['published'] ?? '', 0, 10)];
                }
            } elseif ($src === 'circl') {
                $items = isset($data[0]) ? $data : ($data['results'] ?? []);
                foreach (array_slice($items, 0, 15) as $cve) {
                    $id = $cve['id'] ?? ($cve['cve_id'] ?? '');
                    if (!$id) { continue; }
                    $score = (float)($cve['cvss'] ?? $cve['cvss_score'] ?? 0);
                    $hits[] = ['id' => $id, 'cvss' => $score, 'severity' => classify_severity($score), 'summary' => $cve['summary'] ?? $cve['description'] ?? 'No summary.', 'source' => 'CIRCL', 'vector' => $cve['cvss-vector'] ?? '', 'cwe' => $cve['cwe'] ?? '', 'published' => substr($cve['Published'] ?? $cve['published'] ?? '', 0, 10)];
                }
            } elseif ($src === 'opencve') {
                $items = $data['results'] ?? $data;
                if (!is_array($items)) { continue; }
                foreach (array_slice($items, 0, 20) as $item) {
                    $id = $item['cve_id'] ?? $item['id'] ?? '';
                    if (!$id) { continue; }
                    $score = 0; $vector = '';
                    foreach (['cvssV31', 'cvssV30', 'cvssV2'] as $mk) {
                        if (!empty($item['metrics'][$mk]['data']['score'])) {
                            $score  = (float)$item['metrics'][$mk]['data']['score'];
                            $vector = $item['metrics'][$mk]['data']['vector'] ?? '';
                            break;
                        }
                    }
                    if (!$score && isset($item['cvss'])) { $score = (float)$item['cvss']; }
                    $desc = '';
                    if (!empty($item['description'])) {
                        if (is_string($item['description'])) { $desc = $item['description']; }
                        elseif (is_array($item['description'])) {
                            foreach ($item['description'] as $d) {
                                if (($d['lang'] ?? '') === 'en') { $desc = $d['value']; break; }
                            }
                            if (!$desc) { $desc = $item['description'][0]['value'] ?? ''; }
                        }
                    }
                    $hits[] = ['id' => $id, 'cvss' => $score, 'severity' => classify_severity($score), 'summary' => $desc ?: 'No description.', 'source' => 'OpenCVE', 'vector' => $vector, 'cwe' => $item['cwe'] ?? '', 'published' => substr($item['created_at'] ?? $item['published'] ?? '', 0, 10)];
                }
            }

            foreach ($hits as $hit) {
                foreach ($all_kw_map[$kw] as $ctx) {
                    $add_finding($hit, $ctx['port_id'], $ctx['service_label']);
                }
            }
        }
    }

    // Shodan: internet-exposure CVEs + ports our scanner missed.
    $shodan_data = query_shodan($ip);
    foreach (($shodan_data['vulns'] ?? []) as $hit) {
        if (!isset($findings[$hit['id']])) {
            $hit['port']             = $hit['port'] ?? 'External';
            $hit['affected_service'] = $hit['affected_service'] ?? 'Internet-facing exposure (Shodan)';
            $findings[$hit['id']]    = $hit;
        } else {
            if (!str_contains($findings[$hit['id']]['source'], 'Shodan')) { $findings[$hit['id']]['source'] .= ' / Shodan'; }
            if (($findings[$hit['id']]['cvss'] ?? 0) == 0 && ($hit['cvss'] ?? 0) > 0) {
                $findings[$hit['id']]['cvss']     = $hit['cvss'];
                $findings[$hit['id']]['severity'] = $hit['severity'];
            }
        }
    }
    $existing_ports = array_column($open_ports, 'port');
    foreach (($shodan_data['ports'] ?? []) as $sp) {
        if (!in_array($sp, $existing_ports)) {
            $open_ports[] = ['port' => $sp, 'service' => 'unknown', 'product' => 'Observed by Shodan', 'version' => ''];
        }
    }

    // Censys: service enrichment + product CVE lookups.
    $censys_data = query_censys($ip);
    if ($censys_data && !isset($censys_data['error'])) {
        foreach (extract_censys_services($censys_data) as $csvc) {
            $port_id = $csvc['port'];
            $product = $csvc['product'];
            $version = $csvc['version'];

            $found = false;
            foreach ($open_ports as &$op) {
                if ($op['port'] == $port_id) {
                    if (empty($op['product']) && $product) { $op['product'] = $product; }
                    if (empty($op['version']) && $version) { $op['version'] = $version; }
                    $found = true; break;
                }
            }
            unset($op);
            if (!$found && $port_id) {
                $open_ports[] = ['port' => $port_id, 'service' => $csvc['service'], 'product' => $product, 'version' => $version];
            }

            if ($product) {
                $norm = normalize_product($product);
                foreach (query_nvd($norm . ' ' . $version, 20) as $hit) {
                    $hit['affected_service'] = "$product $version";
                    $hit['port']             = $port_id;
                    if (!isset($findings[$hit['id']])) { $findings[$hit['id']] = $hit; }
                }
                foreach (query_circl($norm, 10) as $hit) {
                    $hit['affected_service'] = "$product $version";
                    $hit['port']             = $port_id;
                    if (!isset($findings[$hit['id']])) { $findings[$hit['id']] = $hit; }
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
        if ($sa !== $sb) { return $sb - $sa; }
        return $b['cvss'] <=> $a['cvss'];
    });

    return [$findings, $open_ports];
}

