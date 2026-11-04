<?php
/**
 * VulnScope Pro — Module 1: recon (DNS / NS / ports / banners / whois / RDAP).
 */
declare(strict_types=1);


/**
 * MODULE 1 — Comprehensive Recon (no-Nmap discovery).
 * Returns: dns, nameservers, ports, banners, whois — structured JSON.
 */
function vs_module1_recon(string $host, string $ip): array {
    $recon = [
        'host'         => $host,
        'ip'           => $ip,
        'timestamp'    => date('c'),
        'dns'          => ['A' => [], 'AAAA' => [], 'MX' => [], 'TXT' => [], 'CNAME' => [], 'NS' => []],
        'nameservers'  => [],
        'ports'        => [],
        'banners'      => [],
        'whois'        => null,
        'errors'       => [],
    ];

    // ---- DNS: A / AAAA / MX / TXT / CNAME / NS ----
    foreach (['A' => DNS_A, 'AAAA' => DNS_AAAA, 'MX' => DNS_MX, 'TXT' => DNS_TXT, 'CNAME' => DNS_CNAME, 'NS' => DNS_NS] as $type => $const) {
        try {
            $records = @dns_get_record($host, $const);
            if (!is_array($records)) { $records = []; }
            foreach ($records as $r) {
                switch ($type) {
                    case 'A':
                        if (!empty($r['ip']))  $recon['dns']['A'][]     = $r['ip'];
                        break;
                    case 'AAAA':
                        if (!empty($r['ipv6'])) $recon['dns']['AAAA'][] = $r['ipv6'];
                        break;
                    case 'MX':
                        if (!empty($r['target'])) $recon['dns']['MX'][] = ['pri' => (int)($r['pri'] ?? 0), 'target' => $r['target']];
                        break;
                    case 'TXT':
                        if (!empty($r['txt'])) $recon['dns']['TXT'][]   = $r['txt'];
                        break;
                    case 'CNAME':
                        if (!empty($r['target'])) $recon['dns']['CNAME'][] = $r['target'];
                        break;
                    case 'NS':
                        if (!empty($r['target'])) $recon['nameservers'][] = $r['target'];
                        break;
                }
            }
        } catch (Throwable $e) {
            $recon['errors'][] = "DNS {$type}: " . $e->getMessage();
        }
    }
    if ($recon['dns']['A'] === [] && $host === $ip) { $recon['dns']['A'][] = $ip; }
    $recon['dns']['NS'] = array_values(array_unique($recon['nameservers']));

    // ---- Port scan + banner grab: Nmap engine when the binary exists, PHP sockets otherwise ----
    try {
        $raw_xml  = run_nmap($host);
        $recon['scan_engine'] = (strpos($raw_xml, 'php-socket-fallback') !== false) ? 'PHP Socket' : 'Nmap';
        $scan_xml = @simplexml_load_string($raw_xml);
        if ($scan_xml) {
            foreach ($scan_xml->host->ports->port as $p) {
                $portId  = (string)$p['portid'];
                $product = (string)($p->service['product'] ?? '');
                $version = (string)($p->service['version'] ?? '');
                $recon['ports'][] = [
                    'port'    => $portId,
                    'state'   => (string)($p->state['state'] ?? 'unknown'),
                    'service' => (string)($p->service['name'] ?? 'unknown'),
                    'product' => $product,
                    'version' => $version,
                ];
                if ($version !== '') {
                    $recon['banners'][] = ['port' => $portId, 'banner' => $version];
                }
            }
        }
    } catch (Throwable $e) {
        $recon['errors'][] = 'Port scan: ' . $e->getMessage();
    }

    // ---- Whois: raw socket (IANA referral chain) with RDAP-over-HTTPS fallback ----
    try {
        $recon['whois'] = vs_whois_lookup($host);
    } catch (Throwable $e) {
        $recon['errors'][] = 'Whois: ' . $e->getMessage();
    }

    return $recon;
}


/**
 * Raw-socket whois: IANA -> registrar referral chain, parsed into structured fields.
 */
function vs_native_whois(string $domain): ?array {
    $req = function (string $server, string $query, int $timeout = 8): string {
        $fp = @fsockopen($server, 43, $errno, $errstr, $timeout);
        if (!$fp) { throw new Exception("whois {$server}: {$errstr}"); }
        stream_set_timeout($fp, $timeout);
        fwrite($fp, $query . "\r\n");
        $out = '';
        while (!feof($fp)) { $out .= fgets($fp, 4096); }
        fclose($fp);
        return $out;
    };

    $grab = function (string $raw) use ($req): array {
        $data = [];
        $patterns = [
            'domain_name'   => '/Domain Name:\s*(.+)/i',
            'registrar'     => '/Registrar:\s*(.+)/i',
            'registrar_url' => '/Registrar URL:\s*(.+)/i',
            'registrar_abuse_email' => '/Abuse Contact Email:\s*(.+)/i',
            'creation_date' => '/Creation Date:\s*(.+)/i',
            'updated_date'  => '/Updated Date:\s*(.+)/i',
            'expiry_date'   => '/Registry Expiry Date:\s*(.+)/i',
            'dnssec'        => '/DNSSEC:\s*(.+)/i',
            'status'        => '/Domain Status:\s*(.+)/i',
            'name_servers'  => '/Name Server:\s*(.+)/i',
        ];
        foreach ($patterns as $key => $re) {
            if ($key === 'name_servers') {
                if (preg_match_all($re, $raw, $m)) { $data[$key] = array_map('trim', array_unique($m[1])); }
            } elseif (preg_match($re, $raw, $m)) {
                $data[$key] = trim($m[1]);
            }
        }
        return $data;
    };

    $raw = $req('whois.iana.org', $domain);
    $referral = null;
    if (preg_match('/refer:\s*(\S+)/i', $raw, $m)) {
        $referral = $m[1];
    } elseif (preg_match('/whois:\s*(\S+)/i', $raw, $m)) {
        $referral = $m[1];
    } elseif (preg_match('/Whois Server:\s*(\S+)/i', $raw, $m)) {
        $referral = $m[1];
    }
    $ianaData = $grab($raw);
    if (!$referral) { return $ianaData ?: null; }

    $regRaw = $req($referral, $domain);
    $regData = $grab($regRaw);
    return array_merge($ianaData, $regData);
}


/** Whois with fallback: raw socket first, RDAP-over-HTTPS when port 43 is blocked. */
function vs_whois_lookup(string $domain): ?array {
    try {
        return vs_native_whois($domain);
    } catch (Throwable $e) {
        $rdap = vs_rdap_whois($domain);
        if ($rdap) { return $rdap; }
        throw $e;
    }
}


/** RDAP whois fallback over HTTPS (registration data via REST). */
function vs_rdap_whois(string $domain): ?array {
    $tld = strtolower(substr($domain, strrpos($domain, '.') + 1));
    if (in_array($tld, ['bd', 'np', 'pk', 'lk', 'ir', 'sy', 'cu', 'kp'], true)) { return null; }
    $ch = curl_init('https://rdap.org/domain/' . rawurlencode($domain));
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 12,
        CURLOPT_CONNECTTIMEOUT => 5,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_USERAGENT      => 'VulnScope-Pro/5.0 (Security Research)',
    ]);
    $body = curl_exec($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    if ($code !== 200 || !is_string($body)) { return null; }
    $j = json_decode($body, true);
    if (!is_array($j)) { return null; }

    $data = ['source' => 'RDAP (HTTPS fallback)'];
    $data['domain_name'] = $j['ldhName'] ?? ($j['unicodeName'] ?? '');
    foreach ($j['events'] ?? [] as $ev) {
        $action = $ev['eventAction'] ?? '';
        if ($action === 'registration')      { $data['creation_date'] = $ev['eventDate'] ?? ''; }
        elseif ($action === 'last changed')  { $data['updated_date']  = $ev['eventDate'] ?? ''; }
        elseif ($action === 'expiration')    { $data['expiry_date']   = $ev['eventDate'] ?? ''; }
    }
    foreach ($j['entities'] ?? [] as $e) {
        if (in_array('registrar', $e['roles'] ?? [], true)) {
            foreach ($e['vcardArray'][1] ?? [] as $item) {
                if (($item[0] ?? '') === 'fn') { $data['registrar'] = $item[3] ?? ''; }
            }
            foreach ($e['publicIds'] ?? [] as $pid) {
                if (($pid['type'] ?? '') === 'IANA Registrar ID') { $data['iana_id'] = $pid['identifier'] ?? ''; }
            }
            foreach ($e['links'] ?? [] as $l) {
                if (!empty($l['href'])) { $data['registrar_url'] = $l['href']; }
            }
        }
    }
    foreach ($j['nameservers'] ?? [] as $ns) {
        if (!empty($ns['ldhName'])) { $data['name_servers'][] = $ns['ldhName']; }
    }
    foreach ($j['status'] ?? [] as $st) { $data['status'][] = $st; }
    return array_filter($data, fn($v) => $v !== '' && $v !== []);
}

