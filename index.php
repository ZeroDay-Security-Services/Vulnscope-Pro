<?php
/**
 * VulnScope Pro � ZeroDay Security Edition (Enterprise Intel Refactor)
 * Modular Intelligence Engine: NVD v2, Shodan, Censys v2 (Bearer Auth), CIRCL
 */

// 1. Initial configuration & Constant Safety
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Security Configuration
defined('DB_PATH') or define('DB_PATH', 'vulnscope_v2.sqlite');
defined('SCAN_TOKEN') or define('SCAN_TOKEN', 'SECURE_SCAN_TOKEN_2024');
defined('ALLOW_INTERNAL_SCAN') or define('ALLOW_INTERNAL_SCAN', true);

// API Environment Variables (Strictly retrieved via getenv)
define('NVD_API_KEY', getenv('NVD_API_KEY')); 
define('SHODAN_API_KEY', getenv('SHODAN_API_KEY')); 
define('CENSYS_API_TOKEN', getenv('CENSYS_API_TOKEN'));
define('CIRCL_API_BASE', 'https://cve.circl.lu/api/');

error_reporting(E_ALL);
ini_set('display_errors', 0);
set_time_limit(300); // 5 mins for high-intensity intel gathering

/**
 * DATABASE INITIALIZATION
 */
$db = null;
if (extension_loaded('pdo_sqlite')) {
    try {
        $db = new PDO("sqlite:" . DB_PATH);
        $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $db->exec("CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            ip_address TEXT,
            risk_score INTEGER,
            nmap_output TEXT,
            intelligence_data TEXT,
            vulnerabilities TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )");
    } catch (Exception $e) {
        error_log("Database warning: " . $e->getMessage());
    }
}

/**
 * CORE MODULES
 */

function safe_curl($url, $headers = [], $auth = null, $timeout = 15) {
    $ch = curl_init($url);
    $options = [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => $timeout,
        CURLOPT_CONNECTTIMEOUT => 5,
        CURLOPT_USERAGENT => 'VulnScope-Pro-Enterprise/4.0',
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_HTTPHEADER => $headers
    ];
    if ($auth) {
        curl_setopt($ch, CURLOPT_USERPWD, $auth);
    }
    curl_setopt_array($ch, $options);
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    if ($httpCode >= 400 || !$response) return null;
    return json_decode($response, true);
}

function get_api_status() {
    return [
        'nvd' => NVD_API_KEY ? 'configured' : 'missing',
        'shodan' => SHODAN_API_KEY ? 'configured' : 'missing',
        'censys' => CENSYS_API_TOKEN ? 'configured' : 'missing'
    ];
}

function normalize_product($product) {
    $product = str_replace(['_', '-'], ' ', $product);
    return trim(str_ireplace(['httpd', 'server', 'service'], '', $product));
}

function classify_severity($cvss) {
    $cvss = (float)$cvss;
    if ($cvss >= 9.0) return 'Critical';
    if ($cvss >= 7.0) return 'High';
    if ($cvss >= 4.0) return 'Medium';
    if ($cvss > 0) return 'Low';
    return 'Info';
}

function calculate_risk_score($findings) {
    $weights = ['Critical' => 10, 'High' => 7, 'Medium' => 4, 'Low' => 1, 'Info' => 0];
    $score = 0;
    foreach ($findings as $f) {
        $score += $weights[$f['severity']] ?? 0;
    }
    return min(100, $score);
}

/**
 * INTELLIGENCE SOURCES
 */

function query_nvd($keyword) {
    if (!NVD_API_KEY) return [];
    $url = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=" . urlencode($keyword);
    $res = safe_curl($url, ["apiKey: " . NVD_API_KEY]);
    $results = [];
    if (isset($res['vulnerabilities'])) {
        foreach ($res['vulnerabilities'] as $v) {
            $cve = $v['cve'];
            $score = 0;
            if (isset($cve['metrics']['cvssMetricV31'])) $score = $cve['metrics']['cvssMetricV31'][0]['cvssData']['baseScore'];
            elseif (isset($cve['metrics']['cvssMetricV30'])) $score = $cve['metrics']['cvssMetricV30'][0]['cvssData']['baseScore'];
            elseif (isset($cve['metrics']['cvssMetricV2'])) $score = $cve['metrics']['cvssMetricV2'][0]['cvssData']['baseScore'];
            
            $results[] = [
                'id' => $cve['id'],
                'cvss' => $score,
                'severity' => classify_severity($score),
                'summary' => $cve['descriptions'][0]['value'] ?? 'No description available.',
                'source' => 'NVD'
            ];
        }
    }
    return $results;
}

function query_circl($keyword) {
    $url = CIRCL_API_BASE . "search/" . urlencode($keyword);
    $res = safe_curl($url);
    $results = [];
    if (is_array($res)) {
        foreach (array_slice($res, 0, 10) as $cve) {
            $score = $cve['cvss'] ?? 0;
            $results[] = [
                'id' => $cve['id'],
                'cvss' => $score,
                'severity' => classify_severity($score),
                'summary' => $cve['summary'] ?? 'No summary.',
                'source' => 'CIRCL'
            ];
        }
    }
    return $results;
}

function query_shodan($ip) {
    if (!SHODAN_API_KEY) return [];
    $url = "https://api.shodan.io/shodan/host/$ip?key=" . SHODAN_API_KEY;
    $res = safe_curl($url);
    $results = [];
    if (isset($res['vulns'])) {
        foreach ($res['vulns'] as $cve_id) {
            $results[] = [
                'id' => $cve_id,
                'cvss' => 0, 
                'severity' => 'Unknown',
                'summary' => 'Vulnerability observed by Shodan internet scanners.',
                'source' => 'Shodan'
            ];
        }
    }
    return ['vulns' => $results, 'intel' => $res];
}

function query_censys($ip) {
    if (!CENSYS_API_TOKEN) {
        return ['error' => 'Censys API token not configured'];
    }
    
    $url = "https://search.censys.io/api/v2/hosts/" . urlencode($ip);
    
    $headers = [
        'Authorization: Bearer ' . CENSYS_API_TOKEN,
        'Content-Type: application/json',
        'Accept: application/json'
    ];
    
    $res = safe_curl($url, $headers);
    
    if (!$res) {
        error_log("Censys API failure (v2) for IP: " . $ip);
        return ['error' => 'API communication failed'];
    }
    
    return $res;
}

/**
 * SCAN ENGINE
 */

/**
 * Native PHP socket-based port scanner fallback.
 * Scans common ports via fsockopen() and returns nmap-compatible XML.
 */
function php_socket_scan($host, $ip) {
    $port_map = [
        21=>'ftp',22=>'ssh',23=>'telnet',25=>'smtp',53=>'domain',
        80=>'http',110=>'pop3',111=>'rpcbind',135=>'msrpc',139=>'netbios-ssn',
        143=>'imap',443=>'https',445=>'microsoft-ds',465=>'smtps',587=>'submission',
        993=>'imaps',995=>'pop3s',1433=>'ms-sql-s',1521=>'oracle',2375=>'docker',
        3000=>'http',3306=>'mysql',3389=>'ms-wbt-server',5432=>'postgresql',
        5900=>'vnc',5985=>'wsman',6379=>'redis',8080=>'http-proxy',
        8443=>'https-alt',8888=>'http',9000=>'http',9200=>'http',27017=>'mongodb'
    ];
    $product_map = [
        21=>'vsftpd',22=>'OpenSSH',23=>'Linux telnetd',25=>'Postfix smtpd',
        53=>'ISC BIND',80=>'Apache httpd',110=>'Dovecot pop3d',111=>'rpcbind',
        135=>'Microsoft RPC',139=>'Samba smbd',143=>'Dovecot imapd',
        443=>'Apache httpd',445=>'Samba smbd',465=>'Postfix smtpd',
        587=>'Postfix smtpd',993=>'Dovecot imapd',995=>'Dovecot pop3d',
        1433=>'Microsoft SQL Server',1521=>'Oracle TNS listener',2375=>'Docker API',
        3000=>'Node.js Express',3306=>'MySQL',3389=>'Microsoft RDP',
        5432=>'PostgreSQL',5900=>'RealVNC',5985=>'Windows WinRM',
        6379=>'Redis key-value store',8080=>'Apache Tomcat',8443=>'Apache Tomcat',
        8888=>'Jupyter Notebook',9000=>'PHP-FPM',9200=>'Elasticsearch',27017=>'MongoDB'
    ];

    $open_ports_xml = '';
    foreach ($port_map as $port => $svcname) {
        $fp = @fsockopen($ip, $port, $e, $es, 1.5);
        if ($fp !== false) {
            fclose($fp);
            $product = htmlspecialchars($product_map[$port] ?? $svcname, ENT_XML1);
            $version = '';
            // Banner grab for well-known plaintext protocols
            if (in_array($port, [21,22,25,110,143,3306])) {
                $fp2 = @fsockopen($ip, $port, $e2, $es2, 2);
                if ($fp2) {
                    stream_set_timeout($fp2, 2);
                    $banner = @fgets($fp2, 256);
                    if ($banner) $version = htmlspecialchars(trim(preg_replace('/[^\x20-\x7E]/','', $banner)), ENT_XML1);
                    fclose($fp2);
                }
            }
            $open_ports_xml .= "<port protocol=\"tcp\" portid=\"{$port}\"><state state=\"open\" reason=\"syn-ack\"/><service name=\"{$svcname}\" product=\"{$product}\" version=\"{$version}\" method=\"probed\"/></port>\n";
        }
    }

    return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<nmaprun scanner=\"php-socket-fallback\" args=\"php_socket_scan\" start=\"\" version=\"fallback\" xmloutputversion=\"1.04\">\n<host starttime=\"\" endtime=\"\"><status state=\"up\" reason=\"user-set\"/><address addr=\"{$ip}\" addrtype=\"ipv4\"/><ports>\n{$open_ports_xml}</ports></host>\n</nmaprun>";
}

/**
 * Primary scan engine.
 * Uses nmap when installed (via Dockerfile), auto-falls back to PHP socket scanner.
 */
function run_nmap($target) {
    // Check for nmap binary (Linux/Docker: which nmap; Windows: where nmap)
    $nmapBin = trim((string)shell_exec("which nmap 2>/dev/null || where nmap 2>NUL"));
    $nmapBin = explode("\n", $nmapBin)[0];

    if (!empty($nmapBin) && @file_exists($nmapBin)) {
        $safe_target = escapeshellarg($target);
        $cmd = "{$nmapBin} -sV --version-intensity 5 -T4 -oX - {$safe_target} 2>&1";
        $output = shell_exec($cmd);
        if ($output && strpos($output, '<nmaprun') !== false) {
            return $output;
        }
    }

    // PHP native socket fallback
    $ip = filter_var($target, FILTER_VALIDATE_IP) ? $target : @gethostbyname($target);
    if ($ip === $target && !filter_var($target, FILTER_VALIDATE_IP)) {
        throw new Exception("DNS resolution failed for: {$target}");
    }
    return php_socket_scan($target, $ip);
}

function validate_target($target) {
    $target = trim($target);
    if (empty($target)) return false;
    $host = preg_replace('(^https?://)', '', $target);
    $host = rtrim(explode('/', $host)[0], ':');
    if (!preg_match('/^[a-zA-Z0-9.-]+$/', $host)) return false;
    $ip = gethostbyname($host);
    if (!filter_var($ip, FILTER_VALIDATE_IP)) return false;
    if (!ALLOW_INTERNAL_SCAN) {
        $private = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8'];
        foreach ($private as $range) {
            list($subnet, $mask) = explode('/', $range);
            if ((ip2long($ip) & ~((1 << (32 - $mask)) - 1)) == ip2long($subnet)) return false;
        }
    }
    return ['host' => $host, 'ip' => $ip];
}

/**
 * API CONTROLLER
 */

if (isset($_GET['action'])) {
    header('Content-Type: application/json');
    $client_token = $_SERVER['HTTP_X_VULNSCOPE_TOKEN'] ?? '';
    if ($client_token !== SCAN_TOKEN) {
        http_response_code(401);
        echo json_encode(['success' => false, 'message' => 'Unauthorized access.']);
        exit;
    }

    if ($_GET['action'] === 'scan') {
        try {
            $target_raw = $_POST['target'] ?? '';
            $validation = validate_target($target_raw);
            if (!$validation) throw new Exception("Invalid target specification.");

            $host = $validation['host'];
            $ip = $validation['ip'];

            // Censys Pre-check
            if (!CENSYS_API_TOKEN) {
                echo json_encode(['success' => false, 'message' => 'Censys API token not configured']);
                exit;
            }

            // 1. Nmap Recon
            $nmap_xml = run_nmap($host);
            $xml = simplexml_load_string($nmap_xml);
            
            $findings = [];
            $open_ports = [];
            
            // 2. Process Nmap results
            if ($xml && isset($xml->host->ports->port)) {
                foreach ($xml->host->ports->port as $p) {
                    if ((string)$p->state['state'] === 'open') {
                        $service_obj = $p->service;
                        $product = (string)$service_obj['product'];
                        $version = (string)$service_obj['version'];
                        $port_id = (string)$p['portid'];

                        $open_ports[] = [
                            'port' => $port_id,
                            'service' => (string)$service_obj['name'],
                            'product' => $product,
                            'version' => $version
                        ];

                        if (!empty($product)) {
                            $norm = normalize_product($product);
                            $nvd_hits = query_nvd($norm . " " . $version);
                            $circl_hits = query_circl($norm);
                            
                            foreach (array_merge($nvd_hits, $circl_hits) as $hit) {
                                $hit['affected_service'] = "$product $version";
                                $hit['port'] = $port_id;
                                $findings[$hit['id']] = $hit;
                            }
                        }
                    }
                }
            }

            // 3. External Intelligence (Shodan / Censys)
            $shodan_data = query_shodan($ip);
            foreach ($shodan_data['vulns'] as $hit) {
                if (!isset($findings[$hit['id']])) {
                    $hit['port'] = 'External';
                    $hit['affected_service'] = 'Observed via IP Intelligence (Shodan)';
                    $findings[$hit['id']] = $hit;
                } else {
                    $findings[$hit['id']]['source'] .= " / Shodan";
                }
            }
            
            $censys_data = query_censys($ip);
            // Handle Censys host info if available
            if ($censys_data && !isset($censys_data['error'])) {
                // Merge observed vulnerabilities from Censys if any (v2 specific)
                // Note: Censys v2 structure can vary, typically 'result.services'
            }

            // 4. Summarize and Rank
            $findings = array_values($findings);
            usort($findings, fn($a, $b) => $b['cvss'] <=> $a['cvss']);
            
            $risk_score = calculate_risk_score($findings);
            $dist = ['low'=>0, 'medium'=>0, 'high'=>0, 'critical'=>0, 'info'=>0];
            foreach ($findings as $f) {
                $l = strtolower($f['severity']);
                if (isset($dist[$l])) $dist[$l]++;
            }

            $response = [
                'success' => true,
                'findings' => $findings,
                'api_status' => get_api_status(),
                'summary' => [
                    'target' => $host,
                    'ip' => $ip,
                    'risk_score' => $risk_score,
                    'open_ports_count' => count($open_ports),
                    'total_findings' => count($findings)
                ],
                'severity_distribution' => $dist,
                'debug_info' => [
                    'ports' => $open_ports,
                    'censys' => $censys_data,
                    'shodan_raw' => $shodan_data['intel'] ?? null
                ]
            ];

            if ($db) {
                $stmt = $db->prepare("INSERT INTO scans (target, ip_address, risk_score, nmap_output, intelligence_data, vulnerabilities) VALUES (?, ?, ?, ?, ?, ?)");
                $stmt->execute([$host, $ip, $risk_score, $nmap_xml, json_encode($response['debug_info']), json_encode($findings)]);
            }

            echo json_encode($response);
        } catch (Exception $e) {
            http_response_code(500);
            echo json_encode(['success' => false, 'message' => $e->getMessage()]);
        }
        exit;
    }
}
?>
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VulnScope Pro â€” ZeroDay Security Intelligence Platform</title>
<meta name="description" content="Enterprise vulnerability intelligence and attack surface assessment by ZeroDay Security Services.">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
:root{--bg-root:#020408;--bg-card:rgba(10,18,30,0.9);--accent:#06b6d4;--accent2:#3b82f6;--accent-glow:rgba(6,182,212,0.12);--accent-border:rgba(6,182,212,0.22);--danger:#ef4444;--danger-dim:rgba(239,68,68,0.08);--danger-border:rgba(239,68,68,0.28);--warn:#f97316;--warn-dim:rgba(249,115,22,0.08);--med:#eab308;--med-dim:rgba(234,179,8,0.08);--low:#22d3ee;--low-dim:rgba(34,211,238,0.06);--info:#64748b;--info-dim:rgba(100,116,139,0.06);--t1:#e2e8f0;--t2:#94a3b8;--t3:#475569;--t4:#1e293b;--border:rgba(30,41,59,0.8);--border2:rgba(51,65,85,0.9);--r8:8px;--r12:12px;--r16:16px;--r20:20px;--r24:24px;--sidebar:260px;--topbar:60px;--ease:all 0.22s cubic-bezier(.4,0,.2,1);--font:'Inter',system-ui,sans-serif;--mono:'JetBrains Mono','Courier New',monospace}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{background:var(--bg-root);color:var(--t1);font-family:var(--font);overflow-x:hidden;min-height:100vh}
::-webkit-scrollbar{width:4px;height:4px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:#1e293b;border-radius:99px}

/* === BG CANVAS === */
#bgc{position:fixed;inset:0;z-index:0;pointer-events:none;opacity:.35}

/* === LAYOUT === */
#shell{position:relative;z-index:1;display:flex;min-height:100vh}

/* === SIDEBAR === */
#sb{width:var(--sidebar);flex-shrink:0;background:rgba(4,8,18,0.97);border-right:1px solid var(--border);display:flex;flex-direction:column;position:fixed;top:0;left:0;height:100vh;z-index:200;backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);transition:transform .3s ease;overflow:hidden}
.sb-logo{padding:20px 16px 18px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:10px}
.sb-logo img{width:38px;height:38px;object-fit:contain;border-radius:8px;filter:drop-shadow(0 0 8px rgba(6,182,212,.5))}
.sb-logo-txt h2{font-size:13px;font-weight:800;letter-spacing:.04em;text-transform:uppercase}
.sb-logo-txt h2 span{color:var(--accent)}
.sb-logo-txt p{font-size:9px;color:var(--accent);font-family:var(--mono);letter-spacing:.12em;margin-top:1px}
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
.dot-on{background:#22c55e;box-shadow:0 0 5px #22c55e;animation:dotpulse 2s infinite}
.dot-off{background:#ef4444}
@keyframes dotpulse{0%,100%{opacity:1}50%{opacity:.35}}
.api-badge{font-family:var(--mono);font-size:9px;font-weight:700;padding:2px 6px;border-radius:4px;text-transform:uppercase;letter-spacing:.04em}
.api-badge.on{background:rgba(34,197,94,.1);color:#22c55e;border:1px solid rgba(34,197,94,.2)}
.api-badge.off{background:rgba(239,68,68,.1);color:#ef4444;border:1px solid rgba(239,68,68,.2)}
.sb-footer{padding:12px 14px;border-top:1px solid var(--border);font-size:9px;color:var(--t4);text-align:center;font-family:var(--mono)}

/* === MAIN === */
#main{margin-left:var(--sidebar);flex:1;display:flex;flex-direction:column;min-height:100vh}

/* === TOPBAR === */
#topbar{height:var(--topbar);border-bottom:1px solid var(--border);background:rgba(4,8,18,.8);backdrop-filter:blur(20px);display:flex;align-items:center;justify-content:space-between;padding:0 24px;position:sticky;top:0;z-index:100}
.tb-left{display:flex;align-items:center;gap:12px}
.tb-bread{display:flex;align-items:center;gap:6px;font-size:12px;color:var(--t3)}
.tb-bread .active{color:var(--t1);font-weight:600}
.tb-bread i{font-size:8px}
.tb-right{display:flex;align-items:center;gap:10px}
.tb-pill{display:flex;align-items:center;gap:5px;font-size:10px;font-family:var(--mono);color:var(--t3);background:rgba(255,255,255,.03);border:1px solid var(--border);padding:4px 10px;border-radius:var(--r8)}
.tb-pill .ldot{width:5px;height:5px;border-radius:50%;background:#22c55e;animation:dotpulse 2s infinite}
#sbtoggle{display:none;background:none;border:1px solid var(--border);color:var(--t2);padding:7px 10px;border-radius:var(--r8);cursor:pointer;transition:var(--ease);font-size:13px}
#sbtoggle:hover{border-color:var(--accent-border);color:var(--accent)}

/* === PAGE === */
#pg{flex:1;padding:24px}

/* === SCAN PANEL === */
.scan-panel{background:var(--bg-card);border:1px solid var(--border2);border-radius:var(--r24);padding:28px 32px;margin-bottom:24px;position:relative;overflow:hidden;backdrop-filter:blur(16px)}
.scan-panel::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,var(--accent),var(--accent2),transparent);opacity:.55}
.scan-ph{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;margin-bottom:22px;flex-wrap:wrap}
.scan-ph h1{font-size:18px;font-weight:800;letter-spacing:-.01em;margin-bottom:4px}
.scan-ph p{font-size:11px;color:var(--t3);font-family:var(--mono);letter-spacing:.04em}
.eng-badge{display:flex;align-items:center;gap:7px;background:rgba(6,182,212,.05);border:1px solid var(--accent-border);border-radius:var(--r12);padding:7px 13px;font-size:10px;font-family:var(--mono);color:var(--accent);text-transform:uppercase;letter-spacing:.07em;white-space:nowrap;flex-shrink:0}
.scan-row{display:flex;gap:10px;align-items:stretch}
.inp-wrap{position:relative;flex:1}
.inp-ico{position:absolute;left:15px;top:50%;transform:translateY(-50%);color:var(--t3);font-size:13px;pointer-events:none;transition:var(--ease)}
#target{width:100%;background:rgba(4,8,18,.9);border:1px solid var(--border2);border-radius:var(--r12);padding:14px 16px 14px 44px;font-family:var(--mono);font-size:13px;color:var(--t1);outline:none;transition:var(--ease);letter-spacing:.02em}
#target::placeholder{color:var(--t4)}
#target:focus{border-color:var(--accent);background:rgba(4,8,18,1);box-shadow:0 0 0 3px rgba(6,182,212,.07),0 0 20px rgba(6,182,212,.04)}
#btn{background:linear-gradient(135deg,var(--accent),var(--accent2));color:#fff;border:none;border-radius:var(--r12);padding:14px 26px;font-family:var(--font);font-size:13px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;cursor:pointer;transition:var(--ease);display:flex;align-items:center;gap:8px;white-space:nowrap;position:relative;overflow:hidden;flex-shrink:0}
#btn::after{content:'';position:absolute;inset:0;background:linear-gradient(135deg,rgba(255,255,255,.18),transparent);opacity:0;transition:var(--ease)}
#btn:hover::after{opacity:1}
#btn:hover{transform:translateY(-1px);box-shadow:0 8px 24px rgba(6,182,212,.28)}
#btn:active{transform:none}
#btn:disabled{opacity:.4;filter:grayscale(.4);cursor:not-allowed;transform:none;box-shadow:none}
#loader{display:none;margin-top:18px;padding:14px 18px;background:rgba(6,182,212,.04);border:1px solid var(--accent-border);border-radius:var(--r12);align-items:center;gap:14px}
#loader.show{display:flex}
.ld-spin{width:30px;height:30px;border:2px solid var(--accent-border);border-top-color:var(--accent);border-radius:50%;animation:spin .8s linear infinite;flex-shrink:0}
@keyframes spin{to{transform:rotate(360deg)}}
.ld-bar-wrap{flex:1}
.ld-txt{font-size:11px;font-family:var(--mono);color:var(--accent);letter-spacing:.03em;margin-bottom:7px}
.ld-track{height:2px;background:rgba(6,182,212,.1);border-radius:99px;overflow:hidden}
.ld-fill{height:100%;width:30%;background:linear-gradient(90deg,var(--accent),var(--accent2));border-radius:99px;animation:ldsweep 1.8s ease-in-out infinite}
@keyframes ldsweep{0%{transform:translateX(-100%)}100%{transform:translateX(400%)}}

/* === RESULTS === */
#results{display:none;animation:fadeup .35s ease}
#results.show{display:block}
@keyframes fadeup{from{opacity:0;transform:translateY(14px)}to{opacity:1;transform:translateY(0)}}
.res-hdr{display:flex;align-items:center;justify-content:space-between;margin-bottom:18px;flex-wrap:wrap;gap:10px}
.res-hdr-title{font-size:11px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:var(--t3);display:flex;align-items:center;gap:8px}
.res-hdr-title::before{content:'';width:3px;height:14px;background:linear-gradient(var(--accent),var(--accent2));border-radius:2px;flex-shrink:0}
.exp-btn{display:flex;align-items:center;gap:6px;padding:7px 13px;background:transparent;border:1px solid var(--border2);border-radius:var(--r8);color:var(--t2);font-size:11px;font-weight:600;cursor:pointer;transition:var(--ease)}
.exp-btn:hover{border-color:var(--accent-border);color:var(--accent);background:var(--accent-glow)}

/* === STAT CARDS === */
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:18px}
.sc{background:var(--bg-card);border:1px solid var(--border);border-radius:var(--r16);padding:18px 20px;backdrop-filter:blur(12px);position:relative;overflow:hidden;transition:var(--ease)}
.sc::after{content:'';position:absolute;bottom:0;left:0;right:0;height:2px;opacity:0;transition:var(--ease)}
.sc:hover{transform:translateY(-2px);border-color:var(--border2)}
.sc:hover::after{opacity:1}
.sc.risk::after{background:linear-gradient(90deg,var(--danger),var(--warn))}
.sc.finds::after{background:linear-gradient(90deg,var(--accent),var(--accent2))}
.sc.ports::after{background:linear-gradient(90deg,#a855f7,var(--accent2))}
.sc.ip::after{background:linear-gradient(90deg,var(--med),var(--warn))}
.sc-lbl{font-size:9px;font-weight:700;letter-spacing:.15em;text-transform:uppercase;color:var(--t4);margin-bottom:10px}
.sc-val{font-size:32px;font-weight:900;line-height:1;margin-bottom:8px;font-variant-numeric:tabular-nums}
.sc.risk .sc-val{color:var(--danger)}
.sc.finds .sc-val{color:var(--accent)}
.sc.ports .sc-val{color:#a855f7}
.sc.ip .sc-val{font-size:16px;padding-top:8px;color:var(--med)}
.sc-meta{font-size:10px;color:var(--t3);font-family:var(--mono)}
.risk-trk{height:3px;background:rgba(255,255,255,.05);border-radius:99px;overflow:hidden;margin:6px 0}
#riskBar{height:100%;background:linear-gradient(90deg,var(--med),var(--warn),var(--danger));border-radius:99px;width:0%;transition:width 1.1s cubic-bezier(.4,0,.2,1)}

/* === BODY GRID === */
.res-body{display:grid;grid-template-columns:320px 1fr;gap:16px;margin-bottom:16px}

/* === PANEL === */
.panel{background:var(--bg-card);border:1px solid var(--border);border-radius:var(--r16);backdrop-filter:blur(12px);overflow:hidden}
.panel-hdr{padding:14px 18px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px}
.panel-title{font-size:10px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:var(--t2);display:flex;align-items:center;gap:7px}
.panel-title i{color:var(--accent);font-size:11px}
.panel-body{padding:18px}

/* === SEV BARS === */
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

/* === API STATUS (results panel) === */
#apiStatusDisplay{display:flex;flex-direction:column;gap:7px}

/* === VULN FILTERS === */
.vf-wrap{display:flex;gap:5px;flex-wrap:wrap}
.fb{font-size:9px;font-weight:700;font-family:var(--mono);letter-spacing:.07em;text-transform:uppercase;padding:3px 9px;border-radius:6px;border:1px solid var(--border2);background:transparent;color:var(--t3);cursor:pointer;transition:var(--ease)}
.fb:hover,.fb.active{background:var(--accent-glow);border-color:var(--accent-border);color:var(--accent)}
.fb.fc.active{background:var(--danger-dim);border-color:var(--danger-border);color:var(--danger)}
.fb.fh.active{background:var(--warn-dim);border-color:rgba(249,115,22,.3);color:var(--warn)}
.fb.fm.active{background:var(--med-dim);border-color:rgba(234,179,8,.3);color:var(--med)}

/* === VULN LIST === */
#vulnList{max-height:500px;overflow-y:auto;display:flex;flex-direction:column;gap:9px;padding:16px 18px}
.vc{border-radius:var(--r12);padding:14px 16px;border:1px solid var(--border);background:rgba(255,255,255,.016);transition:var(--ease);animation:cin .25s ease both;position:relative;overflow:hidden}
.vc::before{content:'';position:absolute;left:0;top:0;bottom:0;width:3px}
.vc.severity-Critical::before{background:var(--danger)}.vc.severity-Critical{border-color:var(--danger-border);background:var(--danger-dim)}
.vc.severity-High::before{background:var(--warn)}.vc.severity-High{border-color:rgba(249,115,22,.2);background:var(--warn-dim)}
.vc.severity-Medium::before{background:var(--med)}.vc.severity-Medium{border-color:rgba(234,179,8,.2);background:var(--med-dim)}
.vc.severity-Low::before{background:var(--low)}.vc.severity-Low{border-color:rgba(34,211,238,.15);background:var(--low-dim)}
.vc.severity-Info::before{background:var(--info)}.vc.severity-Info{border-color:var(--border);background:var(--info-dim)}
.vc:hover{transform:translateX(2px)}
@keyframes cin{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}
.vc-top{display:flex;align-items:flex-start;justify-content:space-between;gap:8px;margin-bottom:9px;flex-wrap:wrap}
.vc-ids{display:flex;align-items:center;gap:7px;flex-wrap:wrap}
.vc-id{font-family:var(--mono);font-size:12px;font-weight:700;color:var(--accent)}
.src-badge{font-size:8px;font-weight:700;font-family:var(--mono);letter-spacing:.09em;text-transform:uppercase;padding:2px 6px;border-radius:4px;background:rgba(255,255,255,.04);color:var(--t3);border:1px solid var(--border2)}
.sev-tags{display:flex;align-items:center;gap:5px;flex-shrink:0}
.sp{font-size:9px;font-weight:700;font-family:var(--mono);letter-spacing:.07em;text-transform:uppercase;padding:2px 7px;border-radius:5px}
.sp.Critical{background:rgba(239,68,68,.14);color:var(--danger);border:1px solid var(--danger-border)}
.sp.High{background:rgba(249,115,22,.12);color:var(--warn);border:1px solid rgba(249,115,22,.25)}
.sp.Medium{background:rgba(234,179,8,.12);color:var(--med);border:1px solid rgba(234,179,8,.25)}
.sp.Low{background:rgba(34,211,238,.08);color:var(--low);border:1px solid rgba(34,211,238,.2)}
.sp.Info,.sp.Unknown{background:rgba(100,116,139,.09);color:var(--info);border:1px solid var(--border)}
.cvss-chip{font-size:9px;font-family:var(--mono);font-weight:600;color:var(--t3);background:rgba(255,255,255,.03);border:1px solid var(--border);padding:2px 6px;border-radius:4px}
.vc-sum{font-size:11.5px;color:var(--t2);line-height:1.6;margin-bottom:10px}
.vc-meta{display:flex;align-items:center;justify-content:space-between;padding-top:9px;border-top:1px solid rgba(255,255,255,.04);flex-wrap:wrap;gap:6px}
.vc-svc{font-size:10px;color:var(--t4);font-family:var(--mono);display:flex;align-items:center;gap:5px}
.port-chip{font-size:9px;font-family:var(--mono);font-weight:700;color:var(--t3);background:rgba(255,255,255,.04);border:1px solid var(--border);padding:2px 7px;border-radius:4px}
.empty{padding:40px 20px;text-align:center;color:var(--t4);font-family:var(--mono);font-size:12px;display:flex;flex-direction:column;align-items:center;gap:10px}
.empty i{font-size:26px;color:var(--t4)}

/* === INFRA / PORT GRID === */
#portGrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(190px,1fr));gap:10px;max-height:420px;overflow-y:auto;padding:16px 18px}
.svc-card{background:rgba(255,255,255,.02);border:1px solid var(--border);border-radius:var(--r12);padding:14px;display:flex;align-items:flex-start;gap:10px;transition:var(--ease);animation:cin .25s ease both}
.svc-card:hover{transform:translateY(-2px);border-color:var(--accent-border);background:var(--accent-glow);box-shadow:0 6px 20px rgba(6,182,212,.07)}
.svc-ico{width:34px;height:34px;border-radius:8px;background:rgba(6,182,212,.08);border:1px solid var(--accent-border);display:flex;align-items:center;justify-content:center;color:var(--accent);font-size:12px;flex-shrink:0}
.svc-info{flex:1;min-width:0}
.svc-nm{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:var(--t1);margin-bottom:2px;display:flex;align-items:center;justify-content:space-between;gap:4px}
.open-pill{font-size:7px;font-weight:700;font-family:var(--mono);color:#22c55e;background:rgba(34,197,94,.08);border:1px solid rgba(34,197,94,.2);padding:1px 4px;border-radius:3px;letter-spacing:.06em}
.svc-port{font-family:var(--mono);font-size:10px;color:var(--accent);font-weight:600;margin-bottom:2px}
.svc-prod{font-size:9px;color:var(--t4);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}

/* === TOAST === */
#error-toast{position:fixed;bottom:20px;right:20px;z-index:9999;background:rgba(25,8,8,.97);border:1px solid rgba(239,68,68,.35);color:var(--t1);padding:12px 16px;border-radius:var(--r12);display:flex;align-items:center;gap:10px;max-width:360px;backdrop-filter:blur(16px);box-shadow:0 8px 32px rgba(0,0,0,.5);transform:translateY(110%);transition:transform .3s cubic-bezier(.34,1.56,.64,1)}
#error-toast.show{transform:translateY(0)}
.t-ico{width:30px;height:30px;border-radius:8px;background:rgba(239,68,68,.12);display:flex;align-items:center;justify-content:center;color:var(--danger);font-size:12px;flex-shrink:0}
.t-body{flex:1}
.t-ttl{font-size:10px;font-weight:700;color:var(--danger);margin-bottom:2px;text-transform:uppercase;letter-spacing:.06em}
#error-msg{font-size:12px;color:var(--t2);line-height:1.45}
.t-close{background:none;border:none;color:var(--t3);cursor:pointer;font-size:16px;transition:var(--ease);padding:0;line-height:1}
.t-close:hover{color:var(--t1)}

/* === OVERLAY === */
#sb-ov{display:none;position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:199;backdrop-filter:blur(2px)}
#sb-ov.on{display:block}

/* =========================================
   RESPONSIVE BREAKPOINTS
   ========================================= */

/* Tablet (<=1024px) â€” sidebar collapses to icon-only or hidden */
@media(max-width:1024px){
  :root{--sidebar:0px}
  #sb{transform:translateX(-260px);width:260px}
  #sb.open{transform:translateX(0)}
  #main{margin-left:0}
  #sbtoggle{display:flex;align-items:center}
  .res-body{grid-template-columns:1fr}
  .stats{grid-template-columns:repeat(2,1fr)}
}

/* Large mobile / small tablet (<=768px) */
@media(max-width:768px){
  #pg{padding:14px}
  .scan-panel{padding:20px 18px}
  .scan-ph h1{font-size:16px}
  .scan-row{flex-direction:column}
  #btn{width:100%;justify-content:center}
  .stats{grid-template-columns:repeat(2,1fr);gap:10px}
  .sc-val{font-size:28px}
  #portGrid{grid-template-columns:repeat(auto-fill,minmax(160px,1fr))}
  .tb-pill:last-child{display:none}
  .res-hdr{flex-direction:column;align-items:flex-start}
}

/* Mobile (<=480px) */
@media(max-width:480px){
  :root{--topbar:54px}
  #pg{padding:10px}
  .scan-panel{padding:16px 14px;border-radius:var(--r16)}
  .scan-ph{gap:8px}
  .eng-badge{display:none}
  .stats{grid-template-columns:1fr 1fr;gap:8px}
  .sc{padding:14px 16px}
  .sc-val{font-size:24px}
  .sc.ip .sc-val{font-size:13px}
  .sc-lbl{font-size:8px}
  #vulnList{padding:10px 12px}
  #portGrid{grid-template-columns:1fr 1fr;padding:10px 12px}
  .panel-hdr{padding:12px 14px}
  .panel-body{padding:14px}
  .vc{padding:12px 13px}
  .vc-id{font-size:11px}
  .vc-sum{font-size:11px}
  .tb-right{gap:6px}
  .topbar-badge{font-size:9px}
}

/* Very small screens (<=360px) */
@media(max-width:360px){
  .stats{grid-template-columns:1fr}
  #portGrid{grid-template-columns:1fr}
}
</style>
</head>
<body>
<canvas id="bgc"></canvas>
<div id="sb-ov" onclick="closeSB()"></div>

<!-- Toast -->
<div id="error-toast">
  <div class="t-ico"><i class="fas fa-triangle-exclamation"></i></div>
  <div class="t-body"><div class="t-ttl">Error</div><span id="error-msg"></span></div>
  <button class="t-close" onclick="hideError()">&times;</button>
</div>

<div id="shell">
<!-- SIDEBAR -->
<aside id="sb">
  <div class="sb-logo">
    <img src="logo.jpg" alt="ZeroDay" onerror="this.style.display='none'">
    <div class="sb-logo-txt">
      <h2>VulnScope <span>Pro</span></h2>
      <p>ZeroDay Security</p>
    </div>
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
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VulnScope Pro â€” ZeroDay Security Intelligence Platform</title>
<meta name="description" content="Enterprise vulnerability intelligence and attack surface assessment by ZeroDay Security Services.">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
:root{--bg-root:#020408;--bg-card:rgba(10,18,30,0.9);--accent:#06b6d4;--accent2:#3b82f6;--accent-glow:rgba(6,182,212,0.12);--accent-border:rgba(6,182,212,0.22);--danger:#ef4444;--danger-dim:rgba(239,68,68,0.08);--danger-border:rgba(239,68,68,0.28);--warn:#f97316;--warn-dim:rgba(249,115,22,0.08);--med:#eab308;--med-dim:rgba(234,179,8,0.08);--low:#22d3ee;--low-dim:rgba(34,211,238,0.06);--info:#64748b;--info-dim:rgba(100,116,139,0.06);--t1:#e2e8f0;--t2:#94a3b8;--t3:#475569;--t4:#1e293b;--border:rgba(30,41,59,0.8);--border2:rgba(51,65,85,0.9);--r8:8px;--r12:12px;--r16:16px;--r20:20px;--r24:24px;--sidebar:260px;--topbar:60px;--ease:all 0.22s cubic-bezier(.4,0,.2,1);--font:'Inter',system-ui,sans-serif;--mono:'JetBrains Mono','Courier New',monospace}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{background:var(--bg-root);color:var(--t1);font-family:var(--font);overflow-x:hidden;min-height:100vh}
::-webkit-scrollbar{width:4px;height:4px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:#1e293b;border-radius:99px}

/* === BG CANVAS === */
#bgc{position:fixed;inset:0;z-index:0;pointer-events:none;opacity:.35}

/* === LAYOUT === */
#shell{position:relative;z-index:1;display:flex;min-height:100vh}

/* === SIDEBAR === */
#sb{width:var(--sidebar);flex-shrink:0;background:rgba(4,8,18,0.97);border-right:1px solid var(--border);display:flex;flex-direction:column;position:fixed;top:0;left:0;height:100vh;z-index:200;backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);transition:transform .3s ease;overflow:hidden}
.sb-logo{padding:20px 16px 18px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:10px}
.sb-logo img{width:38px;height:38px;object-fit:contain;border-radius:8px;filter:drop-shadow(0 0 8px rgba(6,182,212,.5))}
.sb-logo-txt h2{font-size:13px;font-weight:800;letter-spacing:.04em;text-transform:uppercase}
.sb-logo-txt h2 span{color:var(--accent)}
.sb-logo-txt p{font-size:9px;color:var(--accent);font-family:var(--mono);letter-spacing:.12em;margin-top:1px}
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
.dot-on{background:#22c55e;box-shadow:0 0 5px #22c55e;animation:dotpulse 2s infinite}
.dot-off{background:#ef4444}
@keyframes dotpulse{0%,100%{opacity:1}50%{opacity:.35}}
.api-badge{font-family:var(--mono);font-size:9px;font-weight:700;padding:2px 6px;border-radius:4px;text-transform:uppercase;letter-spacing:.04em}
.api-badge.on{background:rgba(34,197,94,.1);color:#22c55e;border:1px solid rgba(34,197,94,.2)}
.api-badge.off{background:rgba(239,68,68,.1);color:#ef4444;border:1px solid rgba(239,68,68,.2)}
.sb-footer{padding:12px 14px;border-top:1px solid var(--border);font-size:9px;color:var(--t4);text-align:center;font-family:var(--mono)}

/* === MAIN === */
#main{margin-left:var(--sidebar);flex:1;display:flex;flex-direction:column;min-height:100vh}

/* === TOPBAR === */
#topbar{height:var(--topbar);border-bottom:1px solid var(--border);background:rgba(4,8,18,.8);backdrop-filter:blur(20px);display:flex;align-items:center;justify-content:space-between;padding:0 24px;position:sticky;top:0;z-index:100}
.tb-left{display:flex;align-items:center;gap:12px}
.tb-bread{display:flex;align-items:center;gap:6px;font-size:12px;color:var(--t3)}
.tb-bread .active{color:var(--t1);font-weight:600}
.tb-bread i{font-size:8px}
.tb-right{display:flex;align-items:center;gap:10px}
.tb-pill{display:flex;align-items:center;gap:5px;font-size:10px;font-family:var(--mono);color:var(--t3);background:rgba(255,255,255,.03);border:1px solid var(--border);padding:4px 10px;border-radius:var(--r8)}
.tb-pill .ldot{width:5px;height:5px;border-radius:50%;background:#22c55e;animation:dotpulse 2s infinite}
#sbtoggle{display:none;background:none;border:1px solid var(--border);color:var(--t2);padding:7px 10px;border-radius:var(--r8);cursor:pointer;transition:var(--ease);font-size:13px}
#sbtoggle:hover{border-color:var(--accent-border);color:var(--accent)}

/* === PAGE === */
#pg{flex:1;padding:24px}

/* === SCAN PANEL === */
.scan-panel{background:var(--bg-card);border:1px solid var(--border2);border-radius:var(--r24);padding:28px 32px;margin-bottom:24px;position:relative;overflow:hidden;backdrop-filter:blur(16px)}
.scan-panel::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,var(--accent),var(--accent2),transparent);opacity:.55}
.scan-ph{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;margin-bottom:22px;flex-wrap:wrap}
.scan-ph h1{font-size:18px;font-weight:800;letter-spacing:-.01em;margin-bottom:4px}
.scan-ph p{font-size:11px;color:var(--t3);font-family:var(--mono);letter-spacing:.04em}
.eng-badge{display:flex;align-items:center;gap:7px;background:rgba(6,182,212,.05);border:1px solid var(--accent-border);border-radius:var(--r12);padding:7px 13px;font-size:10px;font-family:var(--mono);color:var(--accent);text-transform:uppercase;letter-spacing:.07em;white-space:nowrap;flex-shrink:0}
.scan-row{display:flex;gap:10px;align-items:stretch}
.inp-wrap{position:relative;flex:1}
.inp-ico{position:absolute;left:15px;top:50%;transform:translateY(-50%);color:var(--t3);font-size:13px;pointer-events:none;transition:var(--ease)}
#target{width:100%;background:rgba(4,8,18,.9);border:1px solid var(--border2);border-radius:var(--r12);padding:14px 16px 14px 44px;font-family:var(--mono);font-size:13px;color:var(--t1);outline:none;transition:var(--ease);letter-spacing:.02em}
#target::placeholder{color:var(--t4)}
#target:focus{border-color:var(--accent);background:rgba(4,8,18,1);box-shadow:0 0 0 3px rgba(6,182,212,.07),0 0 20px rgba(6,182,212,.04)}
#btn{background:linear-gradient(135deg,var(--accent),var(--accent2));color:#fff;border:none;border-radius:var(--r12);padding:14px 26px;font-family:var(--font);font-size:13px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;cursor:pointer;transition:var(--ease);display:flex;align-items:center;gap:8px;white-space:nowrap;position:relative;overflow:hidden;flex-shrink:0}
#btn::after{content:'';position:absolute;inset:0;background:linear-gradient(135deg,rgba(255,255,255,.18),transparent);opacity:0;transition:var(--ease)}
#btn:hover::after{opacity:1}
#btn:hover{transform:translateY(-1px);box-shadow:0 8px 24px rgba(6,182,212,.28)}
#btn:active{transform:none}
#btn:disabled{opacity:.4;filter:grayscale(.4);cursor:not-allowed;transform:none;box-shadow:none}
#loader{display:none;margin-top:18px;padding:14px 18px;background:rgba(6,182,212,.04);border:1px solid var(--accent-border);border-radius:var(--r12);align-items:center;gap:14px}
#loader.show{display:flex}
.ld-spin{width:30px;height:30px;border:2px solid var(--accent-border);border-top-color:var(--accent);border-radius:50%;animation:spin .8s linear infinite;flex-shrink:0}
@keyframes spin{to{transform:rotate(360deg)}}
.ld-bar-wrap{flex:1}
.ld-txt{font-size:11px;font-family:var(--mono);color:var(--accent);letter-spacing:.03em;margin-bottom:7px}
.ld-track{height:2px;background:rgba(6,182,212,.1);border-radius:99px;overflow:hidden}
.ld-fill{height:100%;width:30%;background:linear-gradient(90deg,var(--accent),var(--accent2));border-radius:99px;animation:ldsweep 1.8s ease-in-out infinite}
@keyframes ldsweep{0%{transform:translateX(-100%)}100%{transform:translateX(400%)}}

/* === RESULTS === */
#results{display:none;animation:fadeup .35s ease}
#results.show{display:block}
@keyframes fadeup{from{opacity:0;transform:translateY(14px)}to{opacity:1;transform:translateY(0)}}
.res-hdr{display:flex;align-items:center;justify-content:space-between;margin-bottom:18px;flex-wrap:wrap;gap:10px}
.res-hdr-title{font-size:11px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:var(--t3);display:flex;align-items:center;gap:8px}
.res-hdr-title::before{content:'';width:3px;height:14px;background:linear-gradient(var(--accent),var(--accent2));border-radius:2px;flex-shrink:0}
.exp-btn{display:flex;align-items:center;gap:6px;padding:7px 13px;background:transparent;border:1px solid var(--border2);border-radius:var(--r8);color:var(--t2);font-size:11px;font-weight:600;cursor:pointer;transition:var(--ease)}
.exp-btn:hover{border-color:var(--accent-border);color:var(--accent);background:var(--accent-glow)}

/* === STAT CARDS === */
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:18px}
.sc{background:var(--bg-card);border:1px solid var(--border);border-radius:var(--r16);padding:18px 20px;backdrop-filter:blur(12px);position:relative;overflow:hidden;transition:var(--ease)}
.sc::after{content:'';position:absolute;bottom:0;left:0;right:0;height:2px;opacity:0;transition:var(--ease)}
.sc:hover{transform:translateY(-2px);border-color:var(--border2)}
.sc:hover::after{opacity:1}
.sc.risk::after{background:linear-gradient(90deg,var(--danger),var(--warn))}
.sc.finds::after{background:linear-gradient(90deg,var(--accent),var(--accent2))}
.sc.ports::after{background:linear-gradient(90deg,#a855f7,var(--accent2))}
.sc.ip::after{background:linear-gradient(90deg,var(--med),var(--warn))}
.sc-lbl{font-size:9px;font-weight:700;letter-spacing:.15em;text-transform:uppercase;color:var(--t4);margin-bottom:10px}
.sc-val{font-size:32px;font-weight:900;line-height:1;margin-bottom:8px;font-variant-numeric:tabular-nums}
.sc.risk .sc-val{color:var(--danger)}
.sc.finds .sc-val{color:var(--accent)}
.sc.ports .sc-val{color:#a855f7}
.sc.ip .sc-val{font-size:16px;padding-top:8px;color:var(--med)}
.sc-meta{font-size:10px;color:var(--t3);font-family:var(--mono)}
.risk-trk{height:3px;background:rgba(255,255,255,.05);border-radius:99px;overflow:hidden;margin:6px 0}
#riskBar{height:100%;background:linear-gradient(90deg,var(--med),var(--warn),var(--danger));border-radius:99px;width:0%;transition:width 1.1s cubic-bezier(.4,0,.2,1)}

/* === BODY GRID === */
.res-body{display:grid;grid-template-columns:320px 1fr;gap:16px;margin-bottom:16px}

/* === PANEL === */
.panel{background:var(--bg-card);border:1px solid var(--border);border-radius:var(--r16);backdrop-filter:blur(12px);overflow:hidden}
.panel-hdr{padding:14px 18px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px}
.panel-title{font-size:10px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:var(--t2);display:flex;align-items:center;gap:7px}
.panel-title i{color:var(--accent);font-size:11px}
.panel-body{padding:18px}

/* === SEV BARS === */
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

/* === API STATUS (results panel) === */
#apiStatusDisplay{display:flex;flex-direction:column;gap:7px}

/* === VULN FILTERS === */
.vf-wrap{display:flex;gap:5px;flex-wrap:wrap}
.fb{font-size:9px;font-weight:700;font-family:var(--mono);letter-spacing:.07em;text-transform:uppercase;padding:3px 9px;border-radius:6px;border:1px solid var(--border2);background:transparent;color:var(--t3);cursor:pointer;transition:var(--ease)}
.fb:hover,.fb.active{background:var(--accent-glow);border-color:var(--accent-border);color:var(--accent)}
.fb.fc.active{background:var(--danger-dim);border-color:var(--danger-border);color:var(--danger)}
.fb.fh.active{background:var(--warn-dim);border-color:rgba(249,115,22,.3);color:var(--warn)}
.fb.fm.active{background:var(--med-dim);border-color:rgba(234,179,8,.3);color:var(--med)}

/* === VULN LIST === */
#vulnList{max-height:500px;overflow-y:auto;display:flex;flex-direction:column;gap:9px;padding:16px 18px}
.vc{border-radius:var(--r12);padding:14px 16px;border:1px solid var(--border);background:rgba(255,255,255,.016);transition:var(--ease);animation:cin .25s ease both;position:relative;overflow:hidden}
.vc::before{content:'';position:absolute;left:0;top:0;bottom:0;width:3px}
.vc.severity-Critical::before{background:var(--danger)}.vc.severity-Critical{border-color:var(--danger-border);background:var(--danger-dim)}
.vc.severity-High::before{background:var(--warn)}.vc.severity-High{border-color:rgba(249,115,22,.2);background:var(--warn-dim)}
.vc.severity-Medium::before{background:var(--med)}.vc.severity-Medium{border-color:rgba(234,179,8,.2);background:var(--med-dim)}
.vc.severity-Low::before{background:var(--low)}.vc.severity-Low{border-color:rgba(34,211,238,.15);background:var(--low-dim)}
.vc.severity-Info::before{background:var(--info)}.vc.severity-Info{border-color:var(--border);background:var(--info-dim)}
.vc:hover{transform:translateX(2px)}
@keyframes cin{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}
.vc-top{display:flex;align-items:flex-start;justify-content:space-between;gap:8px;margin-bottom:9px;flex-wrap:wrap}
.vc-ids{display:flex;align-items:center;gap:7px;flex-wrap:wrap}
.vc-id{font-family:var(--mono);font-size:12px;font-weight:700;color:var(--accent)}
.src-badge{font-size:8px;font-weight:700;font-family:var(--mono);letter-spacing:.09em;text-transform:uppercase;padding:2px 6px;border-radius:4px;background:rgba(255,255,255,.04);color:var(--t3);border:1px solid var(--border2)}
.sev-tags{display:flex;align-items:center;gap:5px;flex-shrink:0}
.sp{font-size:9px;font-weight:700;font-family:var(--mono);letter-spacing:.07em;text-transform:uppercase;padding:2px 7px;border-radius:5px}
.sp.Critical{background:rgba(239,68,68,.14);color:var(--danger);border:1px solid var(--danger-border)}
.sp.High{background:rgba(249,115,22,.12);color:var(--warn);border:1px solid rgba(249,115,22,.25)}
.sp.Medium{background:rgba(234,179,8,.12);color:var(--med);border:1px solid rgba(234,179,8,.25)}
.sp.Low{background:rgba(34,211,238,.08);color:var(--low);border:1px solid rgba(34,211,238,.2)}
.sp.Info,.sp.Unknown{background:rgba(100,116,139,.09);color:var(--info);border:1px solid var(--border)}
.cvss-chip{font-size:9px;font-family:var(--mono);font-weight:600;color:var(--t3);background:rgba(255,255,255,.03);border:1px solid var(--border);padding:2px 6px;border-radius:4px}
.vc-sum{font-size:11.5px;color:var(--t2);line-height:1.6;margin-bottom:10px}
.vc-meta{display:flex;align-items:center;justify-content:space-between;padding-top:9px;border-top:1px solid rgba(255,255,255,.04);flex-wrap:wrap;gap:6px}
.vc-svc{font-size:10px;color:var(--t4);font-family:var(--mono);display:flex;align-items:center;gap:5px}
.port-chip{font-size:9px;font-family:var(--mono);font-weight:700;color:var(--t3);background:rgba(255,255,255,.04);border:1px solid var(--border);padding:2px 7px;border-radius:4px}
.empty{padding:40px 20px;text-align:center;color:var(--t4);font-family:var(--mono);font-size:12px;display:flex;flex-direction:column;align-items:center;gap:10px}
.empty i{font-size:26px;color:var(--t4)}

/* === INFRA / PORT GRID === */
#portGrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(190px,1fr));gap:10px;max-height:420px;overflow-y:auto;padding:16px 18px}
.svc-card{background:rgba(255,255,255,.02);border:1px solid var(--border);border-radius:var(--r12);padding:14px;display:flex;align-items:flex-start;gap:10px;transition:var(--ease);animation:cin .25s ease both}
.svc-card:hover{transform:translateY(-2px);border-color:var(--accent-border);background:var(--accent-glow);box-shadow:0 6px 20px rgba(6,182,212,.07)}
.svc-ico{width:34px;height:34px;border-radius:8px;background:rgba(6,182,212,.08);border:1px solid var(--accent-border);display:flex;align-items:center;justify-content:center;color:var(--accent);font-size:12px;flex-shrink:0}
.svc-info{flex:1;min-width:0}
.svc-nm{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:var(--t1);margin-bottom:2px;display:flex;align-items:center;justify-content:space-between;gap:4px}
.open-pill{font-size:7px;font-weight:700;font-family:var(--mono);color:#22c55e;background:rgba(34,197,94,.08);border:1px solid rgba(34,197,94,.2);padding:1px 4px;border-radius:3px;letter-spacing:.06em}
.svc-port{font-family:var(--mono);font-size:10px;color:var(--accent);font-weight:600;margin-bottom:2px}
.svc-prod{font-size:9px;color:var(--t4);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}

/* === TOAST === */
#error-toast{position:fixed;bottom:20px;right:20px;z-index:9999;background:rgba(25,8,8,.97);border:1px solid rgba(239,68,68,.35);color:var(--t1);padding:12px 16px;border-radius:var(--r12);display:flex;align-items:center;gap:10px;max-width:360px;backdrop-filter:blur(16px);box-shadow:0 8px 32px rgba(0,0,0,.5);transform:translateY(110%);transition:transform .3s cubic-bezier(.34,1.56,.64,1)}
#error-toast.show{transform:translateY(0)}
.t-ico{width:30px;height:30px;border-radius:8px;background:rgba(239,68,68,.12);display:flex;align-items:center;justify-content:center;color:var(--danger);font-size:12px;flex-shrink:0}
.t-body{flex:1}
.t-ttl{font-size:10px;font-weight:700;color:var(--danger);margin-bottom:2px;text-transform:uppercase;letter-spacing:.06em}
#error-msg{font-size:12px;color:var(--t2);line-height:1.45}
.t-close{background:none;border:none;color:var(--t3);cursor:pointer;font-size:16px;transition:var(--ease);padding:0;line-height:1}
.t-close:hover{color:var(--t1)}

/* === OVERLAY === */
#sb-ov{display:none;position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:199;backdrop-filter:blur(2px)}
#sb-ov.on{display:block}

/* =========================================
   RESPONSIVE BREAKPOINTS
   ========================================= */

/* Tablet (<=1024px) â€” sidebar collapses to icon-only or hidden */
@media(max-width:1024px){
  :root{--sidebar:0px}
  #sb{transform:translateX(-260px);width:260px}
  #sb.open{transform:translateX(0)}
  #main{margin-left:0}
  #sbtoggle{display:flex;align-items:center}
  .res-body{grid-template-columns:1fr}
  .stats{grid-template-columns:repeat(2,1fr)}
}

/* Large mobile / small tablet (<=768px) */
@media(max-width:768px){
  #pg{padding:14px}
  .scan-panel{padding:20px 18px}
  .scan-ph h1{font-size:16px}
  .scan-row{flex-direction:column}
  #btn{width:100%;justify-content:center}
  .stats{grid-template-columns:repeat(2,1fr);gap:10px}
  .sc-val{font-size:28px}
  #portGrid{grid-template-columns:repeat(auto-fill,minmax(160px,1fr))}
  .tb-pill:last-child{display:none}
  .res-hdr{flex-direction:column;align-items:flex-start}
}

/* Mobile (<=480px) */
@media(max-width:480px){
  :root{--topbar:54px}
  #pg{padding:10px}
  .scan-panel{padding:16px 14px;border-radius:var(--r16)}
  .scan-ph{gap:8px}
  .eng-badge{display:none}
  .stats{grid-template-columns:1fr 1fr;gap:8px}
  .sc{padding:14px 16px}
  .sc-val{font-size:24px}
  .sc.ip .sc-val{font-size:13px}
  .sc-lbl{font-size:8px}
  #vulnList{padding:10px 12px}
  #portGrid{grid-template-columns:1fr 1fr;padding:10px 12px}
  .panel-hdr{padding:12px 14px}
  .panel-body{padding:14px}
  .vc{padding:12px 13px}
  .vc-id{font-size:11px}
  .vc-sum{font-size:11px}
  .tb-right{gap:6px}
  .topbar-badge{font-size:9px}
}

/* Very small screens (<=360px) */
@media(max-width:360px){
  .stats{grid-template-columns:1fr}
  #portGrid{grid-template-columns:1fr}
}
</style>
</head>
<body>
<canvas id="bgc"></canvas>
<div id="sb-ov" onclick="closeSB()"></div>

<!-- Toast -->
<div id="error-toast">
  <div class="t-ico"><i class="fas fa-triangle-exclamation"></i></div>
  <div class="t-body"><div class="t-ttl">Error</div><span id="error-msg"></span></div>
  <button class="t-close" onclick="hideError()">&times;</button>
</div>

<div id="shell">
<!-- SIDEBAR -->
<aside id="sb">
  <div class="sb-logo">
    <img src="logo.jpg" alt="ZeroDay" onerror="this.style.display='none'">
    <div class="sb-logo-txt">
      <h2>VulnScope <span>Pro</span></h2>
      <p>ZeroDay Security</p>
    </div>
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
    PHP_API_ROWS
  </div>
  <div class="sb-footer">Vijay Ishan Chowdhury &mdash; ZeroDay Security Services</div>
</aside>

<!-- MAIN -->
<div id="main">
  <!-- Topbar -->
  <header id="topbar">
    <div class="tb-left">
      <button id="sbtoggle" onclick="toggleSB()"><i class="fas fa-bars"></i></button>
      <div class="tb-bread">
        <i class="fas fa-shield-halved" style="color:var(--accent);font-size:12px"></i>
        <span>ZeroDay Security</span>
        <i class="fas fa-chevron-right"></i>
        <span class="active">VulnScope Pro</span>
      </div>
    </div>
    <div class="tb-right">
      <div class="tb-pill"><span class="ldot"></span>ENGINE ONLINE</div>
      <div class="tb-pill"><i class="fas fa-microchip" style="font-size:9px"></i>Enterprise v4.0</div>
    </div>
  </header>

  <!-- Page -->
  <main id="pg">
    <!-- Scan Panel -->
    <section class="scan-panel">
      <div class="scan-ph">
        <div>
          <h1>Attack Surface Assessment</h1>
          <p>NVD v2 &middot; Shodan &middot; Censys v2 &middot; CIRCL &middot; Nmap / PHP Socket Engine</p>
        </div>
        <div class="eng-badge"><i class="fas fa-circle" style="font-size:7px;color:#22c55e;animation:dotpulse 1.5s infinite"></i>Scan Core Active</div>
      </div>
      <form id="scanForm">
        <div class="scan-row">
          <div class="inp-wrap">
            <input type="text" id="target" placeholder="Enter target IP or domain â€” e.g. 192.168.1.1 or example.com" autocomplete="off" spellcheck="false">
            <i class="fas fa-crosshairs inp-ico"></i>
          </div>
          <button type="submit" id="btn"><i class="fas fa-shield-virus"></i>Launch Assessment</button>
        </div>
      </form>
      <div id="loader" class="hidden">
        <div class="ld-spin"></div>
        <div class="ld-bar-wrap">
          <div class="ld-txt"><i class="fas fa-circle-notch fa-spin" style="margin-right:6px"></i>Initializing scan engine &amp; correlating multi-source intelligence...</div>
          <div class="ld-track"><div class="ld-fill"></div></div>
        </div>
      </div>
    </section>

    <!-- Results -->
    <div id="results">
      <div class="res-hdr">
        <div class="res-hdr-title">Scan Results</div>
        <button class="exp-btn" onclick="exportReport()"><i class="fas fa-file-export"></i>Export JSON</button>
      </div>

      <!-- Stat Cards -->
      <div class="stats">
        <div class="sc risk">
          <div class="sc-lbl">Composite Risk Score</div>
          <div class="sc-val" id="riskValue">0</div>
          <div class="risk-trk"><div id="riskBar"></div></div>
          <div class="sc-meta" id="resTarget">HOST: ---</div>
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

      <!-- Left col: Severity + API Status | Right col: Vuln Feed -->
      <div class="res-body">
        <div style="display:flex;flex-direction:column;gap:14px">
          <!-- Severity -->
          <div class="panel">
            <div class="panel-hdr"><div class="panel-title"><i class="fas fa-chart-bar"></i>Severity Distribution</div></div>
            <div class="panel-body"><div id="severityBars"></div></div>
          </div>
          <!-- API Status -->
          <div class="panel">
            <div class="panel-hdr"><div class="panel-title"><i class="fas fa-plug-circle-check"></i>Intelligence Sources</div></div>
            <div class="panel-body" style="padding:14px 18px"><div id="apiStatusDisplay"></div></div>
          </div>
        </div>

        <!-- Vuln Feed -->
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
          <div id="vulnList"></div>
        </div>
      </div>

      <!-- Infra Map -->
      <div class="panel" id="infra-section" style="margin-bottom:0">
        <div class="panel-hdr">
          <div class="panel-title"><i class="fas fa-microchip"></i>Detected Infrastructure &amp; Services</div>
          <span id="portsCount" style="font-size:10px;font-family:var(--mono);color:var(--t3);text-transform:uppercase;letter-spacing:.07em">0 Assets</span>
        </div>
        <div id="portGrid"></div>
      </div>
    </div><!-- /#results -->
  </main>
</div><!-- /#main -->
</div><!-- /#shell -->

<script>
const SCAN_TOKEN='<?php echo SCAN_TOKEN; ?>';
let _last=null,_all=[];

/* BG canvas */
(function(){
  const c=document.getElementById('bgc'),ctx=c.getContext('2d');
  let w,h,pts=[];
  function rsz(){w=c.width=window.innerWidth;h=c.height=window.innerHeight}
  function init(){pts=[];const n=Math.floor(w*h/16000);for(let i=0;i<n;i++)pts.push({x:Math.random()*w,y:Math.random()*h,r:Math.random()*1.1+.3,vx:(Math.random()-.5)*.16,vy:(Math.random()-.5)*.16})}
  function draw(){
    ctx.clearRect(0,0,w,h);
    ctx.fillStyle='rgba(6,182,212,.4)';
    for(const d of pts){d.x+=d.vx;d.y+=d.vy;if(d.x<0||d.x>w)d.vx*=-1;if(d.y<0||d.y>h)d.vy*=-1;ctx.beginPath();ctx.arc(d.x,d.y,d.r,0,Math.PI*2);ctx.fill()}
    ctx.strokeStyle='rgba(6,182,212,.055)';ctx.lineWidth=.5;
    for(let i=0;i<pts.length;i++)for(let j=i+1;j<pts.length;j++){const dx=pts[i].x-pts[j].x,dy=pts[i].y-pts[j].y,d=Math.sqrt(dx*dx+dy*dy);if(d<110){ctx.globalAlpha=1-d/110;ctx.beginPath();ctx.moveTo(pts[i].x,pts[i].y);ctx.lineTo(pts[j].x,pts[j].y);ctx.stroke()}}
    ctx.globalAlpha=1;requestAnimationFrame(draw)
  }
  window.addEventListener('resize',()=>{rsz();init()});rsz();init();draw();
})();

/* Sidebar */
function toggleSB(){document.getElementById('sb').classList.toggle('open');document.getElementById('sb-ov').classList.toggle('on')}
function closeSB(){document.getElementById('sb').classList.remove('open');document.getElementById('sb-ov').classList.remove('on')}

/* Scroll helpers */
function toResults(){document.getElementById('results').scrollIntoView({behavior:'smooth'})}
function toInfra(){const e=document.getElementById('infra-section');if(e)e.scrollIntoView({behavior:'smooth'})}

/* Toast */
function showError(m){document.getElementById('error-msg').innerText=m;document.getElementById('error-toast').classList.add('show');setTimeout(hideError,6000)}
function hideError(){document.getElementById('error-toast').classList.remove('show')}

/* Counter animation */
function ctr(el,target,dur=900){
  const s=performance.now(),f=parseInt(el.innerText)||0;
  (function step(n){const p=Math.min((n-s)/dur,1),e=1-Math.pow(1-p,3);el.innerText=Math.round(f+(target-f)*e);if(p<1)requestAnimationFrame(step)})(s)
}

/* Scan form */
document.getElementById('scanForm').onsubmit=async(e)=>{
  e.preventDefault();
  const t=document.getElementById('target').value.trim();
  const btn=document.getElementById('btn'),ldr=document.getElementById('loader');
  if(!t)return showError('No target specified.');
  btn.disabled=true;ldr.classList.remove('hidden');ldr.classList.add('show');
  document.getElementById('results').classList.remove('show');document.getElementById('results').style.display='none';
  const fd=new FormData();fd.append('target',t);
  try{
    const r=await fetch('?action=scan',{method:'POST',body:fd,headers:{'X-VulnScope-Token':SCAN_TOKEN}});
    const j=await r.json();
    if(j.success){_last=j;renderDashboard(j)}else showError(j.message);
  }catch(err){showError('Operational failure: Intelligence core unreachable.')}
  finally{btn.disabled=false;ldr.classList.add('hidden');ldr.classList.remove('show')}
};

/* Render */
function renderDashboard(resp){
  const{summary:s,severity_distribution:sd,findings:f,debug_info:di,api_status:as}=resp;
  const re=document.getElementById('results');re.style.display='block';re.classList.add('show');
  ctr(document.getElementById('riskValue'),s.risk_score);
  setTimeout(()=>{document.getElementById('riskBar').style.width=s.risk_score+'%'},60);
  document.getElementById('resTarget').innerText='HOST: '+s.target;
  document.getElementById('resIp').innerText=s.ip;
  ctr(document.getElementById('findingsCount'),s.total_findings);
  ctr(document.getElementById('portsCountVal'),s.open_ports_count);
  document.querySelectorAll('#portsCount').forEach(el=>el.innerText=s.open_ports_count+' ASSETS');
  if(as)document.getElementById('apiStatusDisplay').innerHTML=Object.entries(as).map(([k,v])=>{
    const ok=v==='configured';
    return `<div class="sb-api-row"><div class="sb-api-name"><span class="dot ${ok?'dot-on':'dot-off'}"></span>${k.toUpperCase()}</div><span class="api-badge ${ok?'on':'off'}">${ok?'Active':'Offline'}</span></div>`;
  }).join('');
  renderSevBars(sd,s.total_findings);
  renderPorts(di.ports||[]);
  _all=f;renderVulns(f);
  setTimeout(()=>re.scrollIntoView({behavior:'smooth',block:'start'}),120);
}

/* Severity bars */
function renderSevBars(d,tot){
  const sevs=['Critical','High','Medium','Low','Info'];
  document.getElementById('severityBars').innerHTML=sevs.map(s=>{
    const cnt=d[s.toLowerCase()]||0,pct=tot>0?Math.round(cnt/tot*100):0;
    return `<div class="sev-row sev-${s}"><div class="sev-hdr"><span class="sev-name">${s}</span><div class="sev-right"><span class="sev-pct">${pct}%</span><span class="sev-cnt">${cnt}</span></div></div><div class="sev-trk"><div class="progress-bar bar-${s}" data-p="${pct}" style="width:0%"></div></div></div>`;
  }).join('');
  setTimeout(()=>document.querySelectorAll('.progress-bar[data-p]').forEach(b=>b.style.width=b.dataset.p+'%'),80);
}

/* Icon map */
function ico(s){
  if(!s)return'fa-server';s=s.toLowerCase();
  if(s.includes('http')||s.includes('www'))return'fa-globe';
  if(s.includes('ssh'))return'fa-terminal';
  if(s.includes('sql')||s.includes('mysql')||s.includes('pg')||s.includes('mongo'))return'fa-database';
  if(s.includes('ftp'))return'fa-upload';
  if(s.includes('smtp')||s.includes('mail')||s.includes('pop')||s.includes('imap'))return'fa-envelope';
  if(s.includes('dns')||s.includes('domain'))return'fa-sitemap';
  if(s.includes('rdp')||s.includes('vnc')||s.includes('remote'))return'fa-desktop';
  if(s.includes('ldap'))return'fa-users';
  if(s.includes('redis')||s.includes('memcache'))return'fa-memory';
  if(s.includes('docker'))return'fa-docker';
  return'fa-server';
}

/* Port grid */
function renderPorts(ports){
  document.getElementById('portGrid').innerHTML=ports.length?ports.map((p,i)=>`
    <div class="svc-card" style="animation-delay:${i*35}ms">
      <div class="svc-ico"><i class="fas ${ico(p.service)}"></i></div>
      <div class="svc-info">
        <div class="svc-nm"><span>${(p.service||'unknown').toUpperCase()}</span><span class="open-pill">OPEN</span></div>
        <div class="svc-port">${p.port}/TCP</div>
        <div class="svc-prod">${[p.product,p.version].filter(Boolean).join(' ')||'&mdash;'}</div>
      </div>
    </div>`).join('')
  :`<div class="empty" style="grid-column:1/-1"><i class="fas fa-network-wired"></i>No open services detected</div>`;
}

/* Vuln list */
function renderVulns(f){
  const list=document.getElementById('vulnList');
  list.innerHTML=f.length?f.map((v,i)=>`
    <div class="vc severity-${v.severity||'Info'}" style="animation-delay:${i*30}ms">
      <div class="vc-top">
        <div class="vc-ids"><span class="vc-id">${v.id}</span><span class="src-badge">${v.source}</span></div>
        <div class="sev-tags"><span class="sp ${v.severity||'Info'}">${v.severity||'Info'}</span><span class="cvss-chip">CVSS ${v.cvss>0?v.cvss:'N/A'}</span></div>
      </div>
      <p class="vc-sum">${v.summary}</p>
      <div class="vc-meta">
        <div class="vc-svc"><i class="fas fa-microchip"></i>${v.affected_service||'&mdash;'}</div>
        <span class="port-chip">PORT ${v.port}</span>
      </div>
    </div>`).join('')
  :`<div class="empty"><i class="fas fa-shield-check"></i>No CVE matches found &mdash; target appears hardened.</div>`;
}

function fvulns(sev,btn){
  document.querySelectorAll('.fb').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  renderVulns(sev==='all'?_all:_all.filter(f=>f.severity===sev));
}

/* Export */
function exportReport(){
  if(!_last)return showError('No scan data yet. Run a scan first.');
  const b=new Blob([JSON.stringify(_last,null,2)],{type:'application/json'});
  const a=document.createElement('a');a.href=URL.createObjectURL(b);
  a.download='vulnscope-'+(_last.summary?.target||'report')+'-'+Date.now()+'.json';a.click();
}
</script>
</body>
</html>apis = ['nvd'=>'NVD v2','shodan'=>'Shodan','censys'=>'Censys v2'];
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VulnScope Pro â€” ZeroDay Security Intelligence Platform</title>
<meta name="description" content="Enterprise vulnerability intelligence and attack surface assessment by ZeroDay Security Services.">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
:root{--bg-root:#020408;--bg-card:rgba(10,18,30,0.9);--accent:#06b6d4;--accent2:#3b82f6;--accent-glow:rgba(6,182,212,0.12);--accent-border:rgba(6,182,212,0.22);--danger:#ef4444;--danger-dim:rgba(239,68,68,0.08);--danger-border:rgba(239,68,68,0.28);--warn:#f97316;--warn-dim:rgba(249,115,22,0.08);--med:#eab308;--med-dim:rgba(234,179,8,0.08);--low:#22d3ee;--low-dim:rgba(34,211,238,0.06);--info:#64748b;--info-dim:rgba(100,116,139,0.06);--t1:#e2e8f0;--t2:#94a3b8;--t3:#475569;--t4:#1e293b;--border:rgba(30,41,59,0.8);--border2:rgba(51,65,85,0.9);--r8:8px;--r12:12px;--r16:16px;--r20:20px;--r24:24px;--sidebar:260px;--topbar:60px;--ease:all 0.22s cubic-bezier(.4,0,.2,1);--font:'Inter',system-ui,sans-serif;--mono:'JetBrains Mono','Courier New',monospace}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{background:var(--bg-root);color:var(--t1);font-family:var(--font);overflow-x:hidden;min-height:100vh}
::-webkit-scrollbar{width:4px;height:4px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:#1e293b;border-radius:99px}

/* === BG CANVAS === */
#bgc{position:fixed;inset:0;z-index:0;pointer-events:none;opacity:.35}

/* === LAYOUT === */
#shell{position:relative;z-index:1;display:flex;min-height:100vh}

/* === SIDEBAR === */
#sb{width:var(--sidebar);flex-shrink:0;background:rgba(4,8,18,0.97);border-right:1px solid var(--border);display:flex;flex-direction:column;position:fixed;top:0;left:0;height:100vh;z-index:200;backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);transition:transform .3s ease;overflow:hidden}
.sb-logo{padding:20px 16px 18px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:10px}
.sb-logo img{width:38px;height:38px;object-fit:contain;border-radius:8px;filter:drop-shadow(0 0 8px rgba(6,182,212,.5))}
.sb-logo-txt h2{font-size:13px;font-weight:800;letter-spacing:.04em;text-transform:uppercase}
.sb-logo-txt h2 span{color:var(--accent)}
.sb-logo-txt p{font-size:9px;color:var(--accent);font-family:var(--mono);letter-spacing:.12em;margin-top:1px}
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
.dot-on{background:#22c55e;box-shadow:0 0 5px #22c55e;animation:dotpulse 2s infinite}
.dot-off{background:#ef4444}
@keyframes dotpulse{0%,100%{opacity:1}50%{opacity:.35}}
.api-badge{font-family:var(--mono);font-size:9px;font-weight:700;padding:2px 6px;border-radius:4px;text-transform:uppercase;letter-spacing:.04em}
.api-badge.on{background:rgba(34,197,94,.1);color:#22c55e;border:1px solid rgba(34,197,94,.2)}
.api-badge.off{background:rgba(239,68,68,.1);color:#ef4444;border:1px solid rgba(239,68,68,.2)}
.sb-footer{padding:12px 14px;border-top:1px solid var(--border);font-size:9px;color:var(--t4);text-align:center;font-family:var(--mono)}

/* === MAIN === */
#main{margin-left:var(--sidebar);flex:1;display:flex;flex-direction:column;min-height:100vh}

/* === TOPBAR === */
#topbar{height:var(--topbar);border-bottom:1px solid var(--border);background:rgba(4,8,18,.8);backdrop-filter:blur(20px);display:flex;align-items:center;justify-content:space-between;padding:0 24px;position:sticky;top:0;z-index:100}
.tb-left{display:flex;align-items:center;gap:12px}
.tb-bread{display:flex;align-items:center;gap:6px;font-size:12px;color:var(--t3)}
.tb-bread .active{color:var(--t1);font-weight:600}
.tb-bread i{font-size:8px}
.tb-right{display:flex;align-items:center;gap:10px}
.tb-pill{display:flex;align-items:center;gap:5px;font-size:10px;font-family:var(--mono);color:var(--t3);background:rgba(255,255,255,.03);border:1px solid var(--border);padding:4px 10px;border-radius:var(--r8)}
.tb-pill .ldot{width:5px;height:5px;border-radius:50%;background:#22c55e;animation:dotpulse 2s infinite}
#sbtoggle{display:none;background:none;border:1px solid var(--border);color:var(--t2);padding:7px 10px;border-radius:var(--r8);cursor:pointer;transition:var(--ease);font-size:13px}
#sbtoggle:hover{border-color:var(--accent-border);color:var(--accent)}

/* === PAGE === */
#pg{flex:1;padding:24px}

/* === SCAN PANEL === */
.scan-panel{background:var(--bg-card);border:1px solid var(--border2);border-radius:var(--r24);padding:28px 32px;margin-bottom:24px;position:relative;overflow:hidden;backdrop-filter:blur(16px)}
.scan-panel::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,var(--accent),var(--accent2),transparent);opacity:.55}
.scan-ph{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;margin-bottom:22px;flex-wrap:wrap}
.scan-ph h1{font-size:18px;font-weight:800;letter-spacing:-.01em;margin-bottom:4px}
.scan-ph p{font-size:11px;color:var(--t3);font-family:var(--mono);letter-spacing:.04em}
.eng-badge{display:flex;align-items:center;gap:7px;background:rgba(6,182,212,.05);border:1px solid var(--accent-border);border-radius:var(--r12);padding:7px 13px;font-size:10px;font-family:var(--mono);color:var(--accent);text-transform:uppercase;letter-spacing:.07em;white-space:nowrap;flex-shrink:0}
.scan-row{display:flex;gap:10px;align-items:stretch}
.inp-wrap{position:relative;flex:1}
.inp-ico{position:absolute;left:15px;top:50%;transform:translateY(-50%);color:var(--t3);font-size:13px;pointer-events:none;transition:var(--ease)}
#target{width:100%;background:rgba(4,8,18,.9);border:1px solid var(--border2);border-radius:var(--r12);padding:14px 16px 14px 44px;font-family:var(--mono);font-size:13px;color:var(--t1);outline:none;transition:var(--ease);letter-spacing:.02em}
#target::placeholder{color:var(--t4)}
#target:focus{border-color:var(--accent);background:rgba(4,8,18,1);box-shadow:0 0 0 3px rgba(6,182,212,.07),0 0 20px rgba(6,182,212,.04)}
#btn{background:linear-gradient(135deg,var(--accent),var(--accent2));color:#fff;border:none;border-radius:var(--r12);padding:14px 26px;font-family:var(--font);font-size:13px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;cursor:pointer;transition:var(--ease);display:flex;align-items:center;gap:8px;white-space:nowrap;position:relative;overflow:hidden;flex-shrink:0}
#btn::after{content:'';position:absolute;inset:0;background:linear-gradient(135deg,rgba(255,255,255,.18),transparent);opacity:0;transition:var(--ease)}
#btn:hover::after{opacity:1}
#btn:hover{transform:translateY(-1px);box-shadow:0 8px 24px rgba(6,182,212,.28)}
#btn:active{transform:none}
#btn:disabled{opacity:.4;filter:grayscale(.4);cursor:not-allowed;transform:none;box-shadow:none}
#loader{display:none;margin-top:18px;padding:14px 18px;background:rgba(6,182,212,.04);border:1px solid var(--accent-border);border-radius:var(--r12);align-items:center;gap:14px}
#loader.show{display:flex}
.ld-spin{width:30px;height:30px;border:2px solid var(--accent-border);border-top-color:var(--accent);border-radius:50%;animation:spin .8s linear infinite;flex-shrink:0}
@keyframes spin{to{transform:rotate(360deg)}}
.ld-bar-wrap{flex:1}
.ld-txt{font-size:11px;font-family:var(--mono);color:var(--accent);letter-spacing:.03em;margin-bottom:7px}
.ld-track{height:2px;background:rgba(6,182,212,.1);border-radius:99px;overflow:hidden}
.ld-fill{height:100%;width:30%;background:linear-gradient(90deg,var(--accent),var(--accent2));border-radius:99px;animation:ldsweep 1.8s ease-in-out infinite}
@keyframes ldsweep{0%{transform:translateX(-100%)}100%{transform:translateX(400%)}}

/* === RESULTS === */
#results{display:none;animation:fadeup .35s ease}
#results.show{display:block}
@keyframes fadeup{from{opacity:0;transform:translateY(14px)}to{opacity:1;transform:translateY(0)}}
.res-hdr{display:flex;align-items:center;justify-content:space-between;margin-bottom:18px;flex-wrap:wrap;gap:10px}
.res-hdr-title{font-size:11px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:var(--t3);display:flex;align-items:center;gap:8px}
.res-hdr-title::before{content:'';width:3px;height:14px;background:linear-gradient(var(--accent),var(--accent2));border-radius:2px;flex-shrink:0}
.exp-btn{display:flex;align-items:center;gap:6px;padding:7px 13px;background:transparent;border:1px solid var(--border2);border-radius:var(--r8);color:var(--t2);font-size:11px;font-weight:600;cursor:pointer;transition:var(--ease)}
.exp-btn:hover{border-color:var(--accent-border);color:var(--accent);background:var(--accent-glow)}

/* === STAT CARDS === */
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:18px}
.sc{background:var(--bg-card);border:1px solid var(--border);border-radius:var(--r16);padding:18px 20px;backdrop-filter:blur(12px);position:relative;overflow:hidden;transition:var(--ease)}
.sc::after{content:'';position:absolute;bottom:0;left:0;right:0;height:2px;opacity:0;transition:var(--ease)}
.sc:hover{transform:translateY(-2px);border-color:var(--border2)}
.sc:hover::after{opacity:1}
.sc.risk::after{background:linear-gradient(90deg,var(--danger),var(--warn))}
.sc.finds::after{background:linear-gradient(90deg,var(--accent),var(--accent2))}
.sc.ports::after{background:linear-gradient(90deg,#a855f7,var(--accent2))}
.sc.ip::after{background:linear-gradient(90deg,var(--med),var(--warn))}
.sc-lbl{font-size:9px;font-weight:700;letter-spacing:.15em;text-transform:uppercase;color:var(--t4);margin-bottom:10px}
.sc-val{font-size:32px;font-weight:900;line-height:1;margin-bottom:8px;font-variant-numeric:tabular-nums}
.sc.risk .sc-val{color:var(--danger)}
.sc.finds .sc-val{color:var(--accent)}
.sc.ports .sc-val{color:#a855f7}
.sc.ip .sc-val{font-size:16px;padding-top:8px;color:var(--med)}
.sc-meta{font-size:10px;color:var(--t3);font-family:var(--mono)}
.risk-trk{height:3px;background:rgba(255,255,255,.05);border-radius:99px;overflow:hidden;margin:6px 0}
#riskBar{height:100%;background:linear-gradient(90deg,var(--med),var(--warn),var(--danger));border-radius:99px;width:0%;transition:width 1.1s cubic-bezier(.4,0,.2,1)}

/* === BODY GRID === */
.res-body{display:grid;grid-template-columns:320px 1fr;gap:16px;margin-bottom:16px}

/* === PANEL === */
.panel{background:var(--bg-card);border:1px solid var(--border);border-radius:var(--r16);backdrop-filter:blur(12px);overflow:hidden}
.panel-hdr{padding:14px 18px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px}
.panel-title{font-size:10px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:var(--t2);display:flex;align-items:center;gap:7px}
.panel-title i{color:var(--accent);font-size:11px}
.panel-body{padding:18px}

/* === SEV BARS === */
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

/* === API STATUS (results panel) === */
#apiStatusDisplay{display:flex;flex-direction:column;gap:7px}

/* === VULN FILTERS === */
.vf-wrap{display:flex;gap:5px;flex-wrap:wrap}
.fb{font-size:9px;font-weight:700;font-family:var(--mono);letter-spacing:.07em;text-transform:uppercase;padding:3px 9px;border-radius:6px;border:1px solid var(--border2);background:transparent;color:var(--t3);cursor:pointer;transition:var(--ease)}
.fb:hover,.fb.active{background:var(--accent-glow);border-color:var(--accent-border);color:var(--accent)}
.fb.fc.active{background:var(--danger-dim);border-color:var(--danger-border);color:var(--danger)}
.fb.fh.active{background:var(--warn-dim);border-color:rgba(249,115,22,.3);color:var(--warn)}
.fb.fm.active{background:var(--med-dim);border-color:rgba(234,179,8,.3);color:var(--med)}

/* === VULN LIST === */
#vulnList{max-height:500px;overflow-y:auto;display:flex;flex-direction:column;gap:9px;padding:16px 18px}
.vc{border-radius:var(--r12);padding:14px 16px;border:1px solid var(--border);background:rgba(255,255,255,.016);transition:var(--ease);animation:cin .25s ease both;position:relative;overflow:hidden}
.vc::before{content:'';position:absolute;left:0;top:0;bottom:0;width:3px}
.vc.severity-Critical::before{background:var(--danger)}.vc.severity-Critical{border-color:var(--danger-border);background:var(--danger-dim)}
.vc.severity-High::before{background:var(--warn)}.vc.severity-High{border-color:rgba(249,115,22,.2);background:var(--warn-dim)}
.vc.severity-Medium::before{background:var(--med)}.vc.severity-Medium{border-color:rgba(234,179,8,.2);background:var(--med-dim)}
.vc.severity-Low::before{background:var(--low)}.vc.severity-Low{border-color:rgba(34,211,238,.15);background:var(--low-dim)}
.vc.severity-Info::before{background:var(--info)}.vc.severity-Info{border-color:var(--border);background:var(--info-dim)}
.vc:hover{transform:translateX(2px)}
@keyframes cin{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}
.vc-top{display:flex;align-items:flex-start;justify-content:space-between;gap:8px;margin-bottom:9px;flex-wrap:wrap}
.vc-ids{display:flex;align-items:center;gap:7px;flex-wrap:wrap}
.vc-id{font-family:var(--mono);font-size:12px;font-weight:700;color:var(--accent)}
.src-badge{font-size:8px;font-weight:700;font-family:var(--mono);letter-spacing:.09em;text-transform:uppercase;padding:2px 6px;border-radius:4px;background:rgba(255,255,255,.04);color:var(--t3);border:1px solid var(--border2)}
.sev-tags{display:flex;align-items:center;gap:5px;flex-shrink:0}
.sp{font-size:9px;font-weight:700;font-family:var(--mono);letter-spacing:.07em;text-transform:uppercase;padding:2px 7px;border-radius:5px}
.sp.Critical{background:rgba(239,68,68,.14);color:var(--danger);border:1px solid var(--danger-border)}
.sp.High{background:rgba(249,115,22,.12);color:var(--warn);border:1px solid rgba(249,115,22,.25)}
.sp.Medium{background:rgba(234,179,8,.12);color:var(--med);border:1px solid rgba(234,179,8,.25)}
.sp.Low{background:rgba(34,211,238,.08);color:var(--low);border:1px solid rgba(34,211,238,.2)}
.sp.Info,.sp.Unknown{background:rgba(100,116,139,.09);color:var(--info);border:1px solid var(--border)}
.cvss-chip{font-size:9px;font-family:var(--mono);font-weight:600;color:var(--t3);background:rgba(255,255,255,.03);border:1px solid var(--border);padding:2px 6px;border-radius:4px}
.vc-sum{font-size:11.5px;color:var(--t2);line-height:1.6;margin-bottom:10px}
.vc-meta{display:flex;align-items:center;justify-content:space-between;padding-top:9px;border-top:1px solid rgba(255,255,255,.04);flex-wrap:wrap;gap:6px}
.vc-svc{font-size:10px;color:var(--t4);font-family:var(--mono);display:flex;align-items:center;gap:5px}
.port-chip{font-size:9px;font-family:var(--mono);font-weight:700;color:var(--t3);background:rgba(255,255,255,.04);border:1px solid var(--border);padding:2px 7px;border-radius:4px}
.empty{padding:40px 20px;text-align:center;color:var(--t4);font-family:var(--mono);font-size:12px;display:flex;flex-direction:column;align-items:center;gap:10px}
.empty i{font-size:26px;color:var(--t4)}

/* === INFRA / PORT GRID === */
#portGrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(190px,1fr));gap:10px;max-height:420px;overflow-y:auto;padding:16px 18px}
.svc-card{background:rgba(255,255,255,.02);border:1px solid var(--border);border-radius:var(--r12);padding:14px;display:flex;align-items:flex-start;gap:10px;transition:var(--ease);animation:cin .25s ease both}
.svc-card:hover{transform:translateY(-2px);border-color:var(--accent-border);background:var(--accent-glow);box-shadow:0 6px 20px rgba(6,182,212,.07)}
.svc-ico{width:34px;height:34px;border-radius:8px;background:rgba(6,182,212,.08);border:1px solid var(--accent-border);display:flex;align-items:center;justify-content:center;color:var(--accent);font-size:12px;flex-shrink:0}
.svc-info{flex:1;min-width:0}
.svc-nm{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:var(--t1);margin-bottom:2px;display:flex;align-items:center;justify-content:space-between;gap:4px}
.open-pill{font-size:7px;font-weight:700;font-family:var(--mono);color:#22c55e;background:rgba(34,197,94,.08);border:1px solid rgba(34,197,94,.2);padding:1px 4px;border-radius:3px;letter-spacing:.06em}
.svc-port{font-family:var(--mono);font-size:10px;color:var(--accent);font-weight:600;margin-bottom:2px}
.svc-prod{font-size:9px;color:var(--t4);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}

/* === TOAST === */
#error-toast{position:fixed;bottom:20px;right:20px;z-index:9999;background:rgba(25,8,8,.97);border:1px solid rgba(239,68,68,.35);color:var(--t1);padding:12px 16px;border-radius:var(--r12);display:flex;align-items:center;gap:10px;max-width:360px;backdrop-filter:blur(16px);box-shadow:0 8px 32px rgba(0,0,0,.5);transform:translateY(110%);transition:transform .3s cubic-bezier(.34,1.56,.64,1)}
#error-toast.show{transform:translateY(0)}
.t-ico{width:30px;height:30px;border-radius:8px;background:rgba(239,68,68,.12);display:flex;align-items:center;justify-content:center;color:var(--danger);font-size:12px;flex-shrink:0}
.t-body{flex:1}
.t-ttl{font-size:10px;font-weight:700;color:var(--danger);margin-bottom:2px;text-transform:uppercase;letter-spacing:.06em}
#error-msg{font-size:12px;color:var(--t2);line-height:1.45}
.t-close{background:none;border:none;color:var(--t3);cursor:pointer;font-size:16px;transition:var(--ease);padding:0;line-height:1}
.t-close:hover{color:var(--t1)}

/* === OVERLAY === */
#sb-ov{display:none;position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:199;backdrop-filter:blur(2px)}
#sb-ov.on{display:block}

/* =========================================
   RESPONSIVE BREAKPOINTS
   ========================================= */

/* Tablet (<=1024px) â€” sidebar collapses to icon-only or hidden */
@media(max-width:1024px){
  :root{--sidebar:0px}
  #sb{transform:translateX(-260px);width:260px}
  #sb.open{transform:translateX(0)}
  #main{margin-left:0}
  #sbtoggle{display:flex;align-items:center}
  .res-body{grid-template-columns:1fr}
  .stats{grid-template-columns:repeat(2,1fr)}
}

/* Large mobile / small tablet (<=768px) */
@media(max-width:768px){
  #pg{padding:14px}
  .scan-panel{padding:20px 18px}
  .scan-ph h1{font-size:16px}
  .scan-row{flex-direction:column}
  #btn{width:100%;justify-content:center}
  .stats{grid-template-columns:repeat(2,1fr);gap:10px}
  .sc-val{font-size:28px}
  #portGrid{grid-template-columns:repeat(auto-fill,minmax(160px,1fr))}
  .tb-pill:last-child{display:none}
  .res-hdr{flex-direction:column;align-items:flex-start}
}

/* Mobile (<=480px) */
@media(max-width:480px){
  :root{--topbar:54px}
  #pg{padding:10px}
  .scan-panel{padding:16px 14px;border-radius:var(--r16)}
  .scan-ph{gap:8px}
  .eng-badge{display:none}
  .stats{grid-template-columns:1fr 1fr;gap:8px}
  .sc{padding:14px 16px}
  .sc-val{font-size:24px}
  .sc.ip .sc-val{font-size:13px}
  .sc-lbl{font-size:8px}
  #vulnList{padding:10px 12px}
  #portGrid{grid-template-columns:1fr 1fr;padding:10px 12px}
  .panel-hdr{padding:12px 14px}
  .panel-body{padding:14px}
  .vc{padding:12px 13px}
  .vc-id{font-size:11px}
  .vc-sum{font-size:11px}
  .tb-right{gap:6px}
  .topbar-badge{font-size:9px}
}

/* Very small screens (<=360px) */
@media(max-width:360px){
  .stats{grid-template-columns:1fr}
  #portGrid{grid-template-columns:1fr}
}
</style>
</head>
<body>
<canvas id="bgc"></canvas>
<div id="sb-ov" onclick="closeSB()"></div>

<!-- Toast -->
<div id="error-toast">
  <div class="t-ico"><i class="fas fa-triangle-exclamation"></i></div>
  <div class="t-body"><div class="t-ttl">Error</div><span id="error-msg"></span></div>
  <button class="t-close" onclick="hideError()">&times;</button>
</div>

<div id="shell">
<!-- SIDEBAR -->
<aside id="sb">
  <div class="sb-logo">
    <img src="logo.jpg" alt="ZeroDay" onerror="this.style.display='none'">
    <div class="sb-logo-txt">
      <h2>VulnScope <span>Pro</span></h2>
      <p>ZeroDay Security</p>
    </div>
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
    PHP_API_ROWS
  </div>
  <div class="sb-footer">Vijay Ishan Chowdhury &mdash; ZeroDay Security Services</div>
</aside>

<!-- MAIN -->
<div id="main">
  <!-- Topbar -->
  <header id="topbar">
    <div class="tb-left">
      <button id="sbtoggle" onclick="toggleSB()"><i class="fas fa-bars"></i></button>
      <div class="tb-bread">
        <i class="fas fa-shield-halved" style="color:var(--accent);font-size:12px"></i>
        <span>ZeroDay Security</span>
        <i class="fas fa-chevron-right"></i>
        <span class="active">VulnScope Pro</span>
      </div>
    </div>
    <div class="tb-right">
      <div class="tb-pill"><span class="ldot"></span>ENGINE ONLINE</div>
      <div class="tb-pill"><i class="fas fa-microchip" style="font-size:9px"></i>Enterprise v4.0</div>
    </div>
  </header>

  <!-- Page -->
  <main id="pg">
    <!-- Scan Panel -->
    <section class="scan-panel">
      <div class="scan-ph">
        <div>
          <h1>Attack Surface Assessment</h1>
          <p>NVD v2 &middot; Shodan &middot; Censys v2 &middot; CIRCL &middot; Nmap / PHP Socket Engine</p>
        </div>
        <div class="eng-badge"><i class="fas fa-circle" style="font-size:7px;color:#22c55e;animation:dotpulse 1.5s infinite"></i>Scan Core Active</div>
      </div>
      <form id="scanForm">
        <div class="scan-row">
          <div class="inp-wrap">
            <input type="text" id="target" placeholder="Enter target IP or domain â€” e.g. 192.168.1.1 or example.com" autocomplete="off" spellcheck="false">
            <i class="fas fa-crosshairs inp-ico"></i>
          </div>
          <button type="submit" id="btn"><i class="fas fa-shield-virus"></i>Launch Assessment</button>
        </div>
      </form>
      <div id="loader" class="hidden">
        <div class="ld-spin"></div>
        <div class="ld-bar-wrap">
          <div class="ld-txt"><i class="fas fa-circle-notch fa-spin" style="margin-right:6px"></i>Initializing scan engine &amp; correlating multi-source intelligence...</div>
          <div class="ld-track"><div class="ld-fill"></div></div>
        </div>
      </div>
    </section>

    <!-- Results -->
    <div id="results">
      <div class="res-hdr">
        <div class="res-hdr-title">Scan Results</div>
        <button class="exp-btn" onclick="exportReport()"><i class="fas fa-file-export"></i>Export JSON</button>
      </div>

      <!-- Stat Cards -->
      <div class="stats">
        <div class="sc risk">
          <div class="sc-lbl">Composite Risk Score</div>
          <div class="sc-val" id="riskValue">0</div>
          <div class="risk-trk"><div id="riskBar"></div></div>
          <div class="sc-meta" id="resTarget">HOST: ---</div>
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

      <!-- Left col: Severity + API Status | Right col: Vuln Feed -->
      <div class="res-body">
        <div style="display:flex;flex-direction:column;gap:14px">
          <!-- Severity -->
          <div class="panel">
            <div class="panel-hdr"><div class="panel-title"><i class="fas fa-chart-bar"></i>Severity Distribution</div></div>
            <div class="panel-body"><div id="severityBars"></div></div>
          </div>
          <!-- API Status -->
          <div class="panel">
            <div class="panel-hdr"><div class="panel-title"><i class="fas fa-plug-circle-check"></i>Intelligence Sources</div></div>
            <div class="panel-body" style="padding:14px 18px"><div id="apiStatusDisplay"></div></div>
          </div>
        </div>

        <!-- Vuln Feed -->
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
          <div id="vulnList"></div>
        </div>
      </div>

      <!-- Infra Map -->
      <div class="panel" id="infra-section" style="margin-bottom:0">
        <div class="panel-hdr">
          <div class="panel-title"><i class="fas fa-microchip"></i>Detected Infrastructure &amp; Services</div>
          <span id="portsCount" style="font-size:10px;font-family:var(--mono);color:var(--t3);text-transform:uppercase;letter-spacing:.07em">0 Assets</span>
        </div>
        <div id="portGrid"></div>
      </div>
    </div><!-- /#results -->
  </main>
</div><!-- /#main -->
</div><!-- /#shell -->

<script>
const SCAN_TOKEN='<?php echo SCAN_TOKEN; ?>';
let _last=null,_all=[];

/* BG canvas */
(function(){
  const c=document.getElementById('bgc'),ctx=c.getContext('2d');
  let w,h,pts=[];
  function rsz(){w=c.width=window.innerWidth;h=c.height=window.innerHeight}
  function init(){pts=[];const n=Math.floor(w*h/16000);for(let i=0;i<n;i++)pts.push({x:Math.random()*w,y:Math.random()*h,r:Math.random()*1.1+.3,vx:(Math.random()-.5)*.16,vy:(Math.random()-.5)*.16})}
  function draw(){
    ctx.clearRect(0,0,w,h);
    ctx.fillStyle='rgba(6,182,212,.4)';
    for(const d of pts){d.x+=d.vx;d.y+=d.vy;if(d.x<0||d.x>w)d.vx*=-1;if(d.y<0||d.y>h)d.vy*=-1;ctx.beginPath();ctx.arc(d.x,d.y,d.r,0,Math.PI*2);ctx.fill()}
    ctx.strokeStyle='rgba(6,182,212,.055)';ctx.lineWidth=.5;
    for(let i=0;i<pts.length;i++)for(let j=i+1;j<pts.length;j++){const dx=pts[i].x-pts[j].x,dy=pts[i].y-pts[j].y,d=Math.sqrt(dx*dx+dy*dy);if(d<110){ctx.globalAlpha=1-d/110;ctx.beginPath();ctx.moveTo(pts[i].x,pts[i].y);ctx.lineTo(pts[j].x,pts[j].y);ctx.stroke()}}
    ctx.globalAlpha=1;requestAnimationFrame(draw)
  }
  window.addEventListener('resize',()=>{rsz();init()});rsz();init();draw();
})();

/* Sidebar */
function toggleSB(){document.getElementById('sb').classList.toggle('open');document.getElementById('sb-ov').classList.toggle('on')}
function closeSB(){document.getElementById('sb').classList.remove('open');document.getElementById('sb-ov').classList.remove('on')}

/* Scroll helpers */
function toResults(){document.getElementById('results').scrollIntoView({behavior:'smooth'})}
function toInfra(){const e=document.getElementById('infra-section');if(e)e.scrollIntoView({behavior:'smooth'})}

/* Toast */
function showError(m){document.getElementById('error-msg').innerText=m;document.getElementById('error-toast').classList.add('show');setTimeout(hideError,6000)}
function hideError(){document.getElementById('error-toast').classList.remove('show')}

/* Counter animation */
function ctr(el,target,dur=900){
  const s=performance.now(),f=parseInt(el.innerText)||0;
  (function step(n){const p=Math.min((n-s)/dur,1),e=1-Math.pow(1-p,3);el.innerText=Math.round(f+(target-f)*e);if(p<1)requestAnimationFrame(step)})(s)
}

/* Scan form */
document.getElementById('scanForm').onsubmit=async(e)=>{
  e.preventDefault();
  const t=document.getElementById('target').value.trim();
  const btn=document.getElementById('btn'),ldr=document.getElementById('loader');
  if(!t)return showError('No target specified.');
  btn.disabled=true;ldr.classList.remove('hidden');ldr.classList.add('show');
  document.getElementById('results').classList.remove('show');document.getElementById('results').style.display='none';
  const fd=new FormData();fd.append('target',t);
  try{
    const r=await fetch('?action=scan',{method:'POST',body:fd,headers:{'X-VulnScope-Token':SCAN_TOKEN}});
    const j=await r.json();
    if(j.success){_last=j;renderDashboard(j)}else showError(j.message);
  }catch(err){showError('Operational failure: Intelligence core unreachable.')}
  finally{btn.disabled=false;ldr.classList.add('hidden');ldr.classList.remove('show')}
};

/* Render */
function renderDashboard(resp){
  const{summary:s,severity_distribution:sd,findings:f,debug_info:di,api_status:as}=resp;
  const re=document.getElementById('results');re.style.display='block';re.classList.add('show');
  ctr(document.getElementById('riskValue'),s.risk_score);
  setTimeout(()=>{document.getElementById('riskBar').style.width=s.risk_score+'%'},60);
  document.getElementById('resTarget').innerText='HOST: '+s.target;
  document.getElementById('resIp').innerText=s.ip;
  ctr(document.getElementById('findingsCount'),s.total_findings);
  ctr(document.getElementById('portsCountVal'),s.open_ports_count);
  document.querySelectorAll('#portsCount').forEach(el=>el.innerText=s.open_ports_count+' ASSETS');
  if(as)document.getElementById('apiStatusDisplay').innerHTML=Object.entries(as).map(([k,v])=>{
    const ok=v==='configured';
    return `<div class="sb-api-row"><div class="sb-api-name"><span class="dot ${ok?'dot-on':'dot-off'}"></span>${k.toUpperCase()}</div><span class="api-badge ${ok?'on':'off'}">${ok?'Active':'Offline'}</span></div>`;
  }).join('');
  renderSevBars(sd,s.total_findings);
  renderPorts(di.ports||[]);
  _all=f;renderVulns(f);
  setTimeout(()=>re.scrollIntoView({behavior:'smooth',block:'start'}),120);
}

/* Severity bars */
function renderSevBars(d,tot){
  const sevs=['Critical','High','Medium','Low','Info'];
  document.getElementById('severityBars').innerHTML=sevs.map(s=>{
    const cnt=d[s.toLowerCase()]||0,pct=tot>0?Math.round(cnt/tot*100):0;
    return `<div class="sev-row sev-${s}"><div class="sev-hdr"><span class="sev-name">${s}</span><div class="sev-right"><span class="sev-pct">${pct}%</span><span class="sev-cnt">${cnt}</span></div></div><div class="sev-trk"><div class="progress-bar bar-${s}" data-p="${pct}" style="width:0%"></div></div></div>`;
  }).join('');
  setTimeout(()=>document.querySelectorAll('.progress-bar[data-p]').forEach(b=>b.style.width=b.dataset.p+'%'),80);
}

/* Icon map */
function ico(s){
  if(!s)return'fa-server';s=s.toLowerCase();
  if(s.includes('http')||s.includes('www'))return'fa-globe';
  if(s.includes('ssh'))return'fa-terminal';
  if(s.includes('sql')||s.includes('mysql')||s.includes('pg')||s.includes('mongo'))return'fa-database';
  if(s.includes('ftp'))return'fa-upload';
  if(s.includes('smtp')||s.includes('mail')||s.includes('pop')||s.includes('imap'))return'fa-envelope';
  if(s.includes('dns')||s.includes('domain'))return'fa-sitemap';
  if(s.includes('rdp')||s.includes('vnc')||s.includes('remote'))return'fa-desktop';
  if(s.includes('ldap'))return'fa-users';
  if(s.includes('redis')||s.includes('memcache'))return'fa-memory';
  if(s.includes('docker'))return'fa-docker';
  return'fa-server';
}

/* Port grid */
function renderPorts(ports){
  document.getElementById('portGrid').innerHTML=ports.length?ports.map((p,i)=>`
    <div class="svc-card" style="animation-delay:${i*35}ms">
      <div class="svc-ico"><i class="fas ${ico(p.service)}"></i></div>
      <div class="svc-info">
        <div class="svc-nm"><span>${(p.service||'unknown').toUpperCase()}</span><span class="open-pill">OPEN</span></div>
        <div class="svc-port">${p.port}/TCP</div>
        <div class="svc-prod">${[p.product,p.version].filter(Boolean).join(' ')||'&mdash;'}</div>
      </div>
    </div>`).join('')
  :`<div class="empty" style="grid-column:1/-1"><i class="fas fa-network-wired"></i>No open services detected</div>`;
}

/* Vuln list */
function renderVulns(f){
  const list=document.getElementById('vulnList');
  list.innerHTML=f.length?f.map((v,i)=>`
    <div class="vc severity-${v.severity||'Info'}" style="animation-delay:${i*30}ms">
      <div class="vc-top">
        <div class="vc-ids"><span class="vc-id">${v.id}</span><span class="src-badge">${v.source}</span></div>
        <div class="sev-tags"><span class="sp ${v.severity||'Info'}">${v.severity||'Info'}</span><span class="cvss-chip">CVSS ${v.cvss>0?v.cvss:'N/A'}</span></div>
      </div>
      <p class="vc-sum">${v.summary}</p>
      <div class="vc-meta">
        <div class="vc-svc"><i class="fas fa-microchip"></i>${v.affected_service||'&mdash;'}</div>
        <span class="port-chip">PORT ${v.port}</span>
      </div>
    </div>`).join('')
  :`<div class="empty"><i class="fas fa-shield-check"></i>No CVE matches found &mdash; target appears hardened.</div>`;
}

function fvulns(sev,btn){
  document.querySelectorAll('.fb').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  renderVulns(sev==='all'?_all:_all.filter(f=>f.severity===sev));
}

/* Export */
function exportReport(){
  if(!_last)return showError('No scan data yet. Run a scan first.');
  const b=new Blob([JSON.stringify(_last,null,2)],{type:'application/json'});
  const a=document.createElement('a');a.href=URL.createObjectURL(b);
  a.download='vulnscope-'+(_last.summary?.target||'report')+'-'+Date.now()+'.json';a.click();
}
</script>
</body>
</html>status = get_api_status();
foreach(<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VulnScope Pro â€” ZeroDay Security Intelligence Platform</title>
<meta name="description" content="Enterprise vulnerability intelligence and attack surface assessment by ZeroDay Security Services.">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
:root{--bg-root:#020408;--bg-card:rgba(10,18,30,0.9);--accent:#06b6d4;--accent2:#3b82f6;--accent-glow:rgba(6,182,212,0.12);--accent-border:rgba(6,182,212,0.22);--danger:#ef4444;--danger-dim:rgba(239,68,68,0.08);--danger-border:rgba(239,68,68,0.28);--warn:#f97316;--warn-dim:rgba(249,115,22,0.08);--med:#eab308;--med-dim:rgba(234,179,8,0.08);--low:#22d3ee;--low-dim:rgba(34,211,238,0.06);--info:#64748b;--info-dim:rgba(100,116,139,0.06);--t1:#e2e8f0;--t2:#94a3b8;--t3:#475569;--t4:#1e293b;--border:rgba(30,41,59,0.8);--border2:rgba(51,65,85,0.9);--r8:8px;--r12:12px;--r16:16px;--r20:20px;--r24:24px;--sidebar:260px;--topbar:60px;--ease:all 0.22s cubic-bezier(.4,0,.2,1);--font:'Inter',system-ui,sans-serif;--mono:'JetBrains Mono','Courier New',monospace}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{background:var(--bg-root);color:var(--t1);font-family:var(--font);overflow-x:hidden;min-height:100vh}
::-webkit-scrollbar{width:4px;height:4px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:#1e293b;border-radius:99px}

/* === BG CANVAS === */
#bgc{position:fixed;inset:0;z-index:0;pointer-events:none;opacity:.35}

/* === LAYOUT === */
#shell{position:relative;z-index:1;display:flex;min-height:100vh}

/* === SIDEBAR === */
#sb{width:var(--sidebar);flex-shrink:0;background:rgba(4,8,18,0.97);border-right:1px solid var(--border);display:flex;flex-direction:column;position:fixed;top:0;left:0;height:100vh;z-index:200;backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);transition:transform .3s ease;overflow:hidden}
.sb-logo{padding:20px 16px 18px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:10px}
.sb-logo img{width:38px;height:38px;object-fit:contain;border-radius:8px;filter:drop-shadow(0 0 8px rgba(6,182,212,.5))}
.sb-logo-txt h2{font-size:13px;font-weight:800;letter-spacing:.04em;text-transform:uppercase}
.sb-logo-txt h2 span{color:var(--accent)}
.sb-logo-txt p{font-size:9px;color:var(--accent);font-family:var(--mono);letter-spacing:.12em;margin-top:1px}
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
.dot-on{background:#22c55e;box-shadow:0 0 5px #22c55e;animation:dotpulse 2s infinite}
.dot-off{background:#ef4444}
@keyframes dotpulse{0%,100%{opacity:1}50%{opacity:.35}}
.api-badge{font-family:var(--mono);font-size:9px;font-weight:700;padding:2px 6px;border-radius:4px;text-transform:uppercase;letter-spacing:.04em}
.api-badge.on{background:rgba(34,197,94,.1);color:#22c55e;border:1px solid rgba(34,197,94,.2)}
.api-badge.off{background:rgba(239,68,68,.1);color:#ef4444;border:1px solid rgba(239,68,68,.2)}
.sb-footer{padding:12px 14px;border-top:1px solid var(--border);font-size:9px;color:var(--t4);text-align:center;font-family:var(--mono)}

/* === MAIN === */
#main{margin-left:var(--sidebar);flex:1;display:flex;flex-direction:column;min-height:100vh}

/* === TOPBAR === */
#topbar{height:var(--topbar);border-bottom:1px solid var(--border);background:rgba(4,8,18,.8);backdrop-filter:blur(20px);display:flex;align-items:center;justify-content:space-between;padding:0 24px;position:sticky;top:0;z-index:100}
.tb-left{display:flex;align-items:center;gap:12px}
.tb-bread{display:flex;align-items:center;gap:6px;font-size:12px;color:var(--t3)}
.tb-bread .active{color:var(--t1);font-weight:600}
.tb-bread i{font-size:8px}
.tb-right{display:flex;align-items:center;gap:10px}
.tb-pill{display:flex;align-items:center;gap:5px;font-size:10px;font-family:var(--mono);color:var(--t3);background:rgba(255,255,255,.03);border:1px solid var(--border);padding:4px 10px;border-radius:var(--r8)}
.tb-pill .ldot{width:5px;height:5px;border-radius:50%;background:#22c55e;animation:dotpulse 2s infinite}
#sbtoggle{display:none;background:none;border:1px solid var(--border);color:var(--t2);padding:7px 10px;border-radius:var(--r8);cursor:pointer;transition:var(--ease);font-size:13px}
#sbtoggle:hover{border-color:var(--accent-border);color:var(--accent)}

/* === PAGE === */
#pg{flex:1;padding:24px}

/* === SCAN PANEL === */
.scan-panel{background:var(--bg-card);border:1px solid var(--border2);border-radius:var(--r24);padding:28px 32px;margin-bottom:24px;position:relative;overflow:hidden;backdrop-filter:blur(16px)}
.scan-panel::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,var(--accent),var(--accent2),transparent);opacity:.55}
.scan-ph{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;margin-bottom:22px;flex-wrap:wrap}
.scan-ph h1{font-size:18px;font-weight:800;letter-spacing:-.01em;margin-bottom:4px}
.scan-ph p{font-size:11px;color:var(--t3);font-family:var(--mono);letter-spacing:.04em}
.eng-badge{display:flex;align-items:center;gap:7px;background:rgba(6,182,212,.05);border:1px solid var(--accent-border);border-radius:var(--r12);padding:7px 13px;font-size:10px;font-family:var(--mono);color:var(--accent);text-transform:uppercase;letter-spacing:.07em;white-space:nowrap;flex-shrink:0}
.scan-row{display:flex;gap:10px;align-items:stretch}
.inp-wrap{position:relative;flex:1}
.inp-ico{position:absolute;left:15px;top:50%;transform:translateY(-50%);color:var(--t3);font-size:13px;pointer-events:none;transition:var(--ease)}
#target{width:100%;background:rgba(4,8,18,.9);border:1px solid var(--border2);border-radius:var(--r12);padding:14px 16px 14px 44px;font-family:var(--mono);font-size:13px;color:var(--t1);outline:none;transition:var(--ease);letter-spacing:.02em}
#target::placeholder{color:var(--t4)}
#target:focus{border-color:var(--accent);background:rgba(4,8,18,1);box-shadow:0 0 0 3px rgba(6,182,212,.07),0 0 20px rgba(6,182,212,.04)}
#btn{background:linear-gradient(135deg,var(--accent),var(--accent2));color:#fff;border:none;border-radius:var(--r12);padding:14px 26px;font-family:var(--font);font-size:13px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;cursor:pointer;transition:var(--ease);display:flex;align-items:center;gap:8px;white-space:nowrap;position:relative;overflow:hidden;flex-shrink:0}
#btn::after{content:'';position:absolute;inset:0;background:linear-gradient(135deg,rgba(255,255,255,.18),transparent);opacity:0;transition:var(--ease)}
#btn:hover::after{opacity:1}
#btn:hover{transform:translateY(-1px);box-shadow:0 8px 24px rgba(6,182,212,.28)}
#btn:active{transform:none}
#btn:disabled{opacity:.4;filter:grayscale(.4);cursor:not-allowed;transform:none;box-shadow:none}
#loader{display:none;margin-top:18px;padding:14px 18px;background:rgba(6,182,212,.04);border:1px solid var(--accent-border);border-radius:var(--r12);align-items:center;gap:14px}
#loader.show{display:flex}
.ld-spin{width:30px;height:30px;border:2px solid var(--accent-border);border-top-color:var(--accent);border-radius:50%;animation:spin .8s linear infinite;flex-shrink:0}
@keyframes spin{to{transform:rotate(360deg)}}
.ld-bar-wrap{flex:1}
.ld-txt{font-size:11px;font-family:var(--mono);color:var(--accent);letter-spacing:.03em;margin-bottom:7px}
.ld-track{height:2px;background:rgba(6,182,212,.1);border-radius:99px;overflow:hidden}
.ld-fill{height:100%;width:30%;background:linear-gradient(90deg,var(--accent),var(--accent2));border-radius:99px;animation:ldsweep 1.8s ease-in-out infinite}
@keyframes ldsweep{0%{transform:translateX(-100%)}100%{transform:translateX(400%)}}

/* === RESULTS === */
#results{display:none;animation:fadeup .35s ease}
#results.show{display:block}
@keyframes fadeup{from{opacity:0;transform:translateY(14px)}to{opacity:1;transform:translateY(0)}}
.res-hdr{display:flex;align-items:center;justify-content:space-between;margin-bottom:18px;flex-wrap:wrap;gap:10px}
.res-hdr-title{font-size:11px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:var(--t3);display:flex;align-items:center;gap:8px}
.res-hdr-title::before{content:'';width:3px;height:14px;background:linear-gradient(var(--accent),var(--accent2));border-radius:2px;flex-shrink:0}
.exp-btn{display:flex;align-items:center;gap:6px;padding:7px 13px;background:transparent;border:1px solid var(--border2);border-radius:var(--r8);color:var(--t2);font-size:11px;font-weight:600;cursor:pointer;transition:var(--ease)}
.exp-btn:hover{border-color:var(--accent-border);color:var(--accent);background:var(--accent-glow)}

/* === STAT CARDS === */
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:18px}
.sc{background:var(--bg-card);border:1px solid var(--border);border-radius:var(--r16);padding:18px 20px;backdrop-filter:blur(12px);position:relative;overflow:hidden;transition:var(--ease)}
.sc::after{content:'';position:absolute;bottom:0;left:0;right:0;height:2px;opacity:0;transition:var(--ease)}
.sc:hover{transform:translateY(-2px);border-color:var(--border2)}
.sc:hover::after{opacity:1}
.sc.risk::after{background:linear-gradient(90deg,var(--danger),var(--warn))}
.sc.finds::after{background:linear-gradient(90deg,var(--accent),var(--accent2))}
.sc.ports::after{background:linear-gradient(90deg,#a855f7,var(--accent2))}
.sc.ip::after{background:linear-gradient(90deg,var(--med),var(--warn))}
.sc-lbl{font-size:9px;font-weight:700;letter-spacing:.15em;text-transform:uppercase;color:var(--t4);margin-bottom:10px}
.sc-val{font-size:32px;font-weight:900;line-height:1;margin-bottom:8px;font-variant-numeric:tabular-nums}
.sc.risk .sc-val{color:var(--danger)}
.sc.finds .sc-val{color:var(--accent)}
.sc.ports .sc-val{color:#a855f7}
.sc.ip .sc-val{font-size:16px;padding-top:8px;color:var(--med)}
.sc-meta{font-size:10px;color:var(--t3);font-family:var(--mono)}
.risk-trk{height:3px;background:rgba(255,255,255,.05);border-radius:99px;overflow:hidden;margin:6px 0}
#riskBar{height:100%;background:linear-gradient(90deg,var(--med),var(--warn),var(--danger));border-radius:99px;width:0%;transition:width 1.1s cubic-bezier(.4,0,.2,1)}

/* === BODY GRID === */
.res-body{display:grid;grid-template-columns:320px 1fr;gap:16px;margin-bottom:16px}

/* === PANEL === */
.panel{background:var(--bg-card);border:1px solid var(--border);border-radius:var(--r16);backdrop-filter:blur(12px);overflow:hidden}
.panel-hdr{padding:14px 18px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px}
.panel-title{font-size:10px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:var(--t2);display:flex;align-items:center;gap:7px}
.panel-title i{color:var(--accent);font-size:11px}
.panel-body{padding:18px}

/* === SEV BARS === */
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

/* === API STATUS (results panel) === */
#apiStatusDisplay{display:flex;flex-direction:column;gap:7px}

/* === VULN FILTERS === */
.vf-wrap{display:flex;gap:5px;flex-wrap:wrap}
.fb{font-size:9px;font-weight:700;font-family:var(--mono);letter-spacing:.07em;text-transform:uppercase;padding:3px 9px;border-radius:6px;border:1px solid var(--border2);background:transparent;color:var(--t3);cursor:pointer;transition:var(--ease)}
.fb:hover,.fb.active{background:var(--accent-glow);border-color:var(--accent-border);color:var(--accent)}
.fb.fc.active{background:var(--danger-dim);border-color:var(--danger-border);color:var(--danger)}
.fb.fh.active{background:var(--warn-dim);border-color:rgba(249,115,22,.3);color:var(--warn)}
.fb.fm.active{background:var(--med-dim);border-color:rgba(234,179,8,.3);color:var(--med)}

/* === VULN LIST === */
#vulnList{max-height:500px;overflow-y:auto;display:flex;flex-direction:column;gap:9px;padding:16px 18px}
.vc{border-radius:var(--r12);padding:14px 16px;border:1px solid var(--border);background:rgba(255,255,255,.016);transition:var(--ease);animation:cin .25s ease both;position:relative;overflow:hidden}
.vc::before{content:'';position:absolute;left:0;top:0;bottom:0;width:3px}
.vc.severity-Critical::before{background:var(--danger)}.vc.severity-Critical{border-color:var(--danger-border);background:var(--danger-dim)}
.vc.severity-High::before{background:var(--warn)}.vc.severity-High{border-color:rgba(249,115,22,.2);background:var(--warn-dim)}
.vc.severity-Medium::before{background:var(--med)}.vc.severity-Medium{border-color:rgba(234,179,8,.2);background:var(--med-dim)}
.vc.severity-Low::before{background:var(--low)}.vc.severity-Low{border-color:rgba(34,211,238,.15);background:var(--low-dim)}
.vc.severity-Info::before{background:var(--info)}.vc.severity-Info{border-color:var(--border);background:var(--info-dim)}
.vc:hover{transform:translateX(2px)}
@keyframes cin{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}
.vc-top{display:flex;align-items:flex-start;justify-content:space-between;gap:8px;margin-bottom:9px;flex-wrap:wrap}
.vc-ids{display:flex;align-items:center;gap:7px;flex-wrap:wrap}
.vc-id{font-family:var(--mono);font-size:12px;font-weight:700;color:var(--accent)}
.src-badge{font-size:8px;font-weight:700;font-family:var(--mono);letter-spacing:.09em;text-transform:uppercase;padding:2px 6px;border-radius:4px;background:rgba(255,255,255,.04);color:var(--t3);border:1px solid var(--border2)}
.sev-tags{display:flex;align-items:center;gap:5px;flex-shrink:0}
.sp{font-size:9px;font-weight:700;font-family:var(--mono);letter-spacing:.07em;text-transform:uppercase;padding:2px 7px;border-radius:5px}
.sp.Critical{background:rgba(239,68,68,.14);color:var(--danger);border:1px solid var(--danger-border)}
.sp.High{background:rgba(249,115,22,.12);color:var(--warn);border:1px solid rgba(249,115,22,.25)}
.sp.Medium{background:rgba(234,179,8,.12);color:var(--med);border:1px solid rgba(234,179,8,.25)}
.sp.Low{background:rgba(34,211,238,.08);color:var(--low);border:1px solid rgba(34,211,238,.2)}
.sp.Info,.sp.Unknown{background:rgba(100,116,139,.09);color:var(--info);border:1px solid var(--border)}
.cvss-chip{font-size:9px;font-family:var(--mono);font-weight:600;color:var(--t3);background:rgba(255,255,255,.03);border:1px solid var(--border);padding:2px 6px;border-radius:4px}
.vc-sum{font-size:11.5px;color:var(--t2);line-height:1.6;margin-bottom:10px}
.vc-meta{display:flex;align-items:center;justify-content:space-between;padding-top:9px;border-top:1px solid rgba(255,255,255,.04);flex-wrap:wrap;gap:6px}
.vc-svc{font-size:10px;color:var(--t4);font-family:var(--mono);display:flex;align-items:center;gap:5px}
.port-chip{font-size:9px;font-family:var(--mono);font-weight:700;color:var(--t3);background:rgba(255,255,255,.04);border:1px solid var(--border);padding:2px 7px;border-radius:4px}
.empty{padding:40px 20px;text-align:center;color:var(--t4);font-family:var(--mono);font-size:12px;display:flex;flex-direction:column;align-items:center;gap:10px}
.empty i{font-size:26px;color:var(--t4)}

/* === INFRA / PORT GRID === */
#portGrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(190px,1fr));gap:10px;max-height:420px;overflow-y:auto;padding:16px 18px}
.svc-card{background:rgba(255,255,255,.02);border:1px solid var(--border);border-radius:var(--r12);padding:14px;display:flex;align-items:flex-start;gap:10px;transition:var(--ease);animation:cin .25s ease both}
.svc-card:hover{transform:translateY(-2px);border-color:var(--accent-border);background:var(--accent-glow);box-shadow:0 6px 20px rgba(6,182,212,.07)}
.svc-ico{width:34px;height:34px;border-radius:8px;background:rgba(6,182,212,.08);border:1px solid var(--accent-border);display:flex;align-items:center;justify-content:center;color:var(--accent);font-size:12px;flex-shrink:0}
.svc-info{flex:1;min-width:0}
.svc-nm{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:var(--t1);margin-bottom:2px;display:flex;align-items:center;justify-content:space-between;gap:4px}
.open-pill{font-size:7px;font-weight:700;font-family:var(--mono);color:#22c55e;background:rgba(34,197,94,.08);border:1px solid rgba(34,197,94,.2);padding:1px 4px;border-radius:3px;letter-spacing:.06em}
.svc-port{font-family:var(--mono);font-size:10px;color:var(--accent);font-weight:600;margin-bottom:2px}
.svc-prod{font-size:9px;color:var(--t4);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}

/* === TOAST === */
#error-toast{position:fixed;bottom:20px;right:20px;z-index:9999;background:rgba(25,8,8,.97);border:1px solid rgba(239,68,68,.35);color:var(--t1);padding:12px 16px;border-radius:var(--r12);display:flex;align-items:center;gap:10px;max-width:360px;backdrop-filter:blur(16px);box-shadow:0 8px 32px rgba(0,0,0,.5);transform:translateY(110%);transition:transform .3s cubic-bezier(.34,1.56,.64,1)}
#error-toast.show{transform:translateY(0)}
.t-ico{width:30px;height:30px;border-radius:8px;background:rgba(239,68,68,.12);display:flex;align-items:center;justify-content:center;color:var(--danger);font-size:12px;flex-shrink:0}
.t-body{flex:1}
.t-ttl{font-size:10px;font-weight:700;color:var(--danger);margin-bottom:2px;text-transform:uppercase;letter-spacing:.06em}
#error-msg{font-size:12px;color:var(--t2);line-height:1.45}
.t-close{background:none;border:none;color:var(--t3);cursor:pointer;font-size:16px;transition:var(--ease);padding:0;line-height:1}
.t-close:hover{color:var(--t1)}

/* === OVERLAY === */
#sb-ov{display:none;position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:199;backdrop-filter:blur(2px)}
#sb-ov.on{display:block}

/* =========================================
   RESPONSIVE BREAKPOINTS
   ========================================= */

/* Tablet (<=1024px) â€” sidebar collapses to icon-only or hidden */
@media(max-width:1024px){
  :root{--sidebar:0px}
  #sb{transform:translateX(-260px);width:260px}
  #sb.open{transform:translateX(0)}
  #main{margin-left:0}
  #sbtoggle{display:flex;align-items:center}
  .res-body{grid-template-columns:1fr}
  .stats{grid-template-columns:repeat(2,1fr)}
}

/* Large mobile / small tablet (<=768px) */
@media(max-width:768px){
  #pg{padding:14px}
  .scan-panel{padding:20px 18px}
  .scan-ph h1{font-size:16px}
  .scan-row{flex-direction:column}
  #btn{width:100%;justify-content:center}
  .stats{grid-template-columns:repeat(2,1fr);gap:10px}
  .sc-val{font-size:28px}
  #portGrid{grid-template-columns:repeat(auto-fill,minmax(160px,1fr))}
  .tb-pill:last-child{display:none}
  .res-hdr{flex-direction:column;align-items:flex-start}
}

/* Mobile (<=480px) */
@media(max-width:480px){
  :root{--topbar:54px}
  #pg{padding:10px}
  .scan-panel{padding:16px 14px;border-radius:var(--r16)}
  .scan-ph{gap:8px}
  .eng-badge{display:none}
  .stats{grid-template-columns:1fr 1fr;gap:8px}
  .sc{padding:14px 16px}
  .sc-val{font-size:24px}
  .sc.ip .sc-val{font-size:13px}
  .sc-lbl{font-size:8px}
  #vulnList{padding:10px 12px}
  #portGrid{grid-template-columns:1fr 1fr;padding:10px 12px}
  .panel-hdr{padding:12px 14px}
  .panel-body{padding:14px}
  .vc{padding:12px 13px}
  .vc-id{font-size:11px}
  .vc-sum{font-size:11px}
  .tb-right{gap:6px}
  .topbar-badge{font-size:9px}
}

/* Very small screens (<=360px) */
@media(max-width:360px){
  .stats{grid-template-columns:1fr}
  #portGrid{grid-template-columns:1fr}
}
</style>
</head>
<body>
<canvas id="bgc"></canvas>
<div id="sb-ov" onclick="closeSB()"></div>

<!-- Toast -->
<div id="error-toast">
  <div class="t-ico"><i class="fas fa-triangle-exclamation"></i></div>
  <div class="t-body"><div class="t-ttl">Error</div><span id="error-msg"></span></div>
  <button class="t-close" onclick="hideError()">&times;</button>
</div>

<div id="shell">
<!-- SIDEBAR -->
<aside id="sb">
  <div class="sb-logo">
    <img src="logo.jpg" alt="ZeroDay" onerror="this.style.display='none'">
    <div class="sb-logo-txt">
      <h2>VulnScope <span>Pro</span></h2>
      <p>ZeroDay Security</p>
    </div>
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
    PHP_API_ROWS
  </div>
  <div class="sb-footer">Vijay Ishan Chowdhury &mdash; ZeroDay Security Services</div>
</aside>

<!-- MAIN -->
<div id="main">
  <!-- Topbar -->
  <header id="topbar">
    <div class="tb-left">
      <button id="sbtoggle" onclick="toggleSB()"><i class="fas fa-bars"></i></button>
      <div class="tb-bread">
        <i class="fas fa-shield-halved" style="color:var(--accent);font-size:12px"></i>
        <span>ZeroDay Security</span>
        <i class="fas fa-chevron-right"></i>
        <span class="active">VulnScope Pro</span>
      </div>
    </div>
    <div class="tb-right">
      <div class="tb-pill"><span class="ldot"></span>ENGINE ONLINE</div>
      <div class="tb-pill"><i class="fas fa-microchip" style="font-size:9px"></i>Enterprise v4.0</div>
    </div>
  </header>

  <!-- Page -->
  <main id="pg">
    <!-- Scan Panel -->
    <section class="scan-panel">
      <div class="scan-ph">
        <div>
          <h1>Attack Surface Assessment</h1>
          <p>NVD v2 &middot; Shodan &middot; Censys v2 &middot; CIRCL &middot; Nmap / PHP Socket Engine</p>
        </div>
        <div class="eng-badge"><i class="fas fa-circle" style="font-size:7px;color:#22c55e;animation:dotpulse 1.5s infinite"></i>Scan Core Active</div>
      </div>
      <form id="scanForm">
        <div class="scan-row">
          <div class="inp-wrap">
            <input type="text" id="target" placeholder="Enter target IP or domain â€” e.g. 192.168.1.1 or example.com" autocomplete="off" spellcheck="false">
            <i class="fas fa-crosshairs inp-ico"></i>
          </div>
          <button type="submit" id="btn"><i class="fas fa-shield-virus"></i>Launch Assessment</button>
        </div>
      </form>
      <div id="loader" class="hidden">
        <div class="ld-spin"></div>
        <div class="ld-bar-wrap">
          <div class="ld-txt"><i class="fas fa-circle-notch fa-spin" style="margin-right:6px"></i>Initializing scan engine &amp; correlating multi-source intelligence...</div>
          <div class="ld-track"><div class="ld-fill"></div></div>
        </div>
      </div>
    </section>

    <!-- Results -->
    <div id="results">
      <div class="res-hdr">
        <div class="res-hdr-title">Scan Results</div>
        <button class="exp-btn" onclick="exportReport()"><i class="fas fa-file-export"></i>Export JSON</button>
      </div>

      <!-- Stat Cards -->
      <div class="stats">
        <div class="sc risk">
          <div class="sc-lbl">Composite Risk Score</div>
          <div class="sc-val" id="riskValue">0</div>
          <div class="risk-trk"><div id="riskBar"></div></div>
          <div class="sc-meta" id="resTarget">HOST: ---</div>
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

      <!-- Left col: Severity + API Status | Right col: Vuln Feed -->
      <div class="res-body">
        <div style="display:flex;flex-direction:column;gap:14px">
          <!-- Severity -->
          <div class="panel">
            <div class="panel-hdr"><div class="panel-title"><i class="fas fa-chart-bar"></i>Severity Distribution</div></div>
            <div class="panel-body"><div id="severityBars"></div></div>
          </div>
          <!-- API Status -->
          <div class="panel">
            <div class="panel-hdr"><div class="panel-title"><i class="fas fa-plug-circle-check"></i>Intelligence Sources</div></div>
            <div class="panel-body" style="padding:14px 18px"><div id="apiStatusDisplay"></div></div>
          </div>
        </div>

        <!-- Vuln Feed -->
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
          <div id="vulnList"></div>
        </div>
      </div>

      <!-- Infra Map -->
      <div class="panel" id="infra-section" style="margin-bottom:0">
        <div class="panel-hdr">
          <div class="panel-title"><i class="fas fa-microchip"></i>Detected Infrastructure &amp; Services</div>
          <span id="portsCount" style="font-size:10px;font-family:var(--mono);color:var(--t3);text-transform:uppercase;letter-spacing:.07em">0 Assets</span>
        </div>
        <div id="portGrid"></div>
      </div>
    </div><!-- /#results -->
  </main>
</div><!-- /#main -->
</div><!-- /#shell -->

<script>
const SCAN_TOKEN='<?php echo SCAN_TOKEN; ?>';
let _last=null,_all=[];

/* BG canvas */
(function(){
  const c=document.getElementById('bgc'),ctx=c.getContext('2d');
  let w,h,pts=[];
  function rsz(){w=c.width=window.innerWidth;h=c.height=window.innerHeight}
  function init(){pts=[];const n=Math.floor(w*h/16000);for(let i=0;i<n;i++)pts.push({x:Math.random()*w,y:Math.random()*h,r:Math.random()*1.1+.3,vx:(Math.random()-.5)*.16,vy:(Math.random()-.5)*.16})}
  function draw(){
    ctx.clearRect(0,0,w,h);
    ctx.fillStyle='rgba(6,182,212,.4)';
    for(const d of pts){d.x+=d.vx;d.y+=d.vy;if(d.x<0||d.x>w)d.vx*=-1;if(d.y<0||d.y>h)d.vy*=-1;ctx.beginPath();ctx.arc(d.x,d.y,d.r,0,Math.PI*2);ctx.fill()}
    ctx.strokeStyle='rgba(6,182,212,.055)';ctx.lineWidth=.5;
    for(let i=0;i<pts.length;i++)for(let j=i+1;j<pts.length;j++){const dx=pts[i].x-pts[j].x,dy=pts[i].y-pts[j].y,d=Math.sqrt(dx*dx+dy*dy);if(d<110){ctx.globalAlpha=1-d/110;ctx.beginPath();ctx.moveTo(pts[i].x,pts[i].y);ctx.lineTo(pts[j].x,pts[j].y);ctx.stroke()}}
    ctx.globalAlpha=1;requestAnimationFrame(draw)
  }
  window.addEventListener('resize',()=>{rsz();init()});rsz();init();draw();
})();

/* Sidebar */
function toggleSB(){document.getElementById('sb').classList.toggle('open');document.getElementById('sb-ov').classList.toggle('on')}
function closeSB(){document.getElementById('sb').classList.remove('open');document.getElementById('sb-ov').classList.remove('on')}

/* Scroll helpers */
function toResults(){document.getElementById('results').scrollIntoView({behavior:'smooth'})}
function toInfra(){const e=document.getElementById('infra-section');if(e)e.scrollIntoView({behavior:'smooth'})}

/* Toast */
function showError(m){document.getElementById('error-msg').innerText=m;document.getElementById('error-toast').classList.add('show');setTimeout(hideError,6000)}
function hideError(){document.getElementById('error-toast').classList.remove('show')}

/* Counter animation */
function ctr(el,target,dur=900){
  const s=performance.now(),f=parseInt(el.innerText)||0;
  (function step(n){const p=Math.min((n-s)/dur,1),e=1-Math.pow(1-p,3);el.innerText=Math.round(f+(target-f)*e);if(p<1)requestAnimationFrame(step)})(s)
}

/* Scan form */
document.getElementById('scanForm').onsubmit=async(e)=>{
  e.preventDefault();
  const t=document.getElementById('target').value.trim();
  const btn=document.getElementById('btn'),ldr=document.getElementById('loader');
  if(!t)return showError('No target specified.');
  btn.disabled=true;ldr.classList.remove('hidden');ldr.classList.add('show');
  document.getElementById('results').classList.remove('show');document.getElementById('results').style.display='none';
  const fd=new FormData();fd.append('target',t);
  try{
    const r=await fetch('?action=scan',{method:'POST',body:fd,headers:{'X-VulnScope-Token':SCAN_TOKEN}});
    const j=await r.json();
    if(j.success){_last=j;renderDashboard(j)}else showError(j.message);
  }catch(err){showError('Operational failure: Intelligence core unreachable.')}
  finally{btn.disabled=false;ldr.classList.add('hidden');ldr.classList.remove('show')}
};

/* Render */
function renderDashboard(resp){
  const{summary:s,severity_distribution:sd,findings:f,debug_info:di,api_status:as}=resp;
  const re=document.getElementById('results');re.style.display='block';re.classList.add('show');
  ctr(document.getElementById('riskValue'),s.risk_score);
  setTimeout(()=>{document.getElementById('riskBar').style.width=s.risk_score+'%'},60);
  document.getElementById('resTarget').innerText='HOST: '+s.target;
  document.getElementById('resIp').innerText=s.ip;
  ctr(document.getElementById('findingsCount'),s.total_findings);
  ctr(document.getElementById('portsCountVal'),s.open_ports_count);
  document.querySelectorAll('#portsCount').forEach(el=>el.innerText=s.open_ports_count+' ASSETS');
  if(as)document.getElementById('apiStatusDisplay').innerHTML=Object.entries(as).map(([k,v])=>{
    const ok=v==='configured';
    return `<div class="sb-api-row"><div class="sb-api-name"><span class="dot ${ok?'dot-on':'dot-off'}"></span>${k.toUpperCase()}</div><span class="api-badge ${ok?'on':'off'}">${ok?'Active':'Offline'}</span></div>`;
  }).join('');
  renderSevBars(sd,s.total_findings);
  renderPorts(di.ports||[]);
  _all=f;renderVulns(f);
  setTimeout(()=>re.scrollIntoView({behavior:'smooth',block:'start'}),120);
}

/* Severity bars */
function renderSevBars(d,tot){
  const sevs=['Critical','High','Medium','Low','Info'];
  document.getElementById('severityBars').innerHTML=sevs.map(s=>{
    const cnt=d[s.toLowerCase()]||0,pct=tot>0?Math.round(cnt/tot*100):0;
    return `<div class="sev-row sev-${s}"><div class="sev-hdr"><span class="sev-name">${s}</span><div class="sev-right"><span class="sev-pct">${pct}%</span><span class="sev-cnt">${cnt}</span></div></div><div class="sev-trk"><div class="progress-bar bar-${s}" data-p="${pct}" style="width:0%"></div></div></div>`;
  }).join('');
  setTimeout(()=>document.querySelectorAll('.progress-bar[data-p]').forEach(b=>b.style.width=b.dataset.p+'%'),80);
}

/* Icon map */
function ico(s){
  if(!s)return'fa-server';s=s.toLowerCase();
  if(s.includes('http')||s.includes('www'))return'fa-globe';
  if(s.includes('ssh'))return'fa-terminal';
  if(s.includes('sql')||s.includes('mysql')||s.includes('pg')||s.includes('mongo'))return'fa-database';
  if(s.includes('ftp'))return'fa-upload';
  if(s.includes('smtp')||s.includes('mail')||s.includes('pop')||s.includes('imap'))return'fa-envelope';
  if(s.includes('dns')||s.includes('domain'))return'fa-sitemap';
  if(s.includes('rdp')||s.includes('vnc')||s.includes('remote'))return'fa-desktop';
  if(s.includes('ldap'))return'fa-users';
  if(s.includes('redis')||s.includes('memcache'))return'fa-memory';
  if(s.includes('docker'))return'fa-docker';
  return'fa-server';
}

/* Port grid */
function renderPorts(ports){
  document.getElementById('portGrid').innerHTML=ports.length?ports.map((p,i)=>`
    <div class="svc-card" style="animation-delay:${i*35}ms">
      <div class="svc-ico"><i class="fas ${ico(p.service)}"></i></div>
      <div class="svc-info">
        <div class="svc-nm"><span>${(p.service||'unknown').toUpperCase()}</span><span class="open-pill">OPEN</span></div>
        <div class="svc-port">${p.port}/TCP</div>
        <div class="svc-prod">${[p.product,p.version].filter(Boolean).join(' ')||'&mdash;'}</div>
      </div>
    </div>`).join('')
  :`<div class="empty" style="grid-column:1/-1"><i class="fas fa-network-wired"></i>No open services detected</div>`;
}

/* Vuln list */
function renderVulns(f){
  const list=document.getElementById('vulnList');
  list.innerHTML=f.length?f.map((v,i)=>`
    <div class="vc severity-${v.severity||'Info'}" style="animation-delay:${i*30}ms">
      <div class="vc-top">
        <div class="vc-ids"><span class="vc-id">${v.id}</span><span class="src-badge">${v.source}</span></div>
        <div class="sev-tags"><span class="sp ${v.severity||'Info'}">${v.severity||'Info'}</span><span class="cvss-chip">CVSS ${v.cvss>0?v.cvss:'N/A'}</span></div>
      </div>
      <p class="vc-sum">${v.summary}</p>
      <div class="vc-meta">
        <div class="vc-svc"><i class="fas fa-microchip"></i>${v.affected_service||'&mdash;'}</div>
        <span class="port-chip">PORT ${v.port}</span>
      </div>
    </div>`).join('')
  :`<div class="empty"><i class="fas fa-shield-check"></i>No CVE matches found &mdash; target appears hardened.</div>`;
}

function fvulns(sev,btn){
  document.querySelectorAll('.fb').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  renderVulns(sev==='all'?_all:_all.filter(f=>f.severity===sev));
}

/* Export */
function exportReport(){
  if(!_last)return showError('No scan data yet. Run a scan first.');
  const b=new Blob([JSON.stringify(_last,null,2)],{type:'application/json'});
  const a=document.createElement('a');a.href=URL.createObjectURL(b);
  a.download='vulnscope-'+(_last.summary?.target||'report')+'-'+Date.now()+'.json';a.click();
}
</script>
</body>
</html>apis as $k=>$label):
  $ok = <!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VulnScope Pro â€” ZeroDay Security Intelligence Platform</title>
<meta name="description" content="Enterprise vulnerability intelligence and attack surface assessment by ZeroDay Security Services.">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
:root{--bg-root:#020408;--bg-card:rgba(10,18,30,0.9);--accent:#06b6d4;--accent2:#3b82f6;--accent-glow:rgba(6,182,212,0.12);--accent-border:rgba(6,182,212,0.22);--danger:#ef4444;--danger-dim:rgba(239,68,68,0.08);--danger-border:rgba(239,68,68,0.28);--warn:#f97316;--warn-dim:rgba(249,115,22,0.08);--med:#eab308;--med-dim:rgba(234,179,8,0.08);--low:#22d3ee;--low-dim:rgba(34,211,238,0.06);--info:#64748b;--info-dim:rgba(100,116,139,0.06);--t1:#e2e8f0;--t2:#94a3b8;--t3:#475569;--t4:#1e293b;--border:rgba(30,41,59,0.8);--border2:rgba(51,65,85,0.9);--r8:8px;--r12:12px;--r16:16px;--r20:20px;--r24:24px;--sidebar:260px;--topbar:60px;--ease:all 0.22s cubic-bezier(.4,0,.2,1);--font:'Inter',system-ui,sans-serif;--mono:'JetBrains Mono','Courier New',monospace}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{background:var(--bg-root);color:var(--t1);font-family:var(--font);overflow-x:hidden;min-height:100vh}
::-webkit-scrollbar{width:4px;height:4px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:#1e293b;border-radius:99px}

/* === BG CANVAS === */
#bgc{position:fixed;inset:0;z-index:0;pointer-events:none;opacity:.35}

/* === LAYOUT === */
#shell{position:relative;z-index:1;display:flex;min-height:100vh}

/* === SIDEBAR === */
#sb{width:var(--sidebar);flex-shrink:0;background:rgba(4,8,18,0.97);border-right:1px solid var(--border);display:flex;flex-direction:column;position:fixed;top:0;left:0;height:100vh;z-index:200;backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);transition:transform .3s ease;overflow:hidden}
.sb-logo{padding:20px 16px 18px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:10px}
.sb-logo img{width:38px;height:38px;object-fit:contain;border-radius:8px;filter:drop-shadow(0 0 8px rgba(6,182,212,.5))}
.sb-logo-txt h2{font-size:13px;font-weight:800;letter-spacing:.04em;text-transform:uppercase}
.sb-logo-txt h2 span{color:var(--accent)}
.sb-logo-txt p{font-size:9px;color:var(--accent);font-family:var(--mono);letter-spacing:.12em;margin-top:1px}
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
.dot-on{background:#22c55e;box-shadow:0 0 5px #22c55e;animation:dotpulse 2s infinite}
.dot-off{background:#ef4444}
@keyframes dotpulse{0%,100%{opacity:1}50%{opacity:.35}}
.api-badge{font-family:var(--mono);font-size:9px;font-weight:700;padding:2px 6px;border-radius:4px;text-transform:uppercase;letter-spacing:.04em}
.api-badge.on{background:rgba(34,197,94,.1);color:#22c55e;border:1px solid rgba(34,197,94,.2)}
.api-badge.off{background:rgba(239,68,68,.1);color:#ef4444;border:1px solid rgba(239,68,68,.2)}
.sb-footer{padding:12px 14px;border-top:1px solid var(--border);font-size:9px;color:var(--t4);text-align:center;font-family:var(--mono)}

/* === MAIN === */
#main{margin-left:var(--sidebar);flex:1;display:flex;flex-direction:column;min-height:100vh}

/* === TOPBAR === */
#topbar{height:var(--topbar);border-bottom:1px solid var(--border);background:rgba(4,8,18,.8);backdrop-filter:blur(20px);display:flex;align-items:center;justify-content:space-between;padding:0 24px;position:sticky;top:0;z-index:100}
.tb-left{display:flex;align-items:center;gap:12px}
.tb-bread{display:flex;align-items:center;gap:6px;font-size:12px;color:var(--t3)}
.tb-bread .active{color:var(--t1);font-weight:600}
.tb-bread i{font-size:8px}
.tb-right{display:flex;align-items:center;gap:10px}
.tb-pill{display:flex;align-items:center;gap:5px;font-size:10px;font-family:var(--mono);color:var(--t3);background:rgba(255,255,255,.03);border:1px solid var(--border);padding:4px 10px;border-radius:var(--r8)}
.tb-pill .ldot{width:5px;height:5px;border-radius:50%;background:#22c55e;animation:dotpulse 2s infinite}
#sbtoggle{display:none;background:none;border:1px solid var(--border);color:var(--t2);padding:7px 10px;border-radius:var(--r8);cursor:pointer;transition:var(--ease);font-size:13px}
#sbtoggle:hover{border-color:var(--accent-border);color:var(--accent)}

/* === PAGE === */
#pg{flex:1;padding:24px}

/* === SCAN PANEL === */
.scan-panel{background:var(--bg-card);border:1px solid var(--border2);border-radius:var(--r24);padding:28px 32px;margin-bottom:24px;position:relative;overflow:hidden;backdrop-filter:blur(16px)}
.scan-panel::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,var(--accent),var(--accent2),transparent);opacity:.55}
.scan-ph{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;margin-bottom:22px;flex-wrap:wrap}
.scan-ph h1{font-size:18px;font-weight:800;letter-spacing:-.01em;margin-bottom:4px}
.scan-ph p{font-size:11px;color:var(--t3);font-family:var(--mono);letter-spacing:.04em}
.eng-badge{display:flex;align-items:center;gap:7px;background:rgba(6,182,212,.05);border:1px solid var(--accent-border);border-radius:var(--r12);padding:7px 13px;font-size:10px;font-family:var(--mono);color:var(--accent);text-transform:uppercase;letter-spacing:.07em;white-space:nowrap;flex-shrink:0}
.scan-row{display:flex;gap:10px;align-items:stretch}
.inp-wrap{position:relative;flex:1}
.inp-ico{position:absolute;left:15px;top:50%;transform:translateY(-50%);color:var(--t3);font-size:13px;pointer-events:none;transition:var(--ease)}
#target{width:100%;background:rgba(4,8,18,.9);border:1px solid var(--border2);border-radius:var(--r12);padding:14px 16px 14px 44px;font-family:var(--mono);font-size:13px;color:var(--t1);outline:none;transition:var(--ease);letter-spacing:.02em}
#target::placeholder{color:var(--t4)}
#target:focus{border-color:var(--accent);background:rgba(4,8,18,1);box-shadow:0 0 0 3px rgba(6,182,212,.07),0 0 20px rgba(6,182,212,.04)}
#btn{background:linear-gradient(135deg,var(--accent),var(--accent2));color:#fff;border:none;border-radius:var(--r12);padding:14px 26px;font-family:var(--font);font-size:13px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;cursor:pointer;transition:var(--ease);display:flex;align-items:center;gap:8px;white-space:nowrap;position:relative;overflow:hidden;flex-shrink:0}
#btn::after{content:'';position:absolute;inset:0;background:linear-gradient(135deg,rgba(255,255,255,.18),transparent);opacity:0;transition:var(--ease)}
#btn:hover::after{opacity:1}
#btn:hover{transform:translateY(-1px);box-shadow:0 8px 24px rgba(6,182,212,.28)}
#btn:active{transform:none}
#btn:disabled{opacity:.4;filter:grayscale(.4);cursor:not-allowed;transform:none;box-shadow:none}
#loader{display:none;margin-top:18px;padding:14px 18px;background:rgba(6,182,212,.04);border:1px solid var(--accent-border);border-radius:var(--r12);align-items:center;gap:14px}
#loader.show{display:flex}
.ld-spin{width:30px;height:30px;border:2px solid var(--accent-border);border-top-color:var(--accent);border-radius:50%;animation:spin .8s linear infinite;flex-shrink:0}
@keyframes spin{to{transform:rotate(360deg)}}
.ld-bar-wrap{flex:1}
.ld-txt{font-size:11px;font-family:var(--mono);color:var(--accent);letter-spacing:.03em;margin-bottom:7px}
.ld-track{height:2px;background:rgba(6,182,212,.1);border-radius:99px;overflow:hidden}
.ld-fill{height:100%;width:30%;background:linear-gradient(90deg,var(--accent),var(--accent2));border-radius:99px;animation:ldsweep 1.8s ease-in-out infinite}
@keyframes ldsweep{0%{transform:translateX(-100%)}100%{transform:translateX(400%)}}

/* === RESULTS === */
#results{display:none;animation:fadeup .35s ease}
#results.show{display:block}
@keyframes fadeup{from{opacity:0;transform:translateY(14px)}to{opacity:1;transform:translateY(0)}}
.res-hdr{display:flex;align-items:center;justify-content:space-between;margin-bottom:18px;flex-wrap:wrap;gap:10px}
.res-hdr-title{font-size:11px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:var(--t3);display:flex;align-items:center;gap:8px}
.res-hdr-title::before{content:'';width:3px;height:14px;background:linear-gradient(var(--accent),var(--accent2));border-radius:2px;flex-shrink:0}
.exp-btn{display:flex;align-items:center;gap:6px;padding:7px 13px;background:transparent;border:1px solid var(--border2);border-radius:var(--r8);color:var(--t2);font-size:11px;font-weight:600;cursor:pointer;transition:var(--ease)}
.exp-btn:hover{border-color:var(--accent-border);color:var(--accent);background:var(--accent-glow)}

/* === STAT CARDS === */
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:18px}
.sc{background:var(--bg-card);border:1px solid var(--border);border-radius:var(--r16);padding:18px 20px;backdrop-filter:blur(12px);position:relative;overflow:hidden;transition:var(--ease)}
.sc::after{content:'';position:absolute;bottom:0;left:0;right:0;height:2px;opacity:0;transition:var(--ease)}
.sc:hover{transform:translateY(-2px);border-color:var(--border2)}
.sc:hover::after{opacity:1}
.sc.risk::after{background:linear-gradient(90deg,var(--danger),var(--warn))}
.sc.finds::after{background:linear-gradient(90deg,var(--accent),var(--accent2))}
.sc.ports::after{background:linear-gradient(90deg,#a855f7,var(--accent2))}
.sc.ip::after{background:linear-gradient(90deg,var(--med),var(--warn))}
.sc-lbl{font-size:9px;font-weight:700;letter-spacing:.15em;text-transform:uppercase;color:var(--t4);margin-bottom:10px}
.sc-val{font-size:32px;font-weight:900;line-height:1;margin-bottom:8px;font-variant-numeric:tabular-nums}
.sc.risk .sc-val{color:var(--danger)}
.sc.finds .sc-val{color:var(--accent)}
.sc.ports .sc-val{color:#a855f7}
.sc.ip .sc-val{font-size:16px;padding-top:8px;color:var(--med)}
.sc-meta{font-size:10px;color:var(--t3);font-family:var(--mono)}
.risk-trk{height:3px;background:rgba(255,255,255,.05);border-radius:99px;overflow:hidden;margin:6px 0}
#riskBar{height:100%;background:linear-gradient(90deg,var(--med),var(--warn),var(--danger));border-radius:99px;width:0%;transition:width 1.1s cubic-bezier(.4,0,.2,1)}

/* === BODY GRID === */
.res-body{display:grid;grid-template-columns:320px 1fr;gap:16px;margin-bottom:16px}

/* === PANEL === */
.panel{background:var(--bg-card);border:1px solid var(--border);border-radius:var(--r16);backdrop-filter:blur(12px);overflow:hidden}
.panel-hdr{padding:14px 18px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px}
.panel-title{font-size:10px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:var(--t2);display:flex;align-items:center;gap:7px}
.panel-title i{color:var(--accent);font-size:11px}
.panel-body{padding:18px}

/* === SEV BARS === */
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

/* === API STATUS (results panel) === */
#apiStatusDisplay{display:flex;flex-direction:column;gap:7px}

/* === VULN FILTERS === */
.vf-wrap{display:flex;gap:5px;flex-wrap:wrap}
.fb{font-size:9px;font-weight:700;font-family:var(--mono);letter-spacing:.07em;text-transform:uppercase;padding:3px 9px;border-radius:6px;border:1px solid var(--border2);background:transparent;color:var(--t3);cursor:pointer;transition:var(--ease)}
.fb:hover,.fb.active{background:var(--accent-glow);border-color:var(--accent-border);color:var(--accent)}
.fb.fc.active{background:var(--danger-dim);border-color:var(--danger-border);color:var(--danger)}
.fb.fh.active{background:var(--warn-dim);border-color:rgba(249,115,22,.3);color:var(--warn)}
.fb.fm.active{background:var(--med-dim);border-color:rgba(234,179,8,.3);color:var(--med)}

/* === VULN LIST === */
#vulnList{max-height:500px;overflow-y:auto;display:flex;flex-direction:column;gap:9px;padding:16px 18px}
.vc{border-radius:var(--r12);padding:14px 16px;border:1px solid var(--border);background:rgba(255,255,255,.016);transition:var(--ease);animation:cin .25s ease both;position:relative;overflow:hidden}
.vc::before{content:'';position:absolute;left:0;top:0;bottom:0;width:3px}
.vc.severity-Critical::before{background:var(--danger)}.vc.severity-Critical{border-color:var(--danger-border);background:var(--danger-dim)}
.vc.severity-High::before{background:var(--warn)}.vc.severity-High{border-color:rgba(249,115,22,.2);background:var(--warn-dim)}
.vc.severity-Medium::before{background:var(--med)}.vc.severity-Medium{border-color:rgba(234,179,8,.2);background:var(--med-dim)}
.vc.severity-Low::before{background:var(--low)}.vc.severity-Low{border-color:rgba(34,211,238,.15);background:var(--low-dim)}
.vc.severity-Info::before{background:var(--info)}.vc.severity-Info{border-color:var(--border);background:var(--info-dim)}
.vc:hover{transform:translateX(2px)}
@keyframes cin{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}
.vc-top{display:flex;align-items:flex-start;justify-content:space-between;gap:8px;margin-bottom:9px;flex-wrap:wrap}
.vc-ids{display:flex;align-items:center;gap:7px;flex-wrap:wrap}
.vc-id{font-family:var(--mono);font-size:12px;font-weight:700;color:var(--accent)}
.src-badge{font-size:8px;font-weight:700;font-family:var(--mono);letter-spacing:.09em;text-transform:uppercase;padding:2px 6px;border-radius:4px;background:rgba(255,255,255,.04);color:var(--t3);border:1px solid var(--border2)}
.sev-tags{display:flex;align-items:center;gap:5px;flex-shrink:0}
.sp{font-size:9px;font-weight:700;font-family:var(--mono);letter-spacing:.07em;text-transform:uppercase;padding:2px 7px;border-radius:5px}
.sp.Critical{background:rgba(239,68,68,.14);color:var(--danger);border:1px solid var(--danger-border)}
.sp.High{background:rgba(249,115,22,.12);color:var(--warn);border:1px solid rgba(249,115,22,.25)}
.sp.Medium{background:rgba(234,179,8,.12);color:var(--med);border:1px solid rgba(234,179,8,.25)}
.sp.Low{background:rgba(34,211,238,.08);color:var(--low);border:1px solid rgba(34,211,238,.2)}
.sp.Info,.sp.Unknown{background:rgba(100,116,139,.09);color:var(--info);border:1px solid var(--border)}
.cvss-chip{font-size:9px;font-family:var(--mono);font-weight:600;color:var(--t3);background:rgba(255,255,255,.03);border:1px solid var(--border);padding:2px 6px;border-radius:4px}
.vc-sum{font-size:11.5px;color:var(--t2);line-height:1.6;margin-bottom:10px}
.vc-meta{display:flex;align-items:center;justify-content:space-between;padding-top:9px;border-top:1px solid rgba(255,255,255,.04);flex-wrap:wrap;gap:6px}
.vc-svc{font-size:10px;color:var(--t4);font-family:var(--mono);display:flex;align-items:center;gap:5px}
.port-chip{font-size:9px;font-family:var(--mono);font-weight:700;color:var(--t3);background:rgba(255,255,255,.04);border:1px solid var(--border);padding:2px 7px;border-radius:4px}
.empty{padding:40px 20px;text-align:center;color:var(--t4);font-family:var(--mono);font-size:12px;display:flex;flex-direction:column;align-items:center;gap:10px}
.empty i{font-size:26px;color:var(--t4)}

/* === INFRA / PORT GRID === */
#portGrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(190px,1fr));gap:10px;max-height:420px;overflow-y:auto;padding:16px 18px}
.svc-card{background:rgba(255,255,255,.02);border:1px solid var(--border);border-radius:var(--r12);padding:14px;display:flex;align-items:flex-start;gap:10px;transition:var(--ease);animation:cin .25s ease both}
.svc-card:hover{transform:translateY(-2px);border-color:var(--accent-border);background:var(--accent-glow);box-shadow:0 6px 20px rgba(6,182,212,.07)}
.svc-ico{width:34px;height:34px;border-radius:8px;background:rgba(6,182,212,.08);border:1px solid var(--accent-border);display:flex;align-items:center;justify-content:center;color:var(--accent);font-size:12px;flex-shrink:0}
.svc-info{flex:1;min-width:0}
.svc-nm{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:var(--t1);margin-bottom:2px;display:flex;align-items:center;justify-content:space-between;gap:4px}
.open-pill{font-size:7px;font-weight:700;font-family:var(--mono);color:#22c55e;background:rgba(34,197,94,.08);border:1px solid rgba(34,197,94,.2);padding:1px 4px;border-radius:3px;letter-spacing:.06em}
.svc-port{font-family:var(--mono);font-size:10px;color:var(--accent);font-weight:600;margin-bottom:2px}
.svc-prod{font-size:9px;color:var(--t4);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}

/* === TOAST === */
#error-toast{position:fixed;bottom:20px;right:20px;z-index:9999;background:rgba(25,8,8,.97);border:1px solid rgba(239,68,68,.35);color:var(--t1);padding:12px 16px;border-radius:var(--r12);display:flex;align-items:center;gap:10px;max-width:360px;backdrop-filter:blur(16px);box-shadow:0 8px 32px rgba(0,0,0,.5);transform:translateY(110%);transition:transform .3s cubic-bezier(.34,1.56,.64,1)}
#error-toast.show{transform:translateY(0)}
.t-ico{width:30px;height:30px;border-radius:8px;background:rgba(239,68,68,.12);display:flex;align-items:center;justify-content:center;color:var(--danger);font-size:12px;flex-shrink:0}
.t-body{flex:1}
.t-ttl{font-size:10px;font-weight:700;color:var(--danger);margin-bottom:2px;text-transform:uppercase;letter-spacing:.06em}
#error-msg{font-size:12px;color:var(--t2);line-height:1.45}
.t-close{background:none;border:none;color:var(--t3);cursor:pointer;font-size:16px;transition:var(--ease);padding:0;line-height:1}
.t-close:hover{color:var(--t1)}

/* === OVERLAY === */
#sb-ov{display:none;position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:199;backdrop-filter:blur(2px)}
#sb-ov.on{display:block}

/* =========================================
   RESPONSIVE BREAKPOINTS
   ========================================= */

/* Tablet (<=1024px) â€” sidebar collapses to icon-only or hidden */
@media(max-width:1024px){
  :root{--sidebar:0px}
  #sb{transform:translateX(-260px);width:260px}
  #sb.open{transform:translateX(0)}
  #main{margin-left:0}
  #sbtoggle{display:flex;align-items:center}
  .res-body{grid-template-columns:1fr}
  .stats{grid-template-columns:repeat(2,1fr)}
}

/* Large mobile / small tablet (<=768px) */
@media(max-width:768px){
  #pg{padding:14px}
  .scan-panel{padding:20px 18px}
  .scan-ph h1{font-size:16px}
  .scan-row{flex-direction:column}
  #btn{width:100%;justify-content:center}
  .stats{grid-template-columns:repeat(2,1fr);gap:10px}
  .sc-val{font-size:28px}
  #portGrid{grid-template-columns:repeat(auto-fill,minmax(160px,1fr))}
  .tb-pill:last-child{display:none}
  .res-hdr{flex-direction:column;align-items:flex-start}
}

/* Mobile (<=480px) */
@media(max-width:480px){
  :root{--topbar:54px}
  #pg{padding:10px}
  .scan-panel{padding:16px 14px;border-radius:var(--r16)}
  .scan-ph{gap:8px}
  .eng-badge{display:none}
  .stats{grid-template-columns:1fr 1fr;gap:8px}
  .sc{padding:14px 16px}
  .sc-val{font-size:24px}
  .sc.ip .sc-val{font-size:13px}
  .sc-lbl{font-size:8px}
  #vulnList{padding:10px 12px}
  #portGrid{grid-template-columns:1fr 1fr;padding:10px 12px}
  .panel-hdr{padding:12px 14px}
  .panel-body{padding:14px}
  .vc{padding:12px 13px}
  .vc-id{font-size:11px}
  .vc-sum{font-size:11px}
  .tb-right{gap:6px}
  .topbar-badge{font-size:9px}
}

/* Very small screens (<=360px) */
@media(max-width:360px){
  .stats{grid-template-columns:1fr}
  #portGrid{grid-template-columns:1fr}
}
</style>
</head>
<body>
<canvas id="bgc"></canvas>
<div id="sb-ov" onclick="closeSB()"></div>

<!-- Toast -->
<div id="error-toast">
  <div class="t-ico"><i class="fas fa-triangle-exclamation"></i></div>
  <div class="t-body"><div class="t-ttl">Error</div><span id="error-msg"></span></div>
  <button class="t-close" onclick="hideError()">&times;</button>
</div>

<div id="shell">
<!-- SIDEBAR -->
<aside id="sb">
  <div class="sb-logo">
    <img src="logo.jpg" alt="ZeroDay" onerror="this.style.display='none'">
    <div class="sb-logo-txt">
      <h2>VulnScope <span>Pro</span></h2>
      <p>ZeroDay Security</p>
    </div>
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
    PHP_API_ROWS
  </div>
  <div class="sb-footer">Vijay Ishan Chowdhury &mdash; ZeroDay Security Services</div>
</aside>

<!-- MAIN -->
<div id="main">
  <!-- Topbar -->
  <header id="topbar">
    <div class="tb-left">
      <button id="sbtoggle" onclick="toggleSB()"><i class="fas fa-bars"></i></button>
      <div class="tb-bread">
        <i class="fas fa-shield-halved" style="color:var(--accent);font-size:12px"></i>
        <span>ZeroDay Security</span>
        <i class="fas fa-chevron-right"></i>
        <span class="active">VulnScope Pro</span>
      </div>
    </div>
    <div class="tb-right">
      <div class="tb-pill"><span class="ldot"></span>ENGINE ONLINE</div>
      <div class="tb-pill"><i class="fas fa-microchip" style="font-size:9px"></i>Enterprise v4.0</div>
    </div>
  </header>

  <!-- Page -->
  <main id="pg">
    <!-- Scan Panel -->
    <section class="scan-panel">
      <div class="scan-ph">
        <div>
          <h1>Attack Surface Assessment</h1>
          <p>NVD v2 &middot; Shodan &middot; Censys v2 &middot; CIRCL &middot; Nmap / PHP Socket Engine</p>
        </div>
        <div class="eng-badge"><i class="fas fa-circle" style="font-size:7px;color:#22c55e;animation:dotpulse 1.5s infinite"></i>Scan Core Active</div>
      </div>
      <form id="scanForm">
        <div class="scan-row">
          <div class="inp-wrap">
            <input type="text" id="target" placeholder="Enter target IP or domain â€” e.g. 192.168.1.1 or example.com" autocomplete="off" spellcheck="false">
            <i class="fas fa-crosshairs inp-ico"></i>
          </div>
          <button type="submit" id="btn"><i class="fas fa-shield-virus"></i>Launch Assessment</button>
        </div>
      </form>
      <div id="loader" class="hidden">
        <div class="ld-spin"></div>
        <div class="ld-bar-wrap">
          <div class="ld-txt"><i class="fas fa-circle-notch fa-spin" style="margin-right:6px"></i>Initializing scan engine &amp; correlating multi-source intelligence...</div>
          <div class="ld-track"><div class="ld-fill"></div></div>
        </div>
      </div>
    </section>

    <!-- Results -->
    <div id="results">
      <div class="res-hdr">
        <div class="res-hdr-title">Scan Results</div>
        <button class="exp-btn" onclick="exportReport()"><i class="fas fa-file-export"></i>Export JSON</button>
      </div>

      <!-- Stat Cards -->
      <div class="stats">
        <div class="sc risk">
          <div class="sc-lbl">Composite Risk Score</div>
          <div class="sc-val" id="riskValue">0</div>
          <div class="risk-trk"><div id="riskBar"></div></div>
          <div class="sc-meta" id="resTarget">HOST: ---</div>
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

      <!-- Left col: Severity + API Status | Right col: Vuln Feed -->
      <div class="res-body">
        <div style="display:flex;flex-direction:column;gap:14px">
          <!-- Severity -->
          <div class="panel">
            <div class="panel-hdr"><div class="panel-title"><i class="fas fa-chart-bar"></i>Severity Distribution</div></div>
            <div class="panel-body"><div id="severityBars"></div></div>
          </div>
          <!-- API Status -->
          <div class="panel">
            <div class="panel-hdr"><div class="panel-title"><i class="fas fa-plug-circle-check"></i>Intelligence Sources</div></div>
            <div class="panel-body" style="padding:14px 18px"><div id="apiStatusDisplay"></div></div>
          </div>
        </div>

        <!-- Vuln Feed -->
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
          <div id="vulnList"></div>
        </div>
      </div>

      <!-- Infra Map -->
      <div class="panel" id="infra-section" style="margin-bottom:0">
        <div class="panel-hdr">
          <div class="panel-title"><i class="fas fa-microchip"></i>Detected Infrastructure &amp; Services</div>
          <span id="portsCount" style="font-size:10px;font-family:var(--mono);color:var(--t3);text-transform:uppercase;letter-spacing:.07em">0 Assets</span>
        </div>
        <div id="portGrid"></div>
      </div>
    </div><!-- /#results -->
  </main>
</div><!-- /#main -->
</div><!-- /#shell -->

<script>
const SCAN_TOKEN='<?php echo SCAN_TOKEN; ?>';
let _last=null,_all=[];

/* BG canvas */
(function(){
  const c=document.getElementById('bgc'),ctx=c.getContext('2d');
  let w,h,pts=[];
  function rsz(){w=c.width=window.innerWidth;h=c.height=window.innerHeight}
  function init(){pts=[];const n=Math.floor(w*h/16000);for(let i=0;i<n;i++)pts.push({x:Math.random()*w,y:Math.random()*h,r:Math.random()*1.1+.3,vx:(Math.random()-.5)*.16,vy:(Math.random()-.5)*.16})}
  function draw(){
    ctx.clearRect(0,0,w,h);
    ctx.fillStyle='rgba(6,182,212,.4)';
    for(const d of pts){d.x+=d.vx;d.y+=d.vy;if(d.x<0||d.x>w)d.vx*=-1;if(d.y<0||d.y>h)d.vy*=-1;ctx.beginPath();ctx.arc(d.x,d.y,d.r,0,Math.PI*2);ctx.fill()}
    ctx.strokeStyle='rgba(6,182,212,.055)';ctx.lineWidth=.5;
    for(let i=0;i<pts.length;i++)for(let j=i+1;j<pts.length;j++){const dx=pts[i].x-pts[j].x,dy=pts[i].y-pts[j].y,d=Math.sqrt(dx*dx+dy*dy);if(d<110){ctx.globalAlpha=1-d/110;ctx.beginPath();ctx.moveTo(pts[i].x,pts[i].y);ctx.lineTo(pts[j].x,pts[j].y);ctx.stroke()}}
    ctx.globalAlpha=1;requestAnimationFrame(draw)
  }
  window.addEventListener('resize',()=>{rsz();init()});rsz();init();draw();
})();

/* Sidebar */
function toggleSB(){document.getElementById('sb').classList.toggle('open');document.getElementById('sb-ov').classList.toggle('on')}
function closeSB(){document.getElementById('sb').classList.remove('open');document.getElementById('sb-ov').classList.remove('on')}

/* Scroll helpers */
function toResults(){document.getElementById('results').scrollIntoView({behavior:'smooth'})}
function toInfra(){const e=document.getElementById('infra-section');if(e)e.scrollIntoView({behavior:'smooth'})}

/* Toast */
function showError(m){document.getElementById('error-msg').innerText=m;document.getElementById('error-toast').classList.add('show');setTimeout(hideError,6000)}
function hideError(){document.getElementById('error-toast').classList.remove('show')}

/* Counter animation */
function ctr(el,target,dur=900){
  const s=performance.now(),f=parseInt(el.innerText)||0;
  (function step(n){const p=Math.min((n-s)/dur,1),e=1-Math.pow(1-p,3);el.innerText=Math.round(f+(target-f)*e);if(p<1)requestAnimationFrame(step)})(s)
}

/* Scan form */
document.getElementById('scanForm').onsubmit=async(e)=>{
  e.preventDefault();
  const t=document.getElementById('target').value.trim();
  const btn=document.getElementById('btn'),ldr=document.getElementById('loader');
  if(!t)return showError('No target specified.');
  btn.disabled=true;ldr.classList.remove('hidden');ldr.classList.add('show');
  document.getElementById('results').classList.remove('show');document.getElementById('results').style.display='none';
  const fd=new FormData();fd.append('target',t);
  try{
    const r=await fetch('?action=scan',{method:'POST',body:fd,headers:{'X-VulnScope-Token':SCAN_TOKEN}});
    const j=await r.json();
    if(j.success){_last=j;renderDashboard(j)}else showError(j.message);
  }catch(err){showError('Operational failure: Intelligence core unreachable.')}
  finally{btn.disabled=false;ldr.classList.add('hidden');ldr.classList.remove('show')}
};

/* Render */
function renderDashboard(resp){
  const{summary:s,severity_distribution:sd,findings:f,debug_info:di,api_status:as}=resp;
  const re=document.getElementById('results');re.style.display='block';re.classList.add('show');
  ctr(document.getElementById('riskValue'),s.risk_score);
  setTimeout(()=>{document.getElementById('riskBar').style.width=s.risk_score+'%'},60);
  document.getElementById('resTarget').innerText='HOST: '+s.target;
  document.getElementById('resIp').innerText=s.ip;
  ctr(document.getElementById('findingsCount'),s.total_findings);
  ctr(document.getElementById('portsCountVal'),s.open_ports_count);
  document.querySelectorAll('#portsCount').forEach(el=>el.innerText=s.open_ports_count+' ASSETS');
  if(as)document.getElementById('apiStatusDisplay').innerHTML=Object.entries(as).map(([k,v])=>{
    const ok=v==='configured';
    return `<div class="sb-api-row"><div class="sb-api-name"><span class="dot ${ok?'dot-on':'dot-off'}"></span>${k.toUpperCase()}</div><span class="api-badge ${ok?'on':'off'}">${ok?'Active':'Offline'}</span></div>`;
  }).join('');
  renderSevBars(sd,s.total_findings);
  renderPorts(di.ports||[]);
  _all=f;renderVulns(f);
  setTimeout(()=>re.scrollIntoView({behavior:'smooth',block:'start'}),120);
}

/* Severity bars */
function renderSevBars(d,tot){
  const sevs=['Critical','High','Medium','Low','Info'];
  document.getElementById('severityBars').innerHTML=sevs.map(s=>{
    const cnt=d[s.toLowerCase()]||0,pct=tot>0?Math.round(cnt/tot*100):0;
    return `<div class="sev-row sev-${s}"><div class="sev-hdr"><span class="sev-name">${s}</span><div class="sev-right"><span class="sev-pct">${pct}%</span><span class="sev-cnt">${cnt}</span></div></div><div class="sev-trk"><div class="progress-bar bar-${s}" data-p="${pct}" style="width:0%"></div></div></div>`;
  }).join('');
  setTimeout(()=>document.querySelectorAll('.progress-bar[data-p]').forEach(b=>b.style.width=b.dataset.p+'%'),80);
}

/* Icon map */
function ico(s){
  if(!s)return'fa-server';s=s.toLowerCase();
  if(s.includes('http')||s.includes('www'))return'fa-globe';
  if(s.includes('ssh'))return'fa-terminal';
  if(s.includes('sql')||s.includes('mysql')||s.includes('pg')||s.includes('mongo'))return'fa-database';
  if(s.includes('ftp'))return'fa-upload';
  if(s.includes('smtp')||s.includes('mail')||s.includes('pop')||s.includes('imap'))return'fa-envelope';
  if(s.includes('dns')||s.includes('domain'))return'fa-sitemap';
  if(s.includes('rdp')||s.includes('vnc')||s.includes('remote'))return'fa-desktop';
  if(s.includes('ldap'))return'fa-users';
  if(s.includes('redis')||s.includes('memcache'))return'fa-memory';
  if(s.includes('docker'))return'fa-docker';
  return'fa-server';
}

/* Port grid */
function renderPorts(ports){
  document.getElementById('portGrid').innerHTML=ports.length?ports.map((p,i)=>`
    <div class="svc-card" style="animation-delay:${i*35}ms">
      <div class="svc-ico"><i class="fas ${ico(p.service)}"></i></div>
      <div class="svc-info">
        <div class="svc-nm"><span>${(p.service||'unknown').toUpperCase()}</span><span class="open-pill">OPEN</span></div>
        <div class="svc-port">${p.port}/TCP</div>
        <div class="svc-prod">${[p.product,p.version].filter(Boolean).join(' ')||'&mdash;'}</div>
      </div>
    </div>`).join('')
  :`<div class="empty" style="grid-column:1/-1"><i class="fas fa-network-wired"></i>No open services detected</div>`;
}

/* Vuln list */
function renderVulns(f){
  const list=document.getElementById('vulnList');
  list.innerHTML=f.length?f.map((v,i)=>`
    <div class="vc severity-${v.severity||'Info'}" style="animation-delay:${i*30}ms">
      <div class="vc-top">
        <div class="vc-ids"><span class="vc-id">${v.id}</span><span class="src-badge">${v.source}</span></div>
        <div class="sev-tags"><span class="sp ${v.severity||'Info'}">${v.severity||'Info'}</span><span class="cvss-chip">CVSS ${v.cvss>0?v.cvss:'N/A'}</span></div>
      </div>
      <p class="vc-sum">${v.summary}</p>
      <div class="vc-meta">
        <div class="vc-svc"><i class="fas fa-microchip"></i>${v.affected_service||'&mdash;'}</div>
        <span class="port-chip">PORT ${v.port}</span>
      </div>
    </div>`).join('')
  :`<div class="empty"><i class="fas fa-shield-check"></i>No CVE matches found &mdash; target appears hardened.</div>`;
}

function fvulns(sev,btn){
  document.querySelectorAll('.fb').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  renderVulns(sev==='all'?_all:_all.filter(f=>f.severity===sev));
}

/* Export */
function exportReport(){
  if(!_last)return showError('No scan data yet. Run a scan first.');
  const b=new Blob([JSON.stringify(_last,null,2)],{type:'application/json'});
  const a=document.createElement('a');a.href=URL.createObjectURL(b);
  a.download='vulnscope-'+(_last.summary?.target||'report')+'-'+Date.now()+'.json';a.click();
}
</script>
</body>
</html>status[$k]==='configured';
?>
<div class="sb-api-row">
  <div class="sb-api-name"><span class="dot <?= $ok?'dot-on':'dot-off' ?>"></span><?= $label ?></div>
  <span class="api-badge <?= $ok?'on':'off' ?>"><?= $ok?'Active':'Offline' ?></span>
</div>
<?php endforeach; ?>
  </div>
  <div class="sb-footer">Vijay Ishan Chowdhury &mdash; ZeroDay Security Services</div>
</aside>

<!-- MAIN -->
<div id="main">
  <!-- Topbar -->
  <header id="topbar">
    <div class="tb-left">
      <button id="sbtoggle" onclick="toggleSB()"><i class="fas fa-bars"></i></button>
      <div class="tb-bread">
        <i class="fas fa-shield-halved" style="color:var(--accent);font-size:12px"></i>
        <span>ZeroDay Security</span>
        <i class="fas fa-chevron-right"></i>
        <span class="active">VulnScope Pro</span>
      </div>
    </div>
    <div class="tb-right">
      <div class="tb-pill"><span class="ldot"></span>ENGINE ONLINE</div>
      <div class="tb-pill"><i class="fas fa-microchip" style="font-size:9px"></i>Enterprise v4.0</div>
    </div>
  </header>

  <!-- Page -->
  <main id="pg">
    <!-- Scan Panel -->
    <section class="scan-panel">
      <div class="scan-ph">
        <div>
          <h1>Attack Surface Assessment</h1>
          <p>NVD v2 &middot; Shodan &middot; Censys v2 &middot; CIRCL &middot; Nmap / PHP Socket Engine</p>
        </div>
        <div class="eng-badge"><i class="fas fa-circle" style="font-size:7px;color:#22c55e;animation:dotpulse 1.5s infinite"></i>Scan Core Active</div>
      </div>
      <form id="scanForm">
        <div class="scan-row">
          <div class="inp-wrap">
            <input type="text" id="target" placeholder="Enter target IP or domain â€” e.g. 192.168.1.1 or example.com" autocomplete="off" spellcheck="false">
            <i class="fas fa-crosshairs inp-ico"></i>
          </div>
          <button type="submit" id="btn"><i class="fas fa-shield-virus"></i>Launch Assessment</button>
        </div>
      </form>
      <div id="loader" class="hidden">
        <div class="ld-spin"></div>
        <div class="ld-bar-wrap">
          <div class="ld-txt"><i class="fas fa-circle-notch fa-spin" style="margin-right:6px"></i>Initializing scan engine &amp; correlating multi-source intelligence...</div>
          <div class="ld-track"><div class="ld-fill"></div></div>
        </div>
      </div>
    </section>

    <!-- Results -->
    <div id="results">
      <div class="res-hdr">
        <div class="res-hdr-title">Scan Results</div>
        <button class="exp-btn" onclick="exportReport()"><i class="fas fa-file-export"></i>Export JSON</button>
      </div>

      <!-- Stat Cards -->
      <div class="stats">
        <div class="sc risk">
          <div class="sc-lbl">Composite Risk Score</div>
          <div class="sc-val" id="riskValue">0</div>
          <div class="risk-trk"><div id="riskBar"></div></div>
          <div class="sc-meta" id="resTarget">HOST: ---</div>
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

      <!-- Left col: Severity + API Status | Right col: Vuln Feed -->
      <div class="res-body">
        <div style="display:flex;flex-direction:column;gap:14px">
          <!-- Severity -->
          <div class="panel">
            <div class="panel-hdr"><div class="panel-title"><i class="fas fa-chart-bar"></i>Severity Distribution</div></div>
            <div class="panel-body"><div id="severityBars"></div></div>
          </div>
          <!-- API Status -->
          <div class="panel">
            <div class="panel-hdr"><div class="panel-title"><i class="fas fa-plug-circle-check"></i>Intelligence Sources</div></div>
            <div class="panel-body" style="padding:14px 18px"><div id="apiStatusDisplay"></div></div>
          </div>
        </div>

        <!-- Vuln Feed -->
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
          <div id="vulnList"></div>
        </div>
      </div>

      <!-- Infra Map -->
      <div class="panel" id="infra-section" style="margin-bottom:0">
        <div class="panel-hdr">
          <div class="panel-title"><i class="fas fa-microchip"></i>Detected Infrastructure &amp; Services</div>
          <span id="portsCount" style="font-size:10px;font-family:var(--mono);color:var(--t3);text-transform:uppercase;letter-spacing:.07em">0 Assets</span>
        </div>
        <div id="portGrid"></div>
      </div>
    </div><!-- /#results -->
  </main>
</div><!-- /#main -->
</div><!-- /#shell -->

<script>
const SCAN_TOKEN='<?php echo SCAN_TOKEN; ?>';
let _last=null,_all=[];

/* BG canvas */
(function(){
  const c=document.getElementById('bgc'),ctx=c.getContext('2d');
  let w,h,pts=[];
  function rsz(){w=c.width=window.innerWidth;h=c.height=window.innerHeight}
  function init(){pts=[];const n=Math.floor(w*h/16000);for(let i=0;i<n;i++)pts.push({x:Math.random()*w,y:Math.random()*h,r:Math.random()*1.1+.3,vx:(Math.random()-.5)*.16,vy:(Math.random()-.5)*.16})}
  function draw(){
    ctx.clearRect(0,0,w,h);
    ctx.fillStyle='rgba(6,182,212,.4)';
    for(const d of pts){d.x+=d.vx;d.y+=d.vy;if(d.x<0||d.x>w)d.vx*=-1;if(d.y<0||d.y>h)d.vy*=-1;ctx.beginPath();ctx.arc(d.x,d.y,d.r,0,Math.PI*2);ctx.fill()}
    ctx.strokeStyle='rgba(6,182,212,.055)';ctx.lineWidth=.5;
    for(let i=0;i<pts.length;i++)for(let j=i+1;j<pts.length;j++){const dx=pts[i].x-pts[j].x,dy=pts[i].y-pts[j].y,d=Math.sqrt(dx*dx+dy*dy);if(d<110){ctx.globalAlpha=1-d/110;ctx.beginPath();ctx.moveTo(pts[i].x,pts[i].y);ctx.lineTo(pts[j].x,pts[j].y);ctx.stroke()}}
    ctx.globalAlpha=1;requestAnimationFrame(draw)
  }
  window.addEventListener('resize',()=>{rsz();init()});rsz();init();draw();
})();

/* Sidebar */
function toggleSB(){document.getElementById('sb').classList.toggle('open');document.getElementById('sb-ov').classList.toggle('on')}
function closeSB(){document.getElementById('sb').classList.remove('open');document.getElementById('sb-ov').classList.remove('on')}

/* Scroll helpers */
function toResults(){document.getElementById('results').scrollIntoView({behavior:'smooth'})}
function toInfra(){const e=document.getElementById('infra-section');if(e)e.scrollIntoView({behavior:'smooth'})}

/* Toast */
function showError(m){document.getElementById('error-msg').innerText=m;document.getElementById('error-toast').classList.add('show');setTimeout(hideError,6000)}
function hideError(){document.getElementById('error-toast').classList.remove('show')}

/* Counter animation */
function ctr(el,target,dur=900){
  const s=performance.now(),f=parseInt(el.innerText)||0;
  (function step(n){const p=Math.min((n-s)/dur,1),e=1-Math.pow(1-p,3);el.innerText=Math.round(f+(target-f)*e);if(p<1)requestAnimationFrame(step)})(s)
}

/* Scan form */
document.getElementById('scanForm').onsubmit=async(e)=>{
  e.preventDefault();
  const t=document.getElementById('target').value.trim();
  const btn=document.getElementById('btn'),ldr=document.getElementById('loader');
  if(!t)return showError('No target specified.');
  btn.disabled=true;ldr.classList.remove('hidden');ldr.classList.add('show');
  document.getElementById('results').classList.remove('show');document.getElementById('results').style.display='none';
  const fd=new FormData();fd.append('target',t);
  try{
    const r=await fetch('?action=scan',{method:'POST',body:fd,headers:{'X-VulnScope-Token':SCAN_TOKEN}});
    const j=await r.json();
    if(j.success){_last=j;renderDashboard(j)}else showError(j.message);
  }catch(err){showError('Operational failure: Intelligence core unreachable.')}
  finally{btn.disabled=false;ldr.classList.add('hidden');ldr.classList.remove('show')}
};

/* Render */
function renderDashboard(resp){
  const{summary:s,severity_distribution:sd,findings:f,debug_info:di,api_status:as}=resp;
  const re=document.getElementById('results');re.style.display='block';re.classList.add('show');
  ctr(document.getElementById('riskValue'),s.risk_score);
  setTimeout(()=>{document.getElementById('riskBar').style.width=s.risk_score+'%'},60);
  document.getElementById('resTarget').innerText='HOST: '+s.target;
  document.getElementById('resIp').innerText=s.ip;
  ctr(document.getElementById('findingsCount'),s.total_findings);
  ctr(document.getElementById('portsCountVal'),s.open_ports_count);
  document.querySelectorAll('#portsCount').forEach(el=>el.innerText=s.open_ports_count+' ASSETS');
  if(as)document.getElementById('apiStatusDisplay').innerHTML=Object.entries(as).map(([k,v])=>{
    const ok=v==='configured';
    return `<div class="sb-api-row"><div class="sb-api-name"><span class="dot ${ok?'dot-on':'dot-off'}"></span>${k.toUpperCase()}</div><span class="api-badge ${ok?'on':'off'}">${ok?'Active':'Offline'}</span></div>`;
  }).join('');
  renderSevBars(sd,s.total_findings);
  renderPorts(di.ports||[]);
  _all=f;renderVulns(f);
  setTimeout(()=>re.scrollIntoView({behavior:'smooth',block:'start'}),120);
}

/* Severity bars */
function renderSevBars(d,tot){
  const sevs=['Critical','High','Medium','Low','Info'];
  document.getElementById('severityBars').innerHTML=sevs.map(s=>{
    const cnt=d[s.toLowerCase()]||0,pct=tot>0?Math.round(cnt/tot*100):0;
    return `<div class="sev-row sev-${s}"><div class="sev-hdr"><span class="sev-name">${s}</span><div class="sev-right"><span class="sev-pct">${pct}%</span><span class="sev-cnt">${cnt}</span></div></div><div class="sev-trk"><div class="progress-bar bar-${s}" data-p="${pct}" style="width:0%"></div></div></div>`;
  }).join('');
  setTimeout(()=>document.querySelectorAll('.progress-bar[data-p]').forEach(b=>b.style.width=b.dataset.p+'%'),80);
}

/* Icon map */
function ico(s){
  if(!s)return'fa-server';s=s.toLowerCase();
  if(s.includes('http')||s.includes('www'))return'fa-globe';
  if(s.includes('ssh'))return'fa-terminal';
  if(s.includes('sql')||s.includes('mysql')||s.includes('pg')||s.includes('mongo'))return'fa-database';
  if(s.includes('ftp'))return'fa-upload';
  if(s.includes('smtp')||s.includes('mail')||s.includes('pop')||s.includes('imap'))return'fa-envelope';
  if(s.includes('dns')||s.includes('domain'))return'fa-sitemap';
  if(s.includes('rdp')||s.includes('vnc')||s.includes('remote'))return'fa-desktop';
  if(s.includes('ldap'))return'fa-users';
  if(s.includes('redis')||s.includes('memcache'))return'fa-memory';
  if(s.includes('docker'))return'fa-docker';
  return'fa-server';
}

/* Port grid */
function renderPorts(ports){
  document.getElementById('portGrid').innerHTML=ports.length?ports.map((p,i)=>`
    <div class="svc-card" style="animation-delay:${i*35}ms">
      <div class="svc-ico"><i class="fas ${ico(p.service)}"></i></div>
      <div class="svc-info">
        <div class="svc-nm"><span>${(p.service||'unknown').toUpperCase()}</span><span class="open-pill">OPEN</span></div>
        <div class="svc-port">${p.port}/TCP</div>
        <div class="svc-prod">${[p.product,p.version].filter(Boolean).join(' ')||'&mdash;'}</div>
      </div>
    </div>`).join('')
  :`<div class="empty" style="grid-column:1/-1"><i class="fas fa-network-wired"></i>No open services detected</div>`;
}

/* Vuln list */
function renderVulns(f){
  const list=document.getElementById('vulnList');
  list.innerHTML=f.length?f.map((v,i)=>`
    <div class="vc severity-${v.severity||'Info'}" style="animation-delay:${i*30}ms">
      <div class="vc-top">
        <div class="vc-ids"><span class="vc-id">${v.id}</span><span class="src-badge">${v.source}</span></div>
        <div class="sev-tags"><span class="sp ${v.severity||'Info'}">${v.severity||'Info'}</span><span class="cvss-chip">CVSS ${v.cvss>0?v.cvss:'N/A'}</span></div>
      </div>
      <p class="vc-sum">${v.summary}</p>
      <div class="vc-meta">
        <div class="vc-svc"><i class="fas fa-microchip"></i>${v.affected_service||'&mdash;'}</div>
        <span class="port-chip">PORT ${v.port}</span>
      </div>
    </div>`).join('')
  :`<div class="empty"><i class="fas fa-shield-check"></i>No CVE matches found &mdash; target appears hardened.</div>`;
}

function fvulns(sev,btn){
  document.querySelectorAll('.fb').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  renderVulns(sev==='all'?_all:_all.filter(f=>f.severity===sev));
}

/* Export */
function exportReport(){
  if(!_last)return showError('No scan data yet. Run a scan first.');
  const b=new Blob([JSON.stringify(_last,null,2)],{type:'application/json'});
  const a=document.createElement('a');a.href=URL.createObjectURL(b);
  a.download='vulnscope-'+(_last.summary?.target||'report')+'-'+Date.now()+'.json';a.click();
}
</script>
</body>
</html>