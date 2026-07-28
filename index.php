<?php
/**
 * VulnScope Pro – ZeroDay Security Edition (Enterprise Intel Refactor)
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

function run_nmap($target) {
    $check = shell_exec("which nmap");
    if (empty($check)) throw new Exception("Nmap binary not found.");
    $safe_target = escapeshellarg($target);
    $cmd = "nmap -sV --version-intensity 5 -T4 -oX - $safe_target 2>&1";
    $output = shell_exec($cmd);
    if (!$output) throw new Exception("Nmap execution failed.");
    return $output;
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
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ZeroDay | VulnScope Pro</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        body { background: #05070a; color: #e2e8f0; font-family: 'Segoe UI', sans-serif; overflow-x: hidden; }
        .zd-gradient { background: linear-gradient(135deg, #0f172a 0%, #020617 100%); border: 1px solid #1e293b; }
        .zd-blue { color: #38bdf8; }
        .zd-border-blue { border-color: #0ea5e9; }
        .zd-btn { background: linear-gradient(to right, #0ea5e9, #2563eb); color: white; transition: 0.3s; cursor: pointer; }
        .zd-btn:disabled { opacity: 0.5; filter: grayscale(1); cursor: not-allowed; }
        .logo-container { filter: drop-shadow(0 0 15px rgba(14, 165, 233, 0.4)); }
        
        .bar-Critical { background-color: #ef4444; }
        .bar-High { background-color: #f97316; }
        .bar-Medium { background-color: #eab308; }
        .bar-Low { background-color: #38bdf8; }
        .bar-Info { background-color: #94a3b8; }

        .severity-Critical { border-left: 4px solid #ef4444; background: rgba(239, 68, 68, 0.05); }
        .severity-High { border-left: 4px solid #f97316; background: rgba(249, 115, 22, 0.05); }
        .severity-Medium { border-left: 4px solid #eab308; background: rgba(234, 179, 8, 0.05); }
        .severity-Low { border-left: 4px solid #38bdf8; background: rgba(56, 189, 248, 0.05); }
        .severity-Info { border-left: 4px solid #94a3b8; background: rgba(148, 163, 184, 0.05); }

        #error-toast { transition: transform 0.3s ease-in-out; transform: translateY(150%); }
        #error-toast.show { transform: translateY(0); }
        .custom-scrollbar::-webkit-scrollbar { width: 6px; }
        .custom-scrollbar::-webkit-scrollbar-track { background: #0f172a; }
        .custom-scrollbar::-webkit-scrollbar-thumb { background: #1e293b; border-radius: 10px; }
        .progress-bar { transition: width 0.8s cubic-bezier(0.4, 0, 0.2, 1); }
        .service-card { transition: all 0.3s ease; }
        .service-card:hover { transform: translateY(-4px); border-color: #38bdf8; background: rgba(56, 189, 248, 0.02); }
    </style>
</head>
<body class="p-4 md:p-6">

    <div id="error-toast" class="fixed bottom-6 right-6 z-50 bg-red-600 text-white px-6 py-4 rounded-xl shadow-2xl flex items-center gap-3">
        <i class="fas fa-exclamation-triangle"></i>
        <span id="error-msg"></span>
        <button onclick="hideError()" class="ml-4 opacity-50 hover:opacity-100">&times;</button>
    </div>

    <div class="max-w-7xl mx-auto">
        <div class="flex flex-col items-center mb-8 text-center">
            <div class="logo-container mb-4">
                <img src="logo.jpg" alt="ZeroDay Logo" class="h-24 md:h-32 w-auto" onerror="this.src='https://via.placeholder.com/150?text=ZERODAY'">
            </div>
            <h1 class="text-2xl md:text-3xl font-bold tracking-widest text-white uppercase">VulnScope <span class="zd-blue">Pro</span></h1>
            <p class="text-slate-500 text-[10px] md:text-xs tracking-[0.3em] uppercase">Intelligence Defense Platform</p>
        </div>

        <div class="zd-gradient p-6 md:p-8 rounded-2xl mb-8 shadow-2xl">
            <form id="scanForm" class="flex flex-col md:flex-row gap-4">
                <div class="relative flex-grow">
                    <i class="fas fa-crosshairs absolute left-4 top-1/2 -translate-y-1/2 text-slate-500"></i>
                    <input type="text" id="target" placeholder="Enter target domain or IP (e.g. 192.168.1.1)" 
                        class="w-full bg-slate-950 border border-slate-800 rounded-xl py-4 pl-12 pr-6 outline-none focus:zd-border-blue transition text-sm">
                </div>
                <button type="submit" id="btn" class="zd-btn px-10 py-4 rounded-xl font-bold uppercase tracking-wider flex items-center justify-center text-sm">
                    <i class="fas fa-shield-virus mr-2"></i> Launch Assessment
                </button>
            </form>
            <div id="loader" class="hidden mt-4 text-center zd-blue text-xs animate-pulse">
                <i class="fas fa-circle-notch fa-spin mr-2"></i> Initializing Secure Nmap Core & Correlating Multi-Source Intelligence...
            </div>
        </div>

        <div id="results" class="grid grid-cols-1 lg:grid-cols-12 gap-6 md:gap-8 hidden">
            <div class="lg:col-span-4 space-y-6">
                <div class="zd-gradient p-6 rounded-2xl border-t-4 zd-border-blue text-center shadow-lg">
                    <h3 class="text-[10px] text-slate-500 uppercase font-bold mb-4 tracking-widest">Composite Risk Score</h3>
                    <div class="text-6xl font-black mb-2 zd-blue" id="riskValue">0</div>
                    <div class="w-full bg-slate-900 h-1.5 rounded-full overflow-hidden">
                        <div id="riskBar" class="h-full bg-blue-500 transition-all duration-1000" style="width: 0%"></div>
                    </div>
                    <div class="mt-4 flex justify-between text-[10px] text-slate-500 font-mono">
                        <span id="resTarget">TARGET: ---</span>
                        <span id="resIp">IP: ---</span>
                    </div>
                </div>

                <div class="zd-gradient p-6 rounded-2xl shadow-lg">
                    <h3 class="text-[10px] text-slate-500 uppercase font-bold mb-6 tracking-widest">Severity Distribution</h3>
                    <div id="severityBars" class="space-y-4"></div>
                </div>

                <div class="zd-gradient p-6 rounded-2xl shadow-lg">
                    <h3 class="text-[10px] text-slate-500 uppercase font-bold mb-4 tracking-widest">API Debug</h3>
                    <div id="apiStatusDisplay" class="space-y-2 text-[10px] font-mono uppercase"></div>
                </div>
            </div>

            <div class="lg:col-span-8 zd-gradient p-6 md:p-8 rounded-2xl flex flex-col h-fit shadow-lg">
                <div class="flex justify-between items-center mb-6">
                    <h3 class="text-lg font-bold flex items-center">
                        <i class="fas fa-list-ul zd-blue mr-3"></i> Security Intelligence Findings 
                        <span id="findingsCount" class="ml-3 px-2 py-0.5 bg-slate-800 text-[10px] rounded-full text-slate-400">0</span>
                    </h3>
                </div>
                
                <div id="vulnList" class="space-y-4 max-h-[600px] overflow-y-auto pr-2 custom-scrollbar"></div>
            </div>

            <div class="lg:col-span-12 zd-gradient p-6 md:p-8 rounded-2xl shadow-lg">
                <div class="flex justify-between items-center mb-6 border-b border-slate-800 pb-4">
                    <h3 class="text-lg font-bold uppercase tracking-widest flex items-center">
                        <i class="fas fa-microchip zd-blue mr-3"></i> Detected Infrastructure & Services
                    </h3>
                    <span id="portsCount" class="text-[10px] font-mono text-slate-500 uppercase">0 Assets Found</span>
                </div>
                <div id="portGrid" class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 max-h-[500px] overflow-y-auto pr-2 custom-scrollbar"></div>
            </div>
        </div>
    </div>

    <script>
        const SCAN_TOKEN = '<?php echo SCAN_TOKEN; ?>';

        function showError(msg) {
            document.getElementById('error-msg').innerText = msg;
            document.getElementById('error-toast').classList.add('show');
            setTimeout(() => document.getElementById('error-toast').classList.remove('show'), 5000);
        }

        document.getElementById('scanForm').onsubmit = async (e) => {
            e.preventDefault();
            const target = document.getElementById('target').value.trim();
            const btn = document.getElementById('btn');
            const loader = document.getElementById('loader');

            if (!target) return showError("No target specified.");

            btn.disabled = true;
            loader.classList.remove('hidden');
            document.getElementById('results').classList.add('hidden');

            const fd = new FormData();
            fd.append('target', target);

            try {
                const res = await fetch('?action=scan', { 
                    method: 'POST', 
                    body: fd,
                    headers: { 'X-VulnScope-Token': SCAN_TOKEN }
                });
                const response = await res.json();
                if (response.success) renderDashboard(response);
                else showError(response.message);
            } catch (err) {
                showError("Operational failure: Intelligence core unreachable.");
            } finally {
                btn.disabled = false;
                loader.classList.add('hidden');
            }
        };

        function renderDashboard(response) {
            const { summary, severity_distribution, findings, debug_info, api_status } = response;

            document.getElementById('results').classList.remove('hidden');
            document.getElementById('riskValue').innerText = summary.risk_score;
            document.getElementById('riskBar').style.width = summary.risk_score + '%';
            document.getElementById('resTarget').innerText = `HOST: ${summary.target}`;
            document.getElementById('resIp').innerText = `IP: ${summary.ip}`;
            document.getElementById('findingsCount').innerText = summary.total_findings;
            document.getElementById('portsCount').innerText = `${summary.open_ports_count} ASSETS`;
            
            // API Status
            if (api_status) {
                document.getElementById('apiStatusDisplay').innerHTML = Object.entries(api_status).map(([api, status]) => `
                    <div class="flex justify-between">
                        <span>${api}</span>
                        <span class="${status === 'configured' ? 'text-green-500' : 'text-red-500'}">${status}</span>
                    </div>
                `).join('');
            }

            // Infrastructure Grid
            document.getElementById('portGrid').innerHTML = debug_info.ports.map(p => `
                <div class="service-card p-4 rounded-xl zd-gradient border border-slate-800 flex items-start gap-4">
                    <div class="w-10 h-10 rounded-lg bg-slate-950 flex items-center justify-center text-blue-400">
                        <i class="fas ${getIcon(p.service)}"></i>
                    </div>
                    <div class="flex-grow">
                        <div class="flex justify-between items-center mb-1 text-xs font-bold text-white uppercase">
                            <span>${p.service}</span>
                            <span class="text-[8px] bg-green-950 text-green-400 px-1 rounded">OPEN</span>
                        </div>
                        <div class="text-[10px] font-mono text-blue-400">${p.port}/TCP</div>
                        <div class="text-[9px] text-slate-500 truncate">${p.product || ''} ${p.version || ''}</div>
                    </div>
                </div>
            `).join('');

            // Intel Cards (Includes Nmap services, CVEs, Shodan, and Censys Metadata)
            document.getElementById('vulnList').innerHTML = findings.length === 0 ? 
                '<div class="p-12 text-center text-slate-600 italic font-mono">No direct matches found. Target appears hardened.</div>' :
                findings.map(v => `
                    <div class="p-5 rounded-xl severity-${v.severity} transition hover:bg-slate-900 shadow-md">
                        <div class="flex flex-col md:flex-row justify-between items-start md:items-center mb-2 gap-2">
                            <div class="flex items-center gap-3">
                                <span class="text-blue-400 font-bold font-mono text-sm">${v.id}</span>
                                <span class="text-[8px] px-2 py-0.5 rounded-full font-bold uppercase tracking-widest bg-slate-800 text-slate-300">
                                    SOURCE: ${v.source}
                                </span>
                            </div>
                            <div class="flex items-center gap-2">
                                <span class="text-[9px] uppercase font-bold px-2 py-0.5 rounded ${getSevClass(v.severity)}">
                                    ${v.severity}
                                </span>
                                <span class="text-[9px] font-bold text-slate-500 font-mono">CVSS ${v.cvss > 0 ? v.cvss : 'N/A'}</span>
                            </div>
                        </div>
                        <p class="text-[11px] text-slate-400 leading-relaxed mb-2">${v.summary}</p>
                        <div class="flex justify-between text-[9px] text-slate-600 italic">
                            <span><i class="fas fa-microchip mr-1"></i> ${v.affected_service}</span>
                            <span>PORT: ${v.port}</span>
                        </div>
                    </div>
                `).join('');

            renderSeverityBars(severity_distribution, summary.total_findings);
        }

        function getIcon(s) {
            s = s.toLowerCase();
            if (s.includes('http')) return 'fa-globe';
            if (s.includes('ssh')) return 'fa-terminal';
            if (s.includes('sql')) return 'fa-database';
            if (s.includes('ftp')) return 'fa-upload';
            return 'fa-server';
        }

        function getSevClass(s) {
            if (s === 'Critical') return 'text-red-400 bg-red-950 border border-red-900';
            if (s === 'High') return 'text-orange-400 bg-orange-950 border border-orange-900';
            if (s === 'Medium') return 'text-yellow-400 bg-yellow-950 border border-yellow-900';
            if (s === 'Low') return 'text-blue-400 bg-blue-950 border border-blue-900';
            return 'text-slate-400 bg-slate-900 border border-slate-800';
        }

        function renderSeverityBars(dist, total) {
            const sevs = ['critical', 'high', 'medium', 'low', 'info'];
            document.getElementById('severityBars').innerHTML = sevs.map(s => {
                const count = dist[s] || 0;
                const p = total > 0 ? Math.round((count / total) * 100) : 0;
                const label = s.charAt(0).toUpperCase() + s.slice(1);
                return `
                    <div class="space-y-1">
                        <div class="flex justify-between text-[9px] font-bold uppercase tracking-widest">
                            <span class="text-slate-400">${label}</span>
                            <span class="text-slate-500">${p}%</span>
                        </div>
                        <div class="w-full bg-slate-950 h-2 rounded-full border border-slate-800 overflow-hidden">
                            <div class="progress-bar bar-${label} h-full" style="width: ${p}%"></div>
                        </div>
                    </div>
                `;
            }).join('');
        }
    </script>
</body>
</html>