<?php
/**
 * VulnScope Pro — target validation, resolution & port-scan engines.
 */
declare(strict_types=1);


/**
 * Accept a user-supplied Cookie header value (authenticated scans).
 */
function vs_sanitize_cookie(string $cookie): string {
    $cookie = str_replace(["\r", "\n"], '', $cookie);
    return (strlen($cookie) > 1200) ? substr($cookie, 0, 1200) : $cookie;
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
    return ['host' => $host, 'ip' => $ip, 'port' => $port_specified];
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


function run_nmap(string $target): string {
    $bin = trim((string)shell_exec('which nmap 2>/dev/null || where nmap 2>NUL'));
    $bin = trim(explode("\n", $bin)[0]);

    if (!empty($bin) && @file_exists($bin)) {
        $safe = escapeshellarg($target);
        // -Pn is essential for real-world WAN hosts: without it, dropped pings make nmap
        // mark the host 'down' and return zero results even when ports are wide open.
        $out = shell_exec("{$bin} -Pn -sV --version-intensity 5 -T4 --max-retries 1 --open --host-timeout 4m -oX - {$safe} 2>&1");
        if ($out && strpos($out, '<nmaprun') !== false) return $out;

        $out2 = shell_exec("{$bin} -Pn -sV --version-intensity 3 -T4 --open -oX - {$safe} 2>&1");
        if ($out2 && strpos($out2, '<nmaprun') !== false) return $out2;

        // Last resort: version detection off entirely — many firewalls tarpit -sV probes.
        $out3 = shell_exec("{$bin} -Pn -T4 --open -oX - {$safe} 2>&1");
        if ($out3 && strpos($out3, '<nmaprun') !== false) return $out3;
    }

    $ip = filter_var($target, FILTER_VALIDATE_IP)
        ? $target
        : @gethostbyname($target);

    if ($ip === $target && !filter_var($target, FILTER_VALIDATE_IP)) {
        throw new Exception("DNS resolution failed for: {$target}");
    }
    return php_socket_scan($target, $ip);
}

