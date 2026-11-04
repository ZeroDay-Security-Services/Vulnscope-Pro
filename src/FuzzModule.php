<?php
/**
 * VulnScope Pro — Module 2: directory & sensitive-file fuzzer (curl_multi).
 */
declare(strict_types=1);


/**
 * MODULE 2 — Web directory / file bruteforcer (curl_multi, threaded equivalent).
 * Probes high-value paths: .env, .git, config.php, backup archives, /admin, etc.
 */
function vs_module2_fuzz(string $host, int $port, bool $tls, int $max_conc = 20, string $cookie = ''): array {
    $base = ($tls ? 'https' : 'http') . "://{$host}:{$port}";
    $cookie_hdr = vs_sanitize_cookie($cookie);

    // Baseline: seed session cookie, then fingerprint the target's own
    // miss-page (random path). Covers BOTH real-404 servers (miss returns
    // 404 + HTML body) and soft-404 servers (miss returns 200 + template).
    $bl   = vs_http_baseline($base, $cookie_hdr ? [CURLOPT_COOKIE => $cookie_hdr] : []);
    $miss_code = 0;
    $miss_len  = null;
    {
        $probe = md5((string)microtime(true));
        $ch = curl_init($base . '/' . $probe);
        curl_setopt_array($ch, vs_curl_defaults());
        curl_setopt($ch, CURLOPT_HEADER, true);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
        if ($cookie_hdr) { curl_setopt($ch, CURLOPT_COOKIE, $cookie_hdr); }
        $praw = curl_exec($ch);
        $miss_code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        if (is_string($praw) && $praw !== '') {
            $sep = strpos($praw, "\r\n\r\n");
            $miss_len = strlen($praw) - ($sep !== false ? $sep + 4 : 0);
            if ($sep === false) { $miss_len = strlen($praw); }
        }
    }

    // Passive path harvesting from robots.txt — real-app custom paths at zero cost.
    $rbl = vs_http_baseline($base . '/robots.txt', $cookie_hdr
        ? [CURLOPT_COOKIE => $cookie_hdr, CURLOPT_FOLLOWLOCATION => false]
        : [CURLOPT_FOLLOWLOCATION => false]);
    $targets = [
        '.env', '.env.bak', '.git/HEAD', '.git/config', '.svn/entries', '.DS_Store',
        'config.php', 'configuration.php', 'wp-config.php', 'settings.py', 'database.yml',
        'backup.zip', 'backup.tar.gz', 'site.tar.gz', 'dump.sql', 'db.sqlite3',
        'admin', 'admin/', 'admin.php', 'administrator', 'phpmyadmin/', 'wp-admin/',
        'robots.txt', 'sitemap.xml', 'composer.json', 'package.json', '.htaccess',
        'web.config', 'server-status', 'phpinfo.php', 'info.php', 'cgi-bin/',
        'uploads/', 'tmp/', 'backup/', 'old/', 'test/', 'api/', '.well-known/security.txt',
    ];
    foreach (preg_split('/\r\n|\r|\n/', $rbl['body']) as $line) {
        if (preg_match('~^(?:Dis)?allow:\s*/(\S+)~i', trim($line), $m)) {
            $p = rtrim($m[1], '/');
            if ($p !== '' && !in_array($p, $targets, true)) { $targets[] = $p; }
        }
    }
    $targets = array_slice(array_unique($targets), 0, 90);
    $results  = [];
    $queue    = $targets;
    $deadline = microtime(true) + 25.0;   // hard ceiling for whole probe run

    while ($queue && microtime(true) < $deadline) {
        $batch = array_splice($queue, 0, $max_conc);
        $mh = curl_multi_init();
        $handles = [];
        foreach ($batch as $path) {
            $url = $base . '/' . ltrim($path, '/');
            $ch = curl_init($url);
            curl_setopt_array($ch, vs_curl_defaults());
            curl_setopt_array($ch, [
                CURLOPT_HEADER         => true,
                CURLOPT_NOBODY         => false,
                CURLOPT_TIMEOUT_MS     => 8000,
                CURLOPT_FOLLOWLOCATION => false,
                CURLOPT_COOKIE         => $cookie_hdr,
            ]);
            curl_multi_add_handle($mh, $ch);
            $handles[$path] = $ch;
        }
        do {
            curl_multi_exec($mh, $running);
            if (microtime(true) > $deadline) { break; }
            curl_multi_select($mh, 0.2);
        } while ($running > 0);

        foreach ($handles as $path => $ch) {
            $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $size = (int)curl_getinfo($ch, CURLINFO_CONTENT_LENGTH_DOWNLOAD_T);
            $resp = curl_multi_getcontent($ch);
            // Body length with headers stripped (CONTENT_LENGTH is -1 on
            // chunked responses; strlen($resp) would count header bytes).
            $body_len = 0;
            if (is_string($resp) && $resp !== '') {
                $sep = strpos($resp, "\r\n\r\n");
                $body_len = ($sep !== false) ? (strlen($resp) - $sep - 4) : strlen($resp);
            }
            if ($size === -1 || $size === 0) { $size = $body_len; }
            $hdr = is_string($resp) ? substr($resp, 0, 4096) : '';
            curl_multi_remove_handle($mh, $ch);
            curl_close($ch);
            // Soft-404 filter:
            //  - a genuine 404 status ALWAYS means "not found" — noise;
            //  - 200s whose body length is (near) identical to the random-miss
            //    baseline are templated miss responses (soft-404 servers) — noise;
            //  - 301/302/401/403/500 etc. are interesting: the resource exists
            //    (possibly behind auth or a redirect).
            $soft404 = $code === 404
                || ($code === $miss_code && $miss_len !== null && abs($body_len - $miss_len) <= 24);
            // Interesting = not a soft-404. 401/403 count: the resource EXISTS behind auth.
            if ($code > 0 && !$soft404) {
                $results[] = ['path' => '/' . ltrim($path, '/'), 'status' => $code, 'length' => $size, 'server_header' => vs_extract_header($hdr, 'Server')];
            }
        }
        curl_multi_close($mh);
    }

    usort($results, fn($a, $b) => ($a['status'] <=> $b['status']) ?: strcmp($a['path'], $b['path']));
    return ['base_url' => $base, 'paths_tested' => count($targets), 'hits' => $results, 'baseline_status' => $bl['code']];
}

