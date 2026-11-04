<?php
/**
 * VulnScope Pro — HTTP layer.
 * Sequential + parallel curl helpers, plus the hardened target-request
 * defaults (browser UA, redirect tracking, TLS-lenient for live targets).
 */
declare(strict_types=1);

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


/** Shared hardened curl defaults (browser-like UA, redirect tracking, TLS-lenient). */
function vs_curl_defaults(): array {
    return [
        CURLOPT_USERAGENT      => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS      => 4,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_SSL_VERIFYHOST => 0,
        CURLOPT_CONNECTTIMEOUT_MS => 6000,
        CURLOPT_TIMEOUT_MS     => 12000,
        CURLOPT_ENCODING       => '',
        CURLOPT_SSL_OPTIONS    => CURLSSLOPT_NO_REVOKE,
    ];
}


/** Baseline GET used to fingerprint soft-404s and seed the session. */
function vs_http_baseline(string $base, array $extra = []): array {
    $ch = curl_init($base);
    curl_setopt_array($ch, vs_curl_defaults());
    curl_setopt_array($ch, $extra);
    $raw  = curl_exec($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $url  = (string)curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
    $size = (int)curl_getinfo($ch, CURLINFO_SIZE_DOWNLOAD_T);
    curl_close($ch);
    return ['code' => $code, 'size' => $size, 'url' => $url, 'body' => is_string($raw) ? $raw : '', 'cookie' => ''];
}

