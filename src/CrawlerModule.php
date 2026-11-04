<?php
/**
 * VulnScope Pro — Spider / crawler (ZAP Spider equivalent).
 *
 * Breadth-first, same-origin crawl with:
 *   - robots.txt + sitemap.xml discovery
 *   - parallel page fetching (curl_multi)
 *   - link, form, parameter and JavaScript-endpoint extraction
 *   - technology fingerprinting
 *
 * The spider output feeds the passive and active scanners directly, so no
 * page is fetched twice by those stages.
 */
declare(strict_types=1);

/** Fetch a page and return status, headers and body. Never throws. */
function vs_fetch_page(string $url, string $cookie = '', int $timeoutMs = 8000): array
{
    $t0 = microtime(true);
    $ch = curl_init($url);
    if ($ch === false) {
        return ['url' => $url, 'final_url' => $url, 'code' => 0, 'headers' => [], 'raw_headers' => '', 'body' => '', 'type' => '', 'error' => 'curl init failed'];
    }
    curl_setopt_array($ch, vs_curl_defaults());
    curl_setopt_array($ch, [
        CURLOPT_HEADER         => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS      => 3,
        CURLOPT_TIMEOUT_MS     => $timeoutMs,
        CURLOPT_COOKIE         => $cookie,
    ]);
    $raw      = curl_exec($ch);
    $code     = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $final    = (string)curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
    $type     = (string)curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
    $hsize    = (int)curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    $error    = curl_error($ch);
    curl_close($ch);

    if (!is_string($raw)) {
        $raw = '';
    }
    $rawHeaders = $hsize > 0 ? substr($raw, 0, $hsize) : '';
    $body       = $hsize > 0 ? substr($raw, $hsize) : $raw;

    vs_log_request('GET', $final !== '' ? $final : $url, $code, strlen($body), (int)((microtime(true) - $t0) * 1000), 'spider', 'crawler');

    return [
        'url'         => $url,
        'final_url'   => $final !== '' ? $final : $url,
        'code'        => $code,
        'headers'     => vs_header_map($rawHeaders),
        'raw_headers' => $rawHeaders,
        'body'        => $body,
        'type'        => $type,
        'size'        => strlen($body),
        'error'       => $error,
    ];
}

/** Parse raw HTTP header block(s) into a lowercase-keyed map (last value wins). */
function vs_header_map(string $raw): array
{
    $map = [];
    foreach (preg_split('/\r\n|\n/', $raw) as $line) {
        if ($line === '' || stripos($line, 'HTTP/') === 0) {
            continue;
        }
        $pos = strpos($line, ':');
        if ($pos === false) {
            continue;
        }
        $name = strtolower(trim(substr($line, 0, $pos)));
        $val  = trim(substr($line, $pos + 1));
        if ($name !== '') {
            $map[$name] = isset($map[$name]) ? $map[$name] . ', ' . $val : $val;
        }
    }
    return $map;
}

/** Resolve a relative reference against an absolute base URL. */
function vs_abs_url(string $base, string $rel): ?string
{
    $rel = trim(html_entity_decode($rel, ENT_QUOTES));
    $rel = preg_replace('/#.*$/', '', $rel);
    if ($rel === '' || $rel === '#') {
        return null;
    }
    if (preg_match('#^(mailto|tel|javascript|data|ftp):#i', $rel)) {
        return null;
    }
    if (preg_match('#^https?://#i', $rel)) {
        return $rel;
    }
    $p = parse_url($base);
    if (empty($p['scheme']) || empty($p['host'])) {
        return null;
    }
    $origin = $p['scheme'] . '://' . $p['host'] . (isset($p['port']) ? ':' . $p['port'] : '');
    if (str_starts_with($rel, '//')) {
        return $p['scheme'] . ':' . $rel;
    }
    if ($rel[0] === '/') {
        return $origin . $rel;
    }
    $path = $p['path'] ?? '/';
    if ($rel[0] === '?') {
        return $origin . $path . $rel;
    }
    $dir = preg_replace('#/[^/]*$#', '/', $path);
    return $origin . $dir . $rel;
}

function vs_is_static_asset(string $url): bool
{
    return (bool)preg_match('/\.(?:css|js|png|jpe?g|gif|svg|ico|webp|woff2?|ttf|eot|mp4|webm|pdf|zip|gz|tar|rar|7z|exe|dmg|apk|iso)(?:\?|$)/i', $url);
}

function vs_is_unsafe_crawl_target(string $url): bool
{
    return (bool)preg_match('/(?:logout|log-out|signout|sign-out|delete|remove|destroy|unsubscribe|revoke|reset|terminate|shutdown)(?:[/?=&._-]|$)/i', $url);
}

/** Extract links, forms, scripts, comments and the title from an HTML page. */
function vs_parse_html(string $base, string $html): array
{
    $out = ['title' => '', 'links' => [], 'forms' => [], 'scripts' => [], 'comments' => [], 'generator' => ''];

    if (preg_match('/<title[^>]*>(.*?)<\/title>/is', $html, $m)) {
        $out['title'] = trim(preg_replace('/\s+/', ' ', html_entity_decode(strip_tags($m[1]), ENT_QUOTES)));
        $out['title'] = substr($out['title'], 0, 160);
    }
    if (preg_match('/<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)/i', $html, $m)) {
        $out['generator'] = trim($m[1]);
    }

    // href / src / action attributes
    if (preg_match_all('/\b(?:href|src|action)\s*=\s*["\']([^"\']+)["\']/i', $html, $m)) {
        foreach ($m[1] as $attr) {
            $abs = vs_abs_url($base, $attr);
            if ($abs !== null) {
                $out['links'][] = $abs;
            }
        }
    }

    // Forms with inputs (the primary active-scan surface).
    if (preg_match_all('/<form\b([^>]*)>(.*?)<\/form>/is', $html, $fm, PREG_SET_ORDER)) {
        foreach ($fm as $f) {
            $attrs = $f[1];
            $inner = $f[2];
            $action = '/';
            if (preg_match('/\baction\s*=\s*["\']([^"\']*)["\']/i', $attrs, $am)) {
                $action = $am[1];
            }
            $method = 'GET';
            if (preg_match('/\bmethod\s*=\s*["\']([^"\']+)["\']/i', $attrs, $mm)) {
                $method = strtoupper($mm[1]);
            }
            $inputs = [];
            if (preg_match_all('/<(?:input|textarea|select)\b([^>]*)>/is', $inner, $im, PREG_SET_ORDER)) {
                foreach ($im as $in) {
                    $ia = $in[1];
                    if (!preg_match('/\bname\s*=\s*["\']([^"\']*)["\']/i', $ia, $nm)) {
                        continue;
                    }
                    $name = $nm[1];
                    if ($name === '') {
                        continue;
                    }
                    $itype = 'text';
                    if (preg_match('/\btype\s*=\s*["\']([^"\']+)["\']/i', $ia, $tm)) {
                        $itype = strtolower($tm[1]);
                    }
                    $value = '';
                    if (preg_match('/\bvalue\s*=\s*["\']([^"\']*)["\']/i', $ia, $vm)) {
                        $value = $vm[1];
                    }
                    $inputs[] = ['name' => $name, 'type' => $itype, 'value' => $value];
                }
            }
            $hasToken = (bool)preg_match('/\b(?:csrf|xsrf|authenticity|_token|token|nonce)\b/i', $inner);
            $abs = vs_abs_url($base, $action) ?: $base;
            $out['forms'][] = [
                'page'      => $base,
                'action'    => $abs,
                'method'    => $method,
                'inputs'    => $inputs,
                'has_token' => $hasToken,
                'sensitive' => (bool)preg_match('/type=["\']password["\']|<input[^>]+type=["\']password/i', $inner),
            ];
        }
    }

    if (preg_match_all('/<script[^>]+src\s*=\s*["\']([^"\']+)["\']/i', $html, $sm)) {
        foreach ($sm[1] as $src) {
            $abs = vs_abs_url($base, $src);
            if ($abs !== null) {
                $out['scripts'][] = $abs;
            }
        }
    }

    if (preg_match_all('/<!--(.*?)-->/s', $html, $cm)) {
        foreach (array_slice($cm[1], 0, 20) as $comment) {
            $c = trim(preg_replace('/\s+/', ' ', $comment));
            if ($c !== '') {
                $out['comments'][] = substr($c, 0, 240);
            }
        }
    }

    $out['links']   = array_values(array_unique($out['links']));
    $out['scripts'] = array_values(array_unique($out['scripts']));
    return $out;
}

/** Technology fingerprinting across headers, cookies and markup. */
function vs_detect_tech(array $page): array
{
    $headers = $page['headers'] ?? [];
    $body    = $page['body'] ?? '';
    $url     = $page['url'] ?? '';
    $tech    = [];

    $add = function (string $name, string $evidence, ?string $version = null) use (&$tech): void {
        $key = strtolower($name);
        if (!isset($tech[$key])) {
            $tech[$key] = ['name' => $name, 'version' => $version, 'evidence' => $evidence];
        } elseif ($version && empty($tech[$key]['version'])) {
            $tech[$key]['version'] = $version;
        }
    };

    $server = strtolower($headers['server'] ?? '');
    foreach (['nginx' => 'Nginx', 'apache' => 'Apache HTTP Server', 'microsoft-iis' => 'Microsoft IIS', 'openresty' => 'OpenResty', 'cloudflare' => 'Cloudflare', 'litespeed' => 'LiteSpeed'] as $needle => $name) {
        if (str_contains($server, $needle)) {
            $ver = null;
            if (preg_match('/' . preg_quote($needle, '/') . '[\/ ]([\d.]+)/i', $headers['server'] ?? '', $m)) {
                $ver = $m[1];
            }
            $add($name, 'Server header: ' . ($headers['server'] ?? ''), $ver);
        }
    }
    if (!empty($headers['x-powered-by'])) {
        $add('Application stack', 'X-Powered-By: ' . $headers['x-powered-by'], null);
        if (preg_match('/PHP\/([\d.]+)/i', $headers['x-powered-by'], $m)) {
            $add('PHP', 'X-Powered-By header', $m[1]);
        }
        if (preg_match('/ASP\.NET/i', $headers['x-powered-by'])) {
            $add('ASP.NET', 'X-Powered-By header');
        }
        if (preg_match('/Express/i', $headers['x-powered-by'])) {
            $add('Express.js', 'X-Powered-By header');
        }
    }
    if (isset($headers['x-aspnet-version'])) {
        $add('ASP.NET', 'X-AspNet-Version header', $headers['x-aspnet-version']);
    }
    if (isset($headers['x-generator'])) {
        $add($headers['x-generator'], 'X-Generator header');
    }
    if (isset($headers['x-drupal-cache'])) {
        $add('Drupal', 'X-Drupal-Cache header');
    }
    if (isset($headers['x-shopify-stage'])) {
        $add('Shopify', 'X-Shopify-Stage header');
    }

    $bodyChecks = [
        ['WordPress', '/wp-(?:content|includes)\//i', '/wp-includes\/js\/[^"\']*?ver=([\d.]+)/i'],
        ['Drupal', '/sites\/(?:all|default)\/(?:files|modules)\//i', '/Drupal\.settings|drupalSettings/i'],
        ['Joomla', '/\/media\/jui\/|\/components\/com_/i', '/Joomla!/i'],
        ['Laravel', '/laravel_(?:session|token)|XSRF-TOKEN/i', null],
        ['Symfony', '/sf-toolbar|_wdt\//i', null],
        ['Django', '/csrftoken|__admin_media_prefix__/i', null],
        ['Flask', '/Werkzeug|flask\.debug/i', null],
        ['Next.js', '/__NEXT_DATA__|_next\/static/i', null],
        ['Nuxt', '/__NUXT__|_nuxt\//i', null],
        ['React', '/data-reactroot|react\.production/i', null],
        ['Angular', '/ng-version="([\d.]+)"/i', null],
        ['Vue.js', '/__VUE__|vue(?:\.min)?\.js/i', null],
        ['Bootstrap', '/bootstrap(?:\.min)?\.css|bootstrap\.bundle/i', '/bootstrap[.@\/-]([\d.]+)/i'],
        ['jQuery', '/jquery(?:-[\d.]+)?(?:\.min)?\.js/i', '/jquery[-\/]?([\d.]+)(?:\.min)?\.js/i'],
        ['Font Awesome', '/font-awesome|fontawesome/i', null],
        ['phpMyAdmin', '/phpMyAdmin|pmahomme/i', null],
        ['Swagger UI', '/swagger-ui|swagger\.json|openapi\.json/i', null],
        ['Grafana', '/grafana|GrafanaVersion/i', null],
        ['Kibana', '/kibana|kbn-injected-metadata/i', null],
        ['Jupyter', '/jupyter|Jupyter Notebook/i', null],
        ['GitLab', '/gitlab|gon\.gitlab_url/i', null],
        ['Jenkins', '/jenkins|Jenkins-Crumb/i', null],
        ['Tomcat', '/tomcat|Apache Tomcat/i', null],
        ['Spring Boot', '/Whitelabel Error Page|spring-boot/i', null],
        ['Cloudflare', '/cdnjs\.cloudflare\.com|__cf_bm/i', null],
    ];
    foreach ($bodyChecks as [$name, $pattern, $versionPattern]) {
        if (preg_match($pattern, $body)) {
            $ver = null;
            if ($versionPattern && preg_match($versionPattern, $body, $m)) {
                $ver = $m[1] ?? null;
            }
            $add($name, 'Markup signature on ' . $url, $ver);
        }
    }

    if (isset($headers['set-cookie'])) {
        $cookieHdr = strtolower($headers['set-cookie']);
        if (str_contains($cookieHdr, 'phpsessid')) {
            $add('PHP session', 'PHPSESSID cookie');
        }
        if (str_contains($cookieHdr, 'jsessionid')) {
            $add('Java servlet', 'JSESSIONID cookie');
        }
        if (str_contains($cookieHdr, 'asp.net_sessionid')) {
            $add('ASP.NET', 'ASP.NET_SessionId cookie');
        }
        if (str_contains($cookieHdr, 'laravel_session')) {
            $add('Laravel', 'laravel_session cookie');
        }
        if (str_contains($cookieHdr, 'ci_session')) {
            $add('CodeIgniter', 'ci_session cookie');
        }
    }

    return array_values($tech);
}

/** Extract API endpoints referenced from JavaScript bundles. */
function vs_extract_js_endpoints(string $base, string $js, array &$seen): array
{
    $found = [];
    $patterns = [
        '/["\']((?:\/|https?:\/\/)[a-z0-9._~:\/?#\[\]@!$&\'()*+,;=%-]*(?:api|graphql|rest|v1|v2|v3)\/[a-z0-9._~:\/?#@!$&\'()*+,;=%\[\]-]*)["\']/i',
        '/(?:fetch|axios\.(?:get|post|put|delete)|\.open)\s*\(\s*["\']([^"\']+)["\']/i',
        '/["\'](\/[a-z0-9_-]+\/[a-z0-9_\/-]{2,})["\']/i',
    ];
    foreach ($patterns as $re) {
        if (preg_match_all($re, $js, $m)) {
            foreach (array_slice($m[1], 0, 40) as $candidate) {
                $abs = vs_abs_url($base, $candidate);
                if ($abs === null || isset($seen[$abs]) || vs_is_static_asset($abs)) {
                    continue;
                }
                $seen[$abs] = true;
                $found[] = $abs;
            }
        }
    }
    return array_slice($found, 0, 25);
}

/**
 * Spider a target.
 *
 * $opts: max_pages (25), max_depth (2), cookie, parallel (6),
 *        max_seconds (35), fetch_js (true), max_js (8).
 */
function vs_spider(string $base, array $opts = []): array
{
    $started = microtime(true);
    $maxPages  = max(1, min(100, (int)($opts['max_pages'] ?? 25)));
    $maxDepth  = max(0, min(4, (int)($opts['max_depth'] ?? 2)));
    $cookie    = vs_sanitize_cookie((string)($opts['cookie'] ?? ''));
    $parallel  = max(1, min(10, (int)($opts['parallel'] ?? 6)));
    $deadline  = $started + max(5, (float)($opts['max_seconds'] ?? 35));

    $baseParts = parse_url($base);
    $origin    = ($baseParts['scheme'] ?? 'http') . '://' . ($baseParts['host'] ?? '')
        . (isset($baseParts['port']) ? ':' . $baseParts['port'] : '');
    $host      = strtolower($baseParts['host'] ?? '');

    $rootUrl     = rtrim($origin, '/') . '/';
    $queue       = [[$rootUrl, 0], [$rootUrl . 'robots.txt', 0], [$rootUrl . 'sitemap.xml', 0]];
    $seen        = [$rootUrl => true, $rootUrl . 'robots.txt' => true, $rootUrl . 'sitemap.xml' => true];
    $pages       = [];
    $allUrls     = [];
    $forms       = [];
    $params      = [];
    $tech        = [];
    $scripts     = [];
    $endpoints   = [];
    $robots      = [];
    $sitemaps    = [];
    $jsSeen      = [];
    $errors      = [];
    $fetched     = 0;
    $disallow    = [];

    /** Fetch one batch in parallel and return page records. */
    $fetchBatch = function (array $batch) use ($cookie): array {
        $mh = curl_multi_init();
        $handles = [];
        foreach ($batch as $i => $item) {
            $url = $item[0];
            $ch = curl_init($url);
            if ($ch === false) {
                continue;
            }
            curl_setopt_array($ch, vs_curl_defaults());
            curl_setopt_array($ch, [
                CURLOPT_HEADER         => true,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_MAXREDIRS      => 3,
                CURLOPT_TIMEOUT_MS     => 9000,
                CURLOPT_COOKIE         => $cookie,
            ]);
            curl_multi_add_handle($mh, $ch);
            $handles[$i] = $ch;
        }
        $running = null;
        do {
            $status = curl_multi_exec($mh, $running);
            if ($running) {
                curl_multi_select($mh, 0.25);
            }
        } while ($running > 0 && $status === CURLM_OK);

        $out = [];
        foreach ($handles as $i => $ch) {
            $code  = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $type  = (string)curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
            $final = (string)curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
            $hsize = (int)curl_getinfo($ch, CURLINFO_HEADER_SIZE);
            $raw   = curl_multi_getcontent($ch);
            $err   = curl_error($ch);
            curl_multi_remove_handle($mh, $ch);
            curl_close($ch);
            $raw = is_string($raw) ? $raw : '';
            $rawHeaders = $hsize > 0 ? substr($raw, 0, $hsize) : '';
            $body = $hsize > 0 ? substr($raw, $hsize) : $raw;
            $out[$i] = [
                'url'         => $batch[$i][0],
                'final_url'   => $final !== '' ? $final : $batch[$i][0],
                'depth'       => $batch[$i][1],
                'code'        => $code,
                'headers'     => vs_header_map($rawHeaders),
                'raw_headers' => $rawHeaders,
                'body'        => $body,
                'type'        => $type,
                'size'        => strlen($body),
                'error'       => $err,
            ];
        }
        curl_multi_close($mh);
        return $out;
    };

    while ($queue && $fetched < $maxPages && microtime(true) < $deadline) {
        $batch = [];
        while ($queue && count($batch) < $parallel && $fetched + count($batch) < $maxPages) {
            $item = array_shift($queue);
            if ($item[1] > $maxDepth) {
                continue;
            }
            $batch[] = $item;
        }
        if (!$batch) {
            break;
        }

        foreach ($fetchBatch($batch) as $page) {
            $fetched++;
            $url = $page['url'];
            $allUrls[$url] = $page['code'];

            if ($page['code'] === 0) {
                $errors[] = $url . ' — ' . ($page['error'] ?: 'connection failed');
                continue;
            }

            // Feed parsing
            if (str_contains($page['url'], 'robots.txt')) {
                foreach (preg_split('/\r\n|\n/', $page['body']) as $line) {
                    if (preg_match('/^(?:Dis)?allow:\s*\/?(\S*)/i', trim($line), $m) && $m[1] !== '') {
                        $robots[] = '/' . ltrim($m[1], '/');
                        if (stripos($line, 'Disallow') === 0) {
                            $disallow[] = trim($m[1], '/');
                        }
                    }
                    if (preg_match('/^Sitemap:\s*(\S+)/i', trim($line), $m)) {
                        $sitemaps[] = $m[1];
                    }
                }
                continue;
            }
            if (str_contains($page['url'], 'sitemap.xml')) {
                if (preg_match_all('/<loc>\s*([^<]+)\s*<\/loc>/i', $page['body'], $m)) {
                    foreach (array_slice($m[1], 0, 40) as $loc) {
                        $loc = html_entity_decode(trim($loc), ENT_QUOTES);
                        $sitemaps[] = $loc;
                        // Crawl a bounded sample of sitemap entries.
                        $locHost = strtolower((string)parse_url($loc, PHP_URL_HOST));
                        if ($locHost === $host && !isset($seen[$loc]) && count($queue) < $maxPages && !vs_is_unsafe_crawl_target($loc)) {
                            $seen[$loc] = true;
                            $queue[] = [$loc, 1];
                        }
                    }
                }
                continue;
            }

            $isHtml = stripos($page['type'], 'html') !== false
                || preg_match('/<html|<body|<form/i', substr($page['body'], 0, 4000));
            if (!$isHtml) {
                continue;
            }

            $parsed = vs_parse_html($page['final_url'], $page['body']);
            $page['title'] = $parsed['title'];
            $page['forms'] = $parsed['forms'];
            $page['comments'] = $parsed['comments'];
            $page['generator'] = $parsed['generator'];
            $page['headers_subset'] = $page['headers'];

            // Params from the page's own query string.
            $q = (string)parse_url($page['final_url'], PHP_URL_QUERY);
            if ($q !== '') {
                parse_str($q, $qv);
                if ($qv) {
                    $params[] = ['url' => $page['final_url'], 'method' => 'GET', 'names' => array_keys($qv)];
                }
            }
            foreach ($parsed['forms'] as $form) {
                $forms[] = $form;
                $names = array_map(fn($i) => $i['name'], $form['inputs']);
                if ($names) {
                    $params[] = ['url' => $form['action'], 'method' => $form['method'], 'names' => array_values(array_unique($names))];
                }
            }
            foreach ($parsed['links'] as $link) {
                $linkHost = strtolower((string)parse_url($link, PHP_URL_HOST));
                if ($linkHost === '' || $linkHost !== $host) {
                    continue;
                }
                $q = (string)parse_url($link, PHP_URL_QUERY);
                if ($q !== '') {
                    parse_str($q, $qv);
                    if ($qv) {
                        $params[] = ['url' => $link, 'method' => 'GET', 'names' => array_keys($qv)];
                    }
                }
                if (isset($seen[$link]) || vs_is_static_asset($link) || vs_is_unsafe_crawl_target($link)) {
                    continue;
                }
                if ($page['depth'] < $maxDepth) {
                    $seen[$link] = true;
                    $queue[] = [$link, $page['depth'] + 1];
                }
            }
            foreach ($parsed['scripts'] as $script) {
                $scripts[$script] = true;
            }

            // Trim stored body: only what the scanners need.
            $page['body'] = substr($page['body'], 0, 200000);
            $pages[] = $page;

            foreach (vs_detect_tech($page) as $t) {
                $tech[strtolower($t['name'])] = $t;
            }
        }
    }

    // JavaScript endpoint harvesting (AJAX-spider style, bounded).
    if (($opts['fetch_js'] ?? true) && microtime(true) < $deadline) {
        $jsList = array_slice(array_keys($scripts), 0, max(0, (int)($opts['max_js'] ?? 8)));
        foreach ($jsList as $jsUrl) {
            if (vs_is_static_asset($jsUrl) === false) {
                continue;
            }
            $js = vs_fetch_page($jsUrl, $cookie, 6000);
            if ($js['code'] === 200 && $js['body'] !== '') {
                foreach (vs_extract_js_endpoints($origin, $js['body'], $jsSeen) as $ep) {
                    $endpoints[$ep] = true;
                }
            }
        }
    }

    // Fold sitemap URLs into the discovered endpoint list.
    foreach ($sitemaps as $sm) {
        $smHost = strtolower((string)parse_url($sm, PHP_URL_HOST));
        if ($smHost === $host) {
            $allUrls[$sm] = $allUrls[$sm] ?? 0;
        }
    }

    // De-duplicate parameters by url+method, merging names.
    $paramMap = [];
    foreach ($params as $p) {
        $k = $p['method'] . ' ' . $p['url'];
        if (!isset($paramMap[$k])) {
            $paramMap[$k] = $p;
        } else {
            $paramMap[$k]['names'] = array_values(array_unique(array_merge($paramMap[$k]['names'], $p['names'])));
        }
    }

    return [
        'base_url'    => $origin,
        'pages'       => $pages,
        'urls'        => array_map(fn($u, $c) => ['url' => $u, 'status' => $c], array_keys($allUrls), array_values($allUrls)),
        'forms'       => $forms,
        'parameters'  => array_values($paramMap),
        'technologies'=> array_values($tech),
        'scripts'     => array_keys($scripts),
        'endpoints'   => array_keys($endpoints),
        'robots'      => array_values(array_unique($robots)),
        'sitemaps'    => array_values(array_unique($sitemaps)),
        'disallow'    => array_values(array_unique($disallow)),
        'errors'      => $errors,
        'stats'       => [
            'pages_fetched'  => count($pages),
            'urls_discovered'=> count($allUrls),
            'forms_found'    => count($forms),
            'parameters'     => count($paramMap),
            'technologies'   => count($tech),
            'duration_ms'    => (int)((microtime(true) - $started) * 1000),
        ],
    ];
}
