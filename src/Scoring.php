<?php
/**
 * VulnScope Pro — scoring & status utilities.
 */
declare(strict_types=1);

function get_api_status() {
    return [
        'nvd'     => NVD_API_KEY      ? 'configured' : 'missing',
        'shodan'  => SHODAN_API_KEY   ? 'configured' : 'missing',
        'censys'  => CENSYS_API_TOKEN ? 'configured' : 'missing',
        'opencve' => (OPENCVE_USER && OPENCVE_PASS) ? 'configured' : 'missing',
    ];
}


function classify_severity($cvss) {
    $v = (float)$cvss;
    if ($v >= 9.0) return 'Critical';
    if ($v >= 7.0) return 'High';
    if ($v >= 4.0) return 'Medium';
    if ($v >  0.0) return 'Low';
    return 'Info';
}


/**
 * Advanced risk scoring — produces realistic varied scores.
 *
 * Algorithm:
 * 1. Base weighted score from severity buckets
 * 2. Attack surface multiplier (open ports count)
 * 3. Criticality bonus for cascading criticals
 * 4. Diversity penalty (many different severity levels = harder to patch)
 * 5. Final normalisation to 0-100 range with realistic distribution
 */
function calculate_risk_score(array $findings, int $open_ports_count = 0): int {
    if (empty($findings)) return 0;

    // Step 1: Weighted severity base
    $weights = ['Critical' => 12, 'High' => 7, 'Medium' => 3, 'Low' => 1, 'Info' => 0, 'Unknown' => 2];
    $counts  = ['Critical' => 0, 'High' => 0, 'Medium' => 0, 'Low' => 0, 'Info' => 0, 'Unknown' => 0];
    $cvss_sum = 0;
    foreach ($findings as $f) {
        $sev = $f['severity'] ?? 'Info';
        $counts[$sev] = ($counts[$sev] ?? 0) + 1;
        $cvss_sum += (float)($f['cvss'] ?? 0);
    }

    $base = 0;
    foreach ($counts as $sev => $cnt) {
        $base += ($weights[$sev] ?? 0) * $cnt;
    }

    // Step 2: Average CVSS contribution (max +20 pts)
    $avg_cvss   = count($findings) > 0 ? $cvss_sum / count($findings) : 0;
    $cvss_bonus = min(20, round($avg_cvss * 2.2));

    // Step 3: Attack surface multiplier — more open ports = wider exposure
    // 0-5 ports: 1.0x, 6-10: 1.15x, 11-20: 1.25x, 21+: 1.35x
    if ($open_ports_count <= 5)       $surface = 1.0;
    elseif ($open_ports_count <= 10)  $surface = 1.15;
    elseif ($open_ports_count <= 20)  $surface = 1.25;
    else                              $surface = 1.35;

    // Step 4: Criticality cascade bonus — multiple criticals amplify each other
    $crit_bonus = 0;
    if ($counts['Critical'] >= 3)     $crit_bonus = 15;
    elseif ($counts['Critical'] >= 1) $crit_bonus = 8;
    elseif ($counts['High'] >= 5)     $crit_bonus = 5;

    // Step 5: Diversity bonus (mix of severities = complex attack surface)
    $sev_types = count(array_filter($counts));
    $diversity = $sev_types >= 4 ? 5 : ($sev_types >= 3 ? 3 : 0);

    // Step 6: CISA KEV bonus — findings with confirmed real-world exploitation
    // are a materially bigger risk than CVSS alone captures.
    $kev_count = 0;
    foreach ($findings as $f) {
        if (!empty($f['is_kev'])) $kev_count++;
    }
    $kev_bonus = min(25, $kev_count * 9);

    // Combine
    $raw = ($base + $cvss_bonus + $crit_bonus + $diversity + $kev_bonus) * $surface;

    // Step 7: Normalise to 0–100 with a logarithmic curve so:
    // — small vulns (~5 findings) score 20–40
    // — medium (~20-30 findings) score 50–70
    // — large (50+ findings) score 75–95
    // — truly catastrophic (100+ criticals) score 95-100
    // Raw scores typically land 10–400+; map to 0-100
    $normalised = round(100 * (1 - exp(-$raw / 120)));

    // Hard floor/ceiling
    return (int) max(1, min(100, $normalised));
}

