<?php
/**
 * VulnScope Pro — Local exploit hazard engine (Shaffer & Voicu model).
 *
 * Faithful port of Vulnerability-Lookup's local exploit hazard model
 * (arXiv:2607.24618, §3 'Exploit hazard'):
 *
 *   1. ELM probability (EPSS) is the likelihood of exploitation in the
 *      next `elm_horizon_days` (default 30).
 *   2. KEV policy adjustment: on confirmed exploitation the likelihood is
 *      raised with a multiplicative `kev_weight` and floored at `kev_floor`.
 *   3. Compensating controls: every control effectiveness `ce` multiplies
 *      the likelihood by (1 - ce); per-attack-vector control sets are
 *      supported (network controls do not reduce local attacks).
 *   4. Daily hazard rate:
 *        exponential:  h = -ln(1 - p) / elm_horizon_days
 *        weibull:      shape k = 0.605 (KEV-calibrated from the paper),
 *                      scale chosen so the CDF matches ELM at the horizon,
 *                      evaluated starting at the advisory's current age
 *                      (conditional probability over [age, age+horizon]).
 *   5. Horizon probability: P(1..T) = 1 - exp(-h * T).
 *
 * Batch output mirrors VL's /api/exploit-hazard/batch:
 *   aggregate_daily_hazard, expected_events, probability_at_least_one_event.
 *
 * Pure deterministic math — no storage, no network (EPSS can be supplied
 * or resolved per record; see vs_exploit_hazard_batch).
 */
declare(strict_types=1);

const VS_ATTACK_VECTORS = ['network', 'adjacent', 'local', 'physical'];

/** Default per-vector control effectiveness tiers (operator-tunable). */
function vs_hazard_default_controls(): array
{
    return [
        'network'      => 0.35,
        'adjacent'     => 0.45,
        'local'        => 0.60,
        'physical'     => 0.80,
    ];
}

/** Weibull shape from the paper's KEV calibration. */
function vs_hazard_default_shape(): float
{
    return 0.605;
}

/** Default KEV policy parameters. */
function vs_hazard_default_kev(): array
{
    return ['weight' => 2.0, 'floor' => 0.5];
}

/** Attack vector from a CVSS vector string (AV:N/A:L/P/L). */
function vs_hazard_attack_vector(string $vector, string $fallback = 'network'): string
{
    if (preg_match('/AV:([NALP])/', strtoupper($vector), $m)) {
        return match ($m[1]) {
            'N' => 'network',
            'A' => 'adjacent',
            'L' => 'local',
            'P' => 'physical',
        };
    }
    return in_array($fallback, VS_ATTACK_VECTORS, true) ? $fallback : 'network';
}

/**
 * Core hazard computation for one instance.
 * Mirrors VL's input schema (subset) and output to_dict().
 *
 * Accepted keys: vulnerability_id, epss, cvss / vector, attack_vector,
 * controls, controls_by_attack_vector, kev, kev_weight, kev_floor,
 * model ('exponential'|'weibull'), weibull_shape, elm_horizon_days,
 * horizon_days, published, age_days.
 */
function vs_exploit_hazard(array $in): array
{
    $defaults = [
        'elm_horizon_days' => 30,
        'horizon_days'     => 30,
        'model'            => 'exponential',
        'kev'              => null,
        'kev_weight'       => null,
        'kev_floor'        => null,
        'weibull_shape'    => vs_hazard_default_shape(),
        'attack_vector'    => null,
        'vector'           => null,
        'published'        => null,
        'age_days'         => null,
        'cvss'             => null,
    ];
    $p = array_merge($defaults, array_filter($in, static fn($v) => $v !== null));

    // ---- Resolve EPSS if the instance didn't carry one -------------------
    $epss = (float)($p['epss'] ?? 0.0);
    if ($epss <= 0.0) {
        $id = strtoupper((string)($p['vulnerability_id'] ?? ''));
        if (preg_match('/^CVE-\d{4}-\d+$/', $id)) {
            try {
                $map = query_epss([$id]);
                if (isset($map[$id]['score'])) {
                    $epss = (float)$map[$id]['score'];
                }
            } catch (Throwable $e) { /* offline: hazard lowers gracefully */ }
        }
    }
    $epss = min(1.0, max(0.0, $epss));

    // ---- Attack vector / KEV determination --------------------------------
    $vector    = (string)($p['vector'] ?? $p['cvss_vector'] ?? '');
    $attackVector = $p['attack_vector'] ?: vs_hazard_attack_vector($vector);
    $isKev = (bool)($p['kev'] ?? false);
    if (!isset($in['kev']) && !empty($p['is_kev'])) {
        $isKev = true;
    }

    // ---- CVSS severity for impact-side display ----------------------------
    $cvss = (float)($p['cvss'] ?? 0.0);

    // ---- Step 2: KEV policy ------------------------------------------------
    $likelihood = $epss;
    $kevApplied = false;
    if ($isKev) {
        $kWeight = (float)($p['kev_weight'] ?? vs_hazard_default_kev()['weight']);
        $kFloor  = (float)($p['kev_floor'] ?? vs_hazard_default_kev()['floor']);
        $kWeight = max(0.0, min(10.0, $kWeight));
        $kFloor  = min(1.0, max(0.0, $kFloor));
        $likelihood = max($likelihood * $kWeight, $kFloor);
        $likelihood = min(0.999, $likelihood);
        $kevApplied = true;
    }

    // ---- Step 3: compensating controls --------------------------------------
    $controlsByVector = $p['controls_by_attack_vector'] ?? [];
    $globalControls   = $p['controls'] ?? [];
    if (is_numeric($globalControls)) {
        $globalControls = [(float)$globalControls];
    }
    $vectorControls = $controlsByVector[$attackVector] ?? [];
    if (is_numeric($vectorControls)) {
        $vectorControls = [(float)$vectorControls];
    }
    $controlNote = [];
    foreach (array_merge((array)$globalControls, (array)$vectorControls) as $ce) {
        $ce = min(1.0, max(0.0, (float)$ce));
        $likelihood *= (1.0 - $ce);
        $likelihood = max(0.0, min(0.999, $likelihood));
        $controlNote[] = $ce;
    }
    $adjustedLikelihood = $likelihood;

    // ---- Age (Weibull needs it; informational for exponential) --------------
    $ageDays = (int)($p['age_days'] ?? 0);
    if (!$ageDays && !empty($p['published'])) {
        $ts = strtotime(substr((string)$p['published'], 0, 10));
        if ($ts) {
            $ageDays = max(0, (int)floor((time() - $ts) / 86400));
        }
    }

    // ---- Step 4: daily hazard rate ------------------------------------------
    $elmHorizon = max(1, min(36600, (int)$p['elm_horizon_days']));
    $horizon    = max(1, min(36600, (int)$p['horizon_days']));
    $model      = ($p['model'] === 'weibull') && ($ageDays >= 0) ? 'weibull' : 'exponential';

    if ($model === 'exponential') {
        $daily = $likelihood >= 1.0 ? INF : -log(max(1e-9, 1.0 - $likelihood)) / $elmHorizon;
        $horizonProb = $daily <= 0 ? 0.0 : 1.0 - exp(-$daily * $horizon);
        $shape = $scale = null;
    } else {
        $shape = max(0.1, min(5.0, (float)$p['weibull_shape']));
        // scale s.t. CDF(elmHorizon) == likelihood:
        //   weibull CDF:  1 - exp(-(x/s)^k) = L  ->  s = x / (-ln(1-L))^(1/k)
        $oneMinus = max(1e-9, 1.0 - min(0.999999, $likelihood));
        $scale = $elmHorizon / pow(-log($oneMinus), 1.0 / $shape);
        // conditional over [age, age + horizon]:
        $cdf = static function (float $x) use ($shape, $scale): float {
            return 1.0 - exp(-pow(max($x, 0.0) / $scale, $shape));
        };
        $a = (float)$ageDays;
        $cdfAfter    = 1.0 - $cdf($a);
        $cdfAfterFull= 1.0 - $cdf($a + $horizon);
        $horizonProb = $cdfAfterFull <= 1e-12 ? 0.0 : ($cdfAfterFull - $cdf($a)) / max($cdfAfter, 1e-12);
        $horizonProb = min(1.0, max(0.0, $horizonProb));
        // average daily hazard over the horizon window
        $daily = $horizonProb <= 0 ? 0.0 : -log(max(1e-9, 1.0 - $horizonProb)) / $horizon;
    }

    $horizonProb = min(1.0, max(0.0, $horizonProb));
    $score = (int)round($horizonProb * 100);

    $band = $score >= 80 ? 'critical' : ($score >= 60 ? 'high' : ($score >= 35 ? 'elevated' : ($score >= 15 ? 'moderate' : 'low')));

    // ---- "Which control helps most" ranking ---------------------------------
    $reduction = [];
    foreach (vs_hazard_default_controls() as $vec => $defaultCe) {
        if ($vec === $attackVector) continue;
        // simulate adding this vector-level control to the current instance
        $alt = $likelihood * (1.0 - $defaultCe);
        $altH = $model === 'exponential'
            ? 1.0 - exp(-(-log(max(1e-9, 1.0 - $alt)) / $elmHorizon) * $horizon)
            : null;
        $reduction[$vec] = $altH !== null ? round(max(0.0, $horizonProb - $altH) * 100, 1) : null;
    }
    arsort($reduction);
    $best = array_key_first($reduction);

    return [
        'vulnerability_id'   => strtoupper((string)($p['vulnerability_id'] ?? '')),
        'attack_vector'      => $attackVector,
        'epss'               => $epss,
        'kev'                => $kevApplied,
        'cvss'               => $cvss,
        'adjusted_likelihood'=> round($adjustedLikelihood, 8),
        'daily_hazard'       => is_infinite($daily) ? null : round($daily, 10),
        'horizon_days'       => $horizon,
        'model'              => $model,
        'age_days'           => $ageDays,
        'weibull_shape'      => $shape,
        'weibull_scale'      => $scale !== null ? round($scale, 2) : null,
        'horizon_probability'=> round($horizonProb, 8),
        'score'              => $score,
        'band'               => $band,
        'controls_applied'   => $controlNote,
        'best_control'       => $best,
        'best_reduction'     => $reduction[$best] ?? 0,
        'reduction_table'    => $reduction,
        'source'             => 'VulnScope-Pro local model',
    ];
}

/**
 * Batch hazard — VL parity for /api/exploit-hazard/batch.
 * `$records` may be arrays or plain CVE strings. Resolves EPSS + KEV for
 * everything first so N instances cost ≤2 upstream calls.
 */
function vs_exploit_hazard_batch(array $records, array $parameters = [], int $horizonDays = 30): array
{
    $ids = [];
    foreach ($records as $i => &$r) {
        if (is_string($r)) {
            $r = ['vulnerability_id' => $r];
        }
        if (!is_array($r)) {
            unset($records[$i]);
            continue;
        }
        $id = strtoupper((string)($r['vulnerability_id'] ?? $r['id'] ?? ''));
        if (preg_match('/^(CVE|GHSA|GCVE)-[A-Z0-9-]+$/', $id)) {
            $ids[$id] = true;
            $r['vulnerability_id'] = $id;
        }
    }
    unset($r);

    // Shared EPSS + KEV prefetch.
    $epssMap = $kevMap = [];
    try {
        if ($ids) {
            $cveIds = array_values(array_filter(array_keys($ids), static fn($v) => str_starts_with($v, 'CVE-')));
            if ($cveIds) {
                $epssMap = query_epss($cveIds);
            }
        }
    } catch (Throwable $e) {
    }
    try {
        $kevMap = query_kev();
    } catch (Throwable $e) {
    }

    $results = $skipped = 0;
    $out = [];
    foreach ($records as $r) {
        $id = (string)($r['vulnerability_id'] ?? '');
        if ($id === '') {
            $skipped++;
            $out[] = ['error' => 'no vulnerability id'];
            continue;
        }
        if (!isset($r['epss']) && isset($epssMap[$id]['score'])) {
            $r['epss'] = $epssMap[$id]['score'];
        }
        if (!isset($r['kev']) && isset($kevMap[$id])) {
            $r['kev'] = true;
            $r['kev_date_added'] = $kevMap[$id]['dateAdded'] ?? '';
        }
        // merge shared parameters (per-instance wins)
        $r = array_merge($parameters, $r, ['horizon_days' => $r['horizon_days'] ?? $horizonDays]);
        $out[] = vs_exploit_hazard($r);
        $results++;
    }

    // Batch aggregate (independence assumption — upper-bound trend only).
    $aggDaily = 0.0;
    foreach ($out as $r) {
        if (!empty($r['daily_hazard'])) {
            $aggDaily += (float)$r['daily_hazard'];
        }
    }
    $expected = $aggDaily * $horizonDays;
    $atLeastOne = $aggDaily > 0 ? 1.0 - exp(-$expected) : 0.0;

    usort($out, static fn($a, $b) => ($b['score'] ?? 0) <=> ($a['score'] ?? 0));

    return [
        'instances'                   => $out,
        'aggregate_daily_hazard'      => round($aggDaily, 10),
        'horizon_days'                => $horizonDays,
        'expected_events'             => round($expected, 6),
        'probability_at_least_one_event' => round($atLeastOne, 8),
        'computed'                    => $results,
        'skipped'                     => $skipped,
        'source'                      => 'VulnScope-Pro local model',
    ];
}

/** Enrich deep-scan findings with hazard (post vl_enrich_findings). */
function vs_hazard_enrich_findings(array $findings, string $controlPreset = 'network'): array
{
    $records = [];
    foreach ($findings as $f) {
        $id = strtoupper((string)($f['id'] ?? ''));
        if (!str_starts_with($id, 'CVE-')) continue;
        $records[] = [
            'vulnerability_id' => $id,
            'epss'   => $f['epss_score'] ?? null,
            'kev'    => !empty($f['is_kev']),
            'cvss'   => $f['cvss'] ?? 0,
            'vector' => $f['vector'] ?? '',
            'published' => $f['published'] ?? null,
            'controls' => [vs_hazard_default_controls()[$controlPreset] ?? 0.35],
        ];
    }
    if (!$records) {
        return $findings;
    }
    $batch = vs_exploit_hazard_batch($records);
    // Map hazard back onto the findings by id.
    $mapped = [];
    foreach ($batch['instances'] as $r) {
        if (empty($r['error'])) {
            $mapped[$r['vulnerability_id']] = $r;
        }
    }
    $out = [];
    foreach ($findings as $f) {
        $id = strtoupper((string)($f['id'] ?? ''));
        if (isset($mapped[$id])) {
            $f['hazard'] = $mapped[$id];
        }
        $out[] = $f;
    }
    return $out;
}
