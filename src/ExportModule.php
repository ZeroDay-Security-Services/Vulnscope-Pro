<?php
/**
 * VulnScope Pro — Module 4: normalized JSON export layer.
 */
declare(strict_types=1);


/**
 * MODULE 4 — UI/Frontend API Export Layer.
 * Normalizes all module output into the report envelope the frontend consumes.
 */
function vs_module4_export(array $module1, array $module2, array $module3, string $host, string $ip, int $risk): array {
    $findings = [];
    $cvss_map = ['Critical' => 9.3, 'High' => 7.5, 'Medium' => 5.4, 'Low' => 3.1];
    foreach ($module3['vulnerabilities'] ?? [] as $v) {
        if (!($v['vulnerable'] ?? false)) { continue; }
        $sev = $v['severity'] ?? 'High';
        $findings[] = [
            'id'          => 'VSP-' . strtoupper(substr(md5(($v['url'] ?? '') . ($v['payload'] ?? '') . ($v['type'] ?? '')), 0, 8)),
            'cvss'        => $cvss_map[$sev] ?? 7.5,
            'severity'    => $sev,
            'summary'     => trim(($v['label'] ?? ucfirst($v['type'] ?? 'Injection')) . ': ' . ($v['evidence'] ?? 'confirmed by active payload test')),
            'source'      => 'Module 3 Payload Scanner',
            'vector'      => '',
            'cwe'         => $v['cwe'] ?? '',
            'published'   => '',
            'port'        => '',
            'affected_service' => $v['url'] ?? '',
        ];
    }
    return [
        'success'  => true,
        'modules'  => ['recon' => $module1, 'fuzz' => $module2, 'payloads' => $module3],
        'findings' => $findings,
        'summary'  => ['target' => $host, 'ip' => $ip, 'risk_score' => $risk],
        'exported_at' => date('c'),
    ];
}

