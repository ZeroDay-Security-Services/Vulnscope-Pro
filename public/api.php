<?php
/**
 * VulnScope Pro — standalone JSON API entry point.
 * Thin wrapper: all routing logic lives in api_router.php so that
 * public/index.php can share it (single-URL behavior preserved).
 */
require_once __DIR__ . '/../bootstrap.php';
require __DIR__ . '/api_router.php';
