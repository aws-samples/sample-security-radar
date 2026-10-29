<?php
/**
 * Plugin Name: Shop Pages
 * Description: Landing-page templates for campaigns. Demo scan target for Security Radar.
 *
 * The internal demo shipped this plugin with an unauthenticated file inclusion (include $_GET['tpl']) for AWS Security
 * Agent to find. The public sample ships the fixed form instead: templates are an allowlist inside this directory.
 */
add_action('template_redirect', function () {
    if (!isset($_GET['tpl'])) {
        return;
    }
    $tpl = preg_replace('/[^a-z0-9-]/', '', strtolower((string) $_GET['tpl']));
    $file = __DIR__ . '/templates/' . $tpl . '.php';
    if ($tpl === '' || !is_file($file)) {
        status_header(404);
        exit;
    }
    include $file;
    exit;
});
