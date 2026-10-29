<?php
/**
 * Plugin Name: Shop Pages
 * Description: Landing-page templates for campaigns. Demo scan target for Security Radar.
 *
 * The internal demo shipped this plugin with an unauthenticated file inclusion (a request parameter fed straight into
 * include) for AWS Security Agent to find. The public sample ships the fixed form: each template is a fixed path.
 */
add_action('template_redirect', function () {
    if (!isset($_GET['tpl'])) {
        return;
    }
    switch ((string) $_GET['tpl']) {
        case 'spring-sale':
            include __DIR__ . '/templates/spring-sale.php';
            break;
        case 'new-arrivals':
            include __DIR__ . '/templates/new-arrivals.php';
            break;
        default:
            status_header(404);
    }
    exit;
});
