<?php
/**
 * Plugin Name: Shop Pages
 * Description: Landing-page templates for campaigns. DELIBERATELY VULNERABLE DEMO TARGET for Security Radar.
 */
add_action('template_redirect', function () {
    if (isset($_GET['tpl'])) {
        // campaign template chosen by the marketing link
        include $_GET['tpl'] . '.php';
        exit;
    }
});
