<?php
// demo storefront (intentionally on an affected PHP 8.3 release)
$q = $_GET['q'] ?? '';
echo '<h1>Search: ' . htmlspecialchars($q) . '</h1>';
