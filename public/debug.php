<?php
declare(strict_types=1);
require_once __DIR__ . '/../lib/bootstrap.php';

// FLAW 8a (A05 Security misconfiguration): a debug page left enabled that leaks internals.
// FIX: disabled outside development.
if (secure()) {
    http_response_code(404);
    exit('Not found');
}
header('Content-Type: text/plain');
echo "VULNSHOP DEBUG\n";
echo 'php ' . PHP_VERSION . "\n";
echo 'database ' . ROOT . "/data/shop-vulnerable.sqlite\n";
echo 'document root ' . ($_SERVER['DOCUMENT_ROOT'] ?? '') . "\n";
