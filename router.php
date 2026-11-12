<?php
declare(strict_types=1);
require_once __DIR__ . '/lib/bootstrap.php';

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';

if ($path === '/backup/shop.sqlite.bak') {
    // FLAW (A05 Security misconfiguration): a database backup left in the web root.
    // FIX: it simply does not exist in secure mode.
    if (secure() || !file_exists(ROOT . '/data/shop-vulnerable.sqlite')) {
        http_response_code(404);
        echo 'Not found';
        return true;
    }
    db();
    header('Content-Type: application/octet-stream');
    readfile(ROOT . '/data/shop-vulnerable.sqlite');
    return true;
}

return false; // let the built-in server handle public/ files and PHP scripts
