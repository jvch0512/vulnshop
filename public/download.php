<?php
declare(strict_types=1);
require_once __DIR__ . '/../lib/bootstrap.php';
start();
$u = require_login();
$file = (string) ($_GET['file'] ?? '');
$dir = ROOT . '/data/invoices';

// FLAW 6 (A01 Broken access control, path traversal): the file name is appended to the directory.
// FIX: strict allowlist pattern, then confirm the resolved path stays inside the directory.
if (secure()) {
    if (!preg_match('/^invoice-\d+\.txt$/', $file)) {
        http_response_code(400);
        exit('Bad file name');
    }
    $real = realpath($dir . '/' . $file);
    if ($real === false || !str_starts_with($real, realpath($dir) . DIRECTORY_SEPARATOR)) {
        http_response_code(404);
        exit('Not found');
    }
    $path = $real;
} else {
    $path = $dir . '/' . $file;
}
if (!is_file($path)) {
    http_response_code(404);
    exit('Not found');
}
header('Content-Type: text/plain; charset=utf-8');
header('Content-Disposition: attachment; filename="' . basename($path) . '"');
readfile($path);
