<?php
declare(strict_types=1);
require_once __DIR__ . '/../lib/bootstrap.php';
start();
$url = (string) ($_GET['url'] ?? '/');

// FLAW 7 (A01 Broken access control, open redirect): any URL is accepted, so the shop's domain
// can be used to make phishing links look trustworthy.
// FIX: only local paths. Reject protocol-relative URLs, backslashes and control characters.
if (secure()) {
    $local = str_starts_with($url, '/') && !str_starts_with($url, '//') && !str_contains($url, '\\') && !preg_match('/[\x00-\x1f]/', $url);
    if (!$local) {
        $url = '/';
    }
}
header('Location: ' . $url);
