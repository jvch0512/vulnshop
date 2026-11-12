<?php
declare(strict_types=1);
require_once __DIR__ . '/../lib/bootstrap.php';
start();
$id = (int) ($_GET['id'] ?? 0);
$st = db()->prepare('SELECT * FROM products WHERE id = ?');
$st->execute([$id]);
$p = $st->fetch();
if (!$p) {
    http_response_code(404);
    head('Not found');
    echo '<h1>Product not found</h1>';
    foot();
    exit;
}
$u = current_user();
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $u) {
    if (secure() && !hash_equals(csrf_token(), (string) ($_POST['csrf'] ?? ''))) {
        http_response_code(403);
        exit('Invalid CSRF token');
    }
    $body = mb_substr((string) ($_POST['body'] ?? ''), 0, 500);
    if ($body !== '') {
        db()->prepare('INSERT INTO reviews(product_id, author, body, created) VALUES(?,?,?,?)')->execute([$id, $u['username'], $body, date('Y-m-d')]);
    }
    header('Location: /product.php?id=' . $id);
    exit;
}
head($p['name']);
echo '<h1>' . e($p['name']) . '</h1><p>' . e($p['description']) . '</p><p class="price">€' . number_format((float) $p['price'], 2) . '</p><h2>Reviews</h2>';
$rv = db()->prepare('SELECT author, body, created FROM reviews WHERE product_id = ? ORDER BY id');
$rv->execute([$id]);
foreach ($rv as $r) {
    // FLAW 3 (A03 Injection, stored XSS): review text is stored and rendered without escaping.
    // FIX: HTML-escape on output.
    echo '<div class="review"><b>' . e($r['author']) . '</b> <small>' . e($r['created']) . '</small><p>' . out((string) $r['body']) . '</p></div>';
}
if ($u) {
    echo '<form class="stack" method="post"><textarea name="body" rows="3" placeholder="Write a review"></textarea>';
    if (secure()) {
        echo '<input type="hidden" name="csrf" value="' . e(csrf_token()) . '">';
    }
    echo '<button>Post review</button></form>';
} else {
    echo '<p><a href="/login.php">Log in</a> to write a review.</p>';
}
foot();
