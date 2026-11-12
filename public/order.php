<?php
declare(strict_types=1);
require_once __DIR__ . '/../lib/bootstrap.php';
start();
$u = require_login();
$id = (int) ($_GET['id'] ?? 0);

// FLAW 4 (A01 Broken access control, IDOR): any logged-in user can read any order by id.
// FIX: scope the query to the owner.
$sql = 'SELECT o.id, o.qty, o.total, o.created, p.name, u.username FROM orders o JOIN products p ON p.id = o.product_id JOIN users u ON u.id = o.user_id WHERE o.id = ?';
$args = [$id];
if (secure()) {
    $sql .= ' AND o.user_id = ?';
    $args[] = $u['id'];
}
$st = db()->prepare($sql);
$st->execute($args);
$o = $st->fetch();
if (!$o) {
    http_response_code(404);
    head('Not found');
    echo '<h1>Order not found</h1>';
    foot();
    exit;
}
head('Order #' . $o['id']);
echo '<h1>Order #' . (int) $o['id'] . '</h1><p>Customer: ' . e($o['username']) . '</p><p>' . e($o['name']) . ' x ' . (int) $o['qty'] . ', total €' . number_format((float) $o['total'], 2) . ' on ' . e($o['created']) . '</p>';
echo '<p><a href="/download.php?file=invoice-' . (int) $o['id'] . '.txt">Download invoice</a></p>';
foot();
