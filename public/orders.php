<?php
declare(strict_types=1);
require_once __DIR__ . '/../lib/bootstrap.php';
start();
$u = require_login();
$st = db()->prepare('SELECT o.id, p.name, o.qty, o.total, o.created FROM orders o JOIN products p ON p.id = o.product_id WHERE o.user_id = ? ORDER BY o.id');
$st->execute([$u['id']]);
head('Orders');
echo '<h1>Your orders</h1><table><tr><th>Order</th><th>Product</th><th>Qty</th><th>Total</th><th>Date</th></tr>';
foreach ($st as $o) {
    echo '<tr><td><a href="/order.php?id=' . (int) $o['id'] . '">#' . (int) $o['id'] . '</a></td><td>' . e($o['name']) . '</td><td>' . (int) $o['qty'] . '</td><td>€' . number_format((float) $o['total'], 2) . '</td><td>' . e($o['created']) . '</td></tr>';
}
echo '</table>';
foot();
