<?php
declare(strict_types=1);
require_once __DIR__ . '/../lib/bootstrap.php';
start();
head('Shop');
echo '<h1>Security gear</h1><div class="grid">';
foreach (db()->query('SELECT id, name, description, price FROM products ORDER BY id') as $p) {
    echo '<div class="card"><h3><a href="/product.php?id=' . (int) $p['id'] . '">' . e($p['name']) . '</a></h3><p>' . e($p['description']) . '</p><div class="price">€' . number_format((float) $p['price'], 2) . '</div></div>';
}
echo '</div>';
foot();
