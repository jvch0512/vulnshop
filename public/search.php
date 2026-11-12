<?php
declare(strict_types=1);
require_once __DIR__ . '/../lib/bootstrap.php';
start();
$q = (string) ($_GET['q'] ?? '');
head('Search');

// FLAW 1 (A03 Injection, SQL): the search term is concatenated into the query.
// FIX: prepared statement with a bound parameter.
if (secure()) {
    $st = db()->prepare('SELECT id, name, description, price, stock FROM products WHERE name LIKE ?');
    $st->execute(['%' . $q . '%']);
    $rows = $st->fetchAll();
} else {
    $rows = db()->query("SELECT id, name, description, price, stock FROM products WHERE name LIKE '%$q%'")->fetchAll();
}

// FLAW 2 (A03 Injection, reflected XSS): the search term is echoed without escaping.
// FIX: HTML-escape on output.
echo '<h1>Results for "' . out($q) . '"</h1>';
if (!$rows) {
    echo '<p>No products found.</p>';
}
echo '<div class="grid">';
foreach ($rows as $p) {
    echo '<div class="card"><h3><a href="/product.php?id=' . (int) $p['id'] . '">' . e((string) $p['name']) . '</a></h3><p>' . e((string) $p['description']) . '</p><div class="price">' . e((string) $p['price']) . '</div></div>';
}
echo '</div>';
foot();
