<?php
declare(strict_types=1);

/*
 * VulnShop: a deliberately vulnerable shop for security training.
 * NEVER deploy the vulnerable mode anywhere reachable by other people.
 *
 * VULNSHOP_MODE=secure switches every flaw to its fixed implementation. The code for the
 * vulnerable and the fixed behaviour sits side by side in each page so they can be diffed.
 */

define('ROOT', dirname(__DIR__));

function secure(): bool
{
    return getenv('VULNSHOP_MODE') === 'secure';
}

/** Escape for HTML. Used everywhere except the places that are flawed on purpose. */
function e(string $s): string
{
    return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/** FLAW helper: raw output in vulnerable mode, escaped in secure mode. */
function out(string $s): string
{
    return secure() ? e($s) : $s;
}

function db(): PDO
{
    static $pdo = null;
    if ($pdo !== null) {
        return $pdo;
    }
    $file = ROOT . '/data/shop-' . (secure() ? 'secure' : 'vulnerable') . '.sqlite';
    $fresh = !file_exists($file);
    $pdo = new PDO('sqlite:' . $file);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
    if ($fresh) {
        seed($pdo);
    }
    return $pdo;
}

function hash_password(string $pw): string
{
    // FLAW (A02 Cryptographic failures): unsalted MD5. FIX: bcrypt/argon2 via password_hash.
    return secure() ? password_hash($pw, PASSWORD_DEFAULT) : md5($pw);
}

function check_password(string $pw, string $stored): bool
{
    return secure() ? password_verify($pw, $stored) : hash_equals($stored, md5($pw));
}

function seed(PDO $pdo): void
{
    $pdo->exec(<<<SQL
CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, email TEXT, role TEXT);
CREATE TABLE products(id INTEGER PRIMARY KEY, name TEXT, description TEXT, price REAL, stock INTEGER);
CREATE TABLE reviews(id INTEGER PRIMARY KEY, product_id INTEGER, author TEXT, body TEXT, created TEXT);
CREATE TABLE orders(id INTEGER PRIMARY KEY, user_id INTEGER, product_id INTEGER, qty INTEGER, total REAL, created TEXT);
SQL);
    $u = $pdo->prepare('INSERT INTO users(username,password,email,role) VALUES(?,?,?,?)');
    foreach ([['admin', 'Adm1n#2026', 'admin@vulnshop.test', 'admin'], ['alice', 'alice123', 'alice@vulnshop.test', 'user'], ['bob', 'bob12345', 'bob@vulnshop.test', 'user']] as $r) {
        $u->execute([$r[0], hash_password($r[1]), $r[2], $r[3]]);
    }
    $p = $pdo->prepare('INSERT INTO products(name,description,price,stock) VALUES(?,?,?,?)');
    foreach ([
        ['Mechanical keyboard', 'Tactile switches, hot-swappable, USB-C.', 89.90, 14],
        ['USB security key', 'FIDO2 hardware token for phishing-resistant login.', 29.00, 60],
        ['Webcam cover (3 pack)', 'Slim slide covers. Low-tech, effective.', 4.50, 300],
        ['Network tap', 'Passive gigabit tap for lab captures.', 119.00, 6],
        ['Raspberry Pi 5 kit', 'Board, case, PSU and a 64 GB card.', 109.00, 22],
        ['Lock pick set', 'Practice set for the lock sport hobby.', 24.90, 40],
    ] as $r) {
        $p->execute($r);
    }
    $o = $pdo->prepare('INSERT INTO orders(user_id,product_id,qty,total,created) VALUES(?,?,?,?,?)');
    foreach ([[2, 2, 1, 29.00], [2, 3, 3, 13.50], [1, 4, 1, 119.00], [3, 1, 1, 89.90]] as $i => $r) {
        $o->execute([$r[0], $r[1], $r[2], $r[3], '2026-0' . ($i + 1) . '-10']);
    }
    $pdo->prepare('INSERT INTO reviews(product_id,author,body,created) VALUES(2,?,?,?)')->execute(['bob', 'Works great with my laptop.', '2026-02-01']);
}

function start(): void
{
    session_name('vsid');
    if (secure()) {
        session_set_cookie_params(['httponly' => true, 'samesite' => 'Lax', 'path' => '/']);
        header('X-Frame-Options: DENY');
        header('X-Content-Type-Options: nosniff');
        header("Content-Security-Policy: default-src 'self'; style-src 'self'; frame-ancestors 'none'; form-action 'self'");
        header('Referrer-Policy: same-origin');
        ini_set('display_errors', '0');
    } else {
        ini_set('display_errors', '1'); // FLAW (A05): verbose errors leak queries and paths
    }
    session_start();
    set_exception_handler(function (Throwable $t): void {
        http_response_code(500);
        if (secure()) {
            error_log((string) $t);
            echo 'Something went wrong.';
        } else {
            echo '<pre>' . htmlspecialchars((string) $t) . '</pre>';
        }
    });
}

function current_user(): ?array
{
    if (empty($_SESSION['uid'])) {
        return null;
    }
    $s = db()->prepare('SELECT id, username, email, role FROM users WHERE id = ?');
    $s->execute([$_SESSION['uid']]);
    return $s->fetch() ?: null;
}

function require_login(): array
{
    $u = current_user();
    if (!$u) {
        header('Location: /login.php');
        exit;
    }
    return $u;
}

function csrf_token(): string
{
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf'];
}

function head(string $title): void
{
    $u = current_user();
    echo '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">';
    echo '<title>' . e($title) . ' | VulnShop</title><link rel="stylesheet" href="/style.css"></head><body>';
    echo '<div class="banner ' . (secure() ? 'ok' : 'bad') . '">' . (secure() ? 'SECURE MODE: every flaw is fixed' : 'VULNERABLE MODE: training only, keep it on localhost') . '</div>';
    echo '<header><a class="logo" href="/">VulnShop</a><form action="/search.php" method="get"><input name="q" placeholder="Search products"><button>Search</button></form><nav>';
    if ($u) {
        echo '<a href="/orders.php">Orders</a><a href="/profile.php">' . e($u['username']) . '</a><a href="/logout.php">Log out</a>';
    } else {
        echo '<a href="/login.php">Log in</a>';
    }
    echo '</nav></header><main>';
}

function foot(): void
{
    echo '</main><footer>Deliberately vulnerable training app. Built with AI assistance.</footer></body></html>';
}
