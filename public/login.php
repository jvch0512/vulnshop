<?php
declare(strict_types=1);
require_once __DIR__ . '/../lib/bootstrap.php';
start();
$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $st = db()->prepare('SELECT id, password FROM users WHERE username = ?');
    $st->execute([(string) ($_POST['username'] ?? '')]);
    $row = $st->fetch();
    if ($row && check_password((string) ($_POST['password'] ?? ''), $row['password'])) {
        session_regenerate_id(true);
        $_SESSION['uid'] = (int) $row['id'];
        header('Location: /');
        exit;
    }
    $error = 'Invalid username or password.';
}
head('Log in');
echo '<h1>Log in</h1>';
if ($error) {
    echo '<div class="msg err">' . e($error) . '</div>';
}
echo '<form class="stack" method="post"><input name="username" placeholder="Username" autocomplete="username"><input name="password" type="password" placeholder="Password" autocomplete="current-password"><button>Log in</button></form>';
foot();
