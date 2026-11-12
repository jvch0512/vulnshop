<?php
declare(strict_types=1);
require_once __DIR__ . '/../lib/bootstrap.php';
start();
$u = require_login();
$msg = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // FLAW 5 (A01 Broken access control, CSRF): state change with no anti-CSRF token and a
    // session cookie that is sent on cross-site requests.
    // FIX: per-session token checked here, and SameSite=Lax on the cookie.
    if (secure() && !hash_equals(csrf_token(), (string) ($_POST['csrf'] ?? ''))) {
        http_response_code(403);
        exit('Invalid CSRF token');
    }
    $email = trim((string) ($_POST['email'] ?? ''));
    if (filter_var($email, FILTER_VALIDATE_EMAIL)) {
        db()->prepare('UPDATE users SET email = ? WHERE id = ?')->execute([$email, $u['id']]);
        $u['email'] = $email;
        $msg = 'Email updated.';
    } else {
        $msg = 'Please enter a valid email address.';
    }
}
head('Profile');
echo '<h1>Your profile</h1>';
if ($msg) {
    echo '<div class="msg">' . e($msg) . '</div>';
}
echo '<form class="stack" method="post"><label>Email<input name="email" value="' . e($u['email']) . '"></label>';
if (secure()) {
    echo '<input type="hidden" name="csrf" value="' . e(csrf_token()) . '">';
}
echo '<button>Update email</button></form>';
foot();
