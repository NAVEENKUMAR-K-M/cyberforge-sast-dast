<?php
$allowed = ['/index.php', '/products.php'];
$to = $_GET['to'] ?? '/index.php';
if (!in_array($to, $allowed, true)) {
    $to = '/index.php';
}
header('Location: ' . $to);
