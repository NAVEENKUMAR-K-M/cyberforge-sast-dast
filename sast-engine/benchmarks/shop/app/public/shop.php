<?php
require_once __DIR__ . '/../lib/bootstrap.php';
$action = $_GET['action'] ?? 'home';
switch ($action) {
    case 'view':
        $pid = $_GET['pid'];
        foreach (run_query("SELECT name, price FROM products WHERE id = $pid") as $row) {
            echo htmlspecialchars($row['name']);
        }
        break;
    case 'track':
        $code = $_GET['code'];
        foreach (run_query("SELECT customer, total FROM orders WHERE code = '$code'") as $row) {
            echo (float) $row['total'];
        }
        break;
    default:
        echo 'Welcome';
}
