<?php
require_once __DIR__ . '/../../lib/bootstrap.php';
header('Content-Type: application/json');
$rows = db()->query("SELECT id, customer, total FROM orders WHERE id = " . $_GET['id'])->fetchAll(PDO::FETCH_ASSOC);
echo json_encode($rows);
