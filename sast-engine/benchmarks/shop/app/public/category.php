<?php
require_once __DIR__ . '/../lib/bootstrap.php';
$id = (int) $_GET['id'];
foreach (run_query("SELECT name FROM products WHERE category = " . $id) as $row) {
    echo htmlspecialchars($row['name']) . "<br>";
}
