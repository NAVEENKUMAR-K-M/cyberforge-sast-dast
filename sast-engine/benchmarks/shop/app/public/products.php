<?php
require_once __DIR__ . '/../lib/bootstrap.php';
$columns = ['name' => 'name', 'price' => 'price'];
$sort = $columns[$_GET['sort'] ?? 'name'] ?? 'name';
foreach (run_query("SELECT id, name FROM products ORDER BY " . $sort) as $row) {
    echo '<li><a href="product.php?id=' . (int) $row['id'] . '">' . htmlspecialchars($row['name']) . '</a></li>';
}
