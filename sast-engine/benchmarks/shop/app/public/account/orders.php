<?php
require_once __DIR__ . '/../../lib/bootstrap.php';
$sort = addslashes(input('sort', 'id'));
$rows = run_query("SELECT id, total FROM orders ORDER BY " . $sort);
foreach ($rows as $row) {
    echo (int) $row['id'] . ': ' . (float) $row['total'] . "<br>";
}
