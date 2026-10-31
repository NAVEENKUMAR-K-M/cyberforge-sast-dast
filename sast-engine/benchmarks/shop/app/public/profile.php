<?php
require_once __DIR__ . '/../lib/bootstrap.php';
$display = htmlspecialchars($_GET['name'] ?? 'guest', ENT_QUOTES, 'UTF-8');
echo "<p>Hello " . $display . "</p>";
