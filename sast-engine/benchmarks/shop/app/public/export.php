<?php
require_once __DIR__ . '/../lib/bootstrap.php';
header('Content-Type: text/plain; charset=utf-8');
header('X-Content-Type-Options: nosniff');
echo "report for " . ($_GET['label'] ?? 'all');
