<?php
require_once __DIR__ . '/../../lib/bootstrap.php';
$domain = input('domain', 'example.test');
echo '<pre>' . htmlspecialchars((string) run_tool("nslookup " . $domain)) . '</pre>';
