<?php
$domain = $_GET['domain'] ?? 'example.test';
echo '<pre>' . htmlspecialchars((string) shell_exec('nslookup ' . escapeshellarg($domain))) . '</pre>';
