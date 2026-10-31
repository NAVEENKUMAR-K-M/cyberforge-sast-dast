<?php
require_once __DIR__ . '/../../lib/bootstrap.php';
$cart = isset($_COOKIE['cart']) ? unserialize($_COOKIE['cart']) : [];
echo 'Items: ' . count($cart);
