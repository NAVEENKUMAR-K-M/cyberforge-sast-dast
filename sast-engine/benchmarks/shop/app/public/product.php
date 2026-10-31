<?php
require_once __DIR__ . '/../lib/bootstrap.php';
$product = ProductRepository::find($_GET['id'] ?? 0);
$repo = new ReviewRepository(db());
render('product', ['product' => $product, 'reviews' => $repo->forProduct($_GET['id'] ?? 0)]);
