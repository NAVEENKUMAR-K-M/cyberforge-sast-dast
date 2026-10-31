<?php
require_once __DIR__ . '/../lib/bootstrap.php';
$q = input('q');
$products = ProductRepository::search($q);
render('results', ['term' => $q, 'products' => $products]);
