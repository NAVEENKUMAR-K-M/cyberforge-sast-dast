<?php
require_once __DIR__ . '/../lib/bootstrap.php';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $repo = new ReviewRepository(db());
    $repo->add((int) $_POST['product_id'], strip_tags($_POST['author']), $_POST['body']);
    echo 'Thanks for your review';
}
