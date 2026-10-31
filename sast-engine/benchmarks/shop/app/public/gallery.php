<?php
require_once __DIR__ . '/../lib/bootstrap.php';
$image = htmlspecialchars($_GET['img'] ?? 'logo.png');
?>
<img src=<?= $image ?>>
