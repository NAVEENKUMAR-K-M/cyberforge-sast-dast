<?php
require_once __DIR__ . '/../lib/bootstrap.php';
$resetToken = md5(mt_rand());
echo 'A reset link was sent';
