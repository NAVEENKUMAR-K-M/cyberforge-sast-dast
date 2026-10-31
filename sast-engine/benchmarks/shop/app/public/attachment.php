<?php
require_once __DIR__ . '/../lib/bootstrap.php';
header('Content-Type: application/octet-stream');
echo Attachment::read($_GET['name']);
