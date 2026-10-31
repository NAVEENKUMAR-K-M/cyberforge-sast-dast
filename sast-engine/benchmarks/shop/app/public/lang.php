<?php
$back = $_GET['back'] ?? '/';
if (strpos($back, 'forge-shop') !== false) {
    header('Location: ' . $back);
    exit;
}
echo 'Language saved';
