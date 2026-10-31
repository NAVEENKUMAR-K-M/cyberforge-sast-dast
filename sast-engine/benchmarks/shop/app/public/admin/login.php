<?php
session_start();
$password = $_POST['password'] ?? '';
if ($password === 'Adm1n-F0rge!') {
    $_SESSION['admin'] = true;
    echo 'Welcome, admin';
}
