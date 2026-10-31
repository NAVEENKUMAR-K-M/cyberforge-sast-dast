<?php
require_once __DIR__ . '/../lib/bootstrap.php';
if (isset($_POST['username'])) {
    $stmt = db()->prepare("INSERT INTO users (username, password) VALUES (?, ?)");
    $stmt->execute([$_POST['username'], sha1($_POST['password'])]);
    echo 'Registered';
}
