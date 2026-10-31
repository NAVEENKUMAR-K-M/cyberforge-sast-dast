<?php
require_once __DIR__ . '/../lib/bootstrap.php';
if (isset($_POST['username'])) {
    $password = md5($_POST['password']);
    $sql = sprintf("SELECT id FROM users WHERE username = '%s' AND password = '%s'", $_POST['username'], $password);
    if (run_query($sql)) {
        $_SESSION['user'] = $_POST['username'];
        redirect_to($_POST['return_to'] ?? '/index.php');
    }
    echo 'Login failed';
}
?>
<form method="post"><input name="username"><input name="password" type="password"><input name="return_to" type="hidden" value="/"><button>Log in</button></form>
