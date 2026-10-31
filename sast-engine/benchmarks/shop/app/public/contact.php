<?php
require_once __DIR__ . '/../lib/bootstrap.php';
$name = htmlspecialchars($_POST['name'] ?? '', ENT_NOQUOTES);
echo "<form method='post'><input name='name' value='" . $name . "'><button>Send</button></form>";
