<?php
require_once __DIR__ . '/../../lib/bootstrap.php';
if (isset($_POST['back'])) {
    redirect_to($_POST['back']);
}
echo 'Order placed';
