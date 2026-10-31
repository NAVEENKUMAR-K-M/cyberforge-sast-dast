<?php
session_start();
session_destroy();
$next = $_REQUEST['next'] ?? '/';
header("Location: $next");
exit;
