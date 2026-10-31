<?php
$name = basename($_GET['name'] ?? 'spec.txt');
header('Content-Type: text/plain');
readfile(__DIR__ . '/../files/' . $name);
