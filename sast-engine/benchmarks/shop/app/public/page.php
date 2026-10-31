<?php
$name = $_GET['name'] ?? 'about';
include __DIR__ . '/../pages/' . $name . '.php';
