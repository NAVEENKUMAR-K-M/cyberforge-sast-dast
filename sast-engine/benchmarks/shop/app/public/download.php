<?php
$file = $_GET['file'];
readfile(__DIR__ . '/../files/' . $file);
