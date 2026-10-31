<?php
$id = str_replace('../', '', $_GET['id']);
echo nl2br(htmlspecialchars(file_get_contents(__DIR__ . '/../files/' . $id)));
