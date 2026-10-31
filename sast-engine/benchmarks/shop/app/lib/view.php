<?php
function render($template, array $vars = []) {
    extract($vars);
    include __DIR__ . '/../templates/' . $template . '.php';
}
