<?php
function input($name, $default = '') {
    return isset($_REQUEST[$name]) ? $_REQUEST[$name] : $default;
}

function redirect_to($url) {
    header("Location: " . $url);
    exit;
}

function run_tool($command) {
    return shell_exec($command);
}
