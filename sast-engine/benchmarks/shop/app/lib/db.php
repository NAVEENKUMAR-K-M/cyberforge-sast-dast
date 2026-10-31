<?php
function db() {
    static $pdo = null;
    if ($pdo === null) {
        $pdo = new PDO('sqlite:' . DB_PATH);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $pdo->exec("CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY, name TEXT, price REAL, category INTEGER)");
        $pdo->exec("CREATE TABLE IF NOT EXISTS orders (id INTEGER PRIMARY KEY, customer TEXT, total REAL, code TEXT)");
        $pdo->exec("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)");
        $pdo->exec("CREATE TABLE IF NOT EXISTS reviews (id INTEGER PRIMARY KEY, product_id INTEGER, author TEXT, body TEXT)");
        if ((int) $pdo->query("SELECT COUNT(*) FROM products")->fetchColumn() === 0) {
            $pdo->exec("INSERT INTO products (name, price, category) VALUES ('Anvil', 99.5, 1), ('Hammer', 19.0, 1), ('Tongs', 12.0, 2)");
            $pdo->exec("INSERT INTO orders (customer, total, code) VALUES ('ada', 99.5, 'A1'), ('bob', 31.0, 'B2')");
            $pdo->exec("INSERT INTO users (username, password) VALUES ('ada', '" . md5('lovelace') . "')");
        }
    }
    return $pdo;
}

function run_query($sql) {
    return db()->query($sql)->fetchAll(PDO::FETCH_ASSOC);
}
