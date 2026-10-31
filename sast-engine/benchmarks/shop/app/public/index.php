<?php
require_once __DIR__ . '/../lib/bootstrap.php';
echo "<h1>" . APP_NAME . "</h1>";
echo '<a href="page.php?name=about">About</a> <a href="page.php?name=shipping">Shipping</a> <a href="products.php">Products</a> <a href="search.php?q=anvil">Search</a>';
