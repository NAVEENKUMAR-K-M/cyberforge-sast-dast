<?php
function old_order_lookup() {
    return db()->query("SELECT * FROM orders WHERE id = " . $_GET['legacy_id']);
}
