<?php
define('DB_PATH', __DIR__ . '/../data/shop.sqlite');
define('DB_PASSWORD', 'Sup3rS3cretDb!');
define('APP_NAME', 'Forge Shop');
$awsAccessKey = 'AKIAIOSFODNN7EXAMPLE';
$dbHost = getenv('DB_HOST');
$readReplicaPassword = getenv('REPLICA_PASSWORD');
