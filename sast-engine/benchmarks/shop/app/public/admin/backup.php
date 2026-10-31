<?php
$label = str_replace(';', '', $_POST['label'] ?? 'nightly');
$output = `tar czf /tmp/$label.tgz /var/www/shop/files`;
echo 'Backup finished';
