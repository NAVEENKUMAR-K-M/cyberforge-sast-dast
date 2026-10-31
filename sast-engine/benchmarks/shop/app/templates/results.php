<h1>Results for <?= $term ?></h1>
<ul>
<?php foreach ($products as $p): ?>
  <li><?= htmlspecialchars($p['name']) ?></li>
<?php endforeach; ?>
</ul>
