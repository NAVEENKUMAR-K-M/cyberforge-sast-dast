<h1><?php echo htmlspecialchars($product['name']); ?></h1>
<?php foreach ($reviews as $review): ?>
  <blockquote><?= $review['body'] ?> by <?= htmlspecialchars($review['author']) ?></blockquote>
<?php endforeach; ?>
