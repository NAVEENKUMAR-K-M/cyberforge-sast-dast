<?php
class ProductRepository {
    public static function search($term) {
        return run_query("SELECT id, name, price FROM products WHERE name LIKE '%" . $term . "%'");
    }

    public static function find($id) {
        $stmt = db()->prepare("SELECT id, name, price FROM products WHERE id = :id");
        $stmt->bindValue(':id', $id);
        $stmt->execute();
        return $stmt->fetch(PDO::FETCH_ASSOC);
    }
}

class ReviewRepository {
    private $pdo;

    public function __construct(PDO $pdo) {
        $this->pdo = $pdo;
    }

    public function add($productId, $author, $body) {
        $stmt = $this->pdo->prepare("INSERT INTO reviews (product_id, author, body) VALUES (?, ?, ?)");
        $stmt->execute([$productId, $author, $body]);
    }

    public function forProduct($productId) {
        $stmt = $this->pdo->prepare("SELECT author, body FROM reviews WHERE product_id = ?");
        $stmt->execute([$productId]);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
}

class Attachment {
    const DIR = __DIR__ . '/../files/';

    public static function read($name) {
        return file_get_contents(self::DIR . $name);
    }
}
