<?php
echo "Docker-first Web System 🚀<br>";

$db = new mysqli(
    getenv('DB_HOST'),
    getenv('DB_USER'),
    getenv('DB_PASS')
);

if ($db->connect_error) {
    die("DB failed<br>");
}

echo "MySQL OK<br>";

$redis = new Redis();
$redis->connect('redis', 6379);

echo "Redis OK<br>";
?>
