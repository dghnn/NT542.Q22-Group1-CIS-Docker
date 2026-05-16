<?php
$dbStatus = false;
$redisStatus = false;

$db = @new mysqli(
    getenv('DB_HOST'),
    getenv('DB_USER'),
    getenv('DB_PASS')
);

if (!$db->connect_error) {
    $dbStatus = true;
}

$redis = new Redis();

try {
    $redis->connect('redis', 6379);
    $redisStatus = true;
} catch (Exception $e) {}
?>

<!DOCTYPE html>
<html lang="en">

<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">

<title>Secure Docker Infrastructure</title>

<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">

<link rel="stylesheet" href="assets/css/style.css">
</head>

<body>

<?php include 'components/navbar.php'; ?>

<section class="hero">

<div class="container text-center">

<h1>Secure Docker Infrastructure</h1>

<p class="subtitle">
Containerized Web System with CIS Docker Benchmark Hardening
</p>

<a href="#dashboard" class="btn btn-primary btn-lg mt-4">
View Dashboard
</a>

</div>

</section>

<section id="dashboard" class="dashboard-section">

<div class="container">

<h2 class="section-title">
Infrastructure Status
</h2>

<div class="row g-4">

<div class="col-md-4">
<div class="status-card">

<h3>MySQL</h3>

<p class="<?php echo $dbStatus ? 'online' : 'offline'; ?>">
<?php echo $dbStatus ? 'ONLINE' : 'OFFLINE'; ?>
</p>

</div>
</div>

<div class="col-md-4">
<div class="status-card">

<h3>Redis</h3>

<p class="<?php echo $redisStatus ? 'online' : 'offline'; ?>">
<?php echo $redisStatus ? 'ONLINE' : 'OFFLINE'; ?>
</p>

</div>
</div>

<div class="col-md-4">
<div class="status-card">

<h3>Nginx</h3>

<p class="online">
RUNNING
</p>

</div>
</div>

</div>

</div>

</section>

<section class="security-section">

<div class="container">

<h2 class="section-title">
Security Hardening
</h2>

<div class="row g-4">

<div class="col-md-3">
<div class="security-card">
<h4>Non-root User</h4>
<p>Container runs with least privilege.</p>
</div>
</div>

<div class="col-md-3">
<div class="security-card">
<h4>Healthcheck</h4>
<p>Automatic container health monitoring.</p>
</div>
</div>

<div class="col-md-3">
<div class="security-card">
<h4>Network Isolation</h4>
<p>Secure communication between containers.</p>
</div>
</div>

<div class="col-md-3">
<div class="security-card">
<h4>CIS Benchmark</h4>
<p>Docker security compliance validation.</p>
</div>
</div>

</div>

</div>

</section>

<?php include 'components/footer.php'; ?>

<script src="assets/js/app.js"></script>

</body>
</html>