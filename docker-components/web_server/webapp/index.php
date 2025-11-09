<?php
/**
 * 🚨 VULNERABLE WEB APPLICATION FOR SECURITY TESTING
 * This application contains intentional vulnerabilities for educational purposes
 * DO NOT USE IN PRODUCTION
 */

session_start();

// Vulnerable: Direct database connection without prepared statements
$db_host = getenv('DB_HOST') ?: 'database_server';
$db_user = getenv('DB_USER') ?: 'webapp';
$db_pass = getenv('DB_PASSWORD') ?: 'password123';
$db_name = getenv('DB_NAME') ?: 'ecommerce';

$conn = new mysqli($db_host, $db_user, $db_pass, $db_name);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VulnShop - E-commerce Platform</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }
        .header { background: #007bff; color: white; padding: 15px; margin: -20px -20px 20px -20px; border-radius: 8px 8px 0 0; }
        .login-form, .search-form { background: #f8f9fa; padding: 15px; margin: 10px 0; border-radius: 5px; }
        .product { border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 5px; }
        .alert { padding: 10px; margin: 10px 0; border-radius: 5px; }
        .alert-danger { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .alert-success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        input, button { padding: 8px 12px; margin: 5px; border: 1px solid #ddd; border-radius: 4px; }
        button { background: #007bff; color: white; border: none; cursor: pointer; }
        button:hover { background: #0056b3; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛒 VulnShop - Vulnerable E-commerce Platform</h1>
            <p>Educational Security Testing Environment</p>
        </div>

        <?php
        // Vulnerable: Direct output without sanitization
        if (isset($_GET['error'])) {
            echo "<div class='alert alert-danger'>Error: " . $_GET['error'] . "</div>";
        }

        if (isset($_GET['success'])) {
            echo "<div class='alert alert-success'>Success: " . $_GET['success'] . "</div>";
        }
        ?>

        <!-- Login Form -->
        <div class="login-form">
            <h3>🔐 Customer Login</h3>
            <form method="POST" action="login.php">
                <input type="text" name="username" placeholder="Username" required>
                <input type="password" name="password" placeholder="Password" required>
                <button type="submit">Login</button>
            </form>
            <p><small>Test credentials: admin/admin123, user/password</small></p>
        </div>

        <!-- Product Search -->
        <div class="search-form">
            <h3>🔍 Product Search</h3>
            <form method="GET" action="">
                <input type="text" name="search" placeholder="Search products..." 
                       value="<?php echo isset($_GET['search']) ? $_GET['search'] : ''; ?>">
                <button type="submit">Search</button>
            </form>
        </div>

        <!-- Products Display -->
        <div class="products">
            <h3>📦 Featured Products</h3>
            
            <?php
            // Vulnerable: SQL Injection
            $search = isset($_GET['search']) ? $_GET['search'] : '';
            
            if ($search) {
                // VULNERABLE: Direct string concatenation in SQL
                $query = "SELECT * FROM products WHERE name LIKE '%$search%' OR description LIKE '%$search%'";
                echo "<p>Searching for: <strong>$search</strong></p>";
            } else {
                $query = "SELECT * FROM products LIMIT 10";
            }
            
            $result = $conn->query($query);
            
            if ($result && $result->num_rows > 0) {
                while($product = $result->fetch_assoc()) {
                    echo "<div class='product'>";
                    echo "<h4>" . htmlspecialchars($product['name']) . "</h4>";
                    echo "<p>" . htmlspecialchars($product['description']) . "</p>";
                    echo "<p><strong>Price: $" . htmlspecialchars($product['price']) . "</strong></p>";
                    
                    // Vulnerable: XSS in comments
                    if (isset($product['comments'])) {
                        echo "<p>Comments: " . $product['comments'] . "</p>";
                    }
                    
                    echo "<button onclick=\"addToCart(" . $product['id'] . ")\">Add to Cart</button>";
                    echo "</div>";
                }
            } else {
                echo "<p>No products found.</p>";
            }
            ?>
        </div>

        <!-- Admin Panel Link -->
        <?php if (isset($_SESSION['user_role']) && $_SESSION['user_role'] === 'admin'): ?>
        <div style="margin-top: 30px; padding: 15px; background: #fff3cd; border-radius: 5px;">
            <h4>🔧 Admin Panel</h4>
            <p><a href="/admin/">Access Admin Dashboard</a></p>
            <p><a href="/admin/backup.php">Download Database Backup</a></p>
            <p><a href="/admin/logs.php">View System Logs</a></p>
        </div>
        <?php endif; ?>

        <!-- Debug Information (Vulnerable) -->
        <?php if (isset($_GET['debug'])): ?>
        <div style="background: #f8f9fa; padding: 15px; margin: 20px 0; border-radius: 5px;">
            <h4>🐛 Debug Information</h4>
            <pre><?php var_dump($_SERVER); ?></pre>
            <pre><?php var_dump($_SESSION); ?></pre>
        </div>
        <?php endif; ?>

        <!-- File Upload (Vulnerable) -->
        <div style="margin-top: 20px; padding: 15px; background: #e9ecef; border-radius: 5px;">
            <h4>📁 File Upload</h4>
            <form method="POST" action="upload.php" enctype="multipart/form-data">
                <input type="file" name="upload_file" accept="*">
                <button type="submit">Upload File</button>
            </form>
            <p><small>Allowed: All file types (Vulnerable configuration)</small></p>
        </div>

        <!-- Footer with System Info -->
        <div style="margin-top: 30px; padding: 15px; background: #6c757d; color: white; border-radius: 5px;">
            <p><strong>System Information:</strong></p>
            <p>Server: <?php echo $_SERVER['SERVER_SOFTWARE']; ?></p>
            <p>PHP Version: <?php echo phpversion(); ?></p>
            <p>Database: MySQL <?php echo $conn->server_info; ?></p>
            <p>Environment: <?php echo getenv('ENVIRONMENT') ?: 'Production'; ?></p>
        </div>
    </div>

    <script>
        function addToCart(productId) {
            // Vulnerable: No CSRF protection
            fetch('/cart/add.php?product_id=' + productId, {
                method: 'GET'
            }).then(response => {
                if (response.ok) {
                    alert('Product added to cart!');
                } else {
                    alert('Error adding product to cart');
                }
            });
        }

        // Vulnerable: Exposed API endpoints
        function loadUserData() {
            fetch('/api/user.php?user_id=' + getUserId())
                .then(response => response.json())
                .then(data => console.log(data));
        }

        function getUserId() {
            // Vulnerable: Client-side user ID
            return localStorage.getItem('user_id') || '1';
        }
    </script>
</body>
</html>

<?php $conn->close(); ?>