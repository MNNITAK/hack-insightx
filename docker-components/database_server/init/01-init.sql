-- Vulnerable Database Initialization Script
-- This script sets up a vulnerable database for security testing

-- Create additional vulnerable users
CREATE USER 'admin'@'%' IDENTIFIED BY 'admin123';
CREATE USER 'guest'@'%' IDENTIFIED BY '';
CREATE USER 'test'@'%' IDENTIFIED BY 'test123';

-- Grant excessive privileges (Vulnerable)
GRANT ALL PRIVILEGES ON *.* TO 'admin'@'%' WITH GRANT OPTION;
GRANT ALL PRIVILEGES ON ecommerce.* TO 'webapp'@'%';
GRANT SELECT, INSERT, UPDATE ON ecommerce.* TO 'guest'@'%';

-- Create e-commerce database structure
USE ecommerce;

-- Products table
CREATE TABLE products (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    price DECIMAL(10,2) NOT NULL,
    stock_quantity INT DEFAULT 0,
    category VARCHAR(100),
    image_url VARCHAR(500),
    comments TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Users table with vulnerable structure
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL, -- Storing plain text passwords (Vulnerable)
    email VARCHAR(255),
    role VARCHAR(20) DEFAULT 'user',
    credit_card VARCHAR(20), -- Storing CC info (Vulnerable)
    ssn VARCHAR(11), -- Storing SSN (Vulnerable)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Orders table
CREATE TABLE orders (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    total_amount DECIMAL(10,2),
    status VARCHAR(50),
    shipping_address TEXT,
    credit_card_number VARCHAR(20), -- Vulnerable storage
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Admin logs table
CREATE TABLE admin_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    admin_user VARCHAR(50),
    action TEXT,
    target_table VARCHAR(50),
    query_executed TEXT, -- Storing executed queries (Vulnerable)
    ip_address VARCHAR(45),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert vulnerable sample data
INSERT INTO products (name, description, price, stock_quantity, category, comments) VALUES
('Laptop Pro', 'High-performance laptop for professionals', 1299.99, 50, 'Electronics', 'Great laptop! <script>alert("XSS")</script>'),
('Smartphone X', 'Latest smartphone with advanced features', 899.99, 100, 'Electronics', 'Love it!'),
('Office Chair', 'Ergonomic office chair for comfort', 299.99, 25, 'Furniture', 'Very comfortable'),
('Coffee Maker', 'Automatic coffee maker with timer', 149.99, 30, 'Appliances', 'Perfect coffee every time'),
('Gaming Mouse', 'High-precision gaming mouse', 79.99, 75, 'Electronics', 'Great for gaming'),
('Desk Lamp', 'LED desk lamp with adjustable brightness', 49.99, 40, 'Lighting', 'Bright and efficient'),
('Wireless Headphones', 'Premium wireless headphones', 199.99, 60, 'Electronics', 'Amazing sound quality'),
('Standing Desk', 'Adjustable standing desk', 599.99, 15, 'Furniture', 'Great for health');

-- Insert vulnerable user data
INSERT INTO users (username, password, email, role, credit_card, ssn) VALUES
('admin', 'admin123', 'admin@vulnshop.com', 'admin', '4532123456789012', '123-45-6789'),
('user', 'password', 'user@email.com', 'user', '5555123456789012', '987-65-4321'),
('guest', '', 'guest@email.com', 'user', NULL, NULL),
('testuser', 'test123', 'test@email.com', 'user', '4111111111111111', '555-55-5555'),
('manager', 'manager123', 'manager@vulnshop.com', 'manager', '4000123456789010', '111-22-3333');

-- Insert sample orders
INSERT INTO orders (user_id, total_amount, status, shipping_address, credit_card_number) VALUES
(1, 1299.99, 'shipped', '123 Main St, Anytown, USA 12345', '4532123456789012'),
(2, 899.99, 'processing', '456 Oak Ave, Somewhere, USA 67890', '5555123456789012'),
(4, 349.98, 'delivered', '789 Pine Rd, Elsewhere, USA 13579', '4111111111111111');

-- Create a view with sensitive data (Vulnerable)
CREATE VIEW user_details AS
SELECT id, username, email, role, credit_card, ssn
FROM users;

-- Create stored procedures with vulnerabilities
DELIMITER ;;

CREATE PROCEDURE GetUserByUsername(IN input_username VARCHAR(50))
BEGIN
    -- Vulnerable: Dynamic SQL construction
    SET @sql = CONCAT('SELECT * FROM users WHERE username = "', input_username, '"');
    PREPARE stmt FROM @sql;
    EXECUTE stmt;
    DEALLOCATE PREPARE stmt;
END;;

CREATE PROCEDURE AddAdminLog(IN admin_user VARCHAR(50), IN action TEXT, IN query_text TEXT, IN ip VARCHAR(45))
BEGIN
    INSERT INTO admin_logs (admin_user, action, query_executed, ip_address) 
    VALUES (admin_user, action, query_text, ip);
END;;

DELIMITER ;

-- Create function with privilege escalation vulnerability
DELIMITER ;;

CREATE FUNCTION GetUserRole(user_id INT) RETURNS VARCHAR(20)
READS SQL DATA
DETERMINISTIC
BEGIN
    DECLARE user_role VARCHAR(20);
    SELECT role INTO user_role FROM users WHERE id = user_id;
    RETURN user_role;
END;;

DELIMITER ;

-- Grant function execution to all users (Vulnerable)
GRANT EXECUTE ON FUNCTION ecommerce.GetUserRole TO 'guest'@'%';

-- Create trigger for logging (Vulnerable - logs sensitive data)
CREATE TRIGGER user_login_log 
    AFTER UPDATE ON users
    FOR EACH ROW
    INSERT INTO admin_logs (admin_user, action, query_executed, ip_address)
    VALUES (NEW.username, 'USER_LOGIN', CONCAT('User ', NEW.username, ' logged in with password ', NEW.password), '0.0.0.0');

-- Insert additional test data for SQL injection testing
INSERT INTO products (name, description, price, stock_quantity, category, comments) VALUES
('Test Product 1', 'Product for testing SQL injection', 1.00, 999, 'Test', '"),("injected","injected",1,1,"injected","injected"),("'),
('Test Product 2', 'Another test product', 2.00, 999, 'Test', 'UNION SELECT * FROM users--');

-- Create configuration table with sensitive settings
CREATE TABLE system_config (
    id INT AUTO_INCREMENT PRIMARY KEY,
    config_key VARCHAR(100),
    config_value TEXT,
    is_sensitive BOOLEAN DEFAULT FALSE
);

INSERT INTO system_config (config_key, config_value, is_sensitive) VALUES
('database_version', '8.0.0', FALSE),
('admin_email', 'admin@vulnshop.com', FALSE),
('secret_key', 'super_secret_key_123!@#', TRUE),
('payment_gateway_key', 'pk_test_123456789', TRUE),
('debug_mode', 'enabled', FALSE),
('backup_location', '/var/backups/database/', TRUE);

-- Flush privileges to ensure changes take effect
FLUSH PRIVILEGES;

-- Log the initialization
INSERT INTO admin_logs (admin_user, action, query_executed, ip_address) 
VALUES ('system', 'DATABASE_INIT', 'Vulnerable database initialized successfully', '127.0.0.1');