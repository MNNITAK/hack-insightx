# Vulnerable Nginx Web Server for Security Testing
FROM nginx:alpine

# Create directories
RUN mkdir -p /var/www/html /var/log/nginx /var/log/webapp

# Set up basic vulnerable configuration
RUN echo 'server { \
    listen 80 default_server; \
    root /var/www/html; \
    index index.html index.php; \
    server_tokens off; \
    autoindex on; \
    location / { \
        try_files $uri $uri/ =404; \
    } \
    location /admin/ { \
        autoindex on; \
    } \
    location /api/ { \
        add_header Access-Control-Allow-Origin *; \
        return 200 "{\"status\":\"vulnerable\",\"endpoints\":[\"users\",\"orders\",\"config\"]}"; \
        add_header Content-Type application/json; \
    } \
}' > /etc/nginx/conf.d/default.conf

# Add vulnerable web application
COPY webapp/ /var/www/html/

# Create a simple test page
RUN echo '<!DOCTYPE html>\
<html>\
<head><title>Vulnerable Web Server</title></head>\
<body>\
<h1>🚨 Vulnerable Web Application</h1>\
<p>This is a test environment for security testing.</p>\
<p>Status: <span style="color: red;">VULNERABLE</span></p>\
<ul>\
<li><a href="/admin/">Admin Panel</a></li>\
<li><a href="/uploads/">File Uploads</a></li>\
<li><a href="/debug.php">Debug Info</a></li>\
</ul>\
</body>\
</html>' > /var/www/html/index.html

# Create admin directory
RUN mkdir -p /var/www/html/admin /var/www/html/uploads

# Expose vulnerable ports
EXPOSE 80

# Use the default nginx entrypoint, no custom start script needed
CMD ["nginx", "-g", "daemon off;"]

