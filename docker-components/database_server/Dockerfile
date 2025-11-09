# Vulnerable MySQL Database for Security Testing
FROM mysql:8.0

# Set environment variables for automatic setup
ENV MYSQL_ROOT_PASSWORD=admin123
ENV MYSQL_DATABASE=ecommerce
ENV MYSQL_USER=webapp
ENV MYSQL_PASSWORD=password123
ENV MYSQL_ROOT_HOST=%

# Create directories
RUN mkdir -p /var/log/mysql

# Copy initialization scripts
COPY init/ /docker-entrypoint-initdb.d/

# Expose database port
EXPOSE 3306

# Use default MySQL entrypoint
CMD ["mysqld"]