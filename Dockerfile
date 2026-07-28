# Use the official PHP image with Apache server
FROM php:8.2-apache

# Install system dependencies: nmap for port scanning + curl for API calls + sqlite3 for the DB
RUN apt-get update && apt-get install -y \
    nmap \
    libcurl4-openssl-dev \
    libsqlite3-dev \
    iputils-ping \
    dnsutils \
    && docker-php-ext-install pdo pdo_sqlite \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Enable mod_rewrite for Apache
RUN a2enmod rewrite

# Copy your files into the server directory
COPY . /var/www/html/

# Set correct permissions
RUN chown -R www-data:www-data /var/www/html && chmod -R 755 /var/www/html

# Expose port 80 for Render to route traffic
EXPOSE 80
