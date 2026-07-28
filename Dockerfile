# Use the official PHP image with Apache server
FROM php:8.2-apache

# Copy your files into the server directory
COPY . /var/www/html/

# Expose port 80 for Render to route traffic
EXPOSE 80
