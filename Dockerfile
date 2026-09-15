# ============================================================
# VulnScope Pro — Enterprise Vulnerability Intelligence Engine
# Single-file app (index.php) with the modular pipeline:
#   Module 1 — Recon (native DNS / whois / port+banner scanner)
#   Module 2 — Directory & sensitive-file fuzzer (curl_multi)
#   Module 3 — Active payload scanner (SQLi / XSS / LFI / redirect)
#   Module 4 — JSON export layer
# Legacy CVE engine still uses Nmap; the modular pipeline does not.
# ============================================================
FROM php:8.2-apache

# ---- System dependencies -----------------------------------------
# nmap                    : legacy CVE scan engine
# curl                    : CLI (used by the container healthcheck)
# libcurl4-openssl-dev    : PHP curl ext — parallel engine for Modules 2 & 3
# libsqlite3-dev          : PHP pdo_sqlite — scan history / cache store
# iputils-ping, dnsutils  : recon fallback utilities
RUN apt-get update && apt-get install -y \
    nmap \
    curl \
    libcurl4-openssl-dev \
    libsqlite3-dev \
    iputils-ping \
    dnsutils \
    && docker-php-ext-install pdo pdo_sqlite curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Enable mod_rewrite
RUN a2enmod rewrite

# ---- App configuration (override at runtime with -e / Render env) --
# SCAN_TOKEN           : frontend -> backend auth token (CHANGE IN PRODUCTION)
# ALLOW_INTERNAL_SCAN  : allow RFC1918/loopback targets (lab use; true here)
ENV SCAN_TOKEN="SECURE_SCAN_TOKEN_2024" \
    ALLOW_INTERNAL_SCAN=true \
    APACHE_DOCUMENT_ROOT=/var/www/html

# Copy Apache vhost + application
COPY 000-default.conf /etc/apache2/sites-available/000-default.conf
COPY index.php /var/www/html/index.php

# Point Apache at the document root (standard php-image pattern)
RUN sed -ri -e 's!/var/www/html!${APACHE_DOCUMENT_ROOT}!g' \
        /etc/apache2/sites-available/000-default.conf \
    && sed -ri -e 's!/var/www/!${APACHE_DOCUMENT_ROOT}/!g' \
        /etc/apache2/apache2.conf /etc/apache2/conf-available/*.conf

# ---- Permissions ---------------------------------------------------
# Webroot owned by the Apache user; pre-create the SQLite DB file so the
# app can write scan history without needing a writable layer mount.
RUN chown -R www-data:www-data /var/www/html \
    && chmod 644 /var/www/html/index.php \
    && touch /var/www/html/vulnscope_v2.sqlite \
    && chown www-data:www-data /var/www/html/vulnscope_v2.sqlite

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -sf http://localhost/ -o /dev/null || exit 1

CMD ["apache2-foreground"]
