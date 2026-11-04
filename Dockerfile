# ============================================================
# VulnScope Pro — Enterprise Vulnerability Intelligence Engine
# Modular layout (Phase 1 split):
#   public/    webroot — index.php (dashboard), api.php (JSON API)
#   src/       recon / fuzz / payload / intel / scoring modules
#   config.php, bootstrap.php, schema.sql — app bootstrap
# Modules:
#   Recon        — DNS / whois / port+banner scanner
#   Spider       — parallel crawler (links, forms, params, JS endpoints, tech)
#   Fuzzer       — directory & sensitive-file brute force (curl_multi)
#   Passive      — ZAP-style rules: headers, cookies, CORS, disclosure
#   Active       — ZAP-style rules: SQLi, XSS, LFI, redirect, CRLF, SSTI, IDOR
#   Intel        — NVD / Vulnerability-Lookup / EPSS / CISA KEV correlation
#   Report       — JSON, SARIF 2.1.0 and standalone HTML exports
# Legacy CVE engine still uses Nmap; the advanced pipeline does not.
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

# Enable rewrite + lightweight response compression/caching
RUN a2enmod rewrite deflate expires headers \
    && printf '%s\n' '<IfModule mod_deflate.c>' \
        '  AddOutputFilterByType DEFLATE text/html text/plain text/css text/javascript application/javascript application/json image/svg+xml' \
        '</IfModule>' > /etc/apache2/conf-available/vulnscope-perf.conf \
    && a2enconf vulnscope-perf

# ---- App configuration (override at runtime with -e / Render env) --
# SCAN_TOKEN           : frontend -> backend auth token (CHANGE IN PRODUCTION)
# ALLOW_INTERNAL_SCAN  : allow RFC1918/loopback targets (lab use; true here)
ENV SCAN_TOKEN="SECURE_SCAN_TOKEN_2024" \
    ALLOW_INTERNAL_SCAN=true \
    DB_PATH=/var/www/vulnscope_v2.sqlite \
    APACHE_DOCUMENT_ROOT=/var/www/html/public

# Copy Apache vhost + the whole application tree.
# Application code must sit ONE LEVEL ABOVE the webroot, because every entry
# point does require_once __DIR__ . '/../bootstrap.php'.
COPY 000-default.conf /etc/apache2/sites-available/000-default.conf
COPY public/ /var/www/html/public/
COPY src/ /var/www/html/src/
COPY bootstrap.php config.php schema.sql /var/www/html/

# Point Apache at the document root (standard php-image pattern)
RUN sed -ri -e 's!/var/www/html!${APACHE_DOCUMENT_ROOT}!g' \
        /etc/apache2/sites-available/000-default.conf \
    && sed -ri -e 's!/var/www/!${APACHE_DOCUMENT_ROOT}/!g' \
        /etc/apache2/apache2.conf /etc/apache2/conf-available/*.conf

# ---- Permissions ---------------------------------------------------
# Webroot owned by the Apache user; pre-create the SQLite DB file so the
# app can write scan history without needing a writable layer mount.
# (DB lives OUTSIDE the webroot — not downloadable over HTTP.)
RUN chown -R www-data:www-data /var/www/html \
    && chmod 644 /var/www/html/public/index.php /var/www/html/public/api.php \
    && touch /var/www/vulnscope_v2.sqlite \
    && chown www-data:www-data /var/www/vulnscope_v2.sqlite

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -sf http://localhost/ -o /dev/null || exit 1

CMD ["apache2-foreground"]
