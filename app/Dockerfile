FROM php:8.2-fpm

# Install dependencies
RUN apt-get update && apt-get install -y \
    libzip-dev \
    unzip \
    git \
    curl \
    && docker-php-ext-install mysqli pdo pdo_mysql \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Redis extension
RUN pecl install redis \
    && docker-php-ext-enable redis

# Create non-root user
RUN useradd -m -u 1001 appuser

# Set working directory
WORKDIR /var/www/html

# Copy application
COPY src/ /var/www/html/

# Set permissions
RUN chown -R appuser:appuser /var/www/html

# Switch to non-root user
USER appuser

# Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
CMD php-fpm -t || exit 1

# Expose php-fpm port
EXPOSE 9000

# Start php-fpm
CMD ["php-fpm"]