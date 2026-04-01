FROM php:8.2-fpm

# Cài dependency
RUN apt-get update && apt-get install -y \
    libzip-dev \
    unzip \
    git \
    && docker-php-ext-install mysqli pdo pdo_mysql

# Cài Redis extension
RUN pecl install redis \
    && docker-php-ext-enable redis

WORKDIR /var/www/html

COPY src/ /var/www/html/