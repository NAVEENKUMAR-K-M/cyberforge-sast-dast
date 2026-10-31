FROM php:8.3-cli
RUN apt-get update -qq && apt-get install -y -qq git unzip libzip-dev iputils-ping >/dev/null \
 && docker-php-ext-install zip >/dev/null && rm -rf /var/lib/apt/lists/*
COPY --from=composer:2 /usr/bin/composer /usr/bin/composer
WORKDIR /srv
# A deliberately vulnerable benchmark, so known advisories are expected: do not let Composer refuse to install.
ENV COMPOSER_NO_SECURITY_BLOCKING=1
RUN composer create-project laravel/laravel:^11.0 lashop --no-interaction --prefer-dist
WORKDIR /srv/lashop
COPY overlay/ /srv/lashop/
# Production mode: no debug page, so an error is a bare 500, as on a real deployment.
RUN cp .env.example .env && php artisan key:generate --force \
 && sed -i 's/^APP_ENV=.*/APP_ENV=production/; s/^APP_DEBUG=.*/APP_DEBUG=false/; s/^DB_CONNECTION=.*/DB_CONNECTION=sqlite/; s/^LOG_LEVEL=.*/LOG_LEVEL=error/' .env \
 && sed -i '/^DB_HOST=/d; /^DB_PORT=/d; /^DB_DATABASE=/d; /^DB_USERNAME=/d; /^DB_PASSWORD=/d' .env \
 && touch database/database.sqlite && php artisan migrate --force --quiet \
 && chmod -R a+rw storage bootstrap/cache database
# Deliberately vulnerable. The port is bound to loopback so it can't be reached from the network.
ENV PHP_CLI_SERVER_WORKERS=4
CMD ["php", "artisan", "serve", "--host=0.0.0.0", "--port=8000"]
