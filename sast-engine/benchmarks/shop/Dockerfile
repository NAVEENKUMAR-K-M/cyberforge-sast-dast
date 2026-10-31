FROM php:8.2-apache
COPY app/ /var/www/shop/
RUN sed -ri 's!/var/www/html!/var/www/shop/public!g' /etc/apache2/sites-available/000-default.conf \
 && sed -ri 's!<Directory /var/www/>!<Directory /var/www/shop/public/>!' /etc/apache2/apache2.conf \
 && apt-get update -qq && apt-get install -y -qq iputils-ping >/dev/null \
 && chown -R www-data:www-data /var/www/shop/data
