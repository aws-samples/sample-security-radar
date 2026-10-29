FROM public.ecr.aws/docker/library/php:8.3.30-apache
COPY src/ /var/www/html/
RUN docker-php-ext-install pdo_mysql
