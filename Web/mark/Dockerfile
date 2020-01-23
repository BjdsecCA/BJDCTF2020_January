FROM php:7.2-apache

COPY src /var/www/html
COPY flag.sh /flag.sh

RUN chmod 777 /flag.sh && \
    /flag.sh

