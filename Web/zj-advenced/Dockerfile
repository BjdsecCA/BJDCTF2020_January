FROM php:5.6-apache

COPY src /var/www/html
COPY flag.sh /flag.sh

RUN chmod 777 /flag.sh && \
    /flag.sh && \
    apt-get update && \ 
    apt-get install vi
