FROM php:7.3-apache

LABEL Author="Shana"

COPY ./html/ /var/www/html/
COPY ./php.ini /usr/local/etc/php/php.ini

RUN chmod -R 755 /var/www/html/ && \
    chown -R root:root /var/www/html 

ENV FLAG=BJD{C00k1e_iS_s0_Subt13_23333}

EXPOSE 80

CMD sh -c "echo $FLAG > /flag && export FLAG=not_flag && FLAG=not_flag && apache2-foreground"