FROM php:7.3-apache

LABEL Author="Shana"

COPY ./html/ /var/www/html/

RUN chmod -R 755 /var/www/html/ && \
    chown -R root:root /var/www/html && \
	mkdir /var/www/html/templates_c && \
	chmod -R 755 /var/www/html/templates_c && \
	chown -R www-data:www-data /var/www/html/templates_c

ENV FLAG=BJD{Smarty_Maybe_danger0us_1sNt_it?}

EXPOSE 80

CMD sh -c "echo $FLAG > /flag && export FLAG=not_flag && FLAG=not_flag && apache2-foreground"