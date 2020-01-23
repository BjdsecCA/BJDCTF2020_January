FROM sakadonohito/php5.6.23-apache

LABEL Author="Shana"

COPY ./html/ /var/www/html/
COPY ./php.ini /usr/local/etc/php/php.ini

RUN chmod -R 755 /var/www/html/ && \
    chown -R root:root /var/www/html 

ENV FLAG=BJD{Congratulations!Y0u_Get_thE_rea1f1114g}

EXPOSE 80

CMD sh -c "export FLAG=not_flag && FLAG=null && apache2-foreground"
