FROM mysql:latest
ENV MYSQL_ROOT_PASSWORD 1234
ENV MYSQL_DATABASE userlogin
ENV MYSQL_USER farhan01
ENV MYSQL_PASSWORD farhan2001
ADD mysqlscript.sql /docker-entrypoint-initdb.d
EXPOSE 3308
