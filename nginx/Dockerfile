FROM nginx:alpine

RUN adduser -D appuser

RUN apk add --no-cache wget

COPY default.conf /etc/nginx/conf.d/default.conf

RUN mkdir -p /run/nginx \
    && chown -R appuser:appuser /run/nginx \
    && chown -R appuser:appuser /var/cache/nginx \
    && chown -R appuser:appuser /var/log/nginx

RUN sed -i 's|/run/nginx.pid|/run/nginx/nginx.pid|g' /etc/nginx/nginx.conf

HEALTHCHECK CMD wget --spider -q http://localhost:8080 || exit 1

USER appuser