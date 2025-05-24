# syntax=docker/dockerfile:1.2
FROM gcr.io/distroless/static-debian12

COPY ./bin/fail2ban-dashboard /fail2ban-dashboard

EXPOSE 3000

STOPSIGNAL SIGTERM

ENTRYPOINT ["/fail2ban-dashboard"]