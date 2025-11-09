# syntax=docker/dockerfile:1.2
FROM gcr.io/distroless/static-debian12

COPY --chmod=755 ./bin/fail2ban-dashboard /fail2ban-dashboard

EXPOSE 3000

STOPSIGNAL SIGTERM

ENV F2BD_ADDRESS=:3000

ENTRYPOINT ["/fail2ban-dashboard"]