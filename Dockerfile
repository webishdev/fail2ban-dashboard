# syntax=docker/dockerfile:1.2
FROM gcr.io/distroless/static-debian12

ARG TARGETPLATFORM
COPY --chmod=755 ./bin/${TARGETPLATFORM}/fail2ban-dashboard /usr/local/bin/fail2ban-dashboard

WORKDIR /f2b-dashboard-data
VOLUME /f2b-dashboard-data

EXPOSE 3000

STOPSIGNAL SIGTERM

ENV F2BD_ADDRESS=:3000

ENTRYPOINT ["/usr/local/bin/fail2ban-dashboard", "serve"]
