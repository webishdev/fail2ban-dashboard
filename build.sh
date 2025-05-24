#!/bin/bash

GIT_HASH=$(git rev-parse --short=11 HEAD)

GOOS=linux GOARCH=amd64 go build -ldflags="-s -w -X 'main.Version=$VERSION' -X 'main.GitHash=$GIT_HASH'" ./cmd/fail2ban-dashboard