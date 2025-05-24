#!/bin/bash

GIT_HASH=$(git rev-parse --short=11 HEAD)
VERSION="${1:-development}"

mkdir -p bin
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w -X 'main.Version=$VERSION' -X 'main.GitHash=$GIT_HASH'" -o bin/fail2ban-dashboard ./cmd/fail2ban-dashboard