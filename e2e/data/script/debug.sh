#!/bin/bash

cd /workspace || exit 1

dlv debug ./cmd/fail2ban-dashboard --headless --listen=:40000 --api-version=2 --accept-multiclient --log