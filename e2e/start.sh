#!/bin/bash

docker run -it --rm -p 3000:3000 -v ${PWD}:/files -v ${PWD}/e2e/jail.conf:/etc/fail2ban/jail.conf docker.io/library/fail2ban-dashboard /bin/bash