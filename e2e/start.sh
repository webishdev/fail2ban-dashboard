#!/bin/bash

docker run -it --rm -p 3000:3000 -v ${PWD}:/files docker.io/library/fail2ban-dashboard /bin/bash