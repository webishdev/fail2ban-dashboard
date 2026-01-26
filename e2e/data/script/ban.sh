#!/bin/bash

echo "will add bans to 'foo' jail"
fail2ban-client set foo banip 103.59.94.155 196.251.84.225 218.92.0.247
fail2ban-client status foo

echo "will add bans to 'bar' jail"
fail2ban-client set bar banip 78.88.88.99
fail2ban-client status bar