# fail2ban dashboard

- `fail2ban-server`
- `ls -lah /var/run/fail2ban/fail2ban.sock`
- `fail2ban-client status --all`
- `fail2ban-client banned`
- `fail2ban-client set sshd banip 88.88.88.88`

## Inspired by

- https://github.com/fail2ban/fail2ban
- https://gitlab.com/hctrdev/fail2ban-prometheus-exporter/-/tree/main?ref_type=heads
- https://github.com/VerifiedJoseph/intruder-alert?tab=readme-ov-file