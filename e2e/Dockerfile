FROM ubuntu:24.10

RUN apt-get update && apt-get install -y openssh-server apache2 supervisor fail2ban
RUN mkdir -p /var/lock/apache2 /var/run/apache2 /var/run/sshd /var/log/supervisor

