# Manual end-to-end testing

This folder is mostly to spin up a local container with `fail2ban` and check the access.

## Usage

From within the `e2e` use `./build.sh` to create a container image which has `fail2ban`.

From the root folder of this project use `./e2e/start.sh` to create a container image which has `fail2ban`.

Inside the container use `fail2ban-server` to spin up the server.

Then use the following commands to check the status or ban some addresses:

- `fail2ban-client status --all`
- `fail2ban-client banned`
- `fail2ban-client set sshd banip 103.59.94.155 196.251.84.225 218.92.0.247`
- `fail2ban-client set apache-auth bantime 20000`
- `fail2ban-client set apache-auth banip 78.88.88.99`