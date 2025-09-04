# fail2ban-dashboard

![build](https://github.com/webishdev/fail2ban-dashboard/actions/workflows/build.yml/badge.svg)

A web based dashboard for `fail2ban` which uses the `/var/run/fail2ban/fail2ban.sock` socket to access `fail2ban`.

![Screenshot of fail2ban-dashboard](./images/screenshot.png "Screenshot of fail2ban-dashboard")


## Build the application

To build the application, use make with the following options:

```
make

    build           - Build the application
    
    test            - Run tests
    
    clean           - Remove build artifacts
    
    help            - Show this help message
    
    all             - Run tests and build the application (default)

```


## Usage

### Command line

```
Usage:
  fail2ban-dashboard [flags]
  fail2ban-dashboard [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  help        Help about any command
  version     Print the version number and git hash

Flags:
      --auth-password string   password for basic auth
      --auth-user string       username for basic auth
  -c, --cache-dir string       directory to cache GeoIP data (default current working directory)
  -h, --help                   help for fail2ban-dashboard
  -p, --port int               port to serve the dashboard on (default 3000)
  -s, --socket string          fail to ban socket (default /var/run/fail2ban/fail2ban.sock)

Use "fail2ban-dashboard [command] --help" for more information about a command.

```

### Docker

With Docker use

`docker run --user=root -v /var/run/fail2ban/fail2ban.sock:/var/run/fail2ban/fail2ban.sock:ro -p 3000:3000 ghcr.io/webishdev/fail2ban-dashboard:latest`

The `root` user is necessary as by default the `fail2ban` socket is only accessible for the `root` user.

## Dashboard

When started, check http://localhost:3000/

Basic authentication can be enabled with the `--auth-user` and/or `--auth-password` flags.  
When only `--auth-user` is provided, the password will be generated and show in the logs/console.  
When only `--auth-password` is provided, the user will be named `admin`.

## Inspired by

- https://github.com/fail2ban/fail2ban
- https://gitlab.com/hctrdev/fail2ban-prometheus-exporter/-/tree/main?ref_type=heads
- https://github.com/VerifiedJoseph/intruder-alert?tab=readme-ov-file