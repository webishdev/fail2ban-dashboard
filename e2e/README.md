# Manual E2E tests

## Build the application

In the root folder do `make`

## Start the E2E env

In the root or `e2e` folder do `./e2e.sh start`

- Run with a specific `fail2ban` version: `./e2e.sh start 0.11.2`

Access the dashboard at `http://localhost:3000`

## Stop the E2E env

In the root or `e2e` folder do `./e2e.sh stop`

## Start the E2E env in debug mode

In the root or `e2e` folder do `./e2e.sh debug`

Afterward you need to remotely connect a debuger at port `40000`

Access the dashboard at `http://localhost:4000`