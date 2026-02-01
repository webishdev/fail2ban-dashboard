#!/bin/bash

set -euo pipefail

usage() {
  echo "Usage: $0 {start|stop|dashboard|debug} [fail2ban_version]"
}

ACTION="${1:-}"
if [[ "$ACTION" != "start" && "$ACTION" != "stop" && "$ACTION" != "dashboard" && "$ACTION" != "debug" ]]; then
  usage
  exit 1
fi

FAIL2BAN_VERSION="${2:-1.1.0}"
export FAIL2BAN_VERSION

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
BASE_COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"
DEBUG_COMPOSE_FILE="$SCRIPT_DIR/docker-compose.debug.yml"

set_compose_cmd() {
  COMPOSE_CMD=(docker compose -f "$BASE_COMPOSE_FILE")
  if [[ "${1:-}" == "debug" ]]; then
    if [[ ! -f "$DEBUG_COMPOSE_FILE" ]]; then
      echo "Missing debug compose file: $DEBUG_COMPOSE_FILE"
      exit 1
    fi
    COMPOSE_CMD+=(-f "$DEBUG_COMPOSE_FILE")
  fi
}

set_compose_cmd

has_running_containers() {
  [[ -n "$("${COMPOSE_CMD[@]}" ps -q)" ]]
}

prepare_after_start() {
  echo "checking fail2ban version"
  FOUND_FAIL2BAN_VERSION=$("${COMPOSE_CMD[@]}" exec fail2ban fail2ban-client version)
  echo "fail2ban version: $FOUND_FAIL2BAN_VERSION"

  echo "Executing ban script"
  "${COMPOSE_CMD[@]}" exec fail2ban /script/ban.sh

  echo "Show current fail2ban status"
  "${COMPOSE_CMD[@]}" exec fail2ban fail2ban-client status
}

prepare_debug() {
    "${COMPOSE_CMD[@]}" exec dashboard go install github.com/go-delve/delve/cmd/dlv@latest
}

if [[ "$ACTION" == "start" ]]; then
  if [[ ! -x "$ROOT_DIR/bin/fail2ban-dashboard" ]]; then
    echo "Missing executable: $ROOT_DIR/bin/fail2ban-dashboard"
    echo "Build the dashboard before starting."
    exit 1
  fi
  if has_running_containers; then
    "${COMPOSE_CMD[@]}" down
  fi
  "${COMPOSE_CMD[@]}" up -d

  prepare_after_start

elif [[ "$ACTION" == "debug" ]]; then
  set_compose_cmd debug
  if has_running_containers; then
    "${COMPOSE_CMD[@]}" down
  fi
  "${COMPOSE_CMD[@]}" up -d

  prepare_after_start
  prepare_debug
  "${COMPOSE_CMD[@]}" exec dashboard /script/debug.sh

elif [[ "$ACTION" == "stop" ]]; then
  if [[ -f "$DEBUG_COMPOSE_FILE" ]]; then
    set_compose_cmd debug
    if ! has_running_containers; then
      set_compose_cmd
    fi
  fi
  if has_running_containers; then
    "${COMPOSE_CMD[@]}" down
  else
    echo "No running containers to stop."
  fi

elif [[ "$ACTION" == "dashboard" ]]; then
  if has_running_containers; then
    "${COMPOSE_CMD[@]}" exec fail2ban /app/fail2ban-dashboard
  else
    echo "No running containers, start before continuing"
    usage
    exit 1
  fi
fi
