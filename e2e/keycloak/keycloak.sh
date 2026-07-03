#!/bin/bash

# login with admin/admin
# http://localhost:8080/admin

# http://localhost:8080/realms/demo/.well-known/openid-configuration
docker run --rm -it \
  -p 8080:8080 \
  -e KEYCLOAK_ADMIN=admin \
  -e KEYCLOAK_ADMIN_PASSWORD=admin \
  -v "$(pwd)/realms.json:/opt/keycloak/data/import/realms.json:ro" \
  quay.io/keycloak/keycloak:latest \
  start-dev --import-realm