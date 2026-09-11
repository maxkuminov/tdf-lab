#!/bin/bash
# =============================================================================
#  Runs ONCE, on the very first boot of tdf-postgres, while its data directory
#  is still empty. Creates a separate role + database for Keycloak so the two
#  consumers of this server share nothing but the postmaster.
#
#  THIS CANNOT BE REPLAYED. docker-entrypoint only runs /docker-entrypoint-initdb.d
#  while the data directory is empty, so if this script fails partway the volume
#  is already initialised and the keycloak database stays missing forever - with
#  a perfectly healthy-looking postgres in front of it.
#
#  That is why tdf-postgres' healthcheck asserts the keycloak database EXISTS in
#  addition to pg_isready: a half-built server never reports healthy, so nothing
#  downstream starts and the cause is visible immediately.
#
#  Recovery is destructive:
#     docker compose down -v          # destroys lab_pgdata
#     docker compose up -d
#  That volume holds BOTH databases - all realm/user AND all policy data.
#  See lab journal §8.
# =============================================================================
set -euo pipefail

: "${KC_DB_USERNAME:?KC_DB_USERNAME must be set}"
: "${KC_DB_PASSWORD:?KC_DB_PASSWORD must be set}"
: "${KC_DB_DATABASE:?KC_DB_DATABASE must be set}"

# psql is invoked by the entrypoint with the superuser ($POSTGRES_USER) on the
# default database. Values are passed as psql variables and quoted with
# :'name' so a password containing quotes cannot break out.
psql -v ON_ERROR_STOP=1 \
     --username "$POSTGRES_USER" \
     --dbname "$POSTGRES_DB" \
     -v kc_user="$KC_DB_USERNAME" \
     -v kc_pass="$KC_DB_PASSWORD" \
     -v kc_db="$KC_DB_DATABASE" <<-'EOSQL'
	SELECT format('CREATE ROLE %I LOGIN PASSWORD %L', :'kc_user', :'kc_pass')
	\gexec
	SELECT format('CREATE DATABASE %I OWNER %I', :'kc_db', :'kc_user')
	\gexec
	-- Keycloak creates its own schema objects in `public` of its own database.
	SELECT format('REVOKE ALL ON DATABASE %I FROM PUBLIC', :'kc_db')
	\gexec
	SELECT format('GRANT ALL ON DATABASE %I TO %I', :'kc_db', :'kc_user')
	\gexec
EOSQL

# The platform runs its own migrations and creates the `opentdf` schema inside
# the POSTGRES_DB database, owned by POSTGRES_USER. Nothing to do for it here.
echo "tdf-lab: created keycloak role '${KC_DB_USERNAME}' and database '${KC_DB_DATABASE}'"
