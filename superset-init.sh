#!/usr/bin/env bash

STEP_CNT=3

echo_step() {
cat <<EOF
######################################################################
Init Step ${1}/${STEP_CNT} [${2}] -- ${3}
######################################################################
EOF
}
ADMIN_PASSWORD="admin"

# Initialize the database
echo_step "1" "Starting" "Applying DB migrations"
superset db upgrade
echo_step "1" "Complete" "Applying DB migrations"

# Create an admin user
echo_step "2" "Starting" "Setting up admin user ( admin / $ADMIN_PASSWORD )"
superset fab create-admin \
              --username admin \
              --firstname Superset \
              --lastname Admin \
              --email admin@superset.com \
              --password $ADMIN_PASSWORD
echo_step "2" "Complete" "Setting up admin user"
# Create default roles and permissions
echo_step "3" "Starting" "Setting up roles and perms"
superset init
echo_step "3" "Complete" "Setting up roles and perms"

flask run -p 8088 --with-threads --reload --debugger --host=0.0.0.0
