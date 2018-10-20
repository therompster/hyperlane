#! /bin/sh
#

USER="rmansour"
PASS="K@ngar0o1!01"
FOREMAN_URL="https://foreman.etc.uspto.gov"
NAME=$1
HOSTGROUP_ID="54"  # Change this to your favorite hostgroup

curl -s -H "Accept:application/json" \
     -k -u $USER:$PASS \
     -d "host[name]=$NAME" -d "host[hostgroup_id]=$HOSTGROUP_ID" \
     -d "host[powerup]=1"  -d "host[build]=1" \
     $FOREMAN_URL/hosts 
