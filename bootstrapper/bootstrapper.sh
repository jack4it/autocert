#!/bin/sh

set -e
#set -x
#export STEPDEBUG=1

#echo "<ENV>"
#env
#echo "</ENV>"

# Download the root certificate and set permissions
step ca root $STEP_ROOT --force
chmod 644 $STEP_ROOT

if [ "$ROOT_ONLY" == "true" ]; then
  echo "fetch root certificate only; exiting..."
  exit
fi

#step certificate inspect $STEP_ROOT --short
#step certificate inspect https://"${AUTOCERT_SVC:-autocert.ca.svc}" --roots $STEP_ROOT --short

saToken=$(cat "${SA_TOKEN:-/var/run/secrets/tokens/autocert-token}")
token=$(curl --cacert $STEP_ROOT -H "Authorization: Bearer $saToken" https://"${AUTOCERT_SVC:-autocert.ca.svc}"/token)

if [ "$DURATION" == "" ]; then
  step ca certificate $COMMON_NAME $CRT $KEY --token $token
else
  step ca certificate --not-after $DURATION $COMMON_NAME $CRT $KEY --token $token
fi
chmod 644 $CRT $KEY
