#!/usr/bin/env bash

[[ -z "$API_KEY" || -z "$DOMAIN" || -z "$FROM" || -z "$TO" || -z "$SUBJECT" ]] && {
    echo 'error: missing env'
    exit 1
}

SUBJECT=`eval echo "$SUBJECT"`

cd "`dirname "$0"`"

curl -s --user "$API_KEY" \
    https://api.mailgun.net/v3/"$DOMAIN"/messages \
    -F from="$FROM" \
    -F to="$TO" \
    -F subject="$SUBJECT" \
    -F text="`TOP_FLOWS_COUNT=100 ./summary.sh`"