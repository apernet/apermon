#!/usr/bin/env bash

API_KEY='api:key-...'
DOMAIN='noreply.example.com'
FROM='AperMon <apermon@noreply.example.com>'
TO='nat@example.com'
SUBJECT="[apermon] $TRIGGER: $TYPE $TARGET"

cd "`dirname "$0"`"

curl -s --user "$API_KEY" \
    https://api.mailgun.net/v3/"$DOMAIN"/messages \
    -F from="$FROM" \
    -F to="$TO" \
    -F subject="$SUBJECT" \
    -F text="`TOP_FLOWS_COUNT=100 ./summary.sh`"