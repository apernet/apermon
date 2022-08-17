#!/usr/bin/env bash


[[ -z "$BOT_TOKEN" || -z "$CHAT_ID" ]] && {
    echo 'error: missing env'
    exit 1
}

cd "`dirname "$0"`"
curl -s "https://api.telegram.org/$BOT_TOKEN/sendMessage"  -d "chat_id=$CHAT_ID" -d "text=`./summary.sh`"