#!/usr/bin/env bash

BOT_TOKEN=''
CHAT_ID=''

cd "`dirname "$0"`"
curl -s "https://api.telegram.org/$BOT_TOKEN/sendMessage"  -d "chat_id=$CHAT_ID" -d "text=`./summary.sh`"