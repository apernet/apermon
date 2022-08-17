#!/usr/bin/env bash

LOGFILE="../logs/$TRIGGER.log"
LOCKFILE="../logs/$TRIGGER.lock"

cd "`dirname "$0"`"

{
    flock 200
    ./summary.sh >> "$LOGFILE"
    echo >> "$LOGFILE"
} 200> "$LOCKFILE"