#!/usr/bin/env bash

EXABGP_CONTROL_SOCKET='/var/run/exabgp.sock'
EXABGP_COMMUNITIES=(65535:666 65001:666)
EXABGP_NEXTHOP='10.66.66.66'
LOCKFILE='/tmp/apermon-exabgp.lock'

EXABGP_ANNOUNCE_TEMPLATE="announce route %s next-hop $EXABGP_NEXTHOP community [ ${EXABGP_COMMUNITIES[*]} ]\n"
EXABGP_WITHDRAW_TEMPLATE="withdraw route %s next-hop $EXABGP_NEXTHOP\n"

[ ! -p "$EXABGP_CONTROL_SOCKET" ] && {
    echo 'error: exabgp control socket not found.'
    exit 1
}

[ ! -w "$EXABGP_CONTROL_SOCKET" ] && {
    echo 'error: exabgp control socket not writable.'
    exit 1
}

[ "$AGGREGATOR" = "net" ] && targets="$PREFIX"
[ "$AGGREGATOR" = "prefix" ] && targets="$PREFIX"
[ "$AGGREGATOR" = "host" ] && {
    targets="$TARGET"
    [ "$AF" = "1" ] && targets="$targets/32"
    [ "$AF" = "2" ] && targets="$targets/128"
}

[ -z "$targets" ] && {
    echo 'error: missing target(s)'
    exit 1
}

{
    flock 200
    for target in $targets; do {
        [ "$TYPE" = "ban" ] && printf "$EXABGP_ANNOUNCE_TEMPLATE" "$target"  > "$EXABGP_CONTROL_SOCKET"
        [ "$TYPE" = "unban" ] && printf "$EXABGP_WITHDRAW_TEMPLATE" "$target" > "$EXABGP_CONTROL_SOCKET"
    }; done

} 200> "$LOCKFILE"