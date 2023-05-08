#!/usr/bin/env bash

TOP_FLOWS_COUNT="${TOP_FLOWS_COUNT:-10}"

[ "$TYPE" = "ban" ] && {
    printf '[%s banned a %s]\n\n' "$TRIGGER" "$AGGREGATOR" 
    printf '%s: %s\n' "$AGGREGATOR" "$TARGET"
    printf 'prefix-list: %s > %s\n' "$NET" "$PREFIX"
    printf 'in: %d Mbps, %d pps\n' "$((IN_BPS / 1000000))" "$IN_PPS"
    printf 'out: %d Mbps, %d pps\n' "$((OUT_BPS / 1000000))" "$OUT_PPS"
    printf '\n'

    <<< "$FLOWS" sed 1d | sort -t, -k9 -nr | head -n $TOP_FLOWS_COUNT | grep -v '^$' | awk -F, '{ print "[" $4 "]:" $7 " -> [" $5 "]:" $8 "\n    proto " $6 ", frag " $11 ", " $9 / 1000000 " mb, " $10 " pkts" }' 
    [ "`<<< "$FLOWS" sed 1d | wc -l`" -gt $TOP_FLOWS_COUNT ] && {
        printf '(only top %d flow(s) are shown)\n' $TOP_FLOWS_COUNT
    }
}

[ "$TYPE" = "unban" ] && {
    printf '[%s unbanned a %s]\n\n' "$TRIGGER" "$AGGREGATOR" 
    printf '%s: %s\n' "$AGGREGATOR" "$TARGET"
    printf 'prefix-list: %s > %s\n' "$NET" "$PREFIX"
    printf 'peak in: %d Mbps, %d pps\n' "$((PEAK_IN_BPS / 1000000))" "$PEAK_IN_PPS"
    printf 'peak out: %d Mbps, %d pps\n' "$((PEAK_OUT_BPS / 1000000))" "$PEAK_OUT_PPS"
    printf 'first triggered: %s\n' "`date -d @$FIRST_TRIGGERED`"
    printf 'last triggered: %s\n' "`date -d @$LAST_TRIGGERED`"
}