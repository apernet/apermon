#!/usr/bin/env bash

TOP_FLOWS_COUNT="${TOP_FLOWS_COUNT:-10}"

[ "$TYPE" = "ban" ] && {
    printf '[a %s in "%s" is triggering ban]\n\n' "$AGGREGATOR" "$NET" 
    printf 'by: %s\n' "$TRIGGER"
    printf '%s: %s\n' "$AGGREGATOR" "$ADDR"
    printf 'prefix: %s\n' "$PREFIX"
    printf 'in: %d Mbps, %d pps\n' "$((IN_BPS / 1000000))" "$IN_PPS"
    printf 'out: %d Mbps, %d pps\n' "$((OUT_BPS / 1000000))" "$OUT_PPS"
    printf '\n'

    <<< "$FLOWS" sed 1d | sort -t, -k9 -nr | head -n $TOP_FLOWS_COUNT | grep -v '^$' | awk -F, '{ print "[" $4 "]:" $7 " -> [" $5 "]:" $8 "\n    proto " $6 ", " $9 / 1000000 " mb, " $10 " pkts" }' 
    [ "`<<< "$FLOWS" sed 1d | wc -l`" -gt $TOP_FLOWS_COUNT ] && {
        printf '(only top %d flow(s) are shown)\n' $TOP_FLOWS_COUNT
    }
}

[ "$TYPE" = "unban" ] && {
    printf '[a %s in "%s" is triggering unban]\n\n' "$AGGREGATOR" "$NET" 
    printf 'by: %s\n' "$TRIGGER"
    printf '%s: %s\n' "$AGGREGATOR" "$ADDR"
    printf 'prefix: %s\n' "$PREFIX"
    printf 'peak in: %d Mbps, %d pps\n' "$((PEAK_IN_BPS / 1000000))" "$PEAK_IN_PPS"
    printf 'peak out: %d Mbps, %d pps\n' "$((PEAK_OUT_BPS / 1000000))" "$PEAK_OUT_PPS"
    printf 'first triggered: %s\n' "`date -d @$FIRST_TRIGGERED`"
    printf 'last triggered: %s\n' "`date -d @$LAST_TRIGGERED`"
}