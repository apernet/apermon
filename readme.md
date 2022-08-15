apermon
---

`apermon` is still WIP. Todos:

- Foolproof configuration validation.
- More filter terms?
    - L3: TTL, Frag bit, DSCP, ECN, etc?
    - L4: TCP flags?

`apermon` is a sflow monitoring program. It can be used for various purposes - but its main goal is to allow setting some rules to filter traffics and triggers some external scripts when the set thresholds are reached.

### usage

First, clone the source and compile it. You will need some build tools, `flex` and `bison` to compile this project. On a debian-based system:

```
# apt install build-essential flex bison
```

Then, clone the project and build it:

```
$ git clone https://github.com/apernet/apermon
$ cd apermon
$ make
```

And now you can run it:

```
$ ./apermon
usage: ./apermon <config-file-path>
```

Configuration for a minimal DDoS protection setup may look like this: 

```
options {
    listen 0.0.0.0 6343 sflow v5;
    min-ban-time 300;
}
agents {
    my-switch {
        addresses [ 10.0.0.254 ];
    }
}
prefixes {
    my-network {
        192.0.2.0/24;
        198.18.0.0/15;
    }
    whitelist {
        192.0.2.0/28;
    }
}
actions {
    blackhole {
        script "/opt/apermon/add-and-withdraw-blackhole.sh" {
            events [ ban unban ];
        }
    }
    notify {
        script "/opt/apermon/send-email.sh" {
            events [ ban ];
        }
        script "/opt/apermon/send-telegram.sh" {
            events [ ban unban ];
        }
    }
}
triggers {
    protect-my-network {
        networks [ my-network ];
        directions [ ingress egress ];
        aggregate-type host;
        thresholds {
            bps 2.5g;
            pps 1m;
        }
        filter {
            not {
                source whitelist;
                destination whitelist;
            }
        }
        actions [ blackhole notify ];
    }
}
```

Let's break it down:

**`options`** - global options. Syntax:

```
options {
    listen <host> <port> <protocol> <protocol-args>;
    min-ban-time <time-in-second>;
    burst-period <time-in-second>;
    status-file "<file-path>" dump-interval <time-in-second>;
}
```

Notes:

- You may have more than one `listen`s.
- Currently, the only supported protocol is `sflow`, and the only sflow arg is `v5`, which specifies sFlow version 5.
- `min-ban-time` sets how long a host or network should be kept "banned" after it stops triggering thresholds. `0` to disable banning.
- `burst-period` sets how long hosts and networks are allowed to burst beyond set thresholds without getting banned. `0` to disable bursting. 
- `status-file` dumps bps/pps of each host/net of each trigger to given file every `<time-in-second>` seconds. Status file are just CSV, but can be viewed in a human-friendly way using the `utils/status-viewer` script.

**`agents`** - defines agent(s) to listen samples from. Syntax:

```
agents {
    agent-name-1 {
        addresses [ address1 address2 ... ];
        sample-rate-cap <number>;
    }
    agent-name-2 {
        addresses [ address1 address2 ... ];
    }
    ...
}
```

Notes:

- For sFlow, `addresses` specify the agent address field in the sFlow header.
- `sample-rate-cap` can be optionally configured for agents to cap sample rate at a max value to smooth out agents with erroneous high sample rate spikes that create abnormal traffic spikes. 

**`prefixes`** - defines prefix list(s). Used in various places. Syntax:

```
prefixes {
    prefix-list-1 {
        192.0.2.0/24;
        198.18.0.0/15;
        2001:db8::/32;
        ...
    }
    prefix-list-2 {
        ...
    }
    ...
}
```

**`actions`** - define actions. Later, we will define `triggers`, which, when triggered, will run an action. `actions` section defines what action(s) can be performed.

```
actions {
    action-1 {
        script "script-1-path" {
            events [ ban unban ];
        }
        script "script-2-path" {
            events [ ban ];
        }
        ...
    }
    action-2 {
        ...
    }
    ...
}
```

Notes:

- Possible event types are:
    - `ban`: run the script when an IP address or network should be "banned." (i.e., trigger fired)
    - `unban`: run the script when an IP address or network should be "unbanned." 
- For `ban` events, the following environment variables are passed to the script (values are just example):
    - `TRIGGER=protect-my-network`: name of the trigger.
    - `TYPE=ban`: type of event. Always `ban` for `ban` event.
    - `AF=1`: address family. `1` - IPv4, `2` - IPv6.
    - `AGGREGATOR=host`: aggergator type. See above. 
    - `ADDR=192.0.2.1`: host/network to be banned.
    - `PREFIX=192.0.2.0/24`: prefix containing the address.
    - `NET=my-network`: name of the network.
    - `IN_PPS=114514`: inbound pps to the host/network.
    - `OUT_PPS=1919810`: outbound pps from the host/network.
    - `IN_BPS=171771000`: inbound bps to the host/network.
    - `OUT_BPS=2879715000`: outbound bps from the host/network.
    - `FLOWS=...`: csv of recent (upto 100) flow records from/to this host/network. Columns:
        - `af`: address family. `1` - IPv4, `2` - IPv6.
        - `in_ifindex`: input interface index.
        - `out_ifindex`: out interface index.
        - `src`: source IP / IPv6 address.
        - `dst`: dst IP / IPv6 address.
        - `proto`: IP protocol / IPv6 next header.
        - `sport`: layer 4 src port.
        - `dport`: layer 4 dst port.
        - `bytes`: number of bytes.
        - `packets`: number of packets.
- For `unban` events, the following environment variables are passed to the script (values are just example):
    - `TRIGGER=protect-my-network`: name of the trigger.
    - `TYPE=unban`: type of event. Always `unban` for `unban` event.
    - `AF=1`: address family. `1` - IPv4, `2` - IPv6.
    - `AGGREGATOR=host`: aggergator type. See above. 
    - `FIRST_TRIGGERED=1660166143`: timestamp of initial trigger.
    - `LAST_TRIGGERED=1660169743`: timestamp of last trigger.
    - `ADDR=192.0.2.1`: host/network to be unbanned.
    - `PREFIX=192.0.2.0/24`: prefix containing the address.
    - `NET=my-network`: name of the network.
    - `PEAK_IN_PPS=114514`: peak inbound pps to the host/network.
    - `PEAK_OUT_PPS=1919810`: peak outbound pps from the host/network.
    - `PEAK_IN_BPS=171771000`: peak inbound bps to the host/network.
    - `PEAK_OUT_BPS=2879715000`: peak outbound bps from the host/network.

**`triggers`** - defines triggers. i.e., when to do what. Syntax:

```
triggers {
    trigger-name-1 {
        min-ban-time <time-in-second>;
        burst-period <time-in-second>;
        networks [ <prefix-name-1> <prefix-name-2> ... ];
        directions [ ingress egress ];
        aggregate-type <host|net>;
        thresholds {
            bps <number>[k|m|g];
            pps <number>[k|m|g];
        }
        filter {
            ...
        }
        actions [ <action-name-1> <action-name-2> ... ];
    }
}
```

Notes:

- `min-ban-time` and `burst-period` override the global value if set.
- `networks` should be the name of a prefix list defined in `prefixes`.
- Possible values of `directions` are:
    - `ingress`: to the network(s) and/or host(s) defined in `networks`.
    - `egress`: from the network(s) and/or host(s) defined in `networks`.
- Possible values of `aggregate-type` are:
    - `host`: aggregate traffic by hosts (i.e., /32 or /128 for inet and inet6)
    - `net`: aggregate traffic by nets (networks defined above under "networks")
- Possible values of `thresholds` are:
    - `bps <number>[k|m|g];`: trigger if aggregated traffic greater than given bps.
    - `pps <number>[k|m|g];`: trigger if aggregated traffic greater than given pps.
- If both `pps` and `bps` are set for `thresholds`, the trigger will fire if either threshold is reached.
- Possible `filter` terms:
    - `and { ... }`: logical and. All sub-term(s) must be true for it to be true.
    - `or { ... }`: logical or. Ture if any sub-term is true.
    - `not { ... }`: logical not. False if any sub-term is true.
    - `source <prefix-list-name>;`: source inet/inet6 address.
    - `destination <prefix-list-name>;`: destination inet/inet6 address.
    - `in-interface <interface-name>;`: input interface.
    - `out-interface <interface-name>;`: output interface.
    - `protocol <udp|tcp|number>;`: inet protocol number / inet6 next-header number.
    - `source-port <number>;`: layer 4 source port.
    - `destination-port <number>;`: layer 4 destination port.
- The three logical operators (`and`, `or`, and `not`) may be nested to build a more complex filter. If the root term under `filter {}` is not one of the logical operators, `and` is assumed.
- `actions` should be a list of names of actions defined in `actions`.

**`interfaces`** - while not used above, you may also define named interfaces: 

```
interfaces {

    # interface name
    ix-lacp {
        # interface ifindexes - format "<agent_name>.<ifindex>"
        ifindexes [ my-switch.100 my-switch.101 ];
    }

    cheap-transit {
        ifindexes [ my-switch.102 ];
    }

    costly-95th-transit {
        ifindexes [ my-switch.103 ];
    }

}
```

This will allow you to use them in a filter:

```
triggers {

    save-money {
        min-ban-time 3600;
        networks [ customer-a-that-pays-way-too-less customer-b-that-pays-way-too-less ];

        # meaning all hosts on the two networks above are added together and becomes two "hosts," one for each net.
        aggregate-type net;

        directions [ ingress egress ];

        filter {
            or {
                in-interface costly-95th-transit;
                out-interface costly-95th-transit;
            }
        }

        thresholds {
            bps 2.5g;
        }

        actions [ witdraw-prefix-from-costly-transit ];
    }

}
```

See `apermon.conf.example` for a more complete example. 