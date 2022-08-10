apermon
---

`apermon` is still now WIP.

`apermon` is a sflow monitoring program. It can be used for various purposes - but its main goal is to allow setting some rules to filter traffics and triggers some external scripts when the set thresholds are reached. A minimal DDoS protection setup may look like this: 

```
# define options - the basics.
options {
    listen 0.0.0.0 6343 sflow v5;
    min-ban-time 300;
}

# define agents - who to listen to?
agents {
    my-switch {
        # note: this is the address in sflow header, not ip header of the sflow packet.
        addresses [ 10.0.0.254 ];
    }
}

# define prefixes - what to look for?
prefixes {

    # name the network
    my-network {
        192.0.2.0/24;
        198.18.0.0/15;
    }

    whitelist {
        192.0.2.0/28;
    }

}

# define actions - what can be done?
actions {

    # name the action
    blackhole {
        # each action can have one or more scripts.

        script "/opt/apermon/add-and-withdraw-blackhole.sh" {
            # when to run the script? ban - when ban; unban - when unban.
            events [ ban unban ];
        }

        script "/opt/apermon/send-email.sh" {
            events [ ban ];
        }
    }

}

# define triggers - when to do what?
triggers {

    # name the trigger
    protect-my-network {

        # what network(s) to look for? define them under "prefixes" above.
        networks [ my-network ];

        # what direction to look for? egress - from the network(s) above; ingress - to the network(s) above.
        directions [ ingress egress ];

        # how to aggregate traffic?
        # host - aggregate traffic for a /32 or /128 (single inet/inet6 address)
        # net - aggregate traffic for all host(s) defined in "networks"
        aggregate-type host;

        # when to run script?
        # bps - bit per second; pps = packet per second
        thresholds {
            bps 2.5g;
            pps 1m;
        }
        
        # filter traffic - keeps only flow records matching the given condition(s).
        filter {
            not {
                source whitelist;
                destination whitelist;
            }
        }

        # what to do when trigger fires?
        action blackhole;
    }

}
```

You may also define named interfaces: 

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

        action witdraw-prefix-from-costly-transit;
    }

}
```

See `apermon.conf.example` for a more complete example. Other possible filter terms are:

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

The three logical operators (`and`, `or`, and `not`) may be nested to build a more complex filter. If the root term under `filter {}` is not one of the logical operators, `and` is assumed.

