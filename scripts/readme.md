apermon script examples
---

Here are some ready-to-use example scripts that can be added to actions. 

### exabgp.sh

Announce / withdraw blackhole routes with [exabgp](https://github.com/Exa-Networks/exabgp). First [install exabgp 4.x](https://github.com/Exa-Networks/exabgp#installation) and socat. On a debian-based system:

```
# apt install exabgp socat
```

Once installed, configure exabgp with your details. If you installed `exabgp` with a package manager like `apt`, the configuration file is likely `/etc/exabgp/exabgp.conf`. Example configuration:

```
process apermon {
    run /usr/bin/socat stdout pipe:/var/run/exabgp.sock;
    encoder json;
}

neighbor 10.66.66.1 {
    router-id 10.66.66.66;
    local-address 10.66.66.66;
    local-as 65001;
    peer-as 65001;

    api {
        processes [ apermon ];
    }
}
```

Then add the script as a script for your action and set environment variables accordingly:

```
actions {
    my-action {
        script "/path/to/exabgp.sh" {
            event [ ban unban ];
            env {
                EXABGP_CONTROL_SOCKET   = "/var/run/exabgp.sock";
                EXABGP_COMMUNITIES      = "65535:666 65001:666";
                EXABGP_NEXTHOP          = "10.66.66.66";
                LOCKFILE                = "/tmp/apermon-exabgp.lock";
            }
        }
        ...
    }
    ...
}
```

The variables should be self-explanatory. Note that: 

- `EXABGP_CONTROL_SOCKET` should be the named pipe you created with socat in your exabgp configuration. You should configure proper permissions so this file is writeable by `apermon`.
- `LOCKFILE` can be any file that's writable by `apermon`. 

### summary.sh

Prints summary of the event when called. It's meant to be called by other scripts (e.g., mailgun, telegram) to generate the message body. 

### mailgun.sh

Sends email with mailgun. Add the script as a script for your action and set environment variables accordingly:

```
actions {
    my-action {
        script "/path/to/mailgun.sh" {
            event [ ban unban ];
            env {
                API_KEY = "api:key-...";
                DOMAIN  = "noreply.example.com";
                FROM    = "AperMon <apermon@noreply.example.com>";
                TO      = "noc@example.com";
                SUBJECT = "[apermon] $TRIGGER: $TYPE $TARGET";
            }
        }
        ...
    }
    ...
}
```

Note that:

- The script must be kept in the same directory with `summary.sh` script.
- `SUBJECT` env will be `eval` by the script (i.e., `eval echo "$SUBJECT"`) to expand the variables.

### telegram.sh

Sends message to [Telegram](https://telegram.org) chat with [Telegram bot API](https://core.telegram.org/bots). Add the script as a script for your action and set environment variables accordingly:

```
actions {
    my-action {
        script "/path/to/telegram.sh" {
            event [ ban unban ];
            env {
                BOT_TOKEN = "...";
                CHAT_ID   = "...";
            }
        }
        ...
    }
    ...
}
```

Note that the script must be kept in the same directory with `summary.sh` script.