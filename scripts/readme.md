apermon script examples
---

Here are some ready-to-use example scripts that can be added to actions. 

### exabgp.sh

Announce / withdraw blackhole routes with [exabgp](https://github.com/Exa-Networks/exabgp). First [install exabgp 4.x](https://github.com/Exa-Networks/exabgp#installation) and socat. On a debian-based system:

```
# apt install exabgp socat
```

Once installed, configure exabgp with your details. Example:

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

If you installed `exabgp` with a package manager like `apt`, the configuration file is likely `/etc/exabgp/exabgp.conf`. Next, edit the script to fill in your details:

```bash
EXABGP_CONTROL_SOCKET='/var/run/exabgp.sock'
EXABGP_COMMUNITIES=(65535:666 65001:666)
EXABGP_NEXTHOP='10.66.66.66'
LOCKFILE='/tmp/apermon-exabgp.lock'
```

- `EXABGP_CONTROL_SOCKET` should be the named pipe you created with socat in your exabgp configuration. You should configure proper permissions so this file is writeable by `apermon`.
- `LOCKFILE` can be any file that's writable by `apermon`. 

Then simply add the script as a script for your action:

```
actions {
    my-action {
        script "/path/to/exabgp.sh" {
            event [ ban unban ];
        }
        ...
    }
    ...
}
```

### summary.sh

Prints summary of the event when called. It's meant to be called by other scripts (e.g., mailgun, telegram) to generate the message body. 

### mailgun.sh

Sends email with mailgun. First edit the script to fill in your details:

```bash
API_KEY='api:key-...'
DOMAIN='noreply.example.com'
FROM='AperMon <apermon@noreply.example.com>'
TO='nat@example.com'
SUBJECT="[apermon] $TYPE $ADDR in $PREFIX ($NET)"
```

Then simply add the script as a script for your action:

```
actions {
    my-action {
        script "/path/to/mailgun.sh" {
            event [ ban unban ];
        }
        ...
    }
    ...
}
```

Note that the script must be kept in the same directory with `summary.sh` script.

### telegram.sh

Sends message to [Telegram](https://telegram.org) chat with [Telegram bot API](https://core.telegram.org/bots). First edit the script to fill in your details:

```
BOT_TOKEN=''
CHAT_ID=''
```

Then simply add the script as a script for your action:

```
actions {
    my-action {
        script "/path/to/telegram.sh" {
            event [ ban unban ];
        }
        ...
    }
    ...
}
```

Note that the script must be kept in the same directory with `summary.sh` script.