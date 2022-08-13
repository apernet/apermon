apermon script examples
---

Here are some ready-to-use example scripts that can be added to actions. 

### exabgp.sh

Announce / withdraw blackhole routes with [exabgp](https://github.com/Exa-Networks/exabgp).

**TODO**

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