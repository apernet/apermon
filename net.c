#include <errno.h>
#include <string.h>
#include <arpa/inet.h>
#include "net.h"
#include "hash.h"
#include "log.h"

static int _running;
static apermon_hash *_servers_tbl; // maps fd -> handler
static int _fds[MAX_LISTENS];
static size_t _nfds;

int init_servers(const apermon_config *config, const apermon_net_handler handlers[]) {
    _running = 0;
    _nfds = 0;
    _servers_tbl = new_hash();

    apermon_config_listens *l = config->listens;
    const struct addrinfo *i;
    int fd, ret;
    void *oldval = NULL;

    while (l != NULL) {
        if (l->addr == NULL) {
            log_fatal("internal error: got listen w/o addrinfo.\n");
            return -1;
        }
        
        for (i = l->addr; i != NULL; i = i->ai_next) {
            fd = socket(i->ai_family, i->ai_socktype, i->ai_protocol);
            if (fd < 0) {
                log_fatal("socket(): %s\n", strerror(errno));
                return -1;
            }

            ret = bind(fd, i->ai_addr, i->ai_addrlen);
            if (ret < 0) {
                log_fatal("bind(): %s\n", strerror(errno));
                return -1;
            }

            hash32_add_or_update(_servers_tbl, (uint32_t *) &fd, handlers[l->proto], &oldval);
            if (oldval != NULL) {
                log_fatal("internal error: server map fd conflict.\n");
                return -1;
            }

            char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
            if (getnameinfo(i->ai_addr, i->ai_addrlen, hbuf, sizeof(hbuf), sbuf, sizeof(sbuf), NI_NUMERICHOST | NI_NUMERICSERV) == 0) {
                log_info("fd %d created for %s port %s.\n", fd, hbuf, sbuf);
            } else {
                log_fatal("internal error: getnameinfo(): %s\n", strerror(errno));
                return -1;
            }

            _fds[_nfds++] = fd;
        }

        l = l->next;
    }

    log_info("server init ok - %zu fd(s) created.\n", _nfds);

    return 0;
}

int start_servers() {
    _running = 1;

    return 0;
}

int stop_severs() {
    _running = 0;

    return 0;
}

void free_severs() {
    free_hash(_servers_tbl);
}
