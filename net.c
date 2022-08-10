#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include "net.h"
#include "hash.h"
#include "log.h"
#include "trigger.h"

static int _running;
static struct epoll_event _events[MAX_LISTENS], _eavil[MAX_EPOLL_EVENTS];
static size_t _nfds;

int init_servers(const apermon_config *config, const apermon_net_handler handlers[]) {
    _running = 0;
    _nfds = 0;

    apermon_config_listens *l = config->listens;
    apermon_net_context *ctx;
    const struct addrinfo *i;
    int fd, ret;

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

            char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
            if (getnameinfo(i->ai_addr, i->ai_addrlen, hbuf, sizeof(hbuf), sbuf, sizeof(sbuf), NI_NUMERICHOST | NI_NUMERICSERV) == 0) {
                log_info("fd %d created for %s port %s.\n", fd, hbuf, sbuf);
            } else {
                log_fatal("internal error: getnameinfo(): %s\n", strerror(errno));
                return -1;
            }

            ret = fcntl(fd, F_GETFD, 0);
            if (ret < 0) {
                log_fatal("fcntl(): %s\n", strerror(errno));
                return -1;
            }

            ret |= O_NONBLOCK;
            ret = fcntl(fd, F_SETFL, ret);
            if (ret < 0) {
                log_fatal("fcntl(): %s\n", strerror(errno));
                return -1;
            }

            ctx = (apermon_net_context *) malloc(sizeof(apermon_net_context));
            ctx->fd = fd;
            ctx->handler = handlers[l->proto];

            _events[_nfds].data.ptr = ctx;
            _events[_nfds].events = EPOLLIN;
            ++_nfds;
        }

        l = l->next;
    }

    log_info("server init ok - %zu fd(s) created.\n", _nfds);

    return 0;
}

int start_servers() {
    if (_running) {
        log_fatal("internal error: start_servers called twice\n");
        return -1;
    }

    _running = 1;

    int efd, j, ret;
    size_t i;
    ssize_t read_sz, parsed_sz;
    uint8_t buffer[0xffff];
    apermon_net_context *ctx;

    efd = epoll_create1(0);

    if (efd < 0) {
        log_fatal("epoll_create1(): %s\n", strerror(errno));
        return -1;
    }

    for (i = 0; i < _nfds; ++i) {
        ctx = (apermon_net_context *) _events[i].data.ptr;
        ret = epoll_ctl(efd, EPOLL_CTL_ADD, ctx->fd, &_events[i]);

        if (ret < 0) {
            log_fatal("epoll_ctl(): %s\n", strerror(errno));
            return -1;
        }
    }

    while (_running) {
        ret = epoll_wait(efd, _eavil, MAX_EPOLL_EVENTS, 1000);

        if (errno == EINTR) {
            continue;
        }

        if (ret < 0) {
            log_fatal("epoll_wait(): %s\n", strerror(errno));
            return -1;
        }

        triggers_timed_callback();

        for (j = 0; j < ret; ++j) {
            ctx = (apermon_net_context *) _eavil[j].data.ptr;
            read_sz = read(ctx->fd, buffer, sizeof(buffer));

            if (read_sz < 0) {
                log_fatal("read(): %s\n", strerror(errno));
                return -1;
            }

            parsed_sz = ctx->handler(buffer, (size_t) read_sz);

            if (parsed_sz < 0) {
                log_debug("got parse error.\n");
            }

            if (parsed_sz != read_sz) {
                log_debug("parsed packet length (%zu) != read length (%zu).\n", parsed_sz, read_sz);
            }
        }
    }

    return 0;
}

int stop_servers(int silent) {
    size_t i;
    apermon_net_context *ctx;

    if (!silent) {
        log_info("shutting down servers...\n");
    }

    for (i = 0; i < _nfds; ++i) {
        ctx = (apermon_net_context *) _events[i].data.ptr;

        close(ctx->fd);
    }

    _running = 0;
    return 0;
}

void free_severs() {
    size_t i;

    for (i = 0; i < _nfds; ++i) {
        free(_events[i].data.ptr);
    }
}
