#ifndef APERMON_NET_H
#define APERMON_NET_H
#include <unistd.h>
#include "config.h"
#include "context.h"
#define MAX_LISTENS 128
#define MAX_EPOLL_EVENTS 16

typedef ssize_t (*apermon_net_handler)(const uint8_t *pkt, size_t pktsz);

typedef struct _apermon_net_context {
    apermon_net_handler handler;
    int fd;
} apermon_net_context;

int init_servers(const apermon_config *config, const apermon_net_handler handlers[]);
int start_servers();
int stop_servers(int silent);
void free_severs();

#endif // APERMON_NET_H

