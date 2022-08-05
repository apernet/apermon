#ifndef APERMON_NET_H
#define APERMON_NET_H
#include <unistd.h>
#include "config.h"
#include "context.h"
#define MAX_LISTENS 128

typedef ssize_t (*apermon_net_handler)(const uint8_t *pkt, size_t pktsz);

int init_servers(const apermon_config *config, const apermon_net_handler handlers[]);
int start_servers();
int stop_severs();
void free_severs();

#endif // APERMON_NET_H

