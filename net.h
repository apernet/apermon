#ifndef APERMON_NET_H
#define APERMON_NET_H
#include <unistd.h>
#include "config.h"

typedef size_t (*apermon_net_handler)(size_t pktsz, const uint8_t *pkt);

int init_servers(const apermon_config *config, const apermon_net_handler handlers[]);
int start_servers();
int stop_severs();
void free_severs();

#endif // APERMON_NET_H

