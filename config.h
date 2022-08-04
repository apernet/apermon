#ifndef APERMON_CONFIG_H
#define APERMON_CONFIG_H
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

enum listen_protocol {
    APERMON_LISTEN_SFLOW_V5,
};

typedef struct _apermon_config_listens {
    struct addrinfo *addr;
    enum listen_protocol proto;
    struct _apermon_config_listens *next;
} apermon_config_listens;

typedef struct _apermon_config {
    apermon_config_listens *listens;
    uint32_t min_ban_time;
} apermon_config;

int parse_config(const char *filename, apermon_config **config);
void free_config(apermon_config *config);

#endif // APERMON_CONFIG_H