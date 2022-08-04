#include "net.h"
#include "hash.h"

static int _running;
static apermon_hash *_servers_tbl;

int init_servers(const apermon_config *config, const apermon_net_handler handlers[]) {
    _running = 0;
    _servers_tbl = new_hash();
}

int start_servers() {
    _running = 1;
}

int stop_severs() {
    _running = 0;
}

void free_severs() {
    free_hash(_servers_tbl);
}
