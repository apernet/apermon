#include <signal.h>
#include "sflow.h"
#include "log.h"
#include "config.h"
#include "net.h"
#include "trigger.h"

static const apermon_net_handler handlers[] = {
    handle_sflow_packet
};

static void handler_signal(__attribute__((unused)) int sig) {
    stop_servers(0);
}

static void help(const char *this) {
    fprintf(stderr, "usage: %s <config-file-path>\n", this);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        help(argv[0]);
        return 1;
    }

    apermon_config *config;
    int ret;

    ret = parse_config(argv[1], &config);

    if (ret < 0) {
        return 1;
    }

    signal(SIGTERM, handler_signal);
    signal(SIGINT, handler_signal);

    ret = init_servers(config, handlers);
    if (ret < 0) {
        return 1;
    }

    init_sflow(config);
    init_triggers(config);

    ret = start_servers();
    if (ret < 0) {
        return 1;
    }

    free_severs();
    free_config(config);

    return 0;
}