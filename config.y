%{
    #include <stdint.h>
    #include <arpa/inet.h>
    #include <string.h>
    #include <errno.h>
    #include "config.h"
    #include "log.h"
    #include "apermon.h"

    extern int yylineno;
    extern int yylex();
    extern FILE *yyin;

    static int _retval;
    static apermon_config *_config;
    static const char *_filename;

    static struct addrinfo _gai_hints;

    static apermon_config_listens *_current_listen;

    void yyerror(const char *s);

    static apermon_config *new_config();
    static apermon_config_listens *new_listen();
    static apermon_config_listens *config_listen(const char *host, uint16_t port);
%}

%locations
%define parse.error verbose

%union {
    uint64_t u64;
    struct in_addr in_addr;
    struct in6_addr in6_addr;
    char *str;
}

%token OPTIONS
%token LISTEN
%token MIN_BAN_TIME

%token LBRACE
%token RBRACE
%token SEMICOLON
%token SFLOW
%token V5

%token <u64> NUMBER
%token <str> IDENT
%token <str> QUOTED_STRING
%token <in_addr> IP
%token <in6_addr> IP6

%%
config: config_item | config config_item

config_item
    : OPTIONS LBRACE options RBRACE

options: option_item | option_item options

option_item
    : LISTEN IDENT NUMBER listen_args SEMICOLON {
        if (config_listen($2, $3) == NULL) {
            YYERROR;
        }

        free($2);
    }
    | LISTEN QUOTED_STRING NUMBER listen_args SEMICOLON {
        if (config_listen($2, $3) == NULL) {
            YYERROR;
        }

        free($2);
    }
    | LISTEN IP NUMBER listen_args SEMICOLON {
        char addr[INET_ADDRSTRLEN + 1];
        memset(addr, 0, sizeof(addr));

        if (inet_ntop(AF_INET, &$2, addr, INET_ADDRSTRLEN) == NULL) {
            log_fatal("inet_ntop(): %s\n", strerror(errno));
            YYERROR;
        }

        if (config_listen(addr, $3) == NULL) {
            YYERROR;
        }
    }
    | LISTEN IP6 NUMBER listen_args SEMICOLON {
        char addr[INET6_ADDRSTRLEN + 1];
        memset(addr, 0, sizeof(addr));

        if (inet_ntop(AF_INET6, &$2, addr, INET6_ADDRSTRLEN) == NULL) {
            log_fatal("inet_ntop(): %s\n", strerror(errno));
            YYERROR;
        }

        if (config_listen(addr, $3) == NULL) {
            YYERROR;
        }
    }
    | MIN_BAN_TIME NUMBER SEMICOLON {
        _config->min_ban_time = $2;
    }

listen_args
    : SFLOW V5 {
        new_listen()->proto = APERMON_LISTEN_SFLOW_V5;
    }
%%

static apermon_config *new_config() {
    apermon_config *config = (apermon_config *) malloc(sizeof(apermon_config));
    config->listens = NULL;
    return config;
}

static apermon_config_listens *new_listen() {
    apermon_config_listens *l = _config->listens, *prev = NULL;
    while (l != NULL) {
        prev = l;
        l = l->next;
    }

    if (prev == NULL) {
        _current_listen = _config->listens = (apermon_config_listens *) malloc(sizeof(apermon_config_listens));
    } else {
        _current_listen = prev->next = (apermon_config_listens *) malloc(sizeof(apermon_config_listens));
    }

    _current_listen->next = NULL;

    return _current_listen;
}

static apermon_config_listens *config_listen(const char *host, uint16_t port) {
    char port_str[6];
    memset(port_str, 0, sizeof(port_str));
    sprintf(port_str, "%u", port);

    int ret = getaddrinfo(host, port_str, &_gai_hints, &_current_listen->addr);

    if (ret != 0) {
        log_fatal("getaddrinfo() on \"%s\" failed: %s\n", host, gai_strerror(ret));
        return NULL;
    }

    return _current_listen;
}

int parse_config(const char *filename, apermon_config **config) {
    _filename = filename;
    _config = new_config();
    _retval = 0;

    memset(&_gai_hints, 0, sizeof(struct addrinfo));
    _gai_hints.ai_family = AF_UNSPEC;
    _gai_hints.ai_socktype = SOCK_DGRAM;
    _gai_hints.ai_flags = AI_PASSIVE;
    _gai_hints.ai_protocol = IPPROTO_UDP;
    _gai_hints.ai_canonname = NULL;
    _gai_hints.ai_addr = NULL;
    _gai_hints.ai_next = NULL;

    FILE *f = fopen(filename, "r");
    if (!f) {
        log_fatal("failed to open config file %s", filename);
        return -1;
    }

    yyin = f;

    yyparse();
    fclose(f);

    *config = _config;

    return _retval;
}

void yyerror(const char *s) {
    log_fatal("%s:%d - %s\n", _filename, yylineno, s);
    _retval = -1;
}