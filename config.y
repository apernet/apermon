%{
    #include <stdint.h>
    #include <arpa/inet.h>
    #include <string.h>
    #include <errno.h>
    #include "config.h"
    #include "config-internal.h"
    #include "log.h"
    #include "prefix-list.h"

    extern int yylineno;
    extern int yylex();
    extern FILE *yyin;

    static const char *_filename;

    void yyerror(const char *s);

    #define ERR_IF_NULL(x) if ((x) == NULL) { \
        store_retval(-1);\
        log_error("internal error while parsing config file.\n");\
        YYERROR;\
    }
%}

%locations
%define parse.error verbose

%union {
    uint64_t u64;
    struct in_addr in_addr;
    struct in6_addr in6_addr;
    char *str;
}

%token OPTIONS LISTEN MIN_BAN_TIME
%token LBRACE RBRACE SEMICOLON LBRACK RBRACK
%token SFLOW V5
%token AGENTS ADDRESSES
%token INTERFACES IFINDEXES DOT

%token <u64> NUMBER
%token <str> IDENT QUOTED_STRING
%token <in_addr> IP
%token <in6_addr> IP6

%%
config: config_item | config config_item

config_item
    : OPTIONS LBRACE options RBRACE
    | AGENTS LBRACE agent_list RBRACE
    | INTERFACES LBRACE iface_list RBRACE

iface_list: iface | iface_list iface

iface: IDENT LBRACE iface_options RBRACE {
    ERR_IF_NULL(end_interface($1));
    free($1);
}

iface_options
    : IFINDEXES LBRACK iface_indexes RBRACK SEMICOLON

iface_indexes: iface_index | iface_indexes iface_index

iface_index: IDENT DOT NUMBER {
    ERR_IF_NULL(add_ifindex($1, $3));
    free($1);
}

agent_list: agent | agent_list agent

agent: IDENT LBRACE agent_options RBRACE {
    ERR_IF_NULL(end_agent($1));
    free($1);
}

agent_options: agent_option | agent_options agent_option

agent_option
    : ADDRESSES LBRACK agent_addresses RBRACK SEMICOLON

agent_addresses: agent_address | agent_addresses agent_address

agent_address
    : IP {
        ERR_IF_NULL(add_agent_address_inet(&$1));
    }
    | IP6 {
        ERR_IF_NULL(add_agent_address_inet6(&$1));
    }

options: option_item | option_item options

option_item
    : LISTEN IDENT NUMBER listen_args SEMICOLON {
        ERR_IF_NULL(end_listen($2, $3));
        free($2);
    }
    | LISTEN QUOTED_STRING NUMBER listen_args SEMICOLON {
        ERR_IF_NULL(end_listen($2, $3));
        free($2);
    }
    | LISTEN IP NUMBER listen_args SEMICOLON {
        char addr[INET_ADDRSTRLEN + 1];
        memset(addr, 0, sizeof(addr));

        if (inet_ntop(AF_INET, &$2, addr, INET_ADDRSTRLEN) == NULL) {
            log_fatal("inet_ntop(): %s\n", strerror(errno));
            YYERROR;
        }

        ERR_IF_NULL(end_listen(addr, $3));
    }
    | LISTEN IP6 NUMBER listen_args SEMICOLON {
        char addr[INET6_ADDRSTRLEN + 1];
        memset(addr, 0, sizeof(addr));

        if (inet_ntop(AF_INET6, &$2, addr, INET6_ADDRSTRLEN) == NULL) {
            log_fatal("inet_ntop(): %s\n", strerror(errno));
            YYERROR;
        }

        ERR_IF_NULL(end_listen(addr, $3));
    }
    | MIN_BAN_TIME NUMBER SEMICOLON {
        get_config()->min_ban_time = $2;
    }

listen_args
    : SFLOW V5 {
        new_listen()->proto = APERMON_LISTEN_SFLOW_V5;
    }
%%

int parse_config(const char *filename, apermon_config **config) {
    _filename = filename;

    FILE *f = fopen(filename, "r");
    if (!f) {
        log_fatal("failed to open config file %s", filename);
        return -1;
    }

    start_config();

    yyin = f;
    yyparse();
    fclose(f);

    *config = get_config();

    return get_retval();
}

void yyerror(const char *s) {
    log_fatal("%s:%d - %s\n", _filename, yylineno, s);
    store_retval(-1);
}