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
%token PREFIXES SLASH
%token ACTIONS SCRIPT EVENTS BAN UNBAN
%token TRIGGERS NETWORKS DIRECTIONS INGRESS EGRESS AGGREGATE_TYPE HOST NET ACTION
%token THRESHOLDS BPS PPS K M G
%token FILTER AND OR NOT SOURCE DESTINATION IN_INTERFACE OUT_INTERFACE PROTOCOL TCP UDP SOURCE_PORT DESTINATION_PORT

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
    | PREFIXES LBRACE prefix_list RBRACE
    | ACTIONS LBRACE action_list RBRACE
    | TRIGGERS LBRACE trigger_list RBRACE

trigger_list: trigger | trigger_list trigger

trigger: IDENT LBRACE trigger_options RBRACE

trigger_options: trigger_option | trigger_options trigger_option

trigger_option
    : NETWORKS LBRACK network_list RBRACK SEMICOLON
    | MIN_BAN_TIME NUMBER SEMICOLON
    | DIRECTIONS LBRACK direction_list RBRACK SEMICOLON
    | AGGREGATE_TYPE HOST SEMICOLON
    | AGGREGATE_TYPE NET SEMICOLON
    | THRESHOLDS LBRACE threshold_list RBRACE
    | FILTER LBRACE filter_list RBRACE
    | ACTION IDENT SEMICOLON

network_list: network | network_list network

network: IDENT

direction_list: direction | direction_list direction

direction
    : INGRESS
    | EGRESS

threshold_list: threshold | threshold_list threshold

threshold
    : BPS NUMBER SEMICOLON
    | BPS NUMBER K SEMICOLON
    | BPS NUMBER M SEMICOLON
    | BPS NUMBER G SEMICOLON
    | PPS NUMBER SEMICOLON
    | PPS NUMBER K SEMICOLON
    | PPS NUMBER M SEMICOLON
    | PPS NUMBER G SEMICOLON
    | BPS NUMBER DOT NUMBER K SEMICOLON
    | BPS NUMBER DOT NUMBER M SEMICOLON
    | BPS NUMBER DOT NUMBER G SEMICOLON
    | PPS NUMBER DOT NUMBER K SEMICOLON
    | PPS NUMBER DOT NUMBER M SEMICOLON
    | PPS NUMBER DOT NUMBER G SEMICOLON

filter_list: filter | filter_list filter

filter
    : AND LBRACE filter_list RBRACE
    | OR LBRACE filter_list RBRACE
    | NOT LBRACE filter_list RBRACE
    | SOURCE IDENT SEMICOLON
    | DESTINATION IDENT SEMICOLON
    | IN_INTERFACE IDENT SEMICOLON
    | OUT_INTERFACE IDENT SEMICOLON
    | PROTOCOL NUMBER SEMICOLON
    | PROTOCOL TCP SEMICOLON
    | PROTOCOL UDP SEMICOLON
    | SOURCE_PORT NUMBER SEMICOLON
    | DESTINATION_PORT NUMBER SEMICOLON

action_list: action | action_list action

action: IDENT LBRACE action_options RBRACE {
    ERR_IF_NULL(end_action($1));
    free($1);
}

action_options: action_option | action_options action_option

action_option
    : SCRIPT QUOTED_STRING LBRACE script_options RBRACE {
        ERR_IF_NULL(end_action_script($2));
        free($2);
    }

script_options: script_option | script_options script_option

script_option
    : EVENTS LBRACK script_events RBRACK SEMICOLON

script_events: script_event | script_events script_event

script_event
    : BAN {
        get_current_action_script()->flags |= APERMON_SCRIPT_EVENT_BAN;
    }
    | UNBAN {
        get_current_action_script()->flags |= APERMON_SCRIPT_EVENT_UNBAN;
    }

prefix_list: prefixes | prefix_list prefixes

prefixes: IDENT LBRACE prefix RBRACE {
    ERR_IF_NULL(end_prefix_list($1));
    free($1);
}

prefix
    : IP SLASH NUMBER SEMICOLON {
        ERR_IF_NULL(add_prefix_inet(&$1, $3));
    }
    | IP6 SLASH NUMBER SEMICOLON {
        ERR_IF_NULL(add_prefix_inet6(&$1, $3));
    }

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