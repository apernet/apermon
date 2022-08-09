%{
    #include <stdint.h>
    #include <arpa/inet.h>
    #include <string.h>
    #include <errno.h>
    #include "config.h"
    #include "config-internal.h"
    #include "log.h"
    #include "prefix-list.h"
    #include "condition.h"

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
    double d;
    uint64_t u64;
    struct in_addr in_addr;
    struct in6_addr in6_addr;
    char *str;

    apermon_config_listens *listen;
    apermon_config_agents *agent;
    apermon_config_agent_addresses *agent_address;
    apermon_config_interfaces *interface;
    apermon_config_ifindexes *ifindex;
    apermon_config_prefix_lists *prefix_list;
    apermon_config_prefix_list_elements *prefix_list_element;
    apermon_config_actions *action;
    apermon_config_action_scripts *action_script;
    apermon_config_triggers *trigger;
    apermon_config_prefix_lists_set *prefix_lists_set;
    apermon_cond_func_list *cond_func_list_element;
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
%token <d> DOUBLE
%token <str> IDENT QUOTED_STRING
%token <in_addr> IP
%token <in6_addr> IP6

%type <listen> listen_args option_item_listens option_item_listen
%type <agent> agent agent_list
%type <agent_address> agent_address agent_addresses
%type <interface> iface_options iface iface_list
%type <ifindex> iface_index iface_indexes 
%type <prefix_list> prefix_list prefixes
%type <prefix_list_element> prefix prefix_elements
%type <action> action action_list
%type <action_script> action_script action_scripts
%type <trigger> trigger trigger_list
%type <prefix_lists_set> prefix_lists_set prefix_lists_set_element
%type <cond_func_list_element> filter filter_list
%type <u64> proto_name

%%
config: config_item | config config_item

config_item
    : OPTIONS LBRACE options RBRACE
    | AGENTS LBRACE agent_list RBRACE {
        get_config()->agents = $3;
    }
    | INTERFACES LBRACE iface_list RBRACE {
        get_config()->interfaces = $3;
    }
    | PREFIXES LBRACE prefix_list RBRACE {
        get_config()->prefix_lists = $3;
    }
    | ACTIONS LBRACE action_list RBRACE {
        get_config()->actions = $3;
    }
    | TRIGGERS LBRACE trigger_list RBRACE {
        get_config()->triggers = $3;
    }

trigger_list
    : trigger
    | trigger trigger_list {
        $1->next = $2;
    }

trigger: IDENT LBRACE trigger_options RBRACE {
    $$ = end_trigger($1);
    free($1);
}

trigger_options: trigger_option | trigger_options trigger_option

trigger_option
    : NETWORKS LBRACK prefix_lists_set RBRACK SEMICOLON {
        get_current_trigger()->networks = $3;
    }
    | MIN_BAN_TIME NUMBER SEMICOLON {
        get_current_trigger()->flags |= APERMON_TRIGGER_SET_BAN_TIME;
        get_current_trigger()->min_ban_time = $2;
    }
    | DIRECTIONS LBRACK direction_list RBRACK SEMICOLON
    | AGGREGATE_TYPE HOST SEMICOLON {
        get_current_trigger()->aggregator = APERMON_AGGREGATOR_HOST;
    }
    | AGGREGATE_TYPE NET SEMICOLON {
        get_current_trigger()->aggregator = APERMON_AGGREGATOR_NET;
    }
    | THRESHOLDS LBRACE threshold_list RBRACE
    | FILTER LBRACE filter_list RBRACE {
        apermon_cond_list *l = (apermon_cond_list *) malloc(sizeof(apermon_cond_list));

        memset(l, 0, sizeof(apermon_cond_list));
        l->funcs = $3;
        l->type = APERMON_COND_AND;

        get_current_trigger()->conds = l;
    }
    | ACTION IDENT SEMICOLON {
        apermon_config_actions *action = get_action($2);

        if (action == NULL) {
            store_retval(-1);
            log_error("unknown action '%s'\n", $2);
            YYERROR;
        }

        get_current_trigger()->action = action;
        free($2);
    }

prefix_lists_set
    : prefix_lists_set_element
    | prefix_lists_set_element prefix_lists_set {
        $1->next = $2;
    }

prefix_lists_set_element: IDENT {
    void *pfxlist = get_prefix_list($1);

    if (pfxlist == NULL) {
        store_retval(-1);
        log_error("prefix list '%s' not defined.\n", $1);
        YYERROR;
    }

    $$ = malloc(sizeof(apermon_config_prefix_lists_set));
    memset($$, 0, sizeof(apermon_config_prefix_lists_set));
    $$->prefix_list = pfxlist;
    free($1);
}

direction_list: direction | direction_list direction

direction
    : INGRESS {
        get_current_trigger()->flags |= APERMON_TRIGGER_CHECK_INGRESS;
    }
    | EGRESS {
        get_current_trigger()->flags |= APERMON_TRIGGER_CHECK_EGRESS;
    }

threshold_list: threshold | threshold_list threshold

threshold
    : BPS NUMBER SEMICOLON {
        get_current_trigger()->bps = $2;
    }
    | BPS NUMBER K SEMICOLON {
        get_current_trigger()->bps = $2 * 1000;
    }
    | BPS NUMBER M SEMICOLON {
        get_current_trigger()->bps = $2 * 1000 * 1000;
    }
    | BPS NUMBER G SEMICOLON {
        get_current_trigger()->bps = $2 * 1000 * 1000 * 1000;
    }
    | PPS NUMBER SEMICOLON {
        get_current_trigger()->pps = $2;
    }
    | PPS NUMBER K SEMICOLON {
        get_current_trigger()->pps = $2 * 1000;
    }
    | PPS NUMBER M SEMICOLON {
        get_current_trigger()->pps = $2 * 1000 * 1000;
    }
    | PPS NUMBER G SEMICOLON {
        get_current_trigger()->pps = $2 * 1000 * 1000 * 1000;
    }
    | BPS DOUBLE K SEMICOLON {
        get_current_trigger()->bps = $2 * 1000;
    }
    | BPS DOUBLE M SEMICOLON {
        get_current_trigger()->bps = $2 * 1000 * 1000;
    }
    | BPS DOUBLE G SEMICOLON {
        get_current_trigger()->bps = $2 * 1000 * 1000 * 1000;
    }
    | PPS DOUBLE K SEMICOLON {
        get_current_trigger()->pps = $2 * 1000;
    }
    | PPS DOUBLE M SEMICOLON {
        get_current_trigger()->pps = $2 * 1000 * 1000;
    }
    | PPS DOUBLE G SEMICOLON {
        get_current_trigger()->pps = $2 * 1000 * 1000 * 1000;
    }

filter_list
    : filter
    | filter filter_list {
        $1->next = $2;
    }

proto_name
    : TCP { $$ = IPPROTO_TCP; }
    | UDP { $$ = IPPROTO_UDP; }
    | NUMBER { $$ = $1; }

filter
    : AND LBRACE filter_list RBRACE {
        apermon_cond_list *l = (apermon_cond_list *) malloc(sizeof(apermon_cond_list));
        memset(l, 0, sizeof(apermon_cond_list));

        l->type = APERMON_COND_AND;
        l->funcs = $3;
        
        $$ = new_cond_func_list_element(cond_list, l);
    }
    | OR LBRACE filter_list RBRACE {
        apermon_cond_list *l = (apermon_cond_list *) malloc(sizeof(apermon_cond_list));
        memset(l, 0, sizeof(apermon_cond_list));

        l->type = APERMON_COND_OR;
        l->funcs = $3;
        
        $$ = new_cond_func_list_element(cond_list, l);
    }
    | NOT LBRACE filter_list RBRACE {
        apermon_cond_list *l = (apermon_cond_list *) malloc(sizeof(apermon_cond_list));
        memset(l, 0, sizeof(apermon_cond_list));

        l->type = APERMON_COND_NOT;
        l->funcs = $3;
        
        $$ = new_cond_func_list_element(cond_list, l);
    }
    | SOURCE IDENT SEMICOLON {
        apermon_config_prefix_lists *pfxlist = get_prefix_list($2);
        apermon_config_prefix_list_elements **arg = malloc(sizeof(void *));

        if (pfxlist == NULL) {
            store_retval(-1);
            log_error("prefix list '%s' not defined.\n", $2);
            YYERROR;
        }

        *arg = pfxlist->elements;

        $$ = new_cond_func_list_element(cond_src, arg);
        free($2);
    }
    | DESTINATION IDENT SEMICOLON {
        apermon_config_prefix_lists *pfxlist = get_prefix_list($2);
        apermon_config_prefix_list_elements **arg = malloc(sizeof(void *));

        if (pfxlist == NULL) {
            store_retval(-1);
            log_error("prefix list '%s' not defined.\n", $2);
            YYERROR;
        }

        *arg = pfxlist->elements;

        $$ = new_cond_func_list_element(cond_dst, arg);
        free($2);
    }
    | IN_INTERFACE IDENT SEMICOLON {
        apermon_config_interfaces **arg = malloc(sizeof(void *));
        *arg = get_interface($2);

        if (*arg == NULL) {
            store_retval(-1);
            log_error("interface '%s' not defined.\n", $2);
            YYERROR;
        }

        $$ = new_cond_func_list_element(cond_in_interface, arg);
        free($2);
    }
    | OUT_INTERFACE IDENT SEMICOLON {
        apermon_config_interfaces **arg = malloc(sizeof(void *));
        *arg = get_interface($2);

        if (*arg == NULL) {
            store_retval(-1);
            log_error("interface '%s' not defined.\n", $2);
            YYERROR;
        }

        $$ = new_cond_func_list_element(cond_out_interface, arg);
        free($2);
    }
    | PROTOCOL proto_name SEMICOLON {
        uint8_t *arg = malloc(sizeof(uint8_t));
        *arg = $2;

        $$ = new_cond_func_list_element(cond_proto, arg);
    }
    | SOURCE_PORT NUMBER SEMICOLON {
        uint16_t *arg = malloc(sizeof(uint16_t));
        *arg = $2;
        $$ = new_cond_func_list_element(cond_src_port, arg);
    }
    | DESTINATION_PORT NUMBER SEMICOLON {
        uint16_t *arg = malloc(sizeof(uint16_t));
        *arg = $2;
        $$ = new_cond_func_list_element(cond_dst_port, arg);
    }

action_list
    : action
    | action action_list {
        $1->next = $2;
    }

action: IDENT LBRACE action_options RBRACE {
    $$ = end_action($1);
    free($1);
}

action_options: action_option | action_options action_option

action_option
    : action_scripts {
        get_current_action()->scripts = $1;
    }

action_scripts
    : action_script
    | action_script action_scripts {
        $1->next = $2;
    }

action_script
    : SCRIPT QUOTED_STRING LBRACE script_options RBRACE {
        $$ = end_action_script($2);
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

prefix_list
    : prefixes
    | prefixes prefix_list {
        $1->next = $2;
    }

prefixes: IDENT LBRACE prefix_elements RBRACE {
    $$ = (apermon_config_prefix_lists *) malloc(sizeof(apermon_config_prefix_lists));
    memset($$, 0, sizeof(apermon_config_prefix_lists));

    $$->name = strdup($1);
    $$->elements = $3;

    free($1);
}

prefix_elements
    : prefix
    | prefix prefix_elements {
        $1->next = $2;
    }

prefix
    : IP SLASH NUMBER SEMICOLON {
        ERR_IF_NULL($$ = new_prefix_inet(&$1, $3));
    }
    | IP6 SLASH NUMBER SEMICOLON {
        ERR_IF_NULL($$ = new_prefix_inet6(&$1, $3));
    }

iface_list
    : iface
    | iface iface_list {
        $1->next = $2;
    }

iface: IDENT LBRACE iface_options RBRACE {
    $$ = end_interface($1);
    free($1);
}

iface_options
    : IFINDEXES LBRACK iface_indexes RBRACK SEMICOLON {
        get_current_interface()->ifindexes = $3;
    }

iface_indexes
    : iface_index
    | iface_index iface_indexes {
        $1->next = $2;
    }

iface_index: IDENT DOT NUMBER {
    $$ = (apermon_config_ifindexes *) malloc(sizeof(apermon_config_ifindexes));
    memset($$, 0, sizeof(apermon_config_ifindexes));

    const apermon_config_agents *agent = get_agent($1);
    if (agent == NULL) {
        store_retval(-1);
        log_error("agent '%s' not defined.\n", $1);
        YYERROR;
    }
    $$->agent = agent;
    $$->ifindex = $3;

    free($1);
}

agent_list
    : agent
    | agent agent_list {
        $1->next = $2;
    }

agent: IDENT LBRACE agent_options RBRACE {
    $$ = end_agent($1);
    free($1);
}

agent_options: agent_option | agent_options agent_option

agent_option
    : ADDRESSES LBRACK agent_addresses RBRACK SEMICOLON {
        get_current_agent()->addresses = $3;
    }

agent_addresses
    : agent_address
    | agent_address agent_addresses {
        $1->next = $2;
    }

agent_address
    : IP {
        $$ = (apermon_config_agent_addresses *) malloc(sizeof(apermon_config_agent_addresses));
        memset($$, 0, sizeof(apermon_config_agent_addresses));
        $$->af = AF_INET;
        $$->inet.s_addr = $1.s_addr;
    }
    | IP6 {
        $$ = (apermon_config_agent_addresses *) malloc(sizeof(apermon_config_agent_addresses));
        memset($$, 0, sizeof(apermon_config_agent_addresses));
        $$->af = AF_INET6;
        memcpy(&$$->inet6, &$1, sizeof($$->inet6));
    }

options: option_items | option_items options

option_items
    : option_item_listens {
        get_config()->listens = $1;
    }
    | MIN_BAN_TIME NUMBER SEMICOLON {
        get_config()->min_ban_time = $2;
    }

option_item_listens
    : option_item_listen
    | option_item_listen option_item_listens {
        $1->next = $2;
    }

option_item_listen
    : LISTEN IDENT NUMBER listen_args SEMICOLON {
        ERR_IF_NULL($$ = listen_fill_gai($4, $2, $3));
        free($2);
    }
    | LISTEN QUOTED_STRING NUMBER listen_args SEMICOLON {
        ERR_IF_NULL($$ = listen_fill_gai($4, $2, $3));
        free($2);
    }
    | LISTEN IP NUMBER listen_args SEMICOLON {
        char addr[INET_ADDRSTRLEN + 1];
        memset(addr, 0, sizeof(addr));

        if (inet_ntop(AF_INET, &$2, addr, INET_ADDRSTRLEN) == NULL) {
            log_fatal("inet_ntop(): %s\n", strerror(errno));
            YYERROR;
        }
        ERR_IF_NULL($$ = listen_fill_gai($4, addr, $3));
    }
    | LISTEN IP6 NUMBER listen_args SEMICOLON {
        char addr[INET6_ADDRSTRLEN + 1];
        memset(addr, 0, sizeof(addr));

        if (inet_ntop(AF_INET6, &$2, addr, INET6_ADDRSTRLEN) == NULL) {
            log_fatal("inet_ntop(): %s\n", strerror(errno));
            YYERROR;
        }
        ERR_IF_NULL($$ = listen_fill_gai($4, addr, $3));
    }
    

listen_args
    : SFLOW V5 {
        $$ = (apermon_config_listens *) malloc(sizeof(apermon_config_listens));
        memset($$, 0, sizeof(apermon_config_listens));

        $$->proto = APERMON_LISTEN_SFLOW_V5;
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

    end_config();

    *config = get_config();

    return get_retval();
}

void yyerror(const char *s) {
    log_fatal("%s:%d - %s\n", _filename, yylineno, s);
    store_retval(-1);
}