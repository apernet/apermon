%{
    #include <arpa/inet.h>
    #include "config.h"
    #include "condition.h"
    #include "config.tab.h"
    #include "prefix-list.h"
%}

%option noyywrap
%option nounput
%option noinput
%option yylineno

%%
[ \t\n] {}

\#[^\n]* {}

options {
    return OPTIONS;
}

listen {
    return LISTEN;
}

sflow {
    return SFLOW;
}

v5 {
    return V5;
}

min-ban-time {
    return MIN_BAN_TIME;
}

burst-period {
    return BURST_PERIOD;
}

status-file {
    return STATUS_FILE;
}

dump-interval {
    return DUMP_INTERVAL;
}

agents {
    return AGENTS;
}

addresses {
    return ADDRESSES;
}

sample-rate-cap {
    return SAMPLE_RATE_CAP;
}

interfaces {
    return INTERFACES;
}

ifindexes {
    return IFINDEXES;
}

prefixes {
    return PREFIXES;
}

actions {
    return ACTIONS;
}

script {
    return SCRIPT;
}

events {
    return EVENTS;
}

ban {
    return BAN;
}

unban {
    return UNBAN;
}

triggers {
    return TRIGGERS;
}

networks {
    return NETWORKS;
}

directions {
    return DIRECTIONS;
}

ingress {
    return INGRESS;
}

egress {
    return EGRESS;
}

aggregate-type {
    return AGGREGATE_TYPE;
}

host {
    return HOST;
}

net {
    return NET;
}

thresholds {
    return THRESHOLDS;
}

bps {
    return BPS;
}

pps {
    return PPS;
}

k {
    return K;
}

m {
    return M;
}

g {
    return G;
}

filter {
    return FILTER;
}

and {
    return AND;
}

or {
    return OR;
}

not {
    return NOT;
}

source {
    return SOURCE;
}

destination {
    return DESTINATION;
}

in-interface {
    return IN_INTERFACE;
}

out-interface {
    return OUT_INTERFACE;
}

protocol {
    return PROTOCOL;
}

tcp {
    return TCP;
}

udp {
    return UDP;
}

source-port {
    return SOURCE_PORT;
}

destination-port {
    return DESTINATION_PORT;
}

\{ {
    return LBRACE;
}

\} {
    return RBRACE;
}

\[ {
    return LBRACK;
}

\] {
    return RBRACK;
}

\; {
    return SEMICOLON;
}

\. {
    return DOT;
}

\/ {
    return SLASH;
}

([0-9]{1,3}\.){3}[0-9]{1,3} {
    inet_pton(AF_INET, yytext, &yylval.in_addr);
    return IP;
}

([a-f0-9:]+:+)+([a-f0-9]?)+ {
    inet_pton(AF_INET6, yytext, &yylval.in6_addr);
    return IP6;
}

[0-9]+\.[0-9]+ {
    yylval.d = atof(yytext);
    return DOUBLE;
}

[0-9]+ {
    yylval.u64 = atoi(yytext);
    return NUMBER;
}

[a-zA-Z]+[a-zA-Z0-9_\-]* {
    yylval.str = strdup(yytext);
    return IDENT;
}

\"(\\.|[^"\\])*\" {
    size_t len = strlen(yytext);
    char *str = (char *) malloc(len - 1);
    memcpy(str, yytext + 1, len - 2);
    str[len - 2] = '\0';

    yylval.str = str;
    return QUOTED_STRING;
}
%%