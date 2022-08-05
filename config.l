%{
    #include <arpa/inet.h>
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

agents {
    return AGENTS;
}

addresses {
    return ADDRESSES;
}

interfaces {
    return INTERFACES;
}

ifindexes {
    return IFINDEXES;
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

([0-9]{1,3}\.){3}[0-9]{1,3} {
    inet_pton(AF_INET, yytext, &yylval.in_addr);
    return IP;
}

([a-f0-9:]+:+)+([a-f0-9]?)+ {
    inet_pton(AF_INET6, yytext, &yylval.in6_addr);
    return IP6;
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
    str[len - 1] = '\0';

    yylval.str = str;
    return QUOTED_STRING;
}
%%