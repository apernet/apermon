CFLAGS+=-O0 -g -Wall -Wextra -march=native
LDFLAGS+=-lm
OBJS=apermon.o condition.o context.o extract.o flow.o hash.o net.o prefix-list.o sflow.o trigger.o config.tab.o config.yy.o config-public.o config-internal.o
FLEX=flex
BISON=bison

.PHONY: all clean

all: $(OBJS)
	$(CC) -o apermon $(OBJS) $(LDFLAGS) 

config.tab.c: config.y
	$(BISON) -d config.y

config.yy.c: config.l
	$(FLEX) -o config.yy.c config.l

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

clean:
	rm -f *.o config.yy.c config.tab.c config.tab.h apermon
