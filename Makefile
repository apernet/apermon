CFLAGS=-O0 -g -Wall -Wextra -march=native
OBJS=apermon.o extract.o sflow.o hash.o net.o config.tab.o config.yy.o config-public.o config-internal.o
FLEX=flex
BISON=bison

.PHONY: all clean

all: $(OBJS)
	$(CC) $(CFLAGS) -o apermon $(OBJS)

config.tab.c: config.y
	$(BISON) -d config.y

config.yy.c: config.l
	$(FLEX) -o config.yy.c config.l

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

clean:
	rm -f *.o config.yy.c config.tab.c config.tab.h apermon