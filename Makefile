CFLAGS+=-Wall -Wextra -march=native
LDFLAGS+=-lm
OBJS=apermon.o condition.o context.o extract.o flow.o hash.o net.o prefix-list.o sflow.o trigger.o config.tab.o config.yy.o config-public.o config-internal.o
FLEX=flex
BISON=bison

.PHONY: all debug verbose-debug clean

all: CFLAGS+=-O3
all: apermon

debug: CFLAGS+=-O0 -g
debug: apermon

debug-verbose: CFLAGS+=-DAPERMON_DEBUG -O0 -g
debug-verbose: apermon

apermon: $(OBJS)
	$(CC) -o apermon $(OBJS) $(LDFLAGS) -O3

config.tab.c: config.y
	$(BISON) -d config.y

config.yy.c: config.l
	$(FLEX) -o config.yy.c config.l

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

clean:
	rm -f *.o config.yy.c config.tab.c config.tab.h apermon
