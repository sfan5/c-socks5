CFLAGS = -pipe -std=gnu11 -pthread -Wall
LDFLAGS =
LIBS = -lcares

ifneq ($(RELEASE),1)
CFLAGS += -Og -g
CFLAGS += -D_FORTIFY_SOURCE=2 -fsanitize=address
else
CFLAGS += -O2 -DNDEBUG
endif

BINDIR ?= /usr/bin
# Note that this path is hardcoded in the source
CONFDIR = /etc

SRC = config.c dns.c forwarder.c async.c main.c
OBJ = $(addsuffix .o, $(basename $(SRC)))

all: c-socks5

c-socks5: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LDFLAGS) $(LIBS)

%.o: %.c *.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) c-socks5

install:
	install -pD -m755 c-socks5 $(DESTDIR)$(BINDIR)/c-socks5
	install -pD -m644 c-socks5.conf $(DESTDIR)$(CONFDIR)/c-socks5.conf

.PHONY: clean
