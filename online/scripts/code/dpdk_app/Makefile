APP = reflector
SRCS = reflector.c

PKGCONF ?= pkg-config

CFLAGS += -O3 -Wall
CFLAGS += $(shell $(PKGCONF) --cflags libdpdk)
LDLIBS += $(shell $(PKGCONF) --libs libdpdk)

all: $(APP)

$(APP): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

clean:
	rm -f $(APP)