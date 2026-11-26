CC ?= cc
AR ?= ar

CFLAGS ?= -std=c11 -O2 -g -D_GNU_SOURCE -Wall -Wextra -Wpedantic
CFLAGS += -Iinclude -Isrc
LDLIBS += -lpthread

CORE_SRCS := \
	src/sha1.c \
	src/ao_aes_cmac.c \
	src/ao_util.c \
	src/ao_table.c \
	src/ao_kdf.c \
	src/ao_sne.c \
	src/ao_codec.c \
	src/ao_conn.c \
	src/ao_rotation.c \
	src/bgp_journal.c \
	src/ao_policy.c

PAL_SRCS := src/pal/ao_linux.c
SRCS := $(CORE_SRCS) $(PAL_SRCS)
OBJS := $(SRCS:.c=.o)

LIB := libtcpao.a
TEST_BIN := build/test_tcp_ao

.PHONY: all test clean check

all: $(LIB) examples/bgp_ao_rollover

$(LIB): $(OBJS)
	$(AR) rcs $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(TEST_BIN): tests/test_tcp_ao.c $(LIB) | build
	$(CC) $(CFLAGS) $< $(LIB) -o $@ $(LDLIBS)

test: $(TEST_BIN)
	./$(TEST_BIN)

check: test

build:
	mkdir -p build

examples/bgp_ao_rollover: examples/bgp_ao_rollover.c $(LIB)
	$(CC) $(CFLAGS) $< $(LIB) -o $@ $(LDLIBS)

clean:
	rm -f $(OBJS) $(LIB) $(TEST_BIN) examples/bgp_ao_rollover
	rm -rf build examples/bgp_ao_rollover.dSYM
