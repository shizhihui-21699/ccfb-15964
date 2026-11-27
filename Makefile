# SPDX-License-Identifier: BSD-2-Clause
#
# Portable build: the KDF/MAC/SNE/rollover/keystore layers and the full
# test suite build on macOS (development) and Linux (target). The kernel
# TCP_AO adapter compiles only on Linux; elsewhere a stub is linked so
# `make test` exercises everything that can be validated off-box.

CC ?= cc
# HMAC_CTX APIs are deprecated in OpenSSL 3 but still the portable choice
# across 1.1/3.x; the EVP_MAC replacement does not exist on 1.1.
CFLAGS ?= -O2 -g -Wall -Wextra -Wno-unused-parameter \
	-Wno-deprecated-declarations -std=gnu11
CPPFLAGS := -Iinclude -D_GNU_SOURCE
LDLIBS := -lcrypto

SRC := src/crypto_openssl.c src/kdf.c src/sne.c src/mac.c \
       src/rollover.c src/keystore.c src/session.c
TEST_SRC := tests/test_main.c tests/test_json.c tests/test_kdf.c \
            tests/test_mac.c tests/test_sne.c tests/test_rollover.c \
            tests/test_keystore.c

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
SRC += src/kernel_linux.c
else
SRC += src/kernel_stub.c
# Homebrew installs OpenSSL outside the default include/lib path.
BREW_SSL := $(shell for d in /opt/homebrew/opt/openssl /usr/local/opt/openssl; \
		do [ -f $$d/include/openssl/hmac.h ] && echo $$d && break; done)
ifneq ($(BREW_SSL),)
CPPFLAGS += -I$(BREW_SSL)/include
LDFLAGS  += -L$(BREW_SSL)/lib
endif
endif

BUILD := build
LIB_OBJS := $(patsubst src/%.c,$(BUILD)/lib/%.o,$(SRC))
TEST_BIN := $(BUILD)/tcpao_tests

.PHONY: all test vectors clean cli example

all: $(TEST_BIN) cli example

$(BUILD)/lib/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

$(BUILD)/tests/%.o: tests/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

vectors:
	python3 -I tests/vectors/gen_vectors.py

$(TEST_BIN): $(LIB_OBJS) $(patsubst tests/%.c,$(BUILD)/tests/%.o,$(TEST_SRC))
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@ $(LDLIBS)

test: vectors $(TEST_BIN)
	./$(TEST_BIN) tests/vectors/vectors.json

# Operator CLI (Linux target only; stub returns EOPNOTSUPP elsewhere).
CLI_BIN := $(BUILD)/bgp-ao-keyctl
cli: $(CLI_BIN)
$(CLI_BIN): $(LIB_OBJS) $(BUILD)/lib/keyctl.o
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@ $(LDLIBS)
$(BUILD)/lib/keyctl.o: tools/keyctl.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

# Integration example (links the portable core + kernel adapter).
EXAMPLE_BIN := $(BUILD)/bgp_daemon_example
example: $(EXAMPLE_BIN)
$(EXAMPLE_BIN): $(LIB_OBJS) $(BUILD)/lib/bgp_daemon_integration.o
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@ $(LDLIBS)
$(BUILD)/lib/bgp_daemon_integration.o: examples/bgp_daemon_integration.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD)
