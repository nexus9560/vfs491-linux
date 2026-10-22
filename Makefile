# Build helpers for the VFS491 open-source driver effort.
#
#   make                build build/vfs491_probe and build/vfs491_session
#   make run            build and run the read-only probe
#   make run-session    build and run the command-set / SSL session probe
#   make run-unlock P1=... P2=...   reproduce HP's init (needs device write access)
#   make test           hardware-free self-tests (no sensor, no root)
#   make clean

CC      ?= cc
CFLAGS  ?= -O2 -g -Wall -Wextra
BUILD   := build

PKG_CONFIG ?= pkg-config
LIBUSB_CFLAGS := $(shell $(PKG_CONFIG) --cflags libusb-1.0 2>/dev/null)
LIBUSB_LIBS   := $(shell $(PKG_CONFIG) --libs   libusb-1.0 2>/dev/null || echo -lusb-1.0)
CRYPTO_LIBS   := $(shell $(PKG_CONFIG) --libs   libcrypto 2>/dev/null || echo -lcrypto)

CFLAGS += $(LIBUSB_CFLAGS)

all: $(BUILD)/vfs491_probe $(BUILD)/vfs491_session $(BUILD)/vfs491_ssl

$(BUILD)/vfs491_probe: tools/vfs491_probe.c | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $< $(LIBUSB_LIBS)

$(BUILD)/vfs491_session: tools/vfs491_session.c | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $< $(LIBUSB_LIBS)

$(BUILD)/vfs491_ssl: tools/vfs491_ssl.c | $(BUILD)
	$(CC) $(CFLAGS) -DOPENSSL_SUPPRESS_DEPRECATED -o $@ $< $(LIBUSB_LIBS) $(CRYPTO_LIBS)

$(BUILD):
	mkdir -p $(BUILD)

run: $(BUILD)/vfs491_probe
	./$(BUILD)/vfs491_probe

run-session: $(BUILD)/vfs491_session
	./$(BUILD)/vfs491_session $(ARGS)

# Reproduce HP's init (patches come from files *you* supply -- vendor IP stays
# outside the repo).  Needs write access to the sensor node (root, or a udev
# rule); this target does not use sudo, so run it as root yourself.
#   make run-unlock P1=/tmp/opencode/patches/patch1.bin P2=/tmp/opencode/patches/patch2.bin
run-unlock: $(BUILD)/vfs491_session
	./$(BUILD)/vfs491_session unlock $(P1) $(P2) $(EXTRA)

# Complete the SSLv3 handshake with our own client (needs device write access).
#   make run-ssl P1=... P2=... PK=.../sensor_pubkey.bin [EXTRA='--modbe --app']
run-ssl: $(BUILD)/vfs491_ssl
	./$(BUILD)/vfs491_ssl $(P1) $(P2) --pubkey $(PK) $(EXTRA)

clean:
	rm -rf $(BUILD)

# Hardware-free self-tests: no sensor, no root, no fprintd.
test:
	python3 capture/selftest.py
	python3 proprietary/selftest.py

.PHONY: all run run-session run-unlock run-ssl clean test
