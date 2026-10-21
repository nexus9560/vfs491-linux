PKG_CONFIG ?= pkg-config
GLIB_CFLAGS := $(shell $(PKG_CONFIG) --cflags glib-2.0)
GLIB_LIBS   := $(shell $(PKG_CONFIG) --libs glib-2.0 gmodule-2.0)
GUSB_CFLAGS := $(shell $(PKG_CONFIG) --cflags gusb)
GUSB_LIBS   := $(shell $(PKG_CONFIG) --libs gusb)
CRYPTO_LIBS := $(shell $(PKG_CONFIG) --libs libcrypto || echo -lcrypto)
PIXMAN_LIBS := $(shell $(PKG_CONFIG) --libs pixman-1)

# Paths to the patched libfprint tree and its build output (see ../../build-libfprint.sh).
REPO_ROOT ?= $(abspath ../..)
OBJ_DIR   ?= $(REPO_ROOT)/build/lfp-full-build/libfprint
LFP_SRC   ?= $(REPO_ROOT)/build/libfprint-v1.94.100

all: replay_assembly driver_crypto_selftest

replay_assembly: replay_assembly.c
	$(CC) $(CFLAGS) -O2 -g $(GLIB_CFLAGS) -I$(OBJ_DIR)/.. -I$(LFP_SRC) \
		-c $< -o replay_assembly.o
	$(CC) replay_assembly.o \
		$(OBJ_DIR)/libfprint-private.a \
		$(OBJ_DIR)/libnbis.a \
		$(OBJ_DIR)/libfprint-2.so.2.0.0 -Wl,-rpath,$(OBJ_DIR) \
		-lm $(PIXMAN_LIBS) $(GLIB_LIBS) -o replay_assembly

driver_crypto_selftest: driver_crypto_selftest.c
	$(CC) $(CFLAGS) -O2 -g $(GLIB_CFLAGS) $(GUSB_CFLAGS) \
		-I$(LFP_SRC) -I$(LFP_SRC)/libfprint -I$(OBJ_DIR) -I$(OBJ_DIR)/.. \
		-c $< -o driver_crypto_selftest.o
	$(CC) driver_crypto_selftest.o \
		$(OBJ_DIR)/libfprint-private.a $(OBJ_DIR)/libfprint-drivers.a $(OBJ_DIR)/libnbis.a \
		$(OBJ_DIR)/libfprint-2.so.2.0.0 -Wl,-rpath,$(OBJ_DIR) \
		$(CRYPTO_LIBS) -lm $(GUSB_LIBS) $(PIXMAN_LIBS) $(GLIB_LIBS) -o driver_crypto_selftest

clean:
	rm -f *.o replay_assembly driver_crypto_selftest

.PHONY: all clean
