CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra
BIN := bin
HDR := common/payload.h

all: $(BIN)/v1 $(BIN)/v2 $(BIN)/v3 $(BIN)/v4

$(BIN):
	mkdir -p $(BIN)

$(BIN)/v1: v1_baseline.c $(HDR) | $(BIN)
	$(CC) $(CFLAGS) -o $@ $<
$(BIN)/v2: v2_mprotect_sigsegv.c $(HDR) | $(BIN)
	$(CC) $(CFLAGS) -o $@ $<
$(BIN)/v3: v3_userfaultfd.c $(HDR) | $(BIN)
	$(CC) $(CFLAGS) -pthread -o $@ $<
$(BIN)/v4: v4_memfd_secret.c $(HDR) | $(BIN)
	$(CC) $(CFLAGS) -o $@ $<

# Syntax-check only (used in CI, where the runtime kernel may lack features),
# with the same warnings as the build.
check:
	$(CC) -fsyntax-only $(CFLAGS) v1_baseline.c
	$(CC) -fsyntax-only $(CFLAGS) v2_mprotect_sigsegv.c
	$(CC) -fsyntax-only $(CFLAGS) -pthread v3_userfaultfd.c
	$(CC) -fsyntax-only $(CFLAGS) v4_memfd_secret.c

clean:
	rm -rf $(BIN)

.PHONY: all check clean
