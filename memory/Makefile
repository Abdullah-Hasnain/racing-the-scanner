CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra
BIN := bin

all: $(BIN)/v1 $(BIN)/v2 $(BIN)/v3 $(BIN)/v4

$(BIN):
	mkdir -p $(BIN)

$(BIN)/v1: v1_baseline.c | $(BIN)
	$(CC) $(CFLAGS) -o $@ $<
$(BIN)/v2: v2_mprotect_sigsegv.c | $(BIN)
	$(CC) $(CFLAGS) -o $@ $<
$(BIN)/v3: v3_userfaultfd.c | $(BIN)
	$(CC) $(CFLAGS) -pthread -o $@ $<
$(BIN)/v4: v4_memfd_secret.c | $(BIN)
	$(CC) $(CFLAGS) -o $@ $<

# Syntax-check only (used in CI, where the runtime kernel may lack features).
check:
	$(CC) -fsyntax-only -Wall v1_baseline.c
	$(CC) -fsyntax-only -Wall v2_mprotect_sigsegv.c
	$(CC) -fsyntax-only -Wall -pthread v3_userfaultfd.c
	$(CC) -fsyntax-only -Wall v4_memfd_secret.c

clean:
	rm -rf $(BIN)

.PHONY: all check clean
