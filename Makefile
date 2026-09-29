# unjerry - build
CC      ?= cc
CFLAGS  ?= -std=c11 -O2 -Wall -Wextra -Wpedantic
SRC      = src/main.c
BIN      = unjerry

JS_DIR   = reference/jerryscript
JS_SNAP  = $(JS_DIR)/build/bin/jerry-snapshot
CORPUS   = reference/corpus

.PHONY: all clean corpus opcodes test

all: $(BIN)

$(BIN): $(SRC) src/reader.h src/cbc_opcodes.inc
	$(CC) $(CFLAGS) -Isrc -o $@ $(SRC)

# regenerate the version-accurate opcode table from the reference source
opcodes:
	./reference/gen-opcodes.sh

# build jerryscript's snapshot tool + generate a reference corpus
corpus:
	@test -x "$(JS_SNAP)" || (cd $(JS_DIR) && python3 tools/build.py \
		--snapshot-save on --snapshot-exec on --jerry-cmdline-snapshot on --lto off)
	@mkdir -p $(CORPUS)
	@for js in $(CORPUS)/*.js; do \
		[ -e "$$js" ] || continue; \
		echo "gen $$js"; "$(JS_SNAP)" generate "$$js" -o "$${js%.js}.snapshot"; \
	done

# smoke test: parse every corpus snapshot without a reader error
test: $(BIN) corpus
	@fail=0; for s in $(CORPUS)/*.snapshot; do \
		[ -e "$$s" ] || continue; \
		printf 'parse %s ... ' "$$s"; \
		if ./$(BIN) --info "$$s" >/dev/null; then echo ok; else echo FAIL; fail=1; fi; \
	done; exit $$fail

clean:
	rm -f $(BIN)
