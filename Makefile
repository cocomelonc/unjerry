# unjerry - build
CC      ?= cc
CFLAGS  ?= -std=c11 -O2 -Wall -Wextra -Wpedantic
SRC      = src/main.c
BIN      = unjerry

JS_DIR   = reference/jerryscript
JS_DIR63 = reference/jerry63
JS_SNAP  = $(JS_DIR)/build/bin/jerry-snapshot
JS_SNAP63= $(JS_DIR63)/build/bin/jerry-snapshot
CORPUS   = reference/corpus
OPCODES  = src/cbc_opcodes_v70.inc src/cbc_opcodes_v63.inc

.PHONY: all clean corpus opcodes test

all: $(BIN)

$(BIN): $(SRC) src/reader.h $(OPCODES)
	$(CC) $(CFLAGS) -Isrc -o $@ $(SRC)

# regenerate the version-accurate opcode tables from each reference source
opcodes:
	./reference/gen-opcodes.sh $(JS_DIR) v70 src/cbc_opcodes_v70.inc
	./reference/gen-opcodes.sh $(JS_DIR63) v63 src/cbc_opcodes_v63.inc \
		"$$(printf '#define JERRY_ESNEXT 0\n#define JERRY_BUILTIN_REALMS 0\n#define JERRY_PARSER_DUMP_BYTE_CODE 0')"

# generate a reference corpus at both snapshot versions (v70 and v63).
# assumes the two jerry-snapshot tools are already built (see reference/).
corpus:
	@mkdir -p $(CORPUS)
	@for js in $(CORPUS)/*.js; do \
		case "$$js" in *.wrapped.js) continue;; esac; \
		[ -e "$$js" ] || continue; \
		test -x "$(JS_SNAP)"   && { echo "gen v70 $$js"; "$(JS_SNAP)"   generate "$$js" -o "$${js%.js}.snapshot"; }; \
		test -x "$(JS_SNAP63)" && { echo "gen v63 $$js"; "$(JS_SNAP63)" generate "$$js" -o "$${js%.js}_v63.snapshot"; }; \
	done

# smoke test: parse every corpus snapshot without a reader error, at its version
test: $(BIN)
	@fail=0; for s in $(CORPUS)/*.snapshot; do \
		[ -e "$$s" ] || continue; \
		printf 'parse %-44s ... ' "$$s"; \
		if ./$(BIN) --info "$$s" >/dev/null; then echo ok; else echo FAIL; fail=1; fi; \
	done; exit $$fail

clean:
	rm -f $(BIN)
