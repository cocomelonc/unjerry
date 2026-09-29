/* unjerry - jerryscript snapshot / cbc bytecode disassembler.
 *
 * milestone 1: parse + validate header, walk function table, annotated hexdump,
 * linear cbc disassembly. read-only; never executes bytecode.
 *
 * format facts (jerryscript v3.0.0, snapshot version 70) are derived from the
 * reference source under reference/jerryscript and pinned here.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "reader.h"

/* --- generated, version-accurate opcode tables (cbc_ops[], cbc_ext_ops[]) --- */
#include "cbc_opcodes.inc"

#define JERRY_SNAPSHOT_MAGIC   0x5952524Au   /* "JRRY" */
#define JERRY_SNAPSHOT_VERSION 70u

/* snapshot header: 5 x u32 then func_offsets[number_of_funcs] */
#define SNAPSHOT_HEADER_FIXED  20u

/* compiled-code status flags we care about */
#define CBC_FLAGS_FULL_LITERAL_ENCODING (1u << 0)
#define CBC_FLAGS_UINT16_ARGUMENTS      (1u << 1)
#define CBC_FLAGS_STRICT_MODE           (1u << 2)

/* cbc opcode arg flags (must match byte-code.h) */
#define CBC_HAS_LITERAL_ARG  0x01u
#define CBC_HAS_LITERAL_ARG2 0x02u
#define CBC_HAS_BYTE_ARG     0x04u
#define CBC_HAS_BRANCH_ARG   0x08u
#define CBC_FORWARD_BRANCH   0x10u

#define CBC_EXT_PREFIX 0x00u /* CBC_EXT_OPCODE */
#define ECMA_VALUE_SIZE 4u   /* sizeof(ecma_value_t) in a default 32-bit-cp build */
#define JMEM_ALIGN_LOG 3u    /* size field is (bytes >> 3) */

#define NELEMS(a) (sizeof(a) / sizeof((a)[0]))

typedef struct {
  uint32_t off;            /* file offset of this compiled_code            */
  uint32_t byte_size;      /* size field << 3                              */
  uint16_t status_flags;
  int      uint16_args;
  uint32_t stack_limit, argument_end, register_end, ident_end,
           const_literal_end, literal_end;
  uint32_t args_size;      /* 16 or 24                                     */
  uint32_t bytecode_start; /* file offset where cbc begins                 */
  int      is_eval_ctx;    /* low bit of func_offset                       */
} func_t;

static const char *op_name(unsigned op, int ext) {
  const cbc_op_t *t = ext ? cbc_ext_ops : cbc_ops;
  size_t n = ext ? NELEMS(cbc_ext_ops) : NELEMS(cbc_ops);
  return (op < n) ? t[op].name : "<unknown>";
}
static unsigned op_flags(unsigned op, int ext) {
  const cbc_op_t *t = ext ? cbc_ext_ops : cbc_ops;
  size_t n = ext ? NELEMS(cbc_ext_ops) : NELEMS(cbc_ops);
  return (op < n) ? t[op].flags : 0;
}

/* read a cbc literal index using the function's encoding mode */
static uint32_t read_literal_index(reader_t *r, int full_encoding) {
  uint32_t limit = full_encoding ? 128u : 255u;
  uint32_t delta = full_encoding ? 0x8000u : 0xfe01u;
  uint32_t idx = rd_u8(r);
  if (idx >= limit) {
    idx = (((idx << 8) | rd_u8(r)) - delta) & 0xffffu;
  }
  return idx;
}

/* parse one compiled_code header at file offset `off` */
static int parse_func(reader_t *r, uint32_t raw_off, func_t *f) {
  memset(f, 0, sizeof(*f));
  f->is_eval_ctx = raw_off & 1u;
  uint32_t off = raw_off & ~1u;
  f->off = off;

  uint16_t size = rd_u16_at(r, off);          /* size >> 3 */
  f->status_flags = rd_u16_at(r, off + 4);
  if (r->err) return -1;
  f->byte_size = (uint32_t) size << JMEM_ALIGN_LOG;
  f->uint16_args = (f->status_flags & CBC_FLAGS_UINT16_ARGUMENTS) ? 1 : 0;

  if (f->uint16_args) {
    f->args_size          = 24;
    f->stack_limit        = rd_u16_at(r, off + 6);
    f->argument_end       = rd_u16_at(r, off + 12);
    f->register_end       = rd_u16_at(r, off + 14);
    f->ident_end          = rd_u16_at(r, off + 16);
    f->const_literal_end  = rd_u16_at(r, off + 18);
    f->literal_end        = rd_u16_at(r, off + 20);
  } else {
    f->args_size          = 16;
    f->stack_limit        = rd_u8_at(r, off + 6);
    f->argument_end       = rd_u8_at(r, off + 7);
    f->register_end       = rd_u8_at(r, off + 12);
    f->ident_end          = rd_u8_at(r, off + 13);
    f->const_literal_end  = rd_u8_at(r, off + 14);
    f->literal_end        = rd_u8_at(r, off + 15);
  }
  if (r->err) return -1;

  /* byte_code_start = args_end + (literal_end - register_end) * sizeof(ecma_value_t) */
  int32_t stored_lits = (int32_t) f->literal_end - (int32_t) f->register_end;
  if (stored_lits < 0) stored_lits = 0; /* defensive: malformed */
  f->bytecode_start = off + f->args_size + (uint32_t) stored_lits * ECMA_VALUE_SIZE;
  return 0;
}

static void print_func_header(const func_t *f, int i) {
  printf("\n; function[%d] @0x%x  ctx=%s  size=%u bytes\n",
         i, f->off, f->is_eval_ctx ? "eval" : "global/func", f->byte_size);
  printf(";   status_flags=0x%04x [%s%s%s]\n", f->status_flags,
         (f->status_flags & CBC_FLAGS_UINT16_ARGUMENTS) ? "u16args " : "u8args ",
         (f->status_flags & CBC_FLAGS_FULL_LITERAL_ENCODING) ? "full-lit-enc " : "small-lit-enc ",
         (f->status_flags & CBC_FLAGS_STRICT_MODE) ? "strict" : "");
  printf(";   args=%u regs=%u ident_end=%u const_lit_end=%u literal_end=%u stack=%u\n",
         f->argument_end, f->register_end, f->ident_end,
         f->const_literal_end, f->literal_end, f->stack_limit);
  printf(";   bytecode @0x%x\n", f->bytecode_start);
}

/* linear disassembly of one function's cbc region */
static void disasm_func(reader_t *r, const func_t *f) {
  int full = (f->status_flags & CBC_FLAGS_FULL_LITERAL_ENCODING) ? 1 : 0;
  uint32_t end = f->off + f->byte_size; /* upper bound of this compiled_code */
  if (end > r->len) end = (uint32_t) r->len;

  reader_t d = *r;
  d.pos = f->bytecode_start;

  while (d.pos < end && !d.err) {
    uint32_t ip = (uint32_t) d.pos;
    unsigned raw = rd_u8(&d);
    int ext = 0;
    unsigned op = raw;
    if (raw == CBC_EXT_PREFIX) { op = rd_u8(&d); ext = 1; }
    if (d.err) break;

    unsigned flags = op_flags(op, ext);
    printf("  0x%04x: %-28s", ip, op_name(op, ext));

    if (flags & CBC_HAS_LITERAL_ARG)
      printf(" lit:%u", read_literal_index(&d, full));
    if (flags & CBC_HAS_LITERAL_ARG2)
      printf(" lit2:%u", read_literal_index(&d, full));
    if (flags & CBC_HAS_BYTE_ARG) {
      unsigned b = rd_u8(&d);
      const char *nm0 = op_name(op, ext);
      /* POS_BYTE / NEG_BYTE number opcodes store (value - 1); decode it */
      if (strstr(nm0, "POS_BYTE"))      printf(" byte:%u (=%u)", b, b + 1);
      else if (strstr(nm0, "NEG_BYTE")) printf(" byte:%u (=-%u)", b, b + 1);
      else                              printf(" byte:%u", b);
    }
    if (flags & CBC_HAS_BRANCH_ARG) {
      unsigned blen = raw & 0x3u;            /* CBC_BRANCH_OFFSET_LENGTH */
      if (blen == 0) blen = 1;
      uint32_t offv = 0;
      for (unsigned k = 0; k < blen && !d.err; k++) offv = (offv << 8) | rd_u8(&d);
      int fwd = (flags & CBC_FORWARD_BRANCH) ? 1 : 0;
      long tgt = fwd ? (long) ip + (long) offv : (long) ip - (long) offv;
      printf(" -> 0x%04lx (%s %u)", tgt, fwd ? "fwd" : "back", offv);
    }
    printf("\n");

    /* stop cleanly at function terminators to avoid running into literal pools */
    const char *nm = op_name(op, ext);
    if (!ext && (strcmp(nm, "CBC_RETURN") == 0
                 || strcmp(nm, "CBC_RETURN_WITH_BLOCK") == 0
                 || strcmp(nm, "CBC_RETURN_FUNCTION_END") == 0))
      break;
  }
  if (d.err) printf("  ; <disasm stopped: reached buffer/section bound>\n");
}

static void hexdump(const uint8_t *p, size_t len, size_t max) {
  size_t n = len < max ? len : max;
  for (size_t i = 0; i < n; i += 16) {
    printf("%08zx: ", i);
    for (size_t j = 0; j < 16; j++) {
      if (i + j < n) printf("%02x", p[i + j]); else printf("  ");
      if (j % 2) printf(" ");
    }
    printf(" ");
    for (size_t j = 0; j < 16 && i + j < n; j++) {
      unsigned c = p[i + j];
      putchar((c >= 32 && c < 127) ? (int) c : '.');
    }
    printf("\n");
  }
  if (len > max) printf("... (%zu more bytes)\n", len - max);
}

static uint8_t *read_file(const char *path, size_t *out_len) {
  FILE *fp = fopen(path, "rb");
  if (!fp) { perror(path); return NULL; }
  fseek(fp, 0, SEEK_END); long sz = ftell(fp); fseek(fp, 0, SEEK_SET);
  if (sz < 0) { fclose(fp); return NULL; }
  uint8_t *buf = malloc((size_t) sz ? (size_t) sz : 1);
  if (!buf) { fclose(fp); return NULL; }
  size_t rd = fread(buf, 1, (size_t) sz, fp);
  fclose(fp);
  *out_len = rd;
  return buf;
}

static void usage(const char *prog) {
  fprintf(stderr,
    "unjerry - jerryscript snapshot/cbc disassembler\n"
    "usage: %s [-x|-d|--info] <file.snapshot>\n"
    "  --info   header + function table (default)\n"
    "  -x       annotated hexdump\n"
    "  -d       disassemble cbc\n", prog);
}

int main(int argc, char **argv) {
  if (argc < 2) { usage(argv[0]); return 2; }
  const char *mode = "--info";
  const char *path = NULL;
  for (int i = 1; i < argc; i++) {
    if (argv[i][0] == '-' && argv[i][1]) mode = argv[i];
    else path = argv[i];
  }
  if (!path) { usage(argv[0]); return 2; }

  size_t len = 0;
  uint8_t *buf = read_file(path, &len);
  if (!buf) return 1;

  reader_t r; rd_init(&r, buf, len);

  uint32_t magic   = rd_u32_at(&r, 0);
  uint32_t version = rd_u32_at(&r, 4);
  uint32_t gflags  = rd_u32_at(&r, 8);
  uint32_t lit_off = rd_u32_at(&r, 12);
  uint32_t nfuncs  = rd_u32_at(&r, 16);

  if (len < SNAPSHOT_HEADER_FIXED) {
    fprintf(stderr, "error: file too small to be a snapshot (%zu bytes)\n", len);
    free(buf); return 1;
  }

  printf("== unjerry: %s (%zu bytes) ==\n", path, len);
  printf("magic          : 0x%08x %s\n", magic,
         magic == JERRY_SNAPSHOT_MAGIC ? "(JRRY ok)" : "(BAD - not a jerryscript snapshot)");
  printf("version        : %u %s\n", version,
         version == JERRY_SNAPSHOT_VERSION ? "(ok)" : "(unsupported - parse may be wrong)");
  printf("global_flags   : 0x%08x\n", gflags);
  printf("lit_table_off  : 0x%x (%u)\n", lit_off, lit_off);
  printf("number_of_funcs: %u\n", nfuncs);

  if (magic != JERRY_SNAPSHOT_MAGIC) { free(buf); return 1; }

  /* sanity-cap nfuncs against the buffer to survive malformed input */
  if (nfuncs > (len - SNAPSHOT_HEADER_FIXED) / 4) {
    fprintf(stderr, "warning: number_of_funcs=%u exceeds file; clamping\n", nfuncs);
    nfuncs = (uint32_t) ((len - SNAPSHOT_HEADER_FIXED) / 4);
  }

  if (strcmp(mode, "-x") == 0) {
    printf("\n-- hexdump --\n");
    hexdump(buf, len, len);
    free(buf); return 0;
  }

  for (uint32_t i = 0; i < nfuncs; i++) {
    uint32_t raw_off = rd_u32_at(&r, SNAPSHOT_HEADER_FIXED + i * 4);
    func_t f;
    if (parse_func(&r, raw_off, &f) != 0) {
      printf("\n; function[%u] @0x%x - parse error (truncated)\n", i, raw_off & ~1u);
      continue;
    }
    print_func_header(&f, (int) i);
    if (strcmp(mode, "-d") == 0) disasm_func(&r, &f);
  }

  free(buf);
  return 0;
}
