/* unjerry - jerryscript snapshot / cbc bytecode disassembler.
 *
 * parse + validate header, walk the function table (recursing into nested
 * functions), annotated hexdump, linear cbc disassembly. read-only; never
 * executes bytecode.
 *
 * multi-version: snapshot v70 (jerryscript 3.0.0) and v63 (the version shipped
 * by iot.js / tizenrt) have different opcode tables AND args-struct layouts;
 * unjerry dispatches on the header version (see VSPECS). format facts are
 * derived from the reference sources under reference/jerryscript (v70) and
 * reference/jerry63 (v63).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "reader.h"

/* cbc opcode table row */
typedef struct { unsigned char op; const char *name; unsigned char flags; signed char stack; } cbc_op_t;

/* --- generated, version-accurate opcode tables (per snapshot version) --- */
#include "cbc_opcodes_v70.inc"  /* cbc_ops_v70[],  cbc_ext_ops_v70[]  */
#include "cbc_opcodes_v63.inc"  /* cbc_ops_v63[],  cbc_ext_ops_v63[]  */

#define JERRY_SNAPSHOT_MAGIC 0x5952524Au   /* "JRRY" */

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

/* --- per-version format spec ---------------------------------------------
 * the snapshot format is versioned: opcode tables AND the cbc args-struct
 * layout differ between releases. v70 (jerryscript 3.0.0) added a `script_value`
 * field to the args struct that v63 (the version iot.js/tizenrt ship) lacks, so
 * offsets and struct sizes differ. unjerry dispatches on the header version. */
typedef struct { uint32_t stack, arg, reg, ident, clit, lit; } argslayout_t;

typedef struct {
  uint32_t version;
  uint32_t u8_size, u16_size;   /* args struct sizes                        */
  argslayout_t u8, u16;         /* field byte offsets within the function   */
  const cbc_op_t *ops;  size_t n_ops;
  const cbc_op_t *ext;  size_t n_ext;
} vspec_t;

static const vspec_t VSPECS[] = {
  /* v70: jerryscript 3.0.0. u8 args=16 (has script_value@8), u16 args=24. */
  { 70, 16, 24,
    /* u8  */ { .stack = 6, .arg = 7,  .reg = 12, .ident = 13, .clit = 14, .lit = 15 },
    /* u16 */ { .stack = 6, .arg = 12, .reg = 14, .ident = 16, .clit = 18, .lit = 20 },
    cbc_ops_v70, NELEMS(cbc_ops_v70), cbc_ext_ops_v70, NELEMS(cbc_ext_ops_v70) },
  /* v63: shipped by iot.js / tizenrt (es5.1, no realms). u8 args=12, u16=20. */
  { 63, 12, 20,
    /* u8  */ { .stack = 6, .arg = 7, .reg = 8,  .ident = 9,  .clit = 10, .lit = 11 },
    /* u16 */ { .stack = 6, .arg = 8, .reg = 10, .ident = 12, .clit = 14, .lit = 16 },
    cbc_ops_v63, NELEMS(cbc_ops_v63), cbc_ext_ops_v63, NELEMS(cbc_ext_ops_v63) },
};

/* active spec, chosen from the header version (see main) */
static const vspec_t *V = &VSPECS[0];

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
  /* stored literal array (register-rebased, per snapshot_load_compiled_code) */
  uint32_t lit_array_off;  /* file offset of the stored literal array      */
  uint32_t n_stored_lits;  /* literal_end - register_end                   */
  uint32_t const_lits_reb; /* const_literal_end - register_end             */
} func_t;

#define MAX_DEPTH 32

static const char *op_name(unsigned op, int ext) {
  const cbc_op_t *t = ext ? V->ext : V->ops;
  size_t n = ext ? V->n_ext : V->n_ops;
  return (op < n) ? t[op].name : "<unknown>";
}
static unsigned op_flags(unsigned op, int ext) {
  const cbc_op_t *t = ext ? V->ext : V->ops;
  size_t n = ext ? V->n_ext : V->n_ops;
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
    const argslayout_t *L = &V->u16;
    f->args_size          = V->u16_size;
    f->stack_limit        = rd_u16_at(r, off + L->stack);
    f->argument_end       = rd_u16_at(r, off + L->arg);
    f->register_end       = rd_u16_at(r, off + L->reg);
    f->ident_end          = rd_u16_at(r, off + L->ident);
    f->const_literal_end  = rd_u16_at(r, off + L->clit);
    f->literal_end        = rd_u16_at(r, off + L->lit);
  } else {
    const argslayout_t *L = &V->u8;
    f->args_size          = V->u8_size;
    f->stack_limit        = rd_u8_at(r, off + L->stack);
    f->argument_end       = rd_u8_at(r, off + L->arg);
    f->register_end       = rd_u8_at(r, off + L->reg);
    f->ident_end          = rd_u8_at(r, off + L->ident);
    f->const_literal_end  = rd_u8_at(r, off + L->clit);
    f->literal_end        = rd_u8_at(r, off + L->lit);
  }
  if (r->err) return -1;

  /* the stored literal array follows the args struct; indices are rebased by
   * register_end (see snapshot_load_compiled_code). value literals occupy
   * [0, const_lits_reb), sub-function literals [const_lits_reb, n_stored_lits). */
  int32_t stored_lits = (int32_t) f->literal_end - (int32_t) f->register_end;
  if (stored_lits < 0) stored_lits = 0; /* defensive: malformed */
  int32_t const_reb = (int32_t) f->const_literal_end - (int32_t) f->register_end;
  if (const_reb < 0) const_reb = 0;
  f->n_stored_lits = (uint32_t) stored_lits;
  f->const_lits_reb = (uint32_t) const_reb;
  f->lit_array_off = off + f->args_size;
  /* byte_code_start = args_end + n_stored_lits * sizeof(ecma_value_t) */
  f->bytecode_start = f->lit_array_off + f->n_stored_lits * ECMA_VALUE_SIZE;
  return 0;
}

static void indent(int depth) { for (int k = 0; k < depth; k++) printf("  "); }

static void print_func_header(const func_t *f, const char *label, int depth) {
  printf("\n");
  indent(depth);
  printf("; %s @0x%x  ctx=%s  size=%u bytes  subfuncs=%u\n",
         label, f->off, f->is_eval_ctx ? "eval" : "global/func", f->byte_size,
         f->n_stored_lits > f->const_lits_reb ? f->n_stored_lits - f->const_lits_reb : 0);
  indent(depth);
  printf(";   status=0x%04x [%s%s%s]  args=%u regs=%u lits=%u(const=%u) stack=%u  bytecode @0x%x\n",
         f->status_flags,
         (f->status_flags & CBC_FLAGS_UINT16_ARGUMENTS) ? "u16args " : "u8args ",
         (f->status_flags & CBC_FLAGS_FULL_LITERAL_ENCODING) ? "full-lit-enc " : "small-lit-enc ",
         (f->status_flags & CBC_FLAGS_STRICT_MODE) ? "strict" : "",
         f->argument_end, f->register_end, f->literal_end, f->const_literal_end,
         f->stack_limit, f->bytecode_start);
}

/* linear disassembly of one function's cbc region */
static void disasm_func(reader_t *r, const func_t *f, int depth) {
  int full = (f->status_flags & CBC_FLAGS_FULL_LITERAL_ENCODING) ? 1 : 0;
  uint32_t end = f->off + f->byte_size; /* upper bound of this compiled_code */
  if (end > r->len) end = (uint32_t) r->len;

  reader_t d = *r;
  d.pos = f->bytecode_start;
  uint32_t max_target = 0; /* farthest forward-branch target seen so far */

  while (d.pos < end && !d.err) {
    uint32_t ip = (uint32_t) d.pos;
    unsigned raw = rd_u8(&d);
    int ext = 0;
    unsigned op = raw;
    if (raw == CBC_EXT_PREFIX) { op = rd_u8(&d); ext = 1; }
    if (d.err) break;

    unsigned flags = op_flags(op, ext);
    indent(depth);
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
      if (fwd && tgt > (long) max_target) max_target = (uint32_t) tgt;
      printf(" -> 0x%04lx (%s %u)", tgt, fwd ? "fwd" : "back", offv);
    }
    printf("\n");

    /* stop at a block terminator, but only once we are past every forward
     * branch target seen (otherwise code after an if/else is still live).
     * this keeps us from disassembling the trailing literal / line-info pool. */
    const char *nm = op_name(op, ext);
    int is_term = (!ext && (strstr(nm, "RETURN") || strstr(nm, "THROW")
                            || strncmp(nm, "CBC_JUMP", 8) == 0));
    if (is_term && (uint32_t) d.pos > max_target) break;
  }
  if (d.err) { indent(depth); printf("  ; <disasm stopped: reached buffer/section bound>\n"); }
}

/* recursively parse + print a function and its nested sub-functions.
 * sub-function file offset = parent_off + literal_offset (relative to the
 * enclosing function's base, per snapshot_load_compiled_code). */
static void walk_func(reader_t *r, uint32_t raw_off, const char *label,
                      int depth, int do_disasm) {
  func_t f;
  if (parse_func(r, raw_off, &f) != 0) {
    indent(depth);
    printf("; %s @0x%x - parse error (truncated)\n", label, raw_off & ~1u);
    return;
  }
  print_func_header(&f, label, depth);
  if (do_disasm) disasm_func(r, &f, depth);

  if (depth >= MAX_DEPTH) {
    indent(depth); printf(";   <max nesting depth reached>\n");
    return;
  }

  /* sub-function literals live at rebased indices [const_lits_reb, n_stored_lits) */
  uint32_t sub_idx = 0;
  for (uint32_t j = f.const_lits_reb; j < f.n_stored_lits; j++) {
    uint32_t lit_off = rd_u32_at(r, f.lit_array_off + j * ECMA_VALUE_SIZE);
    if (r->err) break;
    if (lit_off == 0) continue;               /* self-reference; skip */
    uint32_t sub = f.off + lit_off;           /* relative to enclosing base */
    if (sub <= f.off || sub >= r->len) {       /* defensive against malformed */
      indent(depth + 1);
      printf("; <bad sub-function offset 0x%x at lit %u>\n", sub, j);
      continue;
    }
    char sublabel[64];
    snprintf(sublabel, sizeof(sublabel), "%s.sub[%u]", label, sub_idx++);
    walk_func(r, sub, sublabel, depth + 1, do_disasm);
  }
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

  /* pick the format spec matching the snapshot version */
  const vspec_t *sel = NULL;
  for (size_t i = 0; i < NELEMS(VSPECS); i++)
    if (VSPECS[i].version == version) { sel = &VSPECS[i]; break; }
  if (sel) V = sel;

  printf("== unjerry: %s (%zu bytes) ==\n", path, len);
  printf("magic          : 0x%08x %s\n", magic,
         magic == JERRY_SNAPSHOT_MAGIC ? "(JRRY ok)" : "(BAD - not a jerryscript snapshot)");
  if (sel)
    printf("version        : %u (supported)\n", version);
  else
    printf("version        : %u (UNSUPPORTED - falling back to v%u layout; parse may be wrong)\n",
           version, V->version);
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

  int do_disasm = (strcmp(mode, "-d") == 0);
  for (uint32_t i = 0; i < nfuncs; i++) {
    uint32_t raw_off = rd_u32_at(&r, SNAPSHOT_HEADER_FIXED + i * 4);
    char label[32];
    snprintf(label, sizeof(label), "function[%u]", i);
    walk_func(&r, raw_off, label, 0, do_disasm);
  }

  free(buf);
  return 0;
}
