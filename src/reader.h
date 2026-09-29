/* reader.h - bounds-checked little-endian byte reader.
 *
 * every access is validated against the buffer end. this is deliberate: unjerry
 * is meant to eat hostile / malformed snapshots (the kind that crash the real
 * loader, jerryscript#5301/#5302) without ever reading out of bounds itself.
 */
#ifndef UNJERRY_READER_H
#define UNJERRY_READER_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
  const uint8_t *base; /* start of buffer            */
  size_t         len;  /* total length               */
  size_t         pos;  /* current cursor             */
  int            err;  /* set once any access fails  */
} reader_t;

static inline void rd_init(reader_t *r, const uint8_t *base, size_t len) {
  r->base = base; r->len = len; r->pos = 0; r->err = 0;
}

/* is [off, off+n) fully inside the buffer? */
static inline int rd_in_bounds(const reader_t *r, size_t off, size_t n) {
  return off <= r->len && n <= r->len - off; /* no overflow: subtract on known-ok side */
}

static inline uint8_t rd_u8_at(reader_t *r, size_t off) {
  if (!rd_in_bounds(r, off, 1)) { r->err = 1; return 0; }
  return r->base[off];
}
static inline uint16_t rd_u16_at(reader_t *r, size_t off) {
  if (!rd_in_bounds(r, off, 2)) { r->err = 1; return 0; }
  return (uint16_t) (r->base[off] | (r->base[off + 1] << 8));
}
static inline uint32_t rd_u32_at(reader_t *r, size_t off) {
  if (!rd_in_bounds(r, off, 4)) { r->err = 1; return 0; }
  return (uint32_t) (r->base[off]
                     | ((uint32_t) r->base[off + 1] << 8)
                     | ((uint32_t) r->base[off + 2] << 16)
                     | ((uint32_t) r->base[off + 3] << 24));
}

/* cursor-based reads (advance pos) */
static inline uint8_t rd_u8(reader_t *r) {
  uint8_t v = rd_u8_at(r, r->pos); if (!r->err) r->pos += 1; return v;
}
static inline uint16_t rd_u16(reader_t *r) {
  uint16_t v = rd_u16_at(r, r->pos); if (!r->err) r->pos += 2; return v;
}
static inline uint32_t rd_u32(reader_t *r) {
  uint32_t v = rd_u32_at(r, r->pos); if (!r->err) r->pos += 4; return v;
}

#endif /* UNJERRY_READER_H */
