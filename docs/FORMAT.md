# jerryscript snapshot / cbc format (reverse-engineered notes)

reference: jerryscript v3.0.0, **snapshot version 70**. the snapshot format is
versioned and explicitly *not* stability-guaranteed across releases - treat the
version field as load-bearing.

all integers are little-endian.

## 1. snapshot header

`jerry_snapshot_header_t` (jerry-core/api/jerry-snapshot.h):

| off | type | field             | notes                                          |
|-----|------|-------------------|------------------------------------------------|
| 0   | u32  | magic             | `0x5952524A` = ascii `JRRY`                    |
| 4   | u32  | version           | `70`                                           |
| 8   | u32  | global_flags      | regex(1<<0), class(1<<1) literals present      |
| 12  | u32  | lit_table_offset  | byte offset of the snapshot literal table      |
| 16  | u32  | number_of_funcs   | count of top-level compiled functions          |
| 20  | u32[]| func_offsets[]    | one per func; **bit0** = eval(1)/global(0) ctx |

the fixed header is 20 bytes; `func_offsets` follows inline. mask bit0 off a
func offset to get the byte offset of that function's compiled code.

> note: the fuzz PoC in jerryscript#5301 is shown with a leading `SNAP` marker;
> the on-disk format produced by `jerry-snapshot generate` starts directly with
> `JRRY`. fingerprint firmware on the `JRRY` magic (`4A 52 52 59`).

## 2. compiled code (`ecma_compiled_code_t` + args)

each function begins with a 6-byte header:

| off | type | field         | notes                              |
|-----|------|---------------|------------------------------------|
| 0   | u16  | size          | **real size = size << 3** (bytes)  |
| 2   | u16  | refs          | runtime refcount (ignore)          |
| 4   | u16  | status_flags  | see below                          |

`status_flags` bits that matter for decoding:
- `1<<0` FULL_LITERAL_ENCODING - literal-index encoding mode (see 4)
- `1<<1` UINT16_ARGUMENTS - args struct is the u16 variant
- `1<<2` STRICT_MODE

### args struct

**u8 variant** (16 bytes, when UINT16_ARGUMENTS clear):

| off | type | field             |
|-----|------|-------------------|
| 6   | u8   | stack_limit       |
| 7   | u8   | argument_end      |
| 8   | u32  | script_value      |
| 12  | u8   | register_end      |
| 13  | u8   | ident_end         |
| 14  | u8   | const_literal_end |
| 15  | u8   | literal_end       |

**u16 variant** (24 bytes): stack_limit u16@6, script_value u32@8,
argument_end u16@12, register_end u16@14, ident_end u16@16,
const_literal_end u16@18, literal_end u16@20, padding u16@22.

## 3. locating the bytecode

from `vm_init_exec` (jerry-core/vm/vm.c):

```cpp
literal_p     = (ecma_value_t *)(args_p + 1);   /* == func + args_size */
literal_p    -= register_end;                    /* literal_start_p     */
byte_code_p   = literal_p + literal_end;
```

so, in file offsets (with `sizeof(ecma_value_t) == 4`):

```cpp
bytecode_start = func_off + args_size + (literal_end - register_end) * 4
```

the `(literal_end - register_end)` stored literal slots sit between the args
struct and the bytecode. bytecode runs until `func_off + (size<<3)` (trailing
bytes belong to literal / line-info / extended-info blocks per status_flags).

## 4. instruction encoding (cbc)

one opcode byte. `0x00` (`CBC_EXT_OPCODE`) is a prefix: the next byte selects an
*extended* opcode from a separate table. operand layout is driven by per-opcode
arg flags (from `cbc_flags[]` / `cbc_ext_flags[]`, mirrored in
`src/cbc_opcodes.inc`):

- `0x01` HAS_LITERAL_ARG   - one literal index (encoded, see below)
- `0x02` HAS_LITERAL_ARG2  - a second literal index
- `0x04` HAS_BYTE_ARG      - one raw byte
- `0x08` HAS_BRANCH_ARG    - branch offset, **length = opcode & 3** bytes,
  big-endian; forward if `0x10` FORWARD flag set, else backward.

### literal index encoding

```cpp
idx = u8
if (idx >= limit) idx = ((idx << 8) | u8) - delta
```

- small encoding: limit=255, delta=0xfe01
- full encoding (FULL_LITERAL_ENCODING set): limit=128, delta=0x8000

### small-integer opcodes

`CBC_PUSH_NUMBER_POS_BYTE` / `..._NEG_BYTE` store `value - 1`; the VM pushes
`ecma_make_integer_value(byte + 1)` (resp. negative). unjerry shows the decoded
value in parentheses.

## worked example (`reference/corpus/hello.snapshot`)

```cpp
add(3, 4)  ->  ...
  CBC_PUSH_LITERAL_PUSH_NUMBER_POS_BYTE lit:1 byte:2 (=3)
  CBC_PUSH_NUMBER_POS_BYTE              byte:3 (=4)
  CBC_CALL2_BLOCK
  CBC_RETURN_FUNCTION_END
```

## 5. nested (sub-) functions

`func_offsets[]` in the header lists only the **top-level** functions. nested
functions are stored as separate compiled-code blobs and referenced from a
parent's stored literal array. within a function's literal array (register-
rebased indices), entries in `[const_literal_end - register_end, literal_end -
register_end)` are **sub-function offsets**. the sub-function's file offset is
**relative to the enclosing function's base**:

```
sub_file_offset = parent_file_offset + literal_offset
```

(an offset of 0 is a self-reference.) recurse to walk the whole function tree.

## 6. version deltas (v63 vs v70)

the format is versioned and layout changes across releases. two matter here:
**v70** (jerryscript 3.0.0) and **v63** (what iot.js / tizenrt ship — the version
that shows up in real device firmware).

| thing | v63 | v70 |
|-------|-----|-----|
| snapshot version field | 63 | 70 |
| magic | `0x5952524A` | `0x5952524A` |
| #opcodes (es5.1 build) | 388 | 410 |
| some opcode values | `CBC_RETURN`=0x52, `CBC_ADD`=0x95 | `CBC_RETURN`=0x55, `CBC_ADD`=0x98 |
| u8 args struct | **12 bytes**, no `script_value` | **16 bytes**, has `script_value`@8 |
| u16 args struct | **20 bytes** | **24 bytes** |
| u8 field offsets | stack6 arg7 reg8 ident9 clit10 lit11 | stack6 arg7 reg12 ident13 clit14 lit15 |
| u16 field offsets | stack6 arg8 reg10 ident12 clit14 lit16 | stack6 arg12 reg14 ident16 clit18 lit20 |

the v63 opcode set is **build-config dependent** (opcodes are gated behind
`#if ENABLED(JERRY_ESNEXT)` etc.), so the table must be generated with the same
feature flags as the target firmware. the es5.1 profile (ESNEXT off, no realms)
matches the constrained iot.js builds. unjerry keeps one `vspec` per version.

## open work

- resolve literal indices to names/values via the snapshot literal table (1).
- finish operand decoding for multi-operand opcodes (`*_THREE_LITERALS`, call
  forms with arg counts) - the 4 arg-flag bits don't capture all of them.
- lift branches into structured control flow -> decompile to js-like source.
