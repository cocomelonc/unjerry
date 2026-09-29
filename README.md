# unjerry

a disassembler and (work-in-progress) decompiler for **jerryscript snapshot / cbc bytecode**, written in C.       

jerryscript is an ultra-lightweight javascript engine (samsung) used across
resource-constrained IoT / edge firmware. it can pre-compile javascript into
*snapshots* (compact bytecode, "cbc") that ship on-device instead of source.
unlike lua (`unluac`) or duktape (`nccgroup/detaped`), there is **no public
decompiler for jerryscript cbc** - see upstream request [jerryscript#5116](https://github.com/jerryscript-project/jerryscript/issues/5116).      

`unjerry` fills that gap.

## why

**firmware analysis.** when a device's logic ships as a jerryscript snapshot, today you are stuck reading raw cbc by hand. `unjerry` recovers a readable disassembly / pseudo-source so the logic can be audited.       

**format safety.** the snapshot loader itself parses this format with weak bounds checking (upstream [#5301](https://github.com/jerryscript-project/jerryscript/issues/5301), [#5302](https://github.com/jerryscript-project/jerryscript/issues/5302)). `unjerry`'s reader is fully bounds-checked and treats every snapshot as hostile input - it is meant to survive the malformed blobs that crash the engine, and can double as a triage / corpus-minimisation aid.     

## status

working disassembler; decompiler in progress. staged milestones:

1. **[done] parse** - snapshot header, function table, recursion into nested functions, annotated hexdump.
2. **[done] disassemble** - decode cbc opcodes to a readable listing, with correct branch-target and literal-index decoding. (known gap: a few multi-operand opcodes, e.g. `CBC_PUSH_THREE_LITERALS` and some call forms, are not fully operand-decoded yet.)
3. **[done] multi-version** - snapshot **v70** (jerryscript 3.0.0) and **v63** (shipped by iot.js / tizenrt) both supported; unjerry dispatches on the header version. opcode tables and args-struct layouts differ per version and are generated from each reference source.
4. **[next] lift + decompile** - resolve literals to names/values, reconstruct control flow, emit javascript-like pseudo-source.

> real-world note: iot.js force-enables snapshot mode and bakes every JS module into firmware as a **v63** snapshot, so v63 is the version that matters for real tizenrt / artik device images.

## scope / non-goals

- multi-version by design: the snapshot format is versioned and *not* stability-guaranteed across releases, so unjerry carries a per-version spec (opcode table + args layout) and dispatches on the header version; unknown versions fall back to the nearest with a warning.
- read-only. `unjerry` never executes bytecode.      

## build

Building via MAKEFILE:

```bash
make            # builds ./unjerry
make corpus     # builds jerryscript + generates reference/corpus/*.snapshot
make test       # round-trip: our parse vs. known-good corpus
```

## usage

Tested on Parrot Security OS, just run:      

```bash
unjerry -x file.snapshot      # annotated hexdump of header + sections
unjerry -d file.snapshot      # disassemble cbc
unjerry --json file.snapshot  # machine-readable structure dump
```

## prior art / credit

[`unluac`](https://sourceforge.net/projects/unluac/) - lua bytecode decompiler (the model).      
[`nccgroup/detaped`](https://github.com/nccgroup/detaped) - duktape decompiler.       
jerryscript is apache-2.0; `unjerry` is an independent clean-room tool built against the public format. see `LICENSE`.        

## license

MIT. see `LICENSE`.
