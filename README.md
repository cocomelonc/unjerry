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

early. staged milestones:

1. **[in progress] parse** - snapshot header, literal table, function table.     
2. **disassemble** - decode cbc opcodes to a readable listing.    
3. **lift** - reconstruct control flow + expressions.     
4. **decompile** - emit javascript-like pseudo-source.     

## scope / non-goals

- targets a pinned jerryscript version (snapshot format is versioned and *not* stability-guaranteed across releases; see `reference/`). version detection is explicit and the tool refuses formats it does not model.
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
