# Algorithms

## Static tracer

```mermaid
flowchart TD
    A[Start at RVA] --> B{Decode instruction}
    B -->|NOP / INT3 block| C[Skip, advance RIP]
    C --> B
    B -->|Valid instruction| D[Execute on abstract state]
    D --> E{Instruction type?}
    E -->|CALL to watched func| F[Record target + args]
    E -->|CALL into obfuscated| G[Push return, follow]
    E -->|JMP / JCC| H[Resolve target, follow]
    E -->|RET| I[Pop call stack or stop]
    E -->|Arithmetic / Logic| J[Update registers + flags]
    F --> B
    G --> B
    H --> B
    J --> B
    I --> K[Return trace results]
```

## RTTI recovery

```mermaid
flowchart TD
    A[Scan .rdata for '.?AV' strings] --> B[Parse TypeDescriptor structs]
    B --> C[Match TypeDescriptor RVA in COL structs]
    C --> D{COL signature == 1?}
    D -->|Yes| E[Self-RVA validation]
    D -->|No| C
    E --> F[Find COL pointer in data = vtable at -1]
    F --> G[Walk vtable forward until non-code pointer]
    G --> H[Output: class name + vtable + methods]
```

## Constant propagation

`pefix::ConstProp` runs a worklist-driven dataflow over `Func.blocks`. Each register
holds one of {TOP, CONST, TYPED_PTR, BOTTOM}. The engine folds standard x86 arithmetic
when both inputs are concrete, and ships an extension hook (`transferUnknown`) for
non-x86 opcodes (libgriffin's `MBA_*` ops override this).

```mermaid
flowchart TD
    A[Entry block: seed regs<br/>initRegs, typedPtrs, dispatchKeys] --> B[Worklist pop block]
    B --> C[For each instr: transfer]
    C --> D{op?}
    D -->|MOV/LEA/arith| E[Fold src1,src2 -> dst]
    D -->|MOV from mem| F{base TypedPtr<br/>+ disp 0?}
    F -->|Yes| G[dst = Const imageBase + vtableRVA]
    F -->|No| H{base Const<br/>+ .rdata?}
    H -->|Yes| I[dst = Const value at addr]
    H -->|No| J[dst = TOP]
    D -->|CALL/JMP via mem| K[tryResolveIndirectControlFlow]
    K --> L{base resolves<br/>to .rdata fnptr?}
    L -->|Yes| M[dst = Label target,<br/>simplified = true]
    L -->|No| N[Leave as indirect]
    D -->|Other| O[transferUnknown<br/>or TOP fallback]
    C --> P[Propagate state to succs]
    P -->|Changed| B
```

Downstream tools devirtualize vtable calls by seeding a register with TypedPtr and
running the engine: `mov rax,[rcx]` resolves to Const(vtable VA), then `call [rax+N]`
reads the slot and gets its dst rewritten to a direct LABEL. The dataflow drives this
without any byte-pattern matching, so it covers `(dst,base)` register pairs the older
pattern-based resolver missed.

## Import chain BFS

```mermaid
flowchart LR
    A[Seed: known API RVAs] --> B[Build reverse call map via E8 scan]
    B --> C[BFS from seeds through callers]
    C --> D[Find function start for each caller]
    D --> E[Name function: API_chain_depth]
    E -->|depth < max| C
    E -->|depth reached| F[Output: discovered function names]
```
