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

## Function boundary recovery (FBR)

Discovers function starts in both `.text` and obfuscated executable sections
(`.grfn1`, `.riot*`). Combines structured metadata seeds with caller-driven
expansion, then runs a score-based filter so heuristic-only candidates are kept
out unless multiple independent signals agree.

```mermaid
flowchart TD
    S1[Seed pdata: RUNTIME_FUNCTION.BeginAddress] --> M
    S2[Seed exports: PE export RVAs] --> M
    S3[Seed RTTI vfuncs: vtable slots from parseRTTI] --> M
    S4[Seed data fnptrs: 8B-aligned QWORDs to code] --> M
    S5[Seed EH handlers: UNWIND_INFO.ExceptionHandler] --> M

    M[Merge by RVA<br/>sourceCount += distinct sources] --> EXP

    subgraph EXP[Caller-driven expansion: up to 8 iters]
        EXP1[Linear sweep each frontier func] --> EXP2{E8 direct CALL?}
        EXP2 -->|Yes| EXP3[target -> SRC_DIRECT_CALL]
        EXP2 -->|No| EXP4{E9 tail-call?<br/>byte after JMP is CC/00/90}
        EXP4 -->|Yes| EXP5[target -> SRC_DIRECT_JMP]
    end

    EXP --> SCORE

    subgraph SCORE[Score-based validation]
        SC1[+2 if sourceCount >= 2] --> SC2[+2 if strong source<br/>pdata/export/RTTI/EH]
        SC2 --> SC3[+1 if direct-call seed]
        SC3 --> SC4[+1 if data fnptr seed]
        SC4 --> SC5[+1 if prologue match]
        SC5 --> SC6[+1 if prev byte terminates<br/>CC/00/C3/E9-end/EB-end/FF25/UD2/FF /4]
        SC6 --> SC7{Only-weak gate:<br/>no strong source AND<br/>sourceCount < 2}
        SC7 -->|Yes| SC8{prologue AND prev-term?}
        SC8 -->|No| REJ[Reject]
        SC8 -->|Yes| ACC
        SC7 -->|No| SC9{score >= 2?}
        SC9 -->|Yes| ACC[Accept]
        SC9 -->|No| REJ
    end

    SCORE --> END[computeFuncEnd:<br/>linear scan to next strong-anchor start,<br/>stop on RET/JMP+pad/UD2/4-byte pad run]
    END --> OVL[Overlap resolution:<br/>swap with prev when newScore > prevScore<br/>else discard inner candidate]
    OVL --> OUT[Sorted FunctionBoundary list]
```

Strong sources (pdata / export / RTTI / EH) are treated as ground truth: each
alone is sufficient. Data-fnptr is a weaker signal — any QWORD in `.data`/`.rdata`
that happens to point into code counts toward the score but is not by itself
proof of a real function start. The only-weak gate exists because a single
direct-call target plus prologue match still passes through too many
internal-branch targets (helpers, recursive calls, switch arms) — requiring
both prologue AND prev-byte terminator on weak-only candidates removes the
bulk of those false positives.
