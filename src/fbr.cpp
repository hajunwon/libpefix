#include <pefix/fbr.h>
#include <pefix/exports.h>
#include <pefix/analysis.h>
#include <pefix/log.h>
#include <algorithm>
#include <cstring>
#include <chrono>
#include <unordered_map>
#include <unordered_set>

namespace pefix {

namespace {

struct ExecSection {
    int      sectionIdx;
    char     name[9];
    uint32_t startRVA;
    uint32_t endRVA;
    uint32_t rawOff;
    uint32_t rawSize;
    bool     isObfuscated;  // not the canonical .text — i.e. .grfn1 / .riot* etc.
};

struct DataSection {
    uint32_t startRVA;
    uint32_t endRVA;
    uint32_t rawOff;
    uint32_t rawSize;
};

struct Ctx {
    const PEFile& pe;
    uint64_t imageBase;
    uint32_t sizeOfImage;
    std::vector<ExecSection> exec;
    std::vector<DataSection> data;
    uint32_t pdataRaw = 0, pdataSize = 0;

    int findExec(uint32_t rva) const {
        for (size_t i = 0; i < exec.size(); i++)
            if (rva >= exec[i].startRVA && rva < exec[i].endRVA) return (int)i;
        return -1;
    }
    bool inAnyExec(uint32_t rva) const { return findExec(rva) >= 0; }
    bool isObfRVA(uint32_t rva) const { int i = findExec(rva); return i >= 0 && exec[i].isObfuscated; }
};

Ctx collectSections(const PEFile& pe, uint64_t imageBase) {
    Ctx ctx{pe, imageBase, pe.nt->OptionalHeader.SizeOfImage, {}, {}};
    for (WORD i = 0; i < pe.numSections; i++) {
        char name[9] = {};
        memcpy(name, pe.sections[i].Name, 8);
        uint32_t va = pe.sections[i].VirtualAddress;
        uint32_t vsz = pe.sections[i].Misc.VirtualSize;
        uint32_t raw = pe.sections[i].PointerToRawData;
        uint32_t rsz = pe.sections[i].SizeOfRawData;
        DWORD ch = pe.sections[i].Characteristics;
        if (ch & 0x20000000 /* IMAGE_SCN_MEM_EXECUTE */) {
            // canonical .text is the first executable; everything else (.grfn1/.riot*) is marked obfuscated
            bool obf = strcmp(name, ".text") != 0;
            ExecSection es{(int)i, {}, va, va + vsz, raw, rsz, obf};
            memcpy(es.name, name, 9);
            ctx.exec.push_back(es);
        } else if (strcmp(name, ".rdata") == 0 || strcmp(name, ".data") == 0) {
            ctx.data.push_back({va, va + vsz, raw, rsz});
        }
        if (strcmp(name, ".pdata") == 0) {
            ctx.pdataRaw = raw;
            ctx.pdataSize = rsz;
        }
    }
    return ctx;
}

// Step 1.a — RUNTIME_FUNCTION.BeginAddress
void seedPdata(const Ctx& ctx, std::vector<uint32_t>& out) {
    if (!ctx.pdataRaw) return;
    uint32_t end = std::min<uint32_t>(ctx.pdataRaw + ctx.pdataSize, (uint32_t)ctx.pe.data.size());
    for (uint32_t p = ctx.pdataRaw; p + 12 <= end; p += 12) {
        uint32_t begin = *(uint32_t*)(ctx.pe.data.data() + p);
        uint32_t fend  = *(uint32_t*)(ctx.pe.data.data() + p + 4);
        if (begin == 0 && fend == 0) continue;
        if (begin >= fend) continue;
        if (fend > ctx.sizeOfImage) continue;
        if (!ctx.inAnyExec(begin)) continue;
        out.push_back(begin);
    }
}

// Step 1.b — PE export table
void seedExports(const Ctx& ctx, std::vector<uint32_t>& out) {
    auto exports = readExports(ctx.pe);
    for (auto& e : exports) {
        if (e.isForwarder) continue;
        if (!ctx.inAnyExec(e.rva)) continue;
        out.push_back(e.rva);
    }
}

// Step 1.c — RTTI vtable methods (parseRTTI already walks vftables)
void seedRttiVfunc(const Ctx& ctx, std::vector<uint32_t>& out) {
    auto classes = parseRTTI(ctx.pe, ctx.imageBase);
    for (auto& cls : classes) {
        for (uint64_t va : cls.methodVAs) {
            if (va < ctx.imageBase) continue;
            uint32_t rva = (uint32_t)(va - ctx.imageBase);
            if (!ctx.inAnyExec(rva)) continue;
            out.push_back(rva);
        }
    }
}

// Step 1.d — function pointers stored in .data / .rdata (8-byte aligned QWORDs
// whose value lands inside an executable section).
void seedDataFnPtr(const Ctx& ctx, std::vector<uint32_t>& out) {
    for (auto& ds : ctx.data) {
        uint32_t end = std::min<uint32_t>(ds.rawOff + ds.rawSize, (uint32_t)ctx.pe.data.size());
        for (uint32_t p = ds.rawOff; p + 8 <= end; p += 8) {
            uint64_t val = *(uint64_t*)(ctx.pe.data.data() + p);
            if (val < ctx.imageBase) continue;
            uint32_t rva = (uint32_t)(val - ctx.imageBase);
            if (!ctx.inAnyExec(rva)) continue;
            out.push_back(rva);
        }
    }
}

// Step 1.e — UNWIND_INFO.ExceptionHandler (Flags & UNW_FLAG_EHANDLER).
// Layout (x86-64): UNWIND_INFO header { Version:3; Flags:5; SizeOfProlog; CountOfCodes; FrameRegister; }
// followed by CountOfCodes UNWIND_CODEs, then optional 4-byte ExceptionHandler RVA.
void seedEhHandler(const Ctx& ctx, std::vector<uint32_t>& out) {
    if (!ctx.pdataRaw) return;
    uint32_t end = std::min<uint32_t>(ctx.pdataRaw + ctx.pdataSize, (uint32_t)ctx.pe.data.size());
    for (uint32_t p = ctx.pdataRaw; p + 12 <= end; p += 12) {
        uint32_t begin    = *(uint32_t*)(ctx.pe.data.data() + p);
        uint32_t fend     = *(uint32_t*)(ctx.pe.data.data() + p + 4);
        uint32_t unwindRVA = *(uint32_t*)(ctx.pe.data.data() + p + 8);
        if (begin >= fend) continue;
        if (unwindRVA == 0 || unwindRVA >= ctx.sizeOfImage) continue;

        uint32_t uOff = ctx.pe.rvaToOffset(unwindRVA);
        if (!uOff || uOff + 4 > ctx.pe.data.size()) continue;

        uint8_t verFlags = ctx.pe.data[uOff];
        uint8_t flags = verFlags >> 3;
        if (!(flags & 0x1 /* UNW_FLAG_EHANDLER */) && !(flags & 0x2 /* UNW_FLAG_UHANDLER */)) continue;

        uint8_t count = ctx.pe.data[uOff + 2];
        // codes are 2 bytes each, padded to 4-byte boundary
        uint32_t codesBytes = ((count + 1) & ~1u) * 2u;
        uint32_t handlerOff = uOff + 4 + codesBytes;
        if (handlerOff + 4 > ctx.pe.data.size()) continue;

        uint32_t handlerRVA = *(uint32_t*)(ctx.pe.data.data() + handlerOff);
        if (handlerRVA == 0 || handlerRVA >= ctx.sizeOfImage) continue;
        if (!ctx.inAnyExec(handlerRVA)) continue;
        out.push_back(handlerRVA);
    }
}

// Quick first-byte filter for instruction starts. The full list of prefix /
// opcode lead bytes is large but the union below covers >99% of compiler
// emitted prologue / epilogue / generic instruction openings observed in MSVC
// x64 binaries. Anything outside is treated as 'not a function start'.
bool looksLikeInstrStart(uint8_t b) {
    // REX prefixes
    if (b >= 0x40 && b <= 0x4F) return true;
    // Common single-byte openings
    switch (b) {
    case 0x50: case 0x51: case 0x52: case 0x53: case 0x54: case 0x55: case 0x56: case 0x57: // PUSH r64
    case 0x58: case 0x59: case 0x5A: case 0x5B: case 0x5C: case 0x5D: case 0x5E: case 0x5F: // POP r64
    case 0x8B: case 0x89: case 0x8D: // MOV r,r/m / MOV r/m,r / LEA
    case 0x83: case 0x81: // ADD/SUB/CMP r/m, imm
    case 0xB8: case 0xB9: case 0xBA: case 0xBB: case 0xBC: case 0xBD: case 0xBE: case 0xBF: // MOV r32, imm32
    case 0xE8: case 0xE9: case 0xEB: case 0xC3: case 0xC2: // CALL/JMP/RET
    case 0xFF: // group 5 (CALL/JMP indirect, PUSH r/m, etc.)
    case 0xF6: case 0xF7: // group 3
    case 0x33: case 0x31: case 0x29: case 0x2B: case 0x01: case 0x03: case 0x09: case 0x0B: case 0x21: case 0x23: // arithmetic
    case 0x39: case 0x3B: case 0x85: // CMP / TEST
    case 0x0F: // two-byte opcode
    case 0xC6: case 0xC7: // MOV r/m, imm
    case 0xCC: // INT3 itself isn't a function start
        return b != 0xCC;
    }
    return false;
}

// Match against the small set of byte sequences MSVC almost always emits at
// the very start of a function. The patterns below were chosen because each
// of them is rare *inside* a function body — observing the sequence at offset
// 0 of a candidate makes it very likely (>90% in spot checks) to be a real
// function start, while non-matches mean nothing on their own.
bool matchesPrologue(const PEFile& pe, uint32_t fileOff) {
    if (fileOff >= pe.data.size()) return false;
    const uint8_t* p = pe.data.data() + fileOff;
    size_t avail = pe.data.size() - fileOff;
    if (avail < 1) return false;

    // 1-byte: simple thunks / push variants. Each is a *whole* canonical
    // function-start instruction, so the single byte is sufficient.
    switch (p[0]) {
    case 0x55: case 0x53: case 0x56: case 0x57:        // push rbp/rbx/rsi/rdi
        return true;
    case 0x51: case 0x52:                              // push rcx/rdx — common in callee-saving thunks
        return true;
    }

    // 5-byte: simple `jmp rel32` thunks (raw E9 disp32) and `xor eax,eax; ret`
    // nullsubs / equivalents. Each pattern is rare *inside* a function body.
    if (avail >= 5 && p[0] == 0xE9) {
        // Treat E9 as a function start only when the byte immediately after the
        // 5-byte JMP is padding — i.e. the thunk genuinely ends here.
        if (avail < 6) return true;
        uint8_t after = p[5];
        if (after == 0xCC || after == 0x00 || after == 0x90) return true;
    }
    if (avail >= 3 && p[0] == 0x33 && (p[1] == 0xC0 || p[1] == 0xD2 || p[1] == 0xC9 ||
                                        p[1] == 0xDB) && p[2] == 0xC3) {
        return true; // xor eax/edx/ecx/ebx, same; ret  (nullsub variants)
    }

    if (avail < 6) return false;

    // 6-byte: REX.W + jmp rel32 (`48 E9 disp32`). Used as an import thunk
    // even though REX.W doesn't change semantics on a jump — MSVC emits it
    // for the IAT path it can reach via 32-bit displacement.
    if (p[0] == 0x48 && p[1] == 0xE9) return true;

    // 8-byte: `lea rax, [rip+disp32]; ret` — a constant-return thunk used by
    // protobuf descriptor accessors and similar functions.
    if (avail >= 8 && p[0] == 0x48 && p[1] == 0x8D && p[2] == 0x05 &&
        p[7] == 0xC3) return true;

    if (avail < 2) return false;

    // 2-byte: REX + push extended reg
    if (p[0] == 0x41 && (p[1] == 0x54 || p[1] == 0x55 ||
                         p[1] == 0x56 || p[1] == 0x57)) return true;
    if (p[0] == 0x40 && (p[1] == 0x53 || p[1] == 0x55 ||
                         p[1] == 0x56 || p[1] == 0x57)) return true;

    // 2-byte: jmp qword [rip+disp32] = FF 25 ?? ?? ?? ?? (import thunk)
    if (p[0] == 0xFF && p[1] == 0x25 && avail >= 6) return true;

    if (avail < 3) return false;

    // 3-byte: mov rax,rsp / mov r11,rsp
    if (p[0] == 0x48 && p[1] == 0x8B && p[2] == 0xC4) return true;
    if (p[0] == 0x4C && p[1] == 0x8B && p[2] == 0xDC) return true;

    // 3-byte: sub rsp, imm8 / sub rsp, imm32
    if (p[0] == 0x48 && p[1] == 0x83 && p[2] == 0xEC && avail >= 4) return true;
    if (p[0] == 0x48 && p[1] == 0x81 && p[2] == 0xEC && avail >= 7) return true;

    if (avail < 4) return false;

    // 4-byte: mov [rsp+disp], <reg64> — extremely common save sequence
    //   48 89 5C 24    mov [rsp+...], rbx
    //   48 89 4C 24    mov [rsp+...], rcx
    //   48 89 54 24    mov [rsp+...], rdx
    //   48 89 6C 24    mov [rsp+...], rbp
    //   48 89 74 24    mov [rsp+...], rsi
    //   48 89 7C 24    mov [rsp+...], rdi
    //   4C 89 {44,4C,54,5C,64,6C,74,7C} 24   mov [rsp+...], r8..r15
    if (p[0] == 0x48 && p[1] == 0x89 && p[3] == 0x24) {
        uint8_t modrm = p[2];
        if (modrm == 0x5C || modrm == 0x4C || modrm == 0x54 ||
            modrm == 0x6C || modrm == 0x74 || modrm == 0x7C) return true;
    }
    if (p[0] == 0x4C && p[1] == 0x89 && p[3] == 0x24) {
        uint8_t modrm = p[2];
        if (modrm == 0x44 || modrm == 0x4C || modrm == 0x54 || modrm == 0x5C ||
            modrm == 0x64 || modrm == 0x6C || modrm == 0x74 || modrm == 0x7C) return true;
    }

    // 3-byte: System V → Win64 ABI shuffle thunk. The CRT (and several Riot
    // helpers) emit a series of `mov reg64,reg64` moves at the very start to
    // re-route arguments before the real prologue. The first 3 bytes always
    // look like `48 89 CF`, `48 89 D6`, `4C 89 C2`, or `4C 89 C9`.
    if (p[0] == 0x48 && p[1] == 0x89 && (p[2] == 0xCF || p[2] == 0xD6 ||
                                         p[2] == 0xCA || p[2] == 0xD1)) return true;
    if (p[0] == 0x4C && p[1] == 0x89 && (p[2] == 0xC2 || p[2] == 0xC9 ||
                                         p[2] == 0xCA || p[2] == 0xD1)) return true;

    return false;
}

// Is the byte immediately before 'fileOff' a function terminator? Recognised:
//   CC (INT3 padding), 90 (NOP padding), 00 (zero padding),
//   C3 (RET), C2 ?? ?? (RET imm — checked via two bytes earlier),
//   E9 disp32 immediately preceding (unconditional JMP),
//   EB disp8 immediately preceding (short JMP),
//   FF 25 disp32 ending here (indirect JMP),
//   0F 0B (UD2).
bool prevByteTerminates(const PEFile& pe, uint32_t fileOff) {
    if (fileOff == 0) return true; // start of section
    uint8_t prev = pe.data[fileOff - 1];
    if (prev == 0xCC || prev == 0x90 || prev == 0x00) return true;
    if (prev == 0xC3) return true; // RET
    if (fileOff >= 3 && pe.data[fileOff - 3] == 0xC2) return true;            // RET imm16
    if (fileOff >= 5 && pe.data[fileOff - 5] == 0xE9) return true;            // JMP rel32
    if (fileOff >= 2 && pe.data[fileOff - 2] == 0xEB) return true;            // JMP rel8
    if (fileOff >= 6 && pe.data[fileOff - 6] == 0xFF
                     && pe.data[fileOff - 5] == 0x25) return true;             // JMP [rip+disp]
    if (fileOff >= 2 && pe.data[fileOff - 2] == 0x0F
                     && pe.data[fileOff - 1] == 0x0B) return true;             // UD2
    // JMP r/m64 (FF /4): byte before fileOff is the modrm in range E0..E7 for
    // RAX..RDI, with optional 0x41 REX.B prefix for R8..R15.
    if (fileOff >= 2 && pe.data[fileOff - 2] == 0xFF
                     && prev >= 0xE0 && prev <= 0xE7) return true;
    if (fileOff >= 3 && pe.data[fileOff - 3] == 0x41
                     && pe.data[fileOff - 2] == 0xFF
                     && prev >= 0xE0 && prev <= 0xE7) return true;
    return false;
}

// "Strong" sources are the ones backed by structured metadata on disk —
// pdata, the export table, an RTTI vftable slot, or an EH handler entry.
// Each by itself is sufficient evidence a real function lives at that RVA.
// DATA_FNPTR isn't here because a random QWORD in .data/.rdata that happens
// to land inside code is not unusual; we still count it for the score but
// not as proof of life.
bool hasStrongSource(uint16_t srcMask) {
    return (srcMask & (uint16_t)(SRC_PDATA | SRC_EXPORT |
                                  SRC_RTTI_VFUNC | SRC_EH_HANDLER)) != 0;
}

int confidenceScore(const FunctionBoundary& fb) {
    int s = 0;
    if (fb.sourceCount >= 2)    s += 2;
    if (hasStrongSource(fb.sources)) s += 2;
    if (fb.sources & SRC_PDATA) s += 1; // pdata is the canonical ground truth
    return s;
}

// Linear scan from startRVA until we see a function-terminator pattern
// (RET / JMP-uncond / UD2 followed by padding) or hit nextStartRVA. We don't
// run a full disasm — instead we look for the four byte patterns that mark
// the very end of a function in MSVC x64 binaries.
uint32_t computeFuncEnd(const Ctx& ctx, uint32_t startRVA, uint32_t hardLimitRVA) {
    int es = ctx.findExec(startRVA);
    if (es < 0) return startRVA + 1;
    const auto& sec = ctx.exec[es];
    uint32_t off = ctx.pe.rvaToOffset(startRVA);
    if (!off) return startRVA + 1;

    uint32_t secEndOff = sec.rawOff + sec.rawSize;
    uint32_t limitRVA = std::min(hardLimitRVA, sec.endRVA);
    uint32_t limitOff = off + (limitRVA - startRVA);
    if (limitOff > secEndOff) limitOff = secEndOff;
    if (limitOff > (uint32_t)ctx.pe.data.size()) limitOff = (uint32_t)ctx.pe.data.size();

    uint32_t pos = off;
    uint32_t safety = 0;
    auto rvaOf = [&](uint32_t p) { return startRVA + (p - off); };
    auto peekPad = [&](uint32_t p) -> bool {
        if (p >= limitOff) return true;
        uint8_t b = ctx.pe.data[p];
        return b == 0xCC || b == 0x00 || b == 0x90;
    };

    while (pos < limitOff && safety < 0x10000) {
        safety++;
        uint8_t b = ctx.pe.data[pos];

        // Multi-byte padding run = function end
        if (b == 0xCC || b == 0x00) {
            uint32_t run = 0;
            while (pos + run < limitOff && ctx.pe.data[pos + run] == b) run++;
            if (run >= 4) return rvaOf(pos);
            pos += run;
            continue;
        }

        // RET / RET imm — function end if followed by padding
        if (b == 0xC3) {
            if (peekPad(pos + 1)) return rvaOf(pos + 1);
            pos += 1; continue;
        }
        if (b == 0xC2 && pos + 3 <= limitOff) {
            if (peekPad(pos + 3)) return rvaOf(pos + 3);
            pos += 3; continue;
        }

        // JMP rel32 — function end if followed by padding
        if (b == 0xE9 && pos + 5 <= limitOff) {
            if (peekPad(pos + 5)) return rvaOf(pos + 5);
            pos += 5; continue;
        }
        // JMP rel8 — function end if followed by padding
        if (b == 0xEB && pos + 2 <= limitOff) {
            if (peekPad(pos + 2)) return rvaOf(pos + 2);
            pos += 2; continue;
        }
        // JMP [rip+disp32] (FF 25)
        if (b == 0xFF && pos + 6 <= limitOff && ctx.pe.data[pos + 1] == 0x25) {
            if (peekPad(pos + 6)) return rvaOf(pos + 6);
            pos += 6; continue;
        }
        // UD2 (0F 0B)
        if (b == 0x0F && pos + 2 <= limitOff && ctx.pe.data[pos + 1] == 0x0B) {
            return rvaOf(pos + 2);
        }

        pos++; // fall through: skip 1 byte (conservative undercount)
    }
    return rvaOf(limitOff);
}

// Step 2 — linear-sweep call/jmp scan inside a candidate function. Yields the
// raw E8/E9 target RVAs. Conservative: stops at the first byte that doesn't
// look like an instruction start (likely padding or another function).
void scanCallsAndJumps(const Ctx& ctx, uint32_t startRVA, uint32_t maxScan,
                       std::vector<uint32_t>& callTargets,
                       std::vector<uint32_t>& jmpTargets)
{
    int es = ctx.findExec(startRVA);
    if (es < 0) return;
    const auto& sec = ctx.exec[es];
    uint32_t off = ctx.pe.rvaToOffset(startRVA);
    if (!off) return;

    uint32_t secEndOff = sec.rawOff + sec.rawSize;
    uint32_t limit = std::min<uint32_t>(off + maxScan, secEndOff);

    uint32_t pos = off;
    // Single-step using a tiny manual decoder. Full pefix::Disasm is overkill
    // here (we only need length + branch target).
    int safety = 0;
    while (pos < limit && safety < 200000) {
        safety++;
        uint8_t b = ctx.pe.data[pos];
        uint32_t instrRVA = startRVA + (pos - off);

        // Hard stop on padding runs (likely function end)
        if (b == 0xCC || b == 0x00) {
            // Verify multi-byte padding to avoid stopping on legitimate INT3/zero in code
            uint32_t run = 0;
            while (pos + run < limit && ctx.pe.data[pos + run] == b) run++;
            if (run >= 4) break;
        }

        // Direct CALL — always treat target as a function start candidate.
        if (b == 0xE8) {
            if (pos + 5 > limit) break;
            int32_t disp = *(int32_t*)(ctx.pe.data.data() + pos + 1);
            uint32_t target = instrRVA + 5 + (uint32_t)disp;
            if (ctx.inAnyExec(target)) callTargets.push_back(target);
            pos += 5;
            continue;
        }

        // Direct JMP — only treat the target as a function start when this
        // E9 is a *tail call*, i.e. the bytes immediately following the JMP
        // are padding (CC/00/90/run). Otherwise it's a normal intra-function
        // branch and the target is just a basic-block leader.
        if (b == 0xE9) {
            if (pos + 5 > limit) break;
            int32_t disp = *(int32_t*)(ctx.pe.data.data() + pos + 1);
            uint32_t target = instrRVA + 5 + (uint32_t)disp;
            bool isTailCall = false;
            if (pos + 5 < limit) {
                uint8_t after = ctx.pe.data[pos + 5];
                isTailCall = (after == 0xCC || after == 0x00 || after == 0x90);
            } else {
                isTailCall = true; // ends section/region
            }
            if (isTailCall && ctx.inAnyExec(target)) jmpTargets.push_back(target);
            // Either way, an unconditional JMP terminates linear sweep.
            pos += 5;
            break;
        }

        // Short JMP / Jcc
        if (b == 0xEB) { pos += 2; continue; }
        if (b >= 0x70 && b <= 0x7F) { pos += 2; continue; }
        // Jcc rel32 (0F 80..8F)
        if (b == 0x0F) {
            if (pos + 1 >= limit) { pos++; continue; }
            uint8_t b2 = ctx.pe.data[pos + 1];
            if (b2 >= 0x80 && b2 <= 0x8F) { pos += 6; continue; }
        }

        // RET — function end
        if (b == 0xC3) { pos += 1; break; }
        if (b == 0xC2) { pos += 3; break; }

        // Fallback: skip 1 byte. We accept undercount of branches in exchange
        // for not requiring a full decoder here. Phase 4 / a proper disasm
        // pass will tighten this.
        pos += 1;
    }
}

void mergeBoundary(std::unordered_map<uint32_t, FunctionBoundary>& bmap,
                   uint32_t rva, uint16_t srcBit, const Ctx& ctx)
{
    auto it = bmap.find(rva);
    if (it == bmap.end()) {
        FunctionBoundary fb{};
        fb.startRVA = rva;
        fb.endRVA = 0;
        fb.sources = srcBit;
        fb.sourceCount = 1;
        fb.inObfuscated = ctx.isObfRVA(rva);
        fb.validated = false;
        bmap[rva] = fb;
    } else {
        if (!(it->second.sources & srcBit)) {
            it->second.sources |= srcBit;
            it->second.sourceCount++;
        }
    }
}

// Score-based validation. Each candidate accumulates up to 4 points:
//   +1 multi-source (>=2 independent sources agree on the same RVA)
//   +1 strong source (any source other than DIRECT_CALL/DIRECT_JMP)
//   +1 prologue pattern match at the first byte
//   +1 previous byte is a function terminator
// Accept if score >= 2 (i.e. at least two independent signals).
bool validateScored(const Ctx& ctx, FunctionBoundary& fb,
                     const FbrConfig& cfg, FbrStats& st)
{
    uint32_t off = ctx.pe.rvaToOffset(fb.startRVA);
    if (!off || off >= ctx.pe.data.size()) {
        st.rejectedOutOfRange++;
        return false;
    }

    uint8_t b0 = ctx.pe.data[off];
    if (b0 == 0x00 || b0 == 0xCC || b0 == 0x90 || !looksLikeInstrStart(b0)) {
        st.rejectedBadFirstByte++;
        return false;
    }

    if (!cfg.validateStrict) {
        fb.validated = true;
        return true;
    }

    // Weighted scoring. "Strong" sources (pdata/export/RTTI/eh) and multi-
    // source agreement count two points each. Direct call target and
    // DATA_FNPTR are mid-strength (+1) because each one occasionally points
    // into the middle of a function or at noise data. Prologue match and
    // prev-byte terminator add one each.
    int score = 0;
    if (fb.sourceCount >= 2)                  score += 2;
    if (hasStrongSource(fb.sources))          score += 2;
    if (fb.sources & SRC_DIRECT_CALL)         score += 1;
    if (fb.sources & SRC_DATA_FNPTR)          score += 1;
    bool prologue = matchesPrologue(ctx.pe, off);
    bool prevTerm = prevByteTerminates(ctx.pe, off);
    if (prologue) score += 1;
    if (prevTerm) score += 1;

    // Gate: a candidate seen only through weak signals (call/jmp/fnptr, no
    // pdata-style metadata agreement, no co-discovery) must match BOTH a
    // known prologue AND have a prev-byte terminator. Spot checks show a
    // single weak source plus one of the two heuristics still passes too
    // many internal-branch targets (helpers, recursive calls, switch arms).
    bool onlyWeak = !hasStrongSource(fb.sources) && fb.sourceCount < 2;
    if (onlyWeak && !(prologue && prevTerm)) {
        st.rejectedNoPrevTerm++;
        if (st.rejectSampleNoSignal.size() < 30)
            st.rejectSampleNoSignal.push_back(fb.startRVA);
        return false;
    }

    if (score < 2) {
        st.rejectedNoPrevTerm++;
        if (st.rejectSampleNoSignal.size() < 30)
            st.rejectSampleNoSignal.push_back(fb.startRVA);
        return false;
    }
    fb.validated = true;
    return true;
}

} // namespace

const FunctionBoundary* FbrResult::findExact(uint32_t rva) const {
    auto it = std::lower_bound(functions.begin(), functions.end(), rva,
        [](const FunctionBoundary& f, uint32_t r) { return f.startRVA < r; });
    if (it != functions.end() && it->startRVA == rva) return &*it;
    return nullptr;
}

const FunctionBoundary* FbrResult::findContaining(uint32_t rva) const {
    auto it = std::upper_bound(functions.begin(), functions.end(), rva,
        [](uint32_t r, const FunctionBoundary& f) { return r < f.startRVA; });
    if (it == functions.begin()) return nullptr;
    --it;
    if (it->endRVA && rva >= it->endRVA) return nullptr;
    return &*it;
}

FbrResult discoverFunctionBoundaries(const PEFile& pe, uint64_t imageBase,
                                      const FbrConfig& cfg) {
    auto t0 = std::chrono::high_resolution_clock::now();
    FbrResult result;
    FbrStats& st = result.stats;
    if (!pe.nt) return result;

    Ctx ctx = collectSections(pe, imageBase);
    if (ctx.exec.empty()) return result;

    std::unordered_map<uint32_t, FunctionBoundary> bmap;

    // ---- Step 1: seed collection ----
    auto addAll = [&](const std::vector<uint32_t>& v, uint16_t src) {
        for (uint32_t r : v) mergeBoundary(bmap, r, src, ctx);
    };
    std::vector<uint32_t> tmp;

    if (cfg.collectPdata) {
        tmp.clear(); seedPdata(ctx, tmp);
        st.seedsPdata = (uint32_t)tmp.size();
        addAll(tmp, SRC_PDATA);
    }
    if (cfg.collectExports) {
        tmp.clear(); seedExports(ctx, tmp);
        st.seedsExport = (uint32_t)tmp.size();
        addAll(tmp, SRC_EXPORT);
    }
    if (cfg.collectRttiVfunc) {
        tmp.clear(); seedRttiVfunc(ctx, tmp);
        st.seedsRttiVfunc = (uint32_t)tmp.size();
        addAll(tmp, SRC_RTTI_VFUNC);
    }
    if (cfg.collectDataFnPtr) {
        tmp.clear(); seedDataFnPtr(ctx, tmp);
        st.seedsDataFnPtr = (uint32_t)tmp.size();
        addAll(tmp, SRC_DATA_FNPTR);
    }
    if (cfg.collectEhHandler) {
        tmp.clear(); seedEhHandler(ctx, tmp);
        st.seedsEhHandler = (uint32_t)tmp.size();
        addAll(tmp, SRC_EH_HANDLER);
    }
    st.seedsTotal = (uint32_t)bmap.size();

    // ---- Step 2: caller-driven expansion ----
    std::unordered_set<uint32_t> visited;
    std::vector<uint32_t> frontier;
    frontier.reserve(bmap.size());
    for (auto& kv : bmap) frontier.push_back(kv.first);

    for (uint32_t iter = 0; iter < cfg.maxExpandIters; iter++) {
        st.expandIterations = iter + 1;
        std::vector<uint32_t> nextFrontier;
        for (uint32_t f : frontier) {
            if (!visited.insert(f).second) continue;
            std::vector<uint32_t> callT, jmpT;
            if (cfg.expandCalls || cfg.expandJumps) {
                scanCallsAndJumps(ctx, f, cfg.maxFunctionScan, callT, jmpT);
            }
            if (cfg.expandCalls) {
                for (uint32_t t : callT) {
                    bool fresh = bmap.find(t) == bmap.end();
                    mergeBoundary(bmap, t, SRC_DIRECT_CALL, ctx);
                    if (fresh) { st.expandedDirectCall++; nextFrontier.push_back(t); }
                }
            }
            if (cfg.expandJumps) {
                for (uint32_t t : jmpT) {
                    bool fresh = bmap.find(t) == bmap.end();
                    mergeBoundary(bmap, t, SRC_DIRECT_JMP, ctx);
                    if (fresh) { st.expandedDirectJmp++; nextFrontier.push_back(t); }
                }
            }
        }
        if (nextFrontier.empty()) break;
        frontier.swap(nextFrontier);
    }

    // ---- Step 3: score-based validation ----
    for (auto it = bmap.begin(); it != bmap.end(); ) {
        if (!validateScored(ctx, it->second, cfg, st)) {
            it = bmap.erase(it);
        } else {
            ++it;
        }
    }

    // ---- Output: sort, end-RVA, overlap resolution ----
    std::vector<FunctionBoundary> sorted;
    sorted.reserve(bmap.size());
    for (auto& kv : bmap) sorted.push_back(kv.second);
    std::sort(sorted.begin(), sorted.end(),
              [](const FunctionBoundary& a, const FunctionBoundary& b) {
                  return a.startRVA < b.startRVA;
              });

    // computeFuncEnd: scan until the next "strong anchor" candidate's start.
    // Strong anchors are pdata/export/RTTI/EH-backed boundaries or multi-
    // source agreements — they are trustworthy enough to use as an upper
    // bound. Weak singletons (single call/jmp/fnptr) are bypassed so the
    // linear sweep can run all the way to a real RET / JMP+pad. A weak
    // singleton sitting inside that range is then caught by the overlap
    // resolver below as an internal branch target.
    auto isStrongAnchor = [](const FunctionBoundary& f) {
        return hasStrongSource(f.sources) || f.sourceCount >= 2;
    };
    std::vector<uint32_t> nextStrongLimit(sorted.size(), 0xFFFFFFFFu);
    {
        uint32_t lastStrongRVA = 0xFFFFFFFFu;
        for (size_t i = sorted.size(); i-- > 0; ) {
            nextStrongLimit[i] = lastStrongRVA;
            if (isStrongAnchor(sorted[i])) lastStrongRVA = sorted[i].startRVA;
        }
    }
    for (size_t i = 0; i < sorted.size(); i++) {
        sorted[i].endRVA = computeFuncEnd(ctx, sorted[i].startRVA, nextStrongLimit[i]);
    }

    // Overlap resolution: walk left-to-right, keep the previous boundary as a
    // tentative "winner" and discard any subsequent candidate whose start is
    // inside that winner's [start, end). When the new candidate has a strictly
    // higher confidence score, swap (the older entry was likely a branch
    // target into this real function).
    for (auto& fb : sorted) {
        if (result.functions.empty()) {
            result.functions.push_back(fb);
            continue;
        }
        FunctionBoundary& prev = result.functions.back();
        if (fb.startRVA >= prev.endRVA) {
            result.functions.push_back(fb);
            continue;
        }
        // Overlap. Compare confidence.
        int prevScore = confidenceScore(prev);
        int newScore  = confidenceScore(fb);
        if (newScore > prevScore) {
            // Replace: re-extend end past whatever prev/new covered together.
            uint32_t mergedEnd = std::max(prev.endRVA, fb.endRVA);
            prev = fb;
            prev.endRVA = mergedEnd;
        }
        st.rejectedOverlap++;
    }

    for (auto& fb : result.functions) {
        if (fb.inObfuscated) st.finalGrfnFuncs++;
        else                  st.finalTextFuncs++;
    }
    st.finalTotal = (uint32_t)result.functions.size();

    auto t1 = std::chrono::high_resolution_clock::now();
    st.durationMs = (uint32_t)std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();

    log::ok("FBR: seeds=%u (pd=%u ex=%u rt=%u fp=%u eh=%u), expand=%u iters (+call %u, +jmp %u), final=%u (.text=%u, .grfn=%u), %ums",
        st.seedsTotal, st.seedsPdata, st.seedsExport, st.seedsRttiVfunc,
        st.seedsDataFnPtr, st.seedsEhHandler,
        st.expandIterations, st.expandedDirectCall, st.expandedDirectJmp,
        st.finalTotal, st.finalTextFuncs, st.finalGrfnFuncs, st.durationMs);
    if (st.rejectedBadFirstByte || st.rejectedNoPrevTerm ||
        st.rejectedOutOfRange || st.rejectedOverlap) {
        log::info("FBR rejected: bad-first=%u no-signal=%u out-of-range=%u overlap=%u",
            st.rejectedBadFirstByte, st.rejectedNoPrevTerm,
            st.rejectedOutOfRange, st.rejectedOverlap);
    }

    return result;
}

} // namespace pefix
