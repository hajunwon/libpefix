#pragma once
#include <cstdint>
#include <climits>
#include <vector>
#include <string>
#include <unordered_map>
#include <map>

// x86-64 IR (subset)

namespace pefix {

enum class Reg : uint16_t {
    RAX = 0, RCX, RDX, RBX, RSP, RBP, RSI, RDI,
    R8, R9, R10, R11, R12, R13, R14, R15,
    FLAGS = 32,
    RIP = 33,
    TEMP0 = 64, TEMP1, TEMP2, TEMP3, TEMP4, TEMP5, TEMP6, TEMP7,
    NONE = 0xFFFF
};

inline Reg gpr(uint8_t idx) { return (Reg)(idx & 0xF); }

inline const char* regName(Reg r) {
    static const char* names64[] = {
        "rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
        "r8","r9","r10","r11","r12","r13","r14","r15"
    };
    uint16_t v = (uint16_t)r;
    if (v < 16) return names64[v];
    if (v == 32) return "flags";
    if (v == 33) return "rip";
    if (v >= 64 && v < 72) { static char buf[8]; sprintf_s(buf, "t%d", v - 64); return buf; }
    return "??";
}

inline const char* regName32(Reg r) {
    static const char* names[] = {
        "eax","ecx","edx","ebx","esp","ebp","esi","edi",
        "r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d"
    };
    uint16_t v = (uint16_t)r;
    if (v < 16) return names[v];
    return regName(r);
}

enum class Width : uint8_t { W8 = 8, W16 = 16, W32 = 32, W64 = 64 };

enum class Op : uint16_t {
    // Data movement
    MOV, LOAD, STORE, LEA, PUSH, POP, XCHG, BSWAP,
    MOVZX, MOVSX,
    // Arithmetic
    ADD, SUB, IMUL, MUL, DIV, IDIV, NEG, INC, DEC,
    // Bitwise
    AND, OR, XOR, NOT, SHL, SHR, SAR, ROL, ROR,
    // Comparison / test
    CMP, TEST, BT, BTS, BTR,
    // Control flow
    JMP, JCC, CALL, RET,
    // Conditional move / set
    CMOV, SETcc,
    // Stack frame
    ENTER, LEAVE,
    NOP, INT3, UD2, CDQ, CQO,
    UNDEF,
};

inline const char* opName(Op op) {
    switch (op) {
    case Op::MOV: return "mov"; case Op::LOAD: return "load"; case Op::STORE: return "store";
    case Op::LEA: return "lea"; case Op::PUSH: return "push"; case Op::POP: return "pop";
    case Op::XCHG: return "xchg"; case Op::BSWAP: return "bswap";
    case Op::MOVZX: return "movzx"; case Op::MOVSX: return "movsx";
    case Op::ADD: return "add"; case Op::SUB: return "sub";
    case Op::IMUL: return "imul"; case Op::MUL: return "mul";
    case Op::DIV: return "div"; case Op::IDIV: return "idiv";
    case Op::NEG: return "neg"; case Op::INC: return "inc"; case Op::DEC: return "dec";
    case Op::AND: return "and"; case Op::OR: return "or";
    case Op::XOR: return "xor"; case Op::NOT: return "not";
    case Op::SHL: return "shl"; case Op::SHR: return "shr"; case Op::SAR: return "sar";
    case Op::ROL: return "rol"; case Op::ROR: return "ror";
    case Op::CMP: return "cmp"; case Op::TEST: return "test";
    case Op::BT: return "bt"; case Op::BTS: return "bts"; case Op::BTR: return "btr";
    case Op::JMP: return "jmp"; case Op::JCC: return "jcc";
    case Op::CALL: return "call"; case Op::RET: return "ret";
    case Op::CMOV: return "cmov"; case Op::SETcc: return "setcc";
    case Op::NOP: return "nop"; case Op::INT3: return "int3"; case Op::UD2: return "ud2";
    case Op::CDQ: return "cdq"; case Op::CQO: return "cqo";
    case Op::UNDEF: return "???";
    default: return "???";
    }
}

// Condition codes (shared by JCC, CMOV, SETcc)
enum class CC : uint8_t {
    O = 0, NO, B, AE, Z, NZ, BE, A,
    S, NS, P, NP, L, GE, LE, G,
    NONE = 0xFF
};

inline const char* ccName(CC cc) {
    static const char* names[] = {"o","no","b","ae","z","nz","be","a","s","ns","p","np","l","ge","le","g"};
    return (uint8_t)cc < 16 ? names[(uint8_t)cc] : "";
}

struct Value {
    enum Kind : uint8_t { REG, IMM, MEM, LABEL, NONE } kind = NONE;
    Reg reg = Reg::NONE;
    Reg index = Reg::NONE;
    uint8_t scale = 0;
    int64_t imm = 0;
    Width width = Width::W64;

    static Value Reg(pefix::Reg r, Width w = Width::W64) {
        Value v; v.kind = REG; v.reg = r; v.width = w; return v;
    }
    static Value Imm(int64_t val, Width w = Width::W64) {
        Value v; v.kind = IMM; v.imm = val; v.width = w; return v;
    }
    static Value Mem(pefix::Reg base, int64_t disp = 0, pefix::Reg idx = pefix::Reg::NONE, uint8_t sc = 0, Width w = Width::W64) {
        Value v; v.kind = MEM; v.reg = base; v.imm = disp; v.index = idx; v.scale = sc; v.width = w; return v;
    }
    static Value Label(int64_t va) {
        Value v; v.kind = LABEL; v.imm = va; return v;
    }
    static Value None() { return Value{}; }
    bool isNone() const { return kind == NONE; }
    bool isReg() const { return kind == REG; }
    bool isImm() const { return kind == IMM; }
    bool isMem() const { return kind == MEM; }
};

struct Instr {
    uint64_t addr = 0;
    uint32_t rawLen = 0;
    Op op = Op::UNDEF;
    Value dst;
    Value src1;
    Value src2;
    CC cc = CC::NONE;
    uint8_t flagsRead = 0;
    uint8_t flagsWritten = 0;
    bool simplified = false;
    bool dead = false;
};

constexpr uint8_t FLAG_ZF = 1;
constexpr uint8_t FLAG_CF = 2;
constexpr uint8_t FLAG_SF = 4;
constexpr uint8_t FLAG_OF = 8;
constexpr uint8_t FLAG_PF = 16;
constexpr uint8_t FLAG_ALL = FLAG_ZF | FLAG_CF | FLAG_SF | FLAG_OF | FLAG_PF;

struct Block {
    uint64_t startAddr = 0;
    uint64_t endAddr = 0;
    std::vector<Instr> instrs;
    std::vector<uint32_t> succs;
    std::vector<uint32_t> preds;
    bool isTrampoline = false;
    bool isDeadCode = false;
};

struct DispatchKey {
    Reg reg = Reg::NONE;
    uint32_t value = 0;
    std::vector<uint32_t> imulConsts;
    uint32_t firstImulRVA = 0;
};

struct Func {
    uint64_t entryAddr = 0;
    std::vector<Block> blocks;
    int32_t frameSize = 0;
    std::vector<uint64_t> callTargets;
    std::unordered_map<uint64_t, uint32_t> addrToBlock;
    Reg dispatchKeyReg = Reg::NONE;
    int64_t dispatchKeyValue = INT64_MIN;
    std::vector<DispatchKey> dispatchKeys;

    uint32_t totalInstrs() const {
        uint32_t n = 0;
        for (auto& b : blocks) n += (uint32_t)b.instrs.size();
        return n;
    }
    uint32_t liveInstrs() const {
        uint32_t n = 0;
        for (auto& b : blocks)
            if (!b.isDeadCode)
                for (auto& i : b.instrs)
                    if (!i.dead) n++;
        return n;
    }
};

} // namespace pefix
