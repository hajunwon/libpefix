#include <pefix/x86_64/emu.h>
#include <pefix/x86_64/disasm.h>
#include <cstdio>
#include <cstring>

namespace pefix {

Emulator::Emulator(const PEFile& pe, uint64_t imageBase)
    : pe_(pe), imageBase_(imageBase) {}

void Emulator::loadSections() {
    for (WORD i = 0; i < pe_.numSections; i++) {
        uint32_t rawOff = pe_.sections[i].PointerToRawData;
        uint32_t rawSz = pe_.sections[i].SizeOfRawData;
        uint32_t va = pe_.sections[i].VirtualAddress;
        if (rawOff + rawSz > pe_.data.size()) continue;
        for (uint32_t j = 0; j < rawSz; j++)
            mem_[imageBase_ + va + j] = pe_.data[rawOff + j];
    }
}

void Emulator::setupStack(uint64_t stackBase, uint32_t stackSize) {
    stackBase_ = stackBase;
    state_.regs[(int)Reg::RSP] = stackBase + stackSize - 0x100;
    for (uint32_t i = 0; i < stackSize; i++)
        mem_[stackBase + i] = 0;
}

void Emulator::addStub(uint64_t funcVA, uint64_t retval) {
    stubs_[funcVA] = retval;
}

uint8_t Emulator::readByte(uint64_t addr) {
    auto it = mem_.find(addr);
    return it != mem_.end() ? it->second : 0;
}
uint16_t Emulator::readWord(uint64_t addr) {
    return (uint16_t)readByte(addr) | ((uint16_t)readByte(addr+1) << 8);
}
uint32_t Emulator::readDword(uint64_t addr) {
    return (uint32_t)readWord(addr) | ((uint32_t)readWord(addr+2) << 16);
}
uint64_t Emulator::readQword(uint64_t addr) {
    return (uint64_t)readDword(addr) | ((uint64_t)readDword(addr+4) << 32);
}
uint64_t Emulator::readMem(uint64_t addr, Width w) {
    switch (w) {
    case Width::W8: return readByte(addr);
    case Width::W16: return readWord(addr);
    case Width::W32: return readDword(addr);
    case Width::W64: return readQword(addr);
    }
    return 0;
}

void Emulator::writeByte(uint64_t addr, uint8_t val) {
    mem_[addr] = val;
    logMemAccess(addr, val, 1, true);
}
void Emulator::writeWord(uint64_t addr, uint16_t val) {
    writeByte(addr, val & 0xFF); writeByte(addr+1, (val>>8)&0xFF);
}
void Emulator::writeDword(uint64_t addr, uint32_t val) {
    writeWord(addr, val & 0xFFFF); writeWord(addr+2, (val>>16)&0xFFFF);
}
void Emulator::writeQword(uint64_t addr, uint64_t val) {
    writeDword(addr, (uint32_t)val); writeDword(addr+4, (uint32_t)(val>>32));
}
void Emulator::writeMem(uint64_t addr, uint64_t val, Width w) {
    switch (w) {
    case Width::W8: writeByte(addr, (uint8_t)val); break;
    case Width::W16: writeWord(addr, (uint16_t)val); break;
    case Width::W32: writeDword(addr, (uint32_t)val); break;
    case Width::W64: writeQword(addr, val); break;
    }
}

void Emulator::logMemAccess(uint64_t addr, uint64_t val, uint32_t sz, bool isWrite) {
    if (watchStart_ && (addr >= watchStart_ && addr < watchEnd_)) {
        memLog_.push_back({addr, val, sz, isWrite, state_.rip});
    }
}

void Emulator::push64(uint64_t val) {
    state_.regs[(int)Reg::RSP] -= 8;
    writeQword(state_.regs[(int)Reg::RSP], val);
}

uint64_t Emulator::pop64() {
    uint64_t val = readQword(state_.regs[(int)Reg::RSP]);
    state_.regs[(int)Reg::RSP] += 8;
    return val;
}

uint64_t Emulator::resolveAddr(const Value& v) {
    if (v.kind != Value::MEM) return 0;
    uint64_t addr = v.imm;
    if (v.reg != Reg::NONE && (uint16_t)v.reg < 16)
        addr += state_.regs[(uint16_t)v.reg];
    if (v.index != Reg::NONE && (uint16_t)v.index < 16)
        addr += state_.regs[(uint16_t)v.index] * (v.scale ? v.scale : 1);
    return addr;
}

uint64_t Emulator::resolveValue(const Value& v) {
    switch (v.kind) {
    case Value::REG:
        if ((uint16_t)v.reg < 16) {
            uint64_t val = state_.regs[(uint16_t)v.reg];
            switch (v.width) {
            case Width::W8: return val & 0xFF;
            case Width::W16: return val & 0xFFFF;
            case Width::W32: return val & 0xFFFFFFFF;
            default: return val;
            }
        }
        return 0;
    case Value::IMM: return (uint64_t)v.imm;
    case Value::MEM: return readMem(resolveAddr(v), v.width);
    case Value::LABEL: return (uint64_t)v.imm;
    default: return 0;
    }
}

void Emulator::storeValue(const Value& v, uint64_t val) {
    if (v.kind == Value::REG && (uint16_t)v.reg < 16) {
        switch (v.width) {
        case Width::W8: state_.regs[(uint16_t)v.reg] = (state_.regs[(uint16_t)v.reg] & ~0xFFULL) | (val & 0xFF); break;
        case Width::W16: state_.regs[(uint16_t)v.reg] = (state_.regs[(uint16_t)v.reg] & ~0xFFFFULL) | (val & 0xFFFF); break;
        case Width::W32: state_.regs[(uint16_t)v.reg] = val & 0xFFFFFFFF; break;
        case Width::W64: state_.regs[(uint16_t)v.reg] = val; break;
        }
    } else if (v.kind == Value::MEM) {
        writeMem(resolveAddr(v), val, v.width);
    }
}

bool Emulator::evalCC(CC cc) {
    switch (cc) {
    case CC::O: return state_.of();
    case CC::NO: return !state_.of();
    case CC::B: return state_.cf();
    case CC::AE: return !state_.cf();
    case CC::Z: return state_.zf();
    case CC::NZ: return !state_.zf();
    case CC::BE: return state_.cf() || state_.zf();
    case CC::A: return !state_.cf() && !state_.zf();
    case CC::S: return state_.sf();
    case CC::NS: return !state_.sf();
    case CC::L: return state_.sf() != state_.of();
    case CC::GE: return state_.sf() == state_.of();
    case CC::LE: return state_.zf() || (state_.sf() != state_.of());
    case CC::G: return !state_.zf() && (state_.sf() == state_.of());
    default: return false;
    }
}

bool Emulator::execInstr(const Instr& instr) {
    uint64_t s1, s2, result;
    switch (instr.op) {
    case Op::MOV:
        storeValue(instr.dst, resolveValue(instr.src1));
        break;
    case Op::LEA:
        if (instr.src1.kind == Value::MEM)
            storeValue(instr.dst, resolveAddr(instr.src1));
        break;
    case Op::ADD:
        s1 = resolveValue(instr.src1); s2 = resolveValue(instr.src2);
        result = s1 + s2;
        storeValue(instr.dst, result);
        state_.updateFlags(result, instr.dst.width);
        state_.setCF(result < s1);
        break;
    case Op::SUB:
        s1 = resolveValue(instr.src1); s2 = resolveValue(instr.src2);
        result = s1 - s2;
        storeValue(instr.dst, result);
        state_.updateFlags(result, instr.dst.width);
        state_.setCF(s1 < s2);
        break;
    case Op::IMUL:
        s1 = resolveValue(instr.src1);
        s2 = instr.src2.isNone() ? s1 : resolveValue(instr.src2);
        result = s1 * s2;
        storeValue(instr.dst, result);
        state_.updateFlags(result, instr.dst.width);
        break;
    case Op::AND:
        s1 = resolveValue(instr.src1); s2 = resolveValue(instr.src2);
        result = s1 & s2;
        storeValue(instr.dst, result);
        state_.updateFlags(result, instr.dst.width);
        state_.setCF(false); state_.setOF(false);
        break;
    case Op::OR:
        s1 = resolveValue(instr.src1); s2 = resolveValue(instr.src2);
        result = s1 | s2;
        storeValue(instr.dst, result);
        state_.updateFlags(result, instr.dst.width);
        state_.setCF(false); state_.setOF(false);
        break;
    case Op::XOR:
        s1 = resolveValue(instr.src1); s2 = resolveValue(instr.src2);
        result = s1 ^ s2;
        storeValue(instr.dst, result);
        state_.updateFlags(result, instr.dst.width);
        state_.setCF(false); state_.setOF(false);
        break;
    case Op::NOT:
        result = ~resolveValue(instr.src1);
        storeValue(instr.dst, result);
        break;
    case Op::NEG:
        s1 = resolveValue(instr.src1);
        result = (~s1) + 1;
        storeValue(instr.dst, result);
        state_.updateFlags(result, instr.dst.width);
        state_.setCF(s1 != 0);
        break;
    case Op::SHL:
        s1 = resolveValue(instr.src1); s2 = resolveValue(instr.src2) & 63;
        result = s1 << s2;
        storeValue(instr.dst, result);
        state_.updateFlags(result, instr.dst.width);
        break;
    case Op::SHR:
        s1 = resolveValue(instr.src1); s2 = resolveValue(instr.src2) & 63;
        result = s1 >> s2;
        storeValue(instr.dst, result);
        state_.updateFlags(result, instr.dst.width);
        break;
    case Op::SAR:
        s1 = resolveValue(instr.src1); s2 = resolveValue(instr.src2) & 63;
        result = (uint64_t)((int64_t)s1 >> s2);
        storeValue(instr.dst, result);
        state_.updateFlags(result, instr.dst.width);
        break;
    case Op::ROL: case Op::ROR:
        s1 = resolveValue(instr.src1); s2 = resolveValue(instr.src2) & 63;
        if (instr.op == Op::ROL) result = (s1 << s2) | (s1 >> (64 - s2));
        else result = (s1 >> s2) | (s1 << (64 - s2));
        storeValue(instr.dst, result);
        break;
    case Op::TEST:
        s1 = resolveValue(instr.src1); s2 = resolveValue(instr.src2);
        result = s1 & s2;
        state_.updateFlags(result, instr.src1.width);
        state_.setCF(false); state_.setOF(false);
        break;
    case Op::CMP:
        s1 = resolveValue(instr.src1); s2 = resolveValue(instr.src2);
        result = s1 - s2;
        state_.updateFlags(result, instr.src1.width);
        state_.setCF(s1 < s2);
        state_.setOF(((s1 ^ s2) & (s1 ^ result)) >> 63);
        break;
    case Op::BT:
        s1 = resolveValue(instr.src1); s2 = resolveValue(instr.src2);
        state_.setCF((s1 >> (s2 & 63)) & 1);
        break;
    case Op::CMOV:
        if (evalCC(instr.cc))
            storeValue(instr.dst, resolveValue(instr.src1));
        break;
    case Op::SETcc:
        storeValue(instr.dst, evalCC(instr.cc) ? 1 : 0);
        break;
    case Op::PUSH:
        push64(resolveValue(instr.src1));
        break;
    case Op::POP:
        storeValue(instr.dst, pop64());
        break;
    case Op::XCHG: {
        uint64_t a = resolveValue(instr.dst), b = resolveValue(instr.src1);
        storeValue(instr.dst, b);
        storeValue(instr.src1, a);
        break;
    }
    case Op::BSWAP:
        s1 = resolveValue(instr.dst);
        if (instr.dst.width == Width::W64)
            result = _byteswap_uint64(s1);
        else
            result = _byteswap_ulong((uint32_t)s1);
        storeValue(instr.dst, result);
        break;
    case Op::MOVZX:
        storeValue(instr.dst, resolveValue(instr.src1));
        break;
    case Op::MOVSX: {
        s1 = resolveValue(instr.src1);
        if (instr.src1.width == Width::W8) result = (uint64_t)(int64_t)(int8_t)s1;
        else if (instr.src1.width == Width::W16) result = (uint64_t)(int64_t)(int16_t)s1;
        else if (instr.src1.width == Width::W32) result = (uint64_t)(int64_t)(int32_t)s1;
        else result = s1;
        storeValue(instr.dst, result);
        break;
    }
    case Op::INC:
        s1 = resolveValue(instr.src1);
        result = s1 + 1;
        storeValue(instr.dst, result);
        state_.updateFlags(result, instr.dst.width);
        break;
    case Op::DEC:
        s1 = resolveValue(instr.src1);
        result = s1 - 1;
        storeValue(instr.dst, result);
        state_.updateFlags(result, instr.dst.width);
        break;
    case Op::CDQ:
        if (state_.regs[(int)Reg::RAX] & 0x80000000)
            state_.regs[(int)Reg::RDX] = 0xFFFFFFFF;
        else
            state_.regs[(int)Reg::RDX] = 0;
        break;
    case Op::CQO:
        if (state_.regs[(int)Reg::RAX] & 0x8000000000000000ULL)
            state_.regs[(int)Reg::RDX] = ~0ULL;
        else
            state_.regs[(int)Reg::RDX] = 0;
        break;
    case Op::JMP:
        state_.rip = resolveValue(instr.dst);
        return true;
    case Op::JCC:
        if (evalCC(instr.cc))
            state_.rip = resolveValue(instr.dst);
        else
            state_.rip += instr.rawLen;
        return true;
    case Op::CALL: {
        uint64_t target = resolveValue(instr.dst);
        auto it = stubs_.find(target);
        if (it != stubs_.end()) {
            CallRecord cr;
            cr.caller = state_.rip;
            cr.target = target;
            cr.args[0] = state_.regs[(int)Reg::RCX];
            cr.args[1] = state_.regs[(int)Reg::RDX];
            cr.args[2] = state_.regs[(int)Reg::R8];
            cr.args[3] = state_.regs[(int)Reg::R9];
            cr.retval = it->second;
            callLog_.push_back(cr);
            state_.regs[(int)Reg::RAX] = it->second;
            state_.rip += instr.rawLen;
            return true;
        }
        push64(state_.rip + instr.rawLen);
        state_.rip = target;
        return true;
    }
    case Op::RET:
        state_.rip = pop64();
        return true;
    case Op::NOP: case Op::INT3:
        break;
    default:
        return false;
    }
    state_.rip += instr.rawLen;
    return true;
}

bool Emulator::execute(uint32_t maxSteps) {
    Disasm disasm(pe_, imageBase_);
    steps_ = 0;

    while (steps_ < maxSteps) {
        uint64_t va = state_.rip;
        uint32_t rva = (uint32_t)(va - imageBase_);
        uint32_t off = pe_.rvaToOffset(rva);
        if (!off) return false;

        Instr instr;
        uint32_t len = disasm.decodeOne(off, va, instr);
        if (len == 0) return false;

        // Fix RIP-relative
        if (instr.src1.isMem() && instr.src1.reg == Reg::RIP) {
            instr.src1.reg = Reg::NONE;
            instr.src1.imm = (int64_t)va + len + instr.src1.imm;
        }
        if (instr.dst.isMem() && instr.dst.reg == Reg::RIP) {
            instr.dst.reg = Reg::NONE;
            instr.dst.imm = (int64_t)va + len + instr.dst.imm;
        }

        instr.rawLen = len;

        if (!execInstr(instr)) return false;

        steps_++;
        if (instr.op == Op::INT3) break;
        if (state_.rip == 0) break;
    }

    return true;
}

} // namespace pefix
