#include <pefix/x86_64/trace.h>
#include <pefix/x86_64/disasm.h>
#include <cstdio>
#include <cstring>

namespace pefix {

Tracer::Tracer(const PEFile& pe, uint64_t imageBase)
    : pe_(pe), imageBase_(imageBase)
{
    stackBase_ = 0x7FFE0000ULL;
    stackTop_ = stackBase_ + 0x10000ULL;
    regs_[(int)Reg::RSP] = stackBase_ + 0x8000;
    for (int i = 0; i < 16; i++) {
        if (i != (int)Reg::RSP)
            regs_[i] = 0;
    }
}

void Tracer::setReg(int idx, uint64_t val) {
    if (idx >= 0 && idx < 16)
        regs_[idx] = val;
}

void Tracer::setStack(uint64_t offset, uint64_t val) {
    uint64_t addr = regs_[(int)Reg::RSP] + offset;
    stackMem_[addr] = val;
}

void Tracer::watchFunction(uint32_t rva) {
    watchedFuncs_.insert(rva);
}

void Tracer::addRegOverride(uint32_t rva, int reg, uint64_t val) {
    regOverrides_[rva].push_back({reg, val});
}

bool Tracer::isStackAddr(uint64_t addr) {
    return addr >= stackBase_ && addr < stackTop_;
}

uint8_t Tracer::readCodeByte(uint64_t va) {
    if (va < imageBase_) return 0;
    uint32_t rva = (uint32_t)(va - imageBase_);
    uint32_t off = pe_.rvaToOffset(rva);
    if (!off || off >= pe_.data.size()) return 0;
    return pe_.data[off];
}

uint64_t Tracer::readCodeMem(uint64_t va, Width w) {
    uint64_t result = 0;
    uint32_t bytes = (uint32_t)w / 8;
    for (uint32_t i = 0; i < bytes; i++) {
        result |= (uint64_t)readCodeByte(va + i) << (i * 8);
    }
    return result;
}

uint64_t Tracer::readMem(uint64_t addr, Width w) {
    if (isStackAddr(addr)) {
        uint32_t bytes = (uint32_t)w / 8;
        if (bytes == 8) {
            auto it = stackMem_.find(addr);
            if (it != stackMem_.end()) return it->second;
            if (stackFallback_) {
                uint64_t val = 0;
                if (stackFallback_(addr, w, val)) return val;
            }
            return 0;
        }
        uint64_t aligned = addr & ~7ULL;
        auto it = stackMem_.find(aligned);
        if (it != stackMem_.end()) {
            uint64_t qval = it->second;
            uint32_t shift = (uint32_t)((addr - aligned) * 8);
            uint64_t mask = ((1ULL << ((uint32_t)w)) - 1);
            return (qval >> shift) & mask;
        }
        if (stackFallback_) {
            uint64_t val = 0;
            if (stackFallback_(addr, w, val)) return val;
        }
        return 0;
    }
    return readCodeMem(addr, w);
}

void Tracer::writeMem(uint64_t addr, uint64_t val, Width w) {
    if (!isStackAddr(addr)) return;

    uint32_t bytes = (uint32_t)w / 8;
    if (bytes == 8) {
        stackMem_[addr] = val;
        return;
    }
    uint64_t aligned = addr & ~7ULL;
    uint64_t existing = 0;
    auto it = stackMem_.find(aligned);
    if (it != stackMem_.end()) existing = it->second;

    uint32_t shift = (uint32_t)((addr - aligned) * 8);
    uint64_t mask = ((1ULL << ((uint64_t)bytes * 8)) - 1) << shift;
    existing = (existing & ~mask) | ((val & ((1ULL << ((uint64_t)bytes * 8)) - 1)) << shift);
    stackMem_[aligned] = existing;
}

void Tracer::setFlags(uint64_t result, Width w) {
    uint64_t mask = (w == Width::W64) ? ~0ULL : ((1ULL << (uint8_t)w) - 1);
    result &= mask;
    setZF(result == 0);
    setSF((result >> ((uint8_t)w - 1)) & 1);
}

bool Tracer::evalCC(CC cc) {
    switch (cc) {
    case CC::O:  return getOF();
    case CC::NO: return !getOF();
    case CC::B:  return getCF();
    case CC::AE: return !getCF();
    case CC::Z:  return getZF();
    case CC::NZ: return !getZF();
    case CC::BE: return getCF() || getZF();
    case CC::A:  return !getCF() && !getZF();
    case CC::S:  return getSF();
    case CC::NS: return !getSF();
    case CC::P:  return false;
    case CC::NP: return true;
    case CC::L:  return getSF() != getOF();
    case CC::GE: return getSF() == getOF();
    case CC::LE: return getZF() || (getSF() != getOF());
    case CC::G:  return !getZF() && (getSF() == getOF());
    default: return false;
    }
}

uint64_t Tracer::resolveAddr(const Value& v) {
    if (v.kind != Value::MEM) return 0;
    uint64_t addr = (uint64_t)v.imm;
    if (v.reg != Reg::NONE && (uint16_t)v.reg < 16)
        addr += regs_[(uint16_t)v.reg];
    if (v.index != Reg::NONE && (uint16_t)v.index < 16)
        addr += regs_[(uint16_t)v.index] * (v.scale ? v.scale : 1);
    return addr;
}

uint64_t Tracer::resolveValue(const Value& v) {
    switch (v.kind) {
    case Value::REG:
        if ((uint16_t)v.reg < 16) {
            uint64_t val = regs_[(uint16_t)v.reg];
            switch (v.width) {
            case Width::W8:  return val & 0xFF;
            case Width::W16: return val & 0xFFFF;
            case Width::W32: return val & 0xFFFFFFFF;
            default: return val;
            }
        }
        return 0;
    case Value::IMM:
        return (uint64_t)v.imm;
    case Value::MEM:
        return readMem(resolveAddr(v), v.width);
    case Value::LABEL:
        return (uint64_t)v.imm;
    default:
        return 0;
    }
}

void Tracer::storeValue(const Value& v, uint64_t val) {
    if (v.kind == Value::REG && (uint16_t)v.reg < 16) {
        switch (v.width) {
        case Width::W8:
            regs_[(uint16_t)v.reg] = (regs_[(uint16_t)v.reg] & ~0xFFULL) | (val & 0xFF);
            break;
        case Width::W16:
            regs_[(uint16_t)v.reg] = (regs_[(uint16_t)v.reg] & ~0xFFFFULL) | (val & 0xFFFF);
            break;
        case Width::W32:
            regs_[(uint16_t)v.reg] = val & 0xFFFFFFFF;
            break;
        case Width::W64:
            regs_[(uint16_t)v.reg] = val;
            break;
        }
    } else if (v.kind == Value::MEM) {
        writeMem(resolveAddr(v), val, v.width);
    }
}

uint32_t Tracer::countInt3(uint64_t va) {
    uint32_t count = 0;
    while (readCodeByte(va + count) == 0xCC)
        count++;
    return count;
}

Tracer::ExecAction Tracer::execInstr(const Instr& instr, uint64_t /*va*/) {
    uint64_t s1, s2, result;

    switch (instr.op) {
    case Op::MOV:
        storeValue(instr.dst, resolveValue(instr.src1));
        break;
    case Op::MOVZX:
        storeValue(instr.dst, resolveValue(instr.src1));
        break;
    case Op::MOVSX: {
        s1 = resolveValue(instr.src1);
        switch (instr.src1.width) {
        case Width::W8:  result = (uint64_t)(int64_t)(int8_t)s1; break;
        case Width::W16: result = (uint64_t)(int64_t)(int16_t)s1; break;
        case Width::W32: result = (uint64_t)(int64_t)(int32_t)s1; break;
        default: result = s1; break;
        }
        storeValue(instr.dst, result);
        break;
    }
    case Op::LEA:
        if (instr.src1.kind == Value::MEM)
            storeValue(instr.dst, resolveAddr(instr.src1));
        break;
    case Op::ADD:
        s1 = resolveValue(instr.src1); s2 = resolveValue(instr.src2);
        result = s1 + s2;
        storeValue(instr.dst, result);
        setFlags(result, instr.dst.width);
        setCF(result < s1);
        { uint64_t signBit = 1ULL << ((uint8_t)instr.dst.width - 1);
          setOF(((~(s1 ^ s2)) & (s1 ^ result) & signBit) != 0); }
        break;
    case Op::SUB:
        s1 = resolveValue(instr.src1); s2 = resolveValue(instr.src2);
        result = s1 - s2;
        storeValue(instr.dst, result);
        setFlags(result, instr.dst.width);
        setCF(s1 < s2);
        { uint64_t signBit = 1ULL << ((uint8_t)instr.dst.width - 1);
          setOF(((s1 ^ s2) & (s1 ^ result) & signBit) != 0); }
        break;
    case Op::IMUL:
        s1 = resolveValue(instr.src1);
        s2 = instr.src2.isNone() ? s1 : resolveValue(instr.src2);
        result = s1 * s2;
        storeValue(instr.dst, result);
        setFlags(result, instr.dst.width);
        break;
    case Op::AND:
        s1 = resolveValue(instr.src1); s2 = resolveValue(instr.src2);
        result = s1 & s2;
        storeValue(instr.dst, result);
        setFlags(result, instr.dst.width);
        setCF(false); setOF(false);
        break;
    case Op::OR:
        s1 = resolveValue(instr.src1); s2 = resolveValue(instr.src2);
        result = s1 | s2;
        storeValue(instr.dst, result);
        setFlags(result, instr.dst.width);
        setCF(false); setOF(false);
        break;
    case Op::XOR:
        s1 = resolveValue(instr.src1); s2 = resolveValue(instr.src2);
        result = s1 ^ s2;
        storeValue(instr.dst, result);
        setFlags(result, instr.dst.width);
        setCF(false); setOF(false);
        break;
    case Op::NOT:
        result = ~resolveValue(instr.src1);
        storeValue(instr.dst, result);
        break;
    case Op::NEG:
        s1 = resolveValue(instr.src1);
        result = (~s1) + 1;
        storeValue(instr.dst, result);
        setFlags(result, instr.dst.width);
        setCF(s1 != 0);
        break;
    case Op::SHL:
        s1 = resolveValue(instr.src1); s2 = resolveValue(instr.src2) & 63;
        result = s1 << s2;
        storeValue(instr.dst, result);
        setFlags(result, instr.dst.width);
        break;
    case Op::SHR:
        s1 = resolveValue(instr.src1); s2 = resolveValue(instr.src2) & 63;
        result = s1 >> s2;
        storeValue(instr.dst, result);
        setFlags(result, instr.dst.width);
        break;
    case Op::SAR:
        s1 = resolveValue(instr.src1); s2 = resolveValue(instr.src2) & 63;
        result = (uint64_t)((int64_t)s1 >> s2);
        storeValue(instr.dst, result);
        setFlags(result, instr.dst.width);
        break;
    case Op::ROL:
        s1 = resolveValue(instr.src1); s2 = resolveValue(instr.src2) & 63;
        result = s2 ? ((s1 << s2) | (s1 >> (64 - s2))) : s1;
        storeValue(instr.dst, result);
        break;
    case Op::ROR:
        s1 = resolveValue(instr.src1); s2 = resolveValue(instr.src2) & 63;
        result = s2 ? ((s1 >> s2) | (s1 << (64 - s2))) : s1;
        storeValue(instr.dst, result);
        break;
    case Op::TEST:
        s1 = resolveValue(instr.src1); s2 = resolveValue(instr.src2);
        result = s1 & s2;
        setFlags(result, instr.src1.width);
        setCF(false); setOF(false);
        break;
    case Op::CMP:
        s1 = resolveValue(instr.src1); s2 = resolveValue(instr.src2);
        result = s1 - s2;
        setFlags(result, instr.src1.width);
        setCF(s1 < s2);
        { uint64_t signBit = 1ULL << ((uint8_t)instr.src1.width - 1);
          setOF(((s1 ^ s2) & (s1 ^ result) & signBit) != 0); }
        break;
    case Op::BT:
        s1 = resolveValue(instr.src1); s2 = resolveValue(instr.src2);
        setCF((s1 >> (s2 & 63)) & 1);
        break;
    case Op::CMOV:
        if (evalCC(instr.cc))
            storeValue(instr.dst, resolveValue(instr.src1));
        break;
    case Op::SETcc:
        storeValue(instr.dst, evalCC(instr.cc) ? 1ULL : 0ULL);
        break;
    case Op::PUSH:
        regs_[(int)Reg::RSP] -= 8;
        writeMem(regs_[(int)Reg::RSP], resolveValue(instr.src1), Width::W64);
        break;
    case Op::POP:
        storeValue(instr.dst, readMem(regs_[(int)Reg::RSP], Width::W64));
        regs_[(int)Reg::RSP] += 8;
        break;
    case Op::XCHG: {
        uint64_t a = resolveValue(instr.dst);
        uint64_t b = resolveValue(instr.src1);
        storeValue(instr.dst, b);
        storeValue(instr.src1, a);
        break;
    }
    case Op::BSWAP:
        s1 = resolveValue(instr.dst);
        if (instr.dst.width == Width::W64)
            result = _byteswap_uint64(s1);
        else
            result = (uint64_t)_byteswap_ulong((uint32_t)s1);
        storeValue(instr.dst, result);
        break;
    case Op::INC:
        s1 = resolveValue(instr.src1);
        result = s1 + 1;
        storeValue(instr.dst, result);
        setFlags(result, instr.dst.width);
        break;
    case Op::DEC:
        s1 = resolveValue(instr.src1);
        result = s1 - 1;
        storeValue(instr.dst, result);
        setFlags(result, instr.dst.width);
        break;
    case Op::CDQ:
        if (regs_[(int)Reg::RAX] & 0x80000000)
            regs_[(int)Reg::RDX] = 0xFFFFFFFF;
        else
            regs_[(int)Reg::RDX] = 0;
        break;
    case Op::CQO:
        if (regs_[(int)Reg::RAX] & 0x8000000000000000ULL)
            regs_[(int)Reg::RDX] = ~0ULL;
        else
            regs_[(int)Reg::RDX] = 0;
        break;
    case Op::NOP:
        break;
    case Op::INT3:
        break;
    case Op::JMP:
    case Op::JCC:
    case Op::CALL:
    case Op::RET:
        return STOP;
    default:
        return SKIP;
    }

    return CONTINUE;
}


TraceResult Tracer::trace(uint32_t startRVA, uint32_t maxSteps) {
    calls_.clear();

    TraceResult result;
    result.stepsExecuted = 0;
    result.completed = false;

    Disasm disasm(pe_, imageBase_);
    uint64_t rip = imageBase_ + startRVA;

    struct CallFrame { uint64_t returnAddr; };
    std::vector<CallFrame> callStack;
    const uint32_t maxCallDepth = 32;

    std::unordered_map<uint64_t, uint32_t> visitCount;
    const uint32_t maxVisitPerAddr = maxVisit_;

    auto emitLog = [&](const Instr& instr, uint32_t step, uint32_t rva) {
        if (!traceLog_ || step >= traceLogLimit_) return;
        TraceStep ts = {};
        ts.step = step;
        ts.rva = rva;
        ts.op = instr.op;
        memcpy(ts.regs, regs_, sizeof(regs_));
        ts.memRead = false;
        if (instr.src1.isMem()) {
            ts.memAddr = resolveAddr(instr.src1);
            ts.memVal = readMem(ts.memAddr, instr.src1.width);
            ts.memRead = true;
            ts.isStack = isStackAddr(ts.memAddr);
        }
        traceLog_(ts);
    };

    uint32_t steps = 0;
    uint32_t soiCheck = pe_.nt->OptionalHeader.SizeOfImage;
    lastProgress_ = 0;
    while (steps < maxSteps) {
        if (progressTimeout_ > 0 && steps - lastProgress_ > progressTimeout_) {
            result.stopReason = "no progress";
            break;
        }
        if (rip < imageBase_ || (uint32_t)(rip - imageBase_) >= soiCheck) {
            if (skipExternal_) {
                if (!callStack.empty()) { rip = callStack.back().returnAddr; callStack.pop_back(); steps++; continue; }
                result.stopReason = "RIP outside image (top-level)";
                break;
            }
            result.stopReason = "RIP below image base";
            break;
        }

        uint32_t rva = (uint32_t)(rip - imageBase_);

        uint32_t& vc = visitCount[rip];
        if (vc >= maxVisitPerAddr) {
            if (skipExternal_) {
                forceFlipNext_ = true;
                vc = 0;
                steps++;
                continue;
            }
            result.stopReason = "loop detected";
            break;
        }
        vc++;

        uint8_t rawByte = readCodeByte(rip);

        if (rawByte == 0xCC) {
            uint32_t int3Count = countInt3(rip);
            if (int3Count >= 2) {
                rip += int3Count;
                steps++;
                continue;
            }
            rip++;
            steps++;
            continue;
        }

        if (rawByte == 0x90) {
            rip++;
            steps++;
            continue;
        }

        // Multi-byte NOP
        if (rawByte == 0x0F) {
            uint8_t next = readCodeByte(rip + 1);
            if (next == 0x1F) {
                uint32_t off = pe_.rvaToOffset(rva);
                if (!off) {
                    result.stopReason = "RIP outside mapped memory";
                    break;
                }
                Instr instr;
                uint32_t len = disasm.decodeOne(off, rip, instr);
                if (len == 0) {
                    result.stopReason = "decode failed";
                    break;
                }
                rip += len;
                steps++;
                continue;
            }
        }

        uint32_t off = pe_.rvaToOffset(rva);
        if (!off || off >= pe_.data.size()) {
            result.stopReason = "RIP outside mapped memory";
            break;
        }

        auto ovIt = regOverrides_.find(rva);
        if (ovIt != regOverrides_.end()) {
            for (auto& ov : ovIt->second)
                if (ov.reg >= 0 && ov.reg < 16) regs_[ov.reg] = ov.val;
        }

        Instr instr;
        uint32_t len = disasm.decodeOne(off, rip, instr);
        if (len == 0) {
            result.stopReason = "decode failed";
            break;
        }
        instr.rawLen = len;

        // Fix RIP-relative addressing
        if (instr.src1.isMem() && instr.src1.reg == Reg::RIP) {
            instr.src1.reg = Reg::NONE;
            instr.src1.imm = (int64_t)rip + (int64_t)len + instr.src1.imm;
        }
        if (instr.src2.isMem() && instr.src2.reg == Reg::RIP) {
            instr.src2.reg = Reg::NONE;
            instr.src2.imm = (int64_t)rip + (int64_t)len + instr.src2.imm;
        }
        if (instr.dst.isMem() && instr.dst.reg == Reg::RIP) {
            instr.dst.reg = Reg::NONE;
            instr.dst.imm = (int64_t)rip + (int64_t)len + instr.dst.imm;
        }

        emitLog(instr, steps, rva);

        // Control flow
        if (instr.op == Op::JMP) {
            uint64_t target = resolveValue(instr.dst);
            if (target == 0) {
                if (skipExternal_) { rip += len; steps++; continue; }
                result.stopReason = "JMP to null";
                break;
            }
            uint32_t soi = pe_.nt->OptionalHeader.SizeOfImage;
            if (skipExternal_ && (target < imageBase_ || (uint32_t)(target - imageBase_) >= soi)) {
                rip += len; steps++; continue;
            }
            rip = target;
            steps++;
            continue;
        }

        if (instr.op == Op::JCC) {
            bool taken = evalCC(instr.cc);
            if (forceFlipNext_) { taken = !taken; forceFlipNext_ = false; }
            if (taken) {
                uint64_t target = resolveValue(instr.dst);
                if (target == 0) {
                    result.stopReason = "JCC to null";
                    break;
                }
                rip = target;
            } else {
                rip += len;
            }
            steps++;
            continue;
        }

        if (instr.op == Op::CALL) {
            uint64_t target = resolveValue(instr.dst);
            if (target == 0) {
                if (skipExternal_) { rip += len; steps++; continue; }
                result.stopReason = "CALL to null";
                break;
            }

            uint32_t targetRVA = (uint32_t)(target - imageBase_);
            uint32_t soi = pe_.nt->OptionalHeader.SizeOfImage;
            if (skipExternal_ && (target < imageBase_ || targetRVA >= soi)) {
                regs_[(int)Reg::RAX] = 0;
                rip += len;
                steps++;
                continue;
            }

            {
                TraceCall tc;
                tc.callerVA = rip;
                tc.targetVA = target;
                tc.args[0] = regs_[(int)Reg::RCX];
                tc.args[1] = regs_[(int)Reg::RDX];
                tc.args[2] = regs_[(int)Reg::R8];
                tc.args[3] = regs_[(int)Reg::R9];
                tc.rax = regs_[(int)Reg::RAX];
                memcpy(tc.regs, regs_, sizeof(regs_));
                calls_.push_back(tc);
                lastProgress_ = steps;
            }

            if (watchedFuncs_.count(targetRVA)) {
                rip += len;
                steps++;
                continue;
            }

            // Follow the call if depth allows
            if (callStack.size() < maxCallDepth) {
                callStack.push_back({rip + len});
                rip = target;
                steps++;
                continue;
            }

            regs_[(int)Reg::RAX] = 0;
            rip += len;
            steps++;
            continue;
        }

        if (instr.op == Op::RET) {
            if (!callStack.empty()) {
                rip = callStack.back().returnAddr;
                callStack.pop_back();
                steps++;
                continue;
            }
            result.stopReason = "RET at top level";
            break;
        }

        ExecAction action = execInstr(instr, rip);

        if (progressTimeout_ > 0 && instr.dst.isReg() && (uint16_t)instr.dst.reg < 16) {
            uint64_t v = regs_[(uint16_t)instr.dst.reg];
            if (v >= imageBase_ && (uint32_t)(v - imageBase_) < soiCheck)
                lastProgress_ = steps;
        }

        if (action == STOP) {
            rip += len;
            continue;
        }

        rip += len;
        steps++;
    }

    if (steps >= maxSteps) {
        result.completed = true;
        result.stopReason = "step limit reached";
    }

    result.stepsExecuted = steps;
    result.calls = std::move(calls_);
    return result;
}

} // namespace pefix
