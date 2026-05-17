#include <pefix/constprop.h>
#include <pefix/pe.h>
#include <queue>
#include <cstdio>
#include <algorithm>

namespace pefix {

void ConstProp::initState() {
    for (int i = 0; i < 16; i++) regs_[i] = AbstractValue::Top();
    for (int i = 0; i < 5; i++) flags_[i] = AbstractValue::Top();
    regs_[(int)Reg::RSP] = AbstractValue::MkConst(0, Width::W64);
}

AbstractValue ConstProp::getVal(const Value& v) {
    if (v.kind == Value::IMM) return AbstractValue::MkConst((uint64_t)v.imm, v.width);
    if (v.kind == Value::REG && (uint16_t)v.reg < 16)
        return regs_[(uint16_t)v.reg];
    return AbstractValue::Top();
}

void ConstProp::setVal(const Value& v, AbstractValue av) {
    if (v.kind == Value::REG && (uint16_t)v.reg < 16) {
        if (!av.isConst() && dispatchKeyRegs_.count((uint16_t)v.reg)) return;
        av.width = v.width;
        if (v.width == Width::W32) av.value &= 0xFFFFFFFF;
        else if (v.width == Width::W16) av.value &= 0xFFFF;
        else if (v.width == Width::W8) av.value &= 0xFF;
        regs_[(uint16_t)v.reg] = av;
    }
}

bool ConstProp::tryResolveIndirectControlFlow(const Instr& instr) {
    if (!pe_ || !instr.dst.isMem()) return false;

    AbstractValue base = (instr.dst.reg != Reg::NONE && (uint16_t)instr.dst.reg < 16)
        ? regs_[(uint16_t)instr.dst.reg] : AbstractValue::Top();
    AbstractValue idx = (instr.dst.index != Reg::NONE && (uint16_t)instr.dst.index < 16)
        ? regs_[(uint16_t)instr.dst.index] : AbstractValue::Top();

    // RIP-relative case (FF 15/25 against an IAT/fnptr table) needs no base register;
    // anything else requires base to fold to a concrete value.
    bool baseOk = (instr.dst.reg == Reg::NONE) || (instr.dst.reg == Reg::RIP) || base.isConst();
    bool idxOk  = (instr.dst.index == Reg::NONE) || idx.isConst();
    if (!baseOk || !idxOk) return false;

    uint64_t addr = (uint64_t)instr.dst.imm;
    if (instr.dst.reg != Reg::NONE && instr.dst.reg != Reg::RIP) addr += base.value;
    if (instr.dst.index != Reg::NONE) addr += idx.value * (instr.dst.scale ? instr.dst.scale : 1);

    if (addr < imageBase_) return false;
    uint32_t rva = (uint32_t)(addr - imageBase_);
    uint32_t off = pe_->rvaToOffset(rva);
    if (!off || off + 8 > pe_->data.size()) return false;

    int sec = pe_->findSection(rva);
    if (sec < 0 || pe_->isExecutableSection(sec)) return false;

    uint64_t target = *(uint64_t*)(pe_->data.data() + off);
    if (target < imageBase_) return false;
    uint32_t tRVA = (uint32_t)(target - imageBase_);
    int tsec = pe_->findSection(tRVA);
    if (tsec < 0 || !pe_->isExecutableSection(tsec)) return false;

    const_cast<Instr&>(instr).dst = Value::Label((int64_t)target);
    const_cast<Instr&>(instr).simplified = true;
    return true;
}

void ConstProp::transfer(const Instr& instr) {
    if (instr.dead) return;

    AbstractValue s1 = getVal(instr.src1);
    AbstractValue s2 = getVal(instr.src2);

    switch (instr.op) {
    case Op::MOV:
        if (instr.dst.isReg() && instr.src1.isMem()) {
            AbstractValue base = (instr.src1.reg != Reg::NONE && (uint16_t)instr.src1.reg < 16)
                ? regs_[(uint16_t)instr.src1.reg] : AbstractValue::Top();
            if (base.isTypedPtr() && instr.src1.index == Reg::NONE && imageBase_ > 0) {
                int32_t fieldOff = (int32_t)instr.src1.imm;
                if (fieldOff == 0) {
                    setVal(instr.dst, AbstractValue::MkConst(imageBase_ + base.value, Width::W64));
                    break;
                }
                if (fieldTypes_ && fieldOff > 0) {
                    uint64_t key = ((uint64_t)base.value << 32) | (uint32_t)fieldOff;
                    auto fit = fieldTypes_->find(key);
                    if (fit != fieldTypes_->end()) {
                        setVal(instr.dst, AbstractValue::MkTypedPtr(fit->second));
                        break;
                    }
                }
                if (fieldOff > 0 && fieldOff < 0x200) {
                    setVal(instr.dst, AbstractValue::MkTypedPtr((uint32_t)base.value));
                    break;
                }
            }
            if (instr.src1.reg == Reg::RIP) {
                uint64_t addr = (uint64_t)instr.src1.imm;
                if (pe_ && addr > 0) {
                    uint32_t rva = (uint32_t)(addr & 0xFFFFFFFF);
                    uint32_t off = pe_->rvaToOffset(rva);
                    if (off && off + 8 <= pe_->data.size()) {
                        int sec = pe_->findSection(rva);
                        if (sec >= 0 && !(pe_->sections[sec].Characteristics & IMAGE_SCN_MEM_EXECUTE)) {
                            uint64_t val = *(uint64_t*)(pe_->data.data() + off);
                            setVal(instr.dst, AbstractValue::MkConst(val, instr.dst.width));
                            break;
                        }
                    }
                }
            } else if (base.isConst() || (instr.src1.reg == Reg::NONE && instr.src1.index != Reg::NONE)) {
                AbstractValue idx = (instr.src1.index != Reg::NONE && (uint16_t)instr.src1.index < 16)
                    ? regs_[(uint16_t)instr.src1.index] : AbstractValue::Top();
                bool canCompute = true;
                uint64_t addr = instr.src1.imm;
                if (instr.src1.reg != Reg::NONE) {
                    if (base.isConst()) addr += base.value;
                    else canCompute = false;
                }
                if (instr.src1.index != Reg::NONE) {
                    if (idx.isConst()) addr += idx.value * (instr.src1.scale ? instr.src1.scale : 1);
                    else canCompute = false;
                }
                if (canCompute && pe_ && addr > 0) {
                    uint32_t rva = (addr >= imageBase_) ? (uint32_t)(addr - imageBase_) : (uint32_t)(addr & 0xFFFFFFFF);
                    uint32_t off = pe_->rvaToOffset(rva);
                    if (off && off + 8 <= pe_->data.size()) {
                        int sec = pe_->findSection(rva);
                        if (sec >= 0 && !(pe_->sections[sec].Characteristics & IMAGE_SCN_MEM_EXECUTE)) {
                            uint64_t val = *(uint64_t*)(pe_->data.data() + off);
                            setVal(instr.dst, AbstractValue::MkConst(val, instr.dst.width));
                            break;
                        }
                    }
                }
            }
            setVal(instr.dst, AbstractValue::Top());
        } else {
            setVal(instr.dst, s1);
        }
        break;
    case Op::LEA:
        if (instr.src1.isMem()) {
            AbstractValue base = (instr.src1.reg != Reg::NONE && (uint16_t)instr.src1.reg < 16)
                ? regs_[(uint16_t)instr.src1.reg] : AbstractValue::Top();
            AbstractValue idx = (instr.src1.index != Reg::NONE && (uint16_t)instr.src1.index < 16)
                ? regs_[(uint16_t)instr.src1.index] : AbstractValue::Top();
            if (base.isConst() && (instr.src1.index == Reg::NONE || idx.isConst())) {
                uint64_t result = base.value + instr.src1.imm;
                if (instr.src1.index != Reg::NONE)
                    result += idx.value * (instr.src1.scale ? instr.src1.scale : 1);
                setVal(instr.dst, AbstractValue::MkConst(result, instr.dst.width));
            } else {
                setVal(instr.dst, AbstractValue::Top());
            }
        }
        break;
    case Op::ADD:
        if (s1.isConst() && s2.isConst())
            setVal(instr.dst, AbstractValue::MkConst(s1.masked() + s2.masked(), instr.dst.width));
        else setVal(instr.dst, AbstractValue::Top());
        break;
    case Op::SUB:
        if (s1.isConst() && s2.isConst())
            setVal(instr.dst, AbstractValue::MkConst(s1.masked() - s2.masked(), instr.dst.width));
        else setVal(instr.dst, AbstractValue::Top());
        break;
    case Op::IMUL:
        if (s1.isConst() && s2.isConst())
            setVal(instr.dst, AbstractValue::MkConst(s1.masked() * s2.masked(), instr.dst.width));
        else setVal(instr.dst, AbstractValue::Top());
        break;
    case Op::AND:
        if (s1.isConst() && s2.isConst())
            setVal(instr.dst, AbstractValue::MkConst(s1.masked() & s2.masked(), instr.dst.width));
        else if (s2.isConst() && s2.value == 0)
            setVal(instr.dst, AbstractValue::MkConst(0, instr.dst.width));
        else setVal(instr.dst, AbstractValue::Top());
        break;
    case Op::OR:
        if (s1.isConst() && s2.isConst())
            setVal(instr.dst, AbstractValue::MkConst(s1.masked() | s2.masked(), instr.dst.width));
        else setVal(instr.dst, AbstractValue::Top());
        break;
    case Op::XOR:
        if (s1.isConst() && s2.isConst())
            setVal(instr.dst, AbstractValue::MkConst(s1.masked() ^ s2.masked(), instr.dst.width));
        else if (instr.src1.isReg() && instr.src2.isReg() && instr.src1.reg == instr.src2.reg)
            setVal(instr.dst, AbstractValue::MkConst(0, instr.dst.width));
        else setVal(instr.dst, AbstractValue::Top());
        break;
    case Op::NOT:
        if (s1.isConst())
            setVal(instr.dst, AbstractValue::MkConst(~s1.masked(), instr.dst.width));
        else setVal(instr.dst, AbstractValue::Top());
        break;
    case Op::SHL:
        if (s1.isConst() && s2.isConst())
            setVal(instr.dst, AbstractValue::MkConst(s1.masked() << (s2.value & 63), instr.dst.width));
        else setVal(instr.dst, AbstractValue::Top());
        break;
    case Op::SHR:
        if (s1.isConst() && s2.isConst())
            setVal(instr.dst, AbstractValue::MkConst(s1.masked() >> (s2.value & 63), instr.dst.width));
        else setVal(instr.dst, AbstractValue::Top());
        break;
    case Op::SAR:
        if (s1.isConst() && s2.isConst()) {
            int64_t sv = (int64_t)s1.masked();
            setVal(instr.dst, AbstractValue::MkConst((uint64_t)(sv >> (s2.value & 63)), instr.dst.width));
        } else setVal(instr.dst, AbstractValue::Top());
        break;
    case Op::TEST:
        if (s1.isConst() && s2.isConst()) {
            uint64_t result = s1.masked() & s2.masked();
            setFlag(0, AbstractValue::MkConst(result == 0 ? 1 : 0));
            setFlag(1, AbstractValue::MkConst(0));
            setFlag(2, AbstractValue::MkConst((result >> 63) & 1));
            setFlag(3, AbstractValue::MkConst(0));
        } else {
            for (int i = 0; i < 5; i++) setFlag(i, AbstractValue::Top());
        }
        break;
    case Op::CMP:
        if (s1.isConst() && s2.isConst()) {
            uint64_t a = s1.masked(), b = s2.masked();
            setFlag(0, AbstractValue::MkConst(a == b ? 1 : 0));
            setFlag(1, AbstractValue::MkConst(a < b ? 1 : 0));
            int64_t sa = (int64_t)a, sb = (int64_t)b;
            setFlag(2, AbstractValue::MkConst(((sa - sb) < 0) ? 1 : 0));
        } else {
            for (int i = 0; i < 5; i++) setFlag(i, AbstractValue::Top());
        }
        break;
    case Op::BT:
        if (s1.isConst() && s2.isConst()) {
            uint64_t bit = (s1.masked() >> (s2.value & 63)) & 1;
            setFlag(1, AbstractValue::MkConst(bit));
        } else {
            setFlag(1, AbstractValue::Top());
        }
        break;
    case Op::CALL: {
        tryResolveIndirectControlFlow(instr);
        regs_[(int)Reg::RAX] = AbstractValue::Top();
        regs_[(int)Reg::RCX] = AbstractValue::Top();
        regs_[(int)Reg::RDX] = AbstractValue::Top();
        regs_[(int)Reg::R8]  = AbstractValue::Top();
        regs_[(int)Reg::R9]  = AbstractValue::Top();
        regs_[(int)Reg::R10] = AbstractValue::Top();
        regs_[(int)Reg::R11] = AbstractValue::Top();
        for (int i = 0; i < 5; i++) setFlag(i, AbstractValue::Top());
        if (returnTypes_ && instr.dst.kind == Value::LABEL && instr.dst.imm > 0) {
            uint32_t calleeRVA = (uint32_t)(instr.dst.imm & 0xFFFFFFFF);
            auto rit = returnTypes_->find(calleeRVA);
            if (rit != returnTypes_->end()) {
                regs_[(int)Reg::RAX] = AbstractValue::MkTypedPtr(rit->second);
            }
        }
        break;
    }
    case Op::JMP:
        // tail-call vtable thunk: mov rax,[rcx]; jmp [rax+N]. No regs to kill --
        // control leaves the function.
        tryResolveIndirectControlFlow(instr);
        break;
    default:
        if (transferUnknown(instr)) break;
        if (!instr.dst.isNone()) setVal(instr.dst, AbstractValue::Top());
        if (instr.flagsWritten) {
            for (int i = 0; i < 5; i++) setFlag(i, AbstractValue::Top());
        }
        break;
    }
}

int ConstProp::evalCCResult(CC cc) {
    AbstractValue zf = getFlag(0), cf = getFlag(1), sf = getFlag(2), of = getFlag(3);
    switch (cc) {
    case CC::Z:  return zf.isConst() ? (int)(zf.value & 1) : -1;
    case CC::NZ: return zf.isConst() ? (int)(1 - (zf.value & 1)) : -1;
    case CC::B:  return cf.isConst() ? (int)(cf.value & 1) : -1;
    case CC::AE: return cf.isConst() ? (int)(1 - (cf.value & 1)) : -1;
    case CC::S:  return sf.isConst() ? (int)(sf.value & 1) : -1;
    case CC::NS: return sf.isConst() ? (int)(1 - (sf.value & 1)) : -1;
    case CC::BE: return (cf.isConst() && zf.isConst()) ? (int)((cf.value | zf.value) & 1) : -1;
    case CC::A:  return (cf.isConst() && zf.isConst()) ? (int)(1 - ((cf.value | zf.value) & 1)) : -1;
    case CC::L:  return (sf.isConst() && of.isConst()) ? (int)((sf.value != of.value) ? 1 : 0) : -1;
    case CC::GE: return (sf.isConst() && of.isConst()) ? (int)((sf.value == of.value) ? 1 : 0) : -1;
    default: return -1;
    }
}

void ConstProp::run(Func& func) {
    dispatchKeyRegs_.clear();
    auto& blocks = func.blocks;
    size_t numBlocks = blocks.size();
    if (numBlocks == 0) return;

    struct BlockState {
        AbstractValue regs[16];
        AbstractValue flags[5];
        bool reached = false;
    };
    std::vector<BlockState> blockStates(numBlocks);

    for (int r = 0; r < 16; r++) blockStates[0].regs[r] = AbstractValue::Top();
    for (int f = 0; f < 5; f++) blockStates[0].flags[f] = AbstractValue::Top();
    blockStates[0].regs[(int)Reg::RSP] = AbstractValue::MkConst(0, Width::W64);
    for (auto& [reg, val] : initRegs_) {
        if (reg < 16) blockStates[0].regs[reg] = AbstractValue::MkConst(val, Width::W64);
    }
    for (auto& [reg, vtRVA] : typedPtrs_) {
        if (reg < 16) blockStates[0].regs[reg] = AbstractValue::MkTypedPtr(vtRVA);
    }
    for (auto& dk : func.dispatchKeys) {
        if (dk.reg != Reg::NONE && (uint16_t)dk.reg < 16) {
            blockStates[0].regs[(uint16_t)dk.reg] = AbstractValue::MkConst((uint64_t)dk.value, Width::W32);
            dispatchKeyRegs_.insert((uint16_t)dk.reg);
        }
    }
    if (func.dispatchKeys.empty() && func.dispatchKeyValue != INT64_MIN && func.dispatchKeyReg != Reg::NONE) {
        blockStates[0].regs[(uint16_t)func.dispatchKeyReg] =
            AbstractValue::MkConst((uint64_t)func.dispatchKeyValue, Width::W32);
        dispatchKeyRegs_.insert((uint16_t)func.dispatchKeyReg);
    }
    blockStates[0].reached = true;

    std::vector<bool> inWorklist(numBlocks, false);
    std::queue<uint32_t> worklist;
    worklist.push(0);
    inWorklist[0] = true;

    int iterations = 0;
    while (!worklist.empty() && iterations < (int)numBlocks * 3) {
        uint32_t bi = worklist.front(); worklist.pop(); inWorklist[bi] = false;
        auto& blk = blocks[bi];
        if (blk.isDeadCode) continue;
        iterations++;

        for (int r = 0; r < 16; r++) regs_[r] = blockStates[bi].regs[r];
        for (int f = 0; f < 5; f++) flags_[f] = blockStates[bi].flags[f];

        for (auto& dk : func.dispatchKeys)
            if (dk.reg != Reg::NONE && (uint16_t)dk.reg < 16)
                regs_[(uint16_t)dk.reg] = AbstractValue::MkConst((uint64_t)dk.value, Width::W32);

        for (auto& instr : blk.instrs) {
            if (instr.dead) continue;

            if (instr.op == Op::JCC) {
                int r = evalCCResult(instr.cc);
                if (r == 1) {
                    const_cast<Instr&>(instr).op = Op::JMP;
                    const_cast<Instr&>(instr).cc = CC::NONE;
                    const_cast<Instr&>(instr).simplified = true;
                } else if (r == 0) {
                    const_cast<Instr&>(instr).op = Op::NOP;
                    const_cast<Instr&>(instr).simplified = true;
                }
            }

            if (instr.op == Op::CMOV) {
                int r = evalCCResult(instr.cc);
                if (r == 1) {
                    const_cast<Instr&>(instr).op = Op::MOV;
                    const_cast<Instr&>(instr).cc = CC::NONE;
                    const_cast<Instr&>(instr).simplified = true;
                } else if (r == 0) {
                    const_cast<Instr&>(instr).dead = true;
                }
            }

            if (instr.op == Op::IMUL && instr.src2.isImm()) {
                AbstractValue sv = getVal(instr.src1);
                if (sv.isConst()) {
                    uint64_t result = sv.masked() * (uint64_t)instr.src2.imm;
                    if (instr.dst.width == Width::W32) result &= 0xFFFFFFFF;
                    const_cast<Instr&>(instr).src1 = Value::Imm((int64_t)result, instr.dst.width);
                    const_cast<Instr&>(instr).src2 = Value::None();
                    const_cast<Instr&>(instr).op = Op::MOV;
                    const_cast<Instr&>(instr).simplified = true;
                }
            }

            transfer(instr);
        }

        for (uint32_t succIdx : blk.succs) {
            if (succIdx >= numBlocks) continue;
            auto& ss = blockStates[succIdx];
            bool changed = false;
            if (!ss.reached) {
                for (int r = 0; r < 16; r++) ss.regs[r] = regs_[r];
                for (int f = 0; f < 5; f++) ss.flags[f] = flags_[f];
                ss.reached = true;
                changed = true;
            } else {
                for (int r = 0; r < 16; r++) {
                    if (ss.regs[r].state == regs_[r].state && ss.regs[r].value == regs_[r].value)
                        continue;
                    if (ss.regs[r].state != AbstractValue::AV_TOP) {
                        ss.regs[r] = AbstractValue::Top();
                        changed = true;
                    }
                }
            }
            if (changed && !inWorklist[succIdx]) {
                worklist.push(succIdx);
                inWorklist[succIdx] = true;
            }
        }
    }
}

} // namespace pefix
