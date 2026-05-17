#pragma once
#include <pefix/x86_64/ir.h>
#include <pefix/pe.h>
#include <set>
#include <unordered_map>

namespace pefix {

struct AbstractValue {
    enum State : uint8_t { AV_TOP, AV_CONST, AV_TYPED_PTR, AV_BOTTOM } state = AV_TOP;
    uint64_t value = 0;
    Width width = Width::W64;

    bool isConst() const { return state == AV_CONST; }
    bool isTypedPtr() const { return state == AV_TYPED_PTR; }
    bool isTop() const { return state == AV_TOP; }

    static AbstractValue Top() { return {AV_TOP, 0, Width::W64}; }
    static AbstractValue MkConst(uint64_t v, Width w = Width::W64) { return {AV_CONST, v, w}; }
    static AbstractValue MkTypedPtr(uint32_t vtableRVA) { return {AV_TYPED_PTR, vtableRVA, Width::W64}; }

    uint64_t masked() const {
        switch (width) {
        case Width::W8:  return value & 0xFF;
        case Width::W16: return value & 0xFFFF;
        case Width::W32: return value & 0xFFFFFFFF;
        default: return value;
        }
    }

    AbstractValue meet(const AbstractValue& o) const {
        if (state == AV_TOP) return o;
        if (o.state == AV_TOP) return *this;
        if (state == AV_CONST && o.state == AV_CONST && value == o.value) return *this;
        return {AV_BOTTOM, 0, width};
    }
};

class ConstProp {
public:
    virtual ~ConstProp() = default;

    void run(Func& func);

    void setPE(const PEFile* pe, uint64_t imageBase) { pe_ = pe; imageBase_ = imageBase; }
    void setInitReg(Reg reg, uint64_t val) { initRegs_[(uint16_t)reg] = val; initRegSet_.insert((uint16_t)reg); }
    void setTypedPtr(Reg reg, uint32_t vtableRVA) { typedPtrs_[(uint16_t)reg] = vtableRVA; }
    void setReturnTypes(const std::unordered_map<uint32_t, uint32_t>* rt) { returnTypes_ = rt; }
    void setFieldTypes(const std::unordered_map<uint64_t, uint32_t>* ft) { fieldTypes_ = ft; }

protected:
    // Hook for op values outside the standard x86 set. Return true to claim the op
    // (caller skips the default TOP handling); false to fall through.
    virtual bool transferUnknown(const Instr& instr) { (void)instr; return false; }

    AbstractValue regs_[16];
    AbstractValue flags_[5];

    AbstractValue getVal(const Value& v);
    void setVal(const Value& v, AbstractValue av);
    void setFlag(int idx, AbstractValue av) { if (idx < 5) flags_[idx] = av; }
    AbstractValue getFlag(int idx) { return idx < 5 ? flags_[idx] : AbstractValue::Top(); }

private:
    std::set<uint16_t> dispatchKeyRegs_;
    const PEFile* pe_ = nullptr;
    uint64_t imageBase_ = 0;
    std::unordered_map<uint16_t, uint64_t> initRegs_;
    std::set<uint16_t> initRegSet_;
    const std::unordered_map<uint32_t, uint32_t>* returnTypes_ = nullptr;
    const std::unordered_map<uint64_t, uint32_t>* fieldTypes_ = nullptr;
    std::unordered_map<uint16_t, uint32_t> typedPtrs_;

    void initState();
    void transfer(const Instr& instr);
    int evalCCResult(CC cc);

    // Walks the current abstract state at an indirect CALL/JMP and rewrites the dst
    // to a LABEL when the memory operand resolves to a concrete code pointer.
    bool tryResolveIndirectControlFlow(const Instr& instr);
};

} // namespace pefix
