#pragma once
#include <pefix/x86_64/ir.h>
#include <pefix/pe.h>
#include <unordered_map>
#include <functional>

namespace pefix {

struct EmuState {
    uint64_t regs[16] = {};
    uint64_t rip = 0;
    uint64_t rflags = 0;

    bool zf() const { return (rflags >> 6) & 1; }
    bool cf() const { return rflags & 1; }
    bool sf() const { return (rflags >> 7) & 1; }
    bool of() const { return (rflags >> 11) & 1; }
    void setZF(bool v) { if (v) rflags |= (1<<6); else rflags &= ~(1<<6); }
    void setCF(bool v) { if (v) rflags |= 1; else rflags &= ~1; }
    void setSF(bool v) { if (v) rflags |= (1<<7); else rflags &= ~(1<<7); }
    void setOF(bool v) { if (v) rflags |= (1<<11); else rflags &= ~(1<<11); }
    void updateFlags(uint64_t result, Width w) {
        uint64_t mask = (w == Width::W64) ? ~0ULL : ((1ULL << (uint8_t)w) - 1);
        result &= mask;
        setZF(result == 0);
        setSF((result >> ((uint8_t)w - 1)) & 1);
    }
};

struct MemAccess {
    uint64_t addr;
    uint64_t value;
    uint32_t size;
    bool isWrite;
    uint64_t rip;
};

struct CallRecord {
    uint64_t caller;
    uint64_t target;
    uint64_t args[4]; // rcx, rdx, r8, r9
    uint64_t retval;
};

class Emulator {
public:
    Emulator(const PEFile& pe, uint64_t imageBase);

    void loadSections();
    void setReg(int idx, uint64_t val) { state_.regs[idx] = val; }
    void setRIP(uint64_t va) { state_.rip = va; }
    void setupStack(uint64_t stackBase = 0x7FFE0000, uint32_t stackSize = 0x10000);

    // Register a stub for a function (returns given value instead of executing)
    void addStub(uint64_t funcVA, uint64_t retval = 0);

    // Execute up to maxSteps instructions.
    // Returns false if execution fails or hits an unhandled instruction.
    bool execute(uint32_t maxSteps = 100000);

    const EmuState& state() const { return state_; }
    const std::vector<MemAccess>& memLog() const { return memLog_; }
    const std::vector<CallRecord>& callLog() const { return callLog_; }
    uint64_t stepsExecuted() const { return steps_; }

    void watchRange(uint64_t start, uint64_t end) { watchStart_ = start; watchEnd_ = end; }
    void writeMemory(uint64_t addr, uint64_t val) { writeQword(addr, val); }

private:
    const PEFile& pe_;
    uint64_t imageBase_;

    EmuState state_;
    std::unordered_map<uint64_t, uint8_t> mem_;
    std::unordered_map<uint64_t, uint64_t> stubs_;
    std::vector<MemAccess> memLog_;
    std::vector<CallRecord> callLog_;
    uint64_t steps_ = 0;
    uint64_t stackBase_ = 0;
    uint64_t watchStart_ = 0, watchEnd_ = 0;

    uint8_t readByte(uint64_t addr);
    uint16_t readWord(uint64_t addr);
    uint32_t readDword(uint64_t addr);
    uint64_t readQword(uint64_t addr);
    uint64_t readMem(uint64_t addr, Width w);
    void writeByte(uint64_t addr, uint8_t val);
    void writeWord(uint64_t addr, uint16_t val);
    void writeDword(uint64_t addr, uint32_t val);
    void writeQword(uint64_t addr, uint64_t val);
    void writeMem(uint64_t addr, uint64_t val, Width w);

    void logMemAccess(uint64_t addr, uint64_t val, uint32_t sz, bool isWrite);

    bool execInstr(const Instr& instr);
    uint64_t resolveValue(const Value& v);
    uint64_t resolveAddr(const Value& v);
    void storeValue(const Value& v, uint64_t val);
    bool evalCC(CC cc);

    void push64(uint64_t val);
    uint64_t pop64();
};

} // namespace pefix
