#pragma once
#include <pefix/pe.h>
#include <pefix/x86_64/ir.h>
#include <cstdint>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <string>

namespace pefix {

struct TraceCall {
    uint64_t callerVA;
    uint64_t targetVA;
    uint64_t args[4]; // rcx, rdx, r8, r9
    uint64_t rax;
};

struct TraceResult {
    std::vector<TraceCall> calls;
    uint64_t stepsExecuted;
    bool completed;
    std::string stopReason;
};

class Tracer {
public:
    Tracer(const PEFile& pe, uint64_t imageBase);

    void setReg(int idx, uint64_t val);
    void setStack(uint64_t offset, uint64_t val);

    // Add a function RVA to record calls to
    void watchFunction(uint32_t rva);

    // Trace from startRVA, up to maxSteps instructions
    TraceResult trace(uint32_t startRVA, uint32_t maxSteps = 500000);

private:
    const PEFile& pe_;
    uint64_t imageBase_;

    uint64_t regs_[16] = {};
    uint64_t rflags_ = 0;
    std::unordered_map<uint64_t, uint64_t> stackMem_;

    uint64_t stackBase_ = 0x7FFE0000ULL;
    uint64_t stackTop_ = 0;

    std::unordered_set<uint32_t> watchedFuncs_;
    std::vector<TraceCall> calls_;

    uint64_t readMem(uint64_t addr, Width w);
    void writeMem(uint64_t addr, uint64_t val, Width w);
    bool isStackAddr(uint64_t addr);

    uint8_t readCodeByte(uint64_t va);
    uint64_t readCodeMem(uint64_t va, Width w);

    bool getZF() { return (rflags_ >> 6) & 1; }
    bool getCF() { return rflags_ & 1; }
    bool getSF() { return (rflags_ >> 7) & 1; }
    bool getOF() { return (rflags_ >> 11) & 1; }
    void setZF(bool v) { if (v) rflags_ |= (1ULL << 6); else rflags_ &= ~(1ULL << 6); }
    void setCF(bool v) { if (v) rflags_ |= 1ULL; else rflags_ &= ~1ULL; }
    void setSF(bool v) { if (v) rflags_ |= (1ULL << 7); else rflags_ &= ~(1ULL << 7); }
    void setOF(bool v) { if (v) rflags_ |= (1ULL << 11); else rflags_ &= ~(1ULL << 11); }
    void setFlags(uint64_t result, Width w);
    bool evalCC(CC cc);

    enum ExecAction { CONTINUE, STOP, SKIP };
    ExecAction execInstr(const Instr& instr, uint64_t va);
    uint64_t resolveValue(const Value& v);
    void storeValue(const Value& v, uint64_t val);
    uint64_t resolveAddr(const Value& v);

    uint32_t countInt3(uint64_t va);
};

} // namespace pefix
