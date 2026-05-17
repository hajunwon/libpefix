#pragma once
#include <pefix/pe.h>
#include <pefix/x86_64/ir.h>
#include <cstdint>
#include <functional>
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
    uint64_t regs[16];
};

struct TraceStep {
    uint32_t step;
    uint32_t rva;
    Op op;
    uint64_t regs[16];
    uint64_t memAddr;
    uint64_t memVal;
    bool memRead;
    bool isStack;
};

struct TraceResult {
    std::vector<TraceCall> calls;
    uint64_t stepsExecuted;
    bool completed;
    std::string stopReason;
};

using TraceLogFn = std::function<void(const TraceStep&)>;

class Tracer {
public:
    Tracer(const PEFile& pe, uint64_t imageBase);

    void setReg(int idx, uint64_t val);
    void setStack(uint64_t offset, uint64_t val);

    void setTraceLog(TraceLogFn fn, uint32_t maxSteps = 200) {
        traceLog_ = std::move(fn);
        traceLogLimit_ = maxSteps;
    }

    void watchFunction(uint32_t rva);
    void addRegOverride(uint32_t rva, int reg, uint64_t val);
    void setSkipExternalCalls(bool v) { skipExternal_ = v; }
    void setMaxVisitPerAddr(uint32_t v) { maxVisit_ = v; }
    uint64_t getRSP() const { return regs_[(int)Reg::RSP]; }

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

    TraceLogFn traceLog_;
    uint32_t traceLogLimit_ = 200;
    bool skipExternal_ = false;
    uint32_t maxVisit_ = 8;
    bool forceFlipNext_ = false;
    uint32_t progressTimeout_ = 0;
    uint32_t lastProgress_ = 0;
public:
    void setProgressTimeout(uint32_t steps) { progressTimeout_ = steps; }
private:

    using StackFallbackFn = std::function<bool(uint64_t addr, Width w, uint64_t& outVal)>;
    StackFallbackFn stackFallback_;

    struct RegOverride { int reg; uint64_t val; };
    std::unordered_map<uint32_t, std::vector<RegOverride>> regOverrides_;
public:
    void setStackFallback(StackFallbackFn fn) { stackFallback_ = std::move(fn); }
private:

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
