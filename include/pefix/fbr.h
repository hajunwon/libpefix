#pragma once
#include <pefix/pe.h>
#include <cstdint>
#include <vector>

namespace pefix {

// Function source bitmask. A boundary may carry several when multiple
// independent seeds vote for the same RVA — higher source count = higher
// confidence the start is real.
enum FunctionSource : uint16_t {
    SRC_PDATA       = 1 << 0,  // RUNTIME_FUNCTION.BeginAddress
    SRC_EXPORT      = 1 << 1,  // PE export AddressOfFunctions
    SRC_DIRECT_CALL = 1 << 2,  // discovered via E8 disp32 target
    SRC_DIRECT_JMP  = 1 << 3,  // discovered via E9 disp32 target (tail call)
    SRC_RTTI_VFUNC  = 1 << 4,  // RTTI vtable method slot
    SRC_DATA_FNPTR  = 1 << 5,  // QWORD in .data/.rdata pointing into code
    SRC_EH_HANDLER  = 1 << 6,  // UNWIND_INFO.ExceptionHandler
    SRC_PROLOGUE    = 1 << 7,  // byte-pattern prologue scan (heuristic)
};

struct FunctionBoundary {
    uint32_t startRVA;
    uint32_t endRVA;       // exclusive; 0 if not computed
    uint16_t sources;       // bitmask of FunctionSource
    uint8_t  sourceCount;   // popcount(sources)
    bool     inObfuscated;  // .grfn1 / .riot* / similar non-pdata exec sections
    bool     validated;     // passed first-byte / prev-byte checks
};

struct FbrStats {
    uint32_t seedsPdata = 0;
    uint32_t seedsExport = 0;
    uint32_t seedsRttiVfunc = 0;
    uint32_t seedsDataFnPtr = 0;
    uint32_t seedsEhHandler = 0;
    uint32_t seedsTotal = 0;        // S0 after dedup

    uint32_t expandIterations = 0;
    uint32_t expandedDirectCall = 0;
    uint32_t expandedDirectJmp = 0;

    uint32_t rejectedBadFirstByte = 0;
    uint32_t rejectedNoPrevTerm = 0;
    uint32_t rejectedOutOfRange = 0;
    uint32_t rejectedOverlap = 0;

    std::vector<uint32_t> rejectSampleNoSignal;

    uint32_t finalTextFuncs = 0;
    uint32_t finalGrfnFuncs = 0;
    uint32_t finalTotal = 0;

    uint32_t durationMs = 0;
};

struct FbrConfig {
    bool collectPdata     = true;
    bool collectExports   = true;
    bool collectRttiVfunc = true;
    bool collectDataFnPtr = true;
    bool collectEhHandler = true;
    bool expandCalls      = true;
    bool expandJumps      = true;
    bool validateStrict   = true;   // require prev-byte terminator unless multi-source
    uint32_t maxExpandIters = 8;     // safety cap
    uint32_t maxFunctionScan = 0x4000; // bytes to disasm per function before giving up
};

struct FbrResult {
    std::vector<FunctionBoundary> functions;  // sorted by startRVA
    FbrStats stats;

    const FunctionBoundary* findExact(uint32_t rva) const;
    const FunctionBoundary* findContaining(uint32_t rva) const;
};

FbrResult discoverFunctionBoundaries(const PEFile& pe,
                                      uint64_t imageBase,
                                      const FbrConfig& cfg = {});

} // namespace pefix
