#pragma once
#include <pefix/pe.h>
#include <pefix/fbr.h>
#include <cstdint>
#include <vector>
#include <string>

namespace pefix {

// One immediate-to-memory store collected from a basic block. The reconstruction
// algorithm relies on size + base register + signed displacement being enough
// to spot adjacent / overlapping writes that belong to the same buffer.
struct ByteStore {
    uint32_t instrRVA;
    uint8_t  baseReg;     // pefix::Reg enum value
    int32_t  baseOffset;
    uint64_t value;       // sign-extended immediate, low `size` bytes are written
    uint8_t  size;        // 1 / 2 / 4 / 8
};

// A buffer that was filled by a run of byte/word/dword stores inside a single
// function. content is the printable rendering for human-eyeballed output;
// rawBytes preserves the full reconstruction so callers can do exact compares
// against `.rdata` strings.
struct ConcatString {
    uint32_t funcRVA;
    uint32_t firstStoreRVA;
    uint32_t lastStoreRVA;
    uint8_t  bufferBaseReg;
    int32_t  bufferBaseOff;
    bool     onStack;
    std::string content;
    std::vector<uint8_t> rawBytes;
};

struct BldfStats {
    uint32_t funcsScanned = 0;
    uint32_t storesFound = 0;
    uint32_t groupsBuilt = 0;
    uint32_t stringsReconstructed = 0;
    uint32_t stringsMatchedRdata = 0;
    uint32_t durationMs = 0;
};

struct BldfConfig {
    uint8_t  minLength = 4;     // shorter buffers are too noisy
    uint8_t  maxGap = 8;        // zero-fill across small holes (compiler may dword-patch)
    bool     allowOverwrite = true;
    bool     allowQwordMov = false;  // mov [base+disp], imm32 sign-extended to 8  - disabled in v1
    uint32_t maxBufferBytes = 4096;  // cap per buffer
};

struct BldfResult {
    std::vector<ConcatString> strings;
    BldfStats stats;
};

// v1  - scans `mov [reg+disp8/disp32], imm8/16/32` stores per function, groups
// adjacent writes by (baseReg, contiguous offset), reconstructs the byte
// sequence, filters non-printable buffers. CFG-aware grouping (cross-BB merge)
// and XMM-store handling are deferred to v2/v3 per the spec.
BldfResult extractByteConcatStrings(const PEFile& pe,
                                     const std::vector<FunctionBoundary>& funcs,
                                     const BldfConfig& cfg = {});

// Match each ConcatString against the NUL-terminated strings sitting in `.rdata`.
// Returns the number of pairs (concat string, rdata RVA) discovered. Caller
// supplies the consumer (e.g. xref_trace)  - this helper only does the byte
// compare and yields the join.
struct ConcatStringRdataLink {
    const ConcatString* concat;
    uint32_t rdataRVA;
};

std::vector<ConcatStringRdataLink>
matchConcatStringsToRdata(const PEFile& pe, const BldfResult& res);

} // namespace pefix
