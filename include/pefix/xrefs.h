#pragma once
#include <pefix/pe.h>

namespace pefix {

struct RipRelativeRef {
    uint32_t instrRVA;
    uint32_t instrLen;
    uint32_t dispOffset;
    int32_t displacement;
    uint64_t targetVA;
    uint32_t targetRVA;
    bool isCall;
    bool isJmp;
    bool isLea;
};

struct PointerRef {
    uint32_t ptrRVA;
    uint32_t targetRVA;
};

// Scan executable sections for RIP-relative instructions
std::vector<RipRelativeRef> scanRipRelativeRefs(const PEFile& pe, uint64_t imageBase);

// Resolve pointer chains in data sections
std::vector<PointerRef> resolvePointerChains(const PEFile& pe, uint64_t imageBase);

} // namespace pefix
