#pragma once
#include <pefix/pe.h>
#include <pefix/xrefs.h>
#include <string>
#include <vector>

namespace pefix {

struct RTTIClass {
    std::string demangledName;
    std::string rawName;
    uint64_t vtableVA;
    std::vector<uint64_t> methodVAs;
};

struct InferredName {
    uint64_t va;
    std::string name;
    bool isFunction;
};

std::vector<RTTIClass> parseRTTI(const PEFile& pe, uint64_t imageBase);

std::vector<InferredName> inferFunctionNames(const PEFile& pe, uint64_t imageBase,
    const std::vector<RipRelativeRef>& refs);

// Flatten E9 JMP chains in executable sections.
// sectionFilter: returns true for sections to process (nullptr = all executable)
using SectionFilter = bool(*)(const char* sectionName);
uint32_t flattenJmpChains(PEFile& pe, SectionFilter filter = nullptr);

// Trace API callers via BFS from known function RVAs.
struct ChainedFunc {
    uint32_t rva;
    std::string name;
    int depth;
};
std::vector<ChainedFunc> importChainBFS(const PEFile& pe, uint64_t imageBase,
    const std::vector<std::pair<uint32_t, std::string>>& seeds, int maxDepth = 4);

} // namespace pefix
