#pragma once
#include <pefix/pe.h>
#include <string>
#include <vector>

namespace pefix {

struct NamedAddress {
    uint64_t va;
    std::string name;
};

// Build and append a synthetic export table to the PE.
// All named addresses will appear as exports in IDA automatically.
bool addSyntheticExports(PEFile& pe, uint64_t imageBase,
    const std::vector<NamedAddress>& entries);

} // namespace pefix
