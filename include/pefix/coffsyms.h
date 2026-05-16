#pragma once
#include <pefix/pe.h>
#include <string>
#include <vector>

namespace pefix {

struct CoffSymEntry {
    uint32_t rva;
    uint16_t sectionIndex; // 1-based
    std::string name;
    bool isFunction;
};

// Embed COFF symbol table directly into the PE file.
// IDA reads these automatically (no PDB or IDC needed).
// Handles long names (>8 chars) via string table.
bool embedCoffSymbols(PEFile& pe, uint64_t imageBase,
    const std::vector<CoffSymEntry>& symbols);

} // namespace pefix
