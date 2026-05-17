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

struct ExportEntry {
    uint32_t rva;          // RVA of exported function (or forwarder, see isForwarder)
    uint32_t ordinal;      // ordinal index in export address table
    std::string name;      // empty if exported by ordinal only
    bool isForwarder;      // true if rva points into the export directory itself (DLL forwarder)
};

// Read the PE export directory and return all entries. Empty if no exports.
std::vector<ExportEntry> readExports(const PEFile& pe);

} // namespace pefix
