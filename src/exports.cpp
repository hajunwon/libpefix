#include <pefix/exports.h>
#include <pefix/sections.h>
#include <algorithm>
#include <cstring>

namespace pefix {

bool addSyntheticExports(PEFile& pe, uint64_t imageBase,
    const std::vector<NamedAddress>& entries)
{
    if (entries.empty()) return false;

    struct SortedEntry { uint32_t rva; std::string name; };
    std::vector<SortedEntry> sorted;
    sorted.reserve(entries.size());
    for (auto& e : entries) {
        if (e.va < imageBase) continue;
        uint32_t rva = (uint32_t)(e.va - imageBase);
        std::string safe = e.name;
        for (auto& c : safe) {
            if (c == ' ' || c == ':' || c == '<' || c == '>' || c == ',')
                c = '_';
        }
        if (!safe.empty())
            sorted.push_back({rva, safe});
    }

    // Dedup: same address -> keep longest name
    {
        std::sort(sorted.begin(), sorted.end(),
            [](const SortedEntry& a, const SortedEntry& b) {
                if (a.rva != b.rva) return a.rva < b.rva;
                return a.name.size() > b.name.size();
            });
        auto it = std::unique(sorted.begin(), sorted.end(),
            [](const SortedEntry& a, const SortedEntry& b) { return a.rva == b.rva; });
        sorted.erase(it, sorted.end());
    }

    // Dedup: same name -> append suffix
    {
        std::sort(sorted.begin(), sorted.end(),
            [](const SortedEntry& a, const SortedEntry& b) { return a.name < b.name; });
        for (size_t i = 1; i < sorted.size(); i++) {
            if (sorted[i].name == sorted[i-1].name) {
                int suffix = 2;
                for (size_t j = i; j < sorted.size() && sorted[j].name == sorted[i-1].name; j++) {
                    sorted[j].name += "_" + std::to_string(suffix++);
                }
            }
        }
    }

    // PE export table requires sorted names for binary search
    std::sort(sorted.begin(), sorted.end(),
        [](const SortedEntry& a, const SortedEntry& b) { return a.name < b.name; });

    uint32_t numFuncs = (uint32_t)sorted.size();

    auto& expDir = pe.nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (expDir.VirtualAddress != 0) {
        printf("[!] PE already has an export directory at RVA 0x%X -- overwriting\n", expDir.VirtualAddress);
    }

    printf("[*] Building synthetic export table: %u entries\n", numFuncs);

    uint32_t nameStringsSize = 0;
    for (auto& e : sorted) nameStringsSize += (uint32_t)e.name.size() + 1;
    const char* moduleName = "module.exe";
    uint32_t moduleNameSize = (uint32_t)strlen(moduleName) + 1;

    uint32_t dirSize = 40;
    uint32_t addrTableSize = numFuncs * 4;
    uint32_t namePtrTableSize = numFuncs * 4;
    uint32_t ordTableSize = numFuncs * 2;
    uint32_t totalSize = dirSize + addrTableSize + namePtrTableSize + ordTableSize
                        + moduleNameSize + nameStringsSize;
    totalSize = (totalSize + 15) & ~15;

    std::vector<uint8_t> expData(totalSize, 0);

    uint32_t secAlign = pe.nt->OptionalHeader.SectionAlignment;
    if (!secAlign) secAlign = 0x1000;
    uint32_t newSectionRVA = 0;
    for (WORD i = 0; i < pe.numSections; i++) {
        uint32_t end = pe.sections[i].VirtualAddress + pe.sections[i].Misc.VirtualSize;
        if (end > newSectionRVA) newSectionRVA = end;
    }
    newSectionRVA = (newSectionRVA + secAlign - 1) & ~(secAlign - 1);

    uint32_t offAddrTable = dirSize;
    uint32_t offNamePtrTable = offAddrTable + addrTableSize;
    uint32_t offOrdTable = offNamePtrTable + namePtrTableSize;
    uint32_t offModuleName = offOrdTable + ordTableSize;
    uint32_t offNames = offModuleName + moduleNameSize;

    IMAGE_EXPORT_DIRECTORY* dir = (IMAGE_EXPORT_DIRECTORY*)expData.data();
    dir->Characteristics = 0;
    dir->TimeDateStamp = 0;
    dir->MajorVersion = 0;
    dir->MinorVersion = 0;
    dir->Name = newSectionRVA + offModuleName;
    dir->Base = 1;
    dir->NumberOfFunctions = numFuncs;
    dir->NumberOfNames = numFuncs;
    dir->AddressOfFunctions = newSectionRVA + offAddrTable;
    dir->AddressOfNames = newSectionRVA + offNamePtrTable;
    dir->AddressOfNameOrdinals = newSectionRVA + offOrdTable;

    uint32_t nameOffset = offNames;
    for (uint32_t i = 0; i < numFuncs; i++) {
        *(uint32_t*)(expData.data() + offAddrTable + i * 4) = sorted[i].rva;
        *(uint32_t*)(expData.data() + offNamePtrTable + i * 4) = newSectionRVA + nameOffset;
        *(uint16_t*)(expData.data() + offOrdTable + i * 2) = (uint16_t)i;
        memcpy(expData.data() + nameOffset, sorted[i].name.c_str(), sorted[i].name.size() + 1);
        nameOffset += (uint32_t)sorted[i].name.size() + 1;
    }

    memcpy(expData.data() + offModuleName, moduleName, moduleNameSize);

    if (!appendSection(pe, ".edata", expData,
            IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ)) {
        printf("[!] Failed to append .edata section\n");
        return false;
    }

    pe.nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = newSectionRVA;
    pe.nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size = totalSize;

    printf("[+] Synthetic export table added: %u entries in .edata section (RVA=0x%X)\n",
           numFuncs, newSectionRVA);
    return true;
}

} // namespace pefix
