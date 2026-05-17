#include <pefix/coffsyms.h>
#include <pefix/log.h>
#include <cstring>
#include <algorithm>

namespace pefix {

#pragma pack(push, 1)
struct CoffSymbol {
    union {
        char ShortName[8];
        struct {
            uint32_t Zeros;
            uint32_t Offset;
        } LongName;
    } Name;
    uint32_t Value;
    int16_t  SectionNumber;
    uint16_t Type;
    uint8_t  StorageClass;
    uint8_t  NumberOfAuxSymbols;
};
#pragma pack(pop)

static_assert(sizeof(CoffSymbol) == 18, "COFF symbol must be 18 bytes");

bool embedCoffSymbols(PEFile& pe, uint64_t imageBase,
    const std::vector<CoffSymEntry>& symbols)
{
    (void)imageBase;
    if (symbols.empty()) return false;

    log::info("Embedding COFF symbol table: %zu entries", symbols.size());

    std::vector<CoffSymbol> symTable;
    std::vector<uint8_t> strTable;

    // String table starts with 4-byte size
    strTable.resize(4, 0);

    for (auto& sym : symbols) {
        if (sym.sectionIndex == 0) continue;
        if (sym.rva == 0 || sym.name.empty()) continue;

        std::string cleanName;
        for (char c : sym.name) {
            if (c >= '!' && c <= '~') cleanName += c;
            else if (c == ' ') cleanName += '_';
        }
        if (cleanName.empty() || cleanName.size() > 256) continue;

        CoffSymbol cs = {};
        cs.Name.LongName.Zeros = 0;
        cs.Name.LongName.Offset = (uint32_t)strTable.size();
        strTable.insert(strTable.end(), cleanName.begin(), cleanName.end());
        strTable.push_back(0);

        if (sym.sectionIndex > 0 && sym.sectionIndex <= pe.numSections) {
            uint32_t secVA = pe.sections[sym.sectionIndex - 1].VirtualAddress;
            cs.Value = sym.rva >= secVA ? sym.rva - secVA : sym.rva;
        } else {
            cs.Value = sym.rva;
        }

        cs.SectionNumber = (int16_t)sym.sectionIndex;
        cs.Type = sym.isFunction ? 0x20 : 0x00;
        cs.StorageClass = 2; // IMAGE_SYM_CLASS_EXTERNAL
        cs.NumberOfAuxSymbols = 0;

        symTable.push_back(cs);
    }

    // Update string table size field
    uint32_t strSize = (uint32_t)strTable.size();
    memcpy(strTable.data(), &strSize, 4);

    // Append symbol table after file data
    uint32_t symTableOffset = (uint32_t)pe.data.size();

    size_t symBytes = symTable.size() * sizeof(CoffSymbol);
    pe.data.insert(pe.data.end(),
        (uint8_t*)symTable.data(),
        (uint8_t*)symTable.data() + symBytes);

    // Append string table
    pe.data.insert(pe.data.end(), strTable.begin(), strTable.end());

    // Update PE header
    pe.reparse();
    pe.nt->FileHeader.PointerToSymbolTable = symTableOffset;
    pe.nt->FileHeader.NumberOfSymbols = (DWORD)symTable.size();

    log::ok("COFF symbols embedded: %zu entries (%zu KB sym + %zu KB strings)",
            symTable.size(), symBytes / 1024, strTable.size() / 1024);
    return true;
}

} // namespace pefix
