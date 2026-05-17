#include <pefix/sections.h>
#include <pefix/log.h>

namespace pefix {

bool appendSection(PEFile& pe, const char* name, const std::vector<uint8_t>& sectionData,
                   DWORD characteristics) {
    if (sectionData.empty()) return false;

    // If section with same name exists, remove it first
    for (WORD i = 0; i < pe.numSections; i++) {
        char sn[9] = {};
        memcpy(sn, pe.sections[i].Name, 8);
        if (strcmp(sn, name) == 0) {
            if (strcmp(name, ".edata") == 0) {
                pe.nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = 0;
                pe.nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size = 0;
            }
            memset(&pe.sections[i], 0, sizeof(IMAGE_SECTION_HEADER));
            for (WORD j = i; j + 1 < pe.numSections; j++)
                pe.sections[j] = pe.sections[j + 1];
            memset(&pe.sections[pe.numSections - 1], 0, sizeof(IMAGE_SECTION_HEADER));
            pe.nt->FileHeader.NumberOfSections--;
            pe.reparse();
            break;
        }
    }

    uint32_t fileAlign = pe.nt->OptionalHeader.FileAlignment;
    if (!fileAlign) fileAlign = 0x200;
    uint32_t secAlign = pe.nt->OptionalHeader.SectionAlignment;
    if (!secAlign) secAlign = 0x1000;

    uint32_t newRVA = 0;
    for (WORD i = 0; i < pe.numSections; i++) {
        uint32_t end = pe.sections[i].VirtualAddress + pe.sections[i].Misc.VirtualSize;
        if (end > newRVA) newRVA = end;
    }
    newRVA = (newRVA + secAlign - 1) & ~(secAlign - 1);

    uint32_t rawAligned = ((uint32_t)sectionData.size() + fileAlign - 1) & ~(fileAlign - 1);
    std::vector<uint8_t> alignedData = sectionData;
    alignedData.resize(rawAligned, 0);

    uint32_t newRawPtr = (uint32_t)pe.data.size();

    size_t secTableEnd = (size_t)((uint8_t*)&pe.sections[pe.numSections] - pe.data.data());
    if (secTableEnd + sizeof(IMAGE_SECTION_HEADER) > pe.sections[0].PointerToRawData) {
        log::warn("No room in PE header for new section header.");
        return false;
    }

    // Pad file to FileAlignment boundary
    size_t padNeeded = (fileAlign - (pe.data.size() % fileAlign)) % fileAlign;
    if (padNeeded > 0)
        pe.data.insert(pe.data.end(), padNeeded, 0);
    newRawPtr = (uint32_t)pe.data.size();

    pe.data.insert(pe.data.end(), alignedData.begin(), alignedData.end());
    pe.reparse();

    auto& ns = pe.sections[pe.numSections];
    memset(&ns, 0, sizeof(IMAGE_SECTION_HEADER));
    size_t nameLen = strlen(name);
    if (nameLen > 8) nameLen = 8;
    memcpy(ns.Name, name, nameLen);
    ns.Misc.VirtualSize = (DWORD)sectionData.size();
    ns.VirtualAddress = newRVA;
    ns.SizeOfRawData = rawAligned;
    ns.PointerToRawData = newRawPtr;
    ns.Characteristics = characteristics;

    pe.nt->FileHeader.NumberOfSections = pe.numSections + 1;
    pe.nt->OptionalHeader.SizeOfImage = newRVA + ((rawAligned + secAlign - 1) & ~(secAlign - 1));
    pe.reparse();

    return true;
}

int recoverHiddenSections(PEFile& pe) {
    uint32_t secAlign = pe.nt->OptionalHeader.SectionAlignment;
    if (!secAlign) secAlign = 0x1000;
    int added = 0;

    struct Range { uint32_t start; uint32_t end; };
    std::vector<Range> covered;
    for (WORD i = 0; i < pe.numSections; i++) {
        uint32_t va = pe.sections[i].VirtualAddress;
        uint32_t vsize = pe.sections[i].Misc.VirtualSize;
        if (!vsize) vsize = pe.sections[i].SizeOfRawData;
        if (va && vsize) covered.push_back({va, va + vsize});
    }
    std::sort(covered.begin(), covered.end(), [](auto& a, auto& b) { return a.start < b.start; });

    uint32_t headerEnd = (secAlign > 0x1000) ? secAlign : 0x1000;
    struct Gap { uint32_t start; uint32_t size; };
    std::vector<Gap> gaps;

    if (!covered.empty() && covered[0].start > headerEnd) {
        uint32_t gapSize = covered[0].start - headerEnd;
        if (gapSize >= 0x1000)
            gaps.push_back({headerEnd, gapSize});
    }

    for (size_t i = 0; i + 1 < covered.size(); i++) {
        uint32_t alignedEnd = (covered[i].end + secAlign - 1) & ~(secAlign - 1);
        if (alignedEnd < covered[i + 1].start) {
            uint32_t gapSize = covered[i + 1].start - alignedEnd;
            if (gapSize >= 0x1000)
                gaps.push_back({alignedEnd, gapSize});
        }
    }

    if (gaps.empty()) return 0;

    for (auto& gap : gaps) {
        uint32_t fileOff = pe.rvaToOffset(gap.start);
        if (!fileOff) fileOff = gap.start;
        if (fileOff + gap.size > pe.data.size()) continue;

        bool hasContent = false;
        for (uint32_t i = 0; i < gap.size && i < 0x10000; i += 8) {
            if (*(uint64_t*)(pe.data.data() + fileOff + i) != 0) {
                hasContent = true;
                break;
            }
        }
        if (!hasContent) continue;

        size_t secTableEnd = (size_t)((uint8_t*)&pe.sections[pe.numSections] - pe.data.data());
        if (secTableEnd + sizeof(IMAGE_SECTION_HEADER) > pe.sections[0].PointerToRawData)
            continue;

        int insertIdx = pe.numSections;
        for (WORD i = 0; i < pe.numSections; i++) {
            if (pe.sections[i].VirtualAddress > gap.start) {
                insertIdx = i;
                break;
            }
        }

        for (int i = pe.numSections; i > insertIdx; i--)
            pe.sections[i] = pe.sections[i - 1];

        auto& ns = pe.sections[insertIdx];
        memset(&ns, 0, sizeof(IMAGE_SECTION_HEADER));
        memcpy(ns.Name, ".text", 5);
        ns.Misc.VirtualSize = gap.size;
        ns.VirtualAddress = gap.start;
        ns.SizeOfRawData = gap.size;
        ns.PointerToRawData = fileOff;
        ns.Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE;

        pe.nt->FileHeader.NumberOfSections++;
        pe.reparse();
        added++;

        log::detail("Added .text section: VA=0x%08X  Size=0x%08X", gap.start, gap.size);
    }

    return added;
}

} // namespace pefix
