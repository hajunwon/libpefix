#include <pefix/pe.h>

namespace pefix {

bool PEFile::load(const char* path) {
    FILE* f = nullptr;
    fopen_s(&f, path, "rb");
    if (!f) return false;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    data.resize(sz);
    fread(data.data(), 1, sz, f);
    fclose(f);
    return parse();
}

bool PEFile::parse() {
    if (data.size() < sizeof(IMAGE_DOS_HEADER)) return false;
    dos = (IMAGE_DOS_HEADER*)data.data();
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    if ((DWORD)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > data.size()) return false;
    nt = (IMAGE_NT_HEADERS64*)(data.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return false;
    numSections = nt->FileHeader.NumberOfSections;
    sections = IMAGE_FIRST_SECTION(nt);
    return true;
}

void PEFile::reparse() {
    dos = (IMAGE_DOS_HEADER*)data.data();
    nt = (IMAGE_NT_HEADERS64*)(data.data() + dos->e_lfanew);
    sections = IMAGE_FIRST_SECTION(nt);
    numSections = nt->FileHeader.NumberOfSections;
}

bool PEFile::save(const char* path) const {
    FILE* f = nullptr;
    fopen_s(&f, path, "wb");
    if (!f) return false;
    fwrite(data.data(), 1, data.size(), f);
    fclose(f);
    return true;
}

uint32_t PEFile::rvaToOffset(uint32_t rva) const {
    for (WORD i = 0; i < numSections; i++) {
        uint32_t va = sections[i].VirtualAddress;
        uint32_t rawSz = sections[i].SizeOfRawData;
        uint32_t vSz = sections[i].Misc.VirtualSize;
        uint32_t effectiveSize = (rawSz > vSz && vSz > 0) ? vSz : rawSz;
        if (rva >= va && rva < va + effectiveSize)
            return sections[i].PointerToRawData + (rva - va);
    }
    return 0;
}

int PEFile::findSection(uint32_t rva) const {
    for (WORD i = 0; i < numSections; i++) {
        uint32_t va = sections[i].VirtualAddress;
        uint32_t sz = sections[i].Misc.VirtualSize;
        if (!sz) sz = sections[i].SizeOfRawData;
        if (rva >= va && rva < va + sz) return i;
    }
    return -1;
}

bool PEFile::isExecutableSection(int idx) const {
    if (idx < 0 || idx >= numSections) return false;
    return (sections[idx].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
}

} // namespace pefix
