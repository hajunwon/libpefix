#pragma once
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>
#include <string>
#include <algorithm>
#include <map>
#include <set>
#include <unordered_map>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

namespace pefix {

struct PEFile {
    std::vector<uint8_t> data;
    IMAGE_DOS_HEADER* dos = nullptr;
    IMAGE_NT_HEADERS64* nt = nullptr;
    IMAGE_SECTION_HEADER* sections = nullptr;
    WORD numSections = 0;

    bool load(const char* path);
    bool parse();
    void reparse();
    bool save(const char* path) const;
    uint32_t rvaToOffset(uint32_t rva) const;
    int findSection(uint32_t rva) const;
    bool isExecutableSection(int idx) const;
};

} // namespace pefix
