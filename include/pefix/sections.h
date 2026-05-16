#pragma once
#include <pefix/pe.h>

namespace pefix {

// Recover hidden code sections (gaps in section layout)
int recoverHiddenSections(PEFile& pe);

// Append a new section to the PE
bool appendSection(PEFile& pe, const char* name, const std::vector<uint8_t>& data, DWORD characteristics);

} // namespace pefix
