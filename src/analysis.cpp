#include <pefix/analysis.h>
#include <cstring>
#include <algorithm>
#include <set>
#include <map>
#include <unordered_map>

namespace pefix {

static std::string demangleRTTI(const std::string& raw) {
    if (raw.size() < 5 || raw.substr(0, 4) != ".?AV") return raw;
    std::string name = raw.substr(4);
    if (name.size() >= 2 && name.substr(name.size()-2) == "@@")
        name = name.substr(0, name.size()-2);
    std::vector<std::string> parts;
    size_t pos = 0;
    while (pos < name.size()) {
        size_t at = name.find('@', pos);
        if (at == std::string::npos) { parts.push_back(name.substr(pos)); break; }
        parts.push_back(name.substr(pos, at - pos));
        pos = at + 1;
    }
    std::vector<std::string> clean;
    for (auto& p : parts) if (!p.empty()) clean.push_back(p);
    std::string result;
    for (int i = (int)clean.size()-1; i >= 0; i--) {
        if (!result.empty()) result += "::";
        result += clean[i];
    }
    if (result.empty()) return raw;

    for (const char* ns : {"CryptoPP::", "std::", "nlohmann::", "google::"}) {
        std::string doubled = std::string(ns) + ns;
        while (result.find(doubled) != std::string::npos)
            result.replace(result.find(doubled), doubled.size(), ns);
    }

    size_t qpos;
    while ((qpos = result.find("?$")) != std::string::npos)
        result.erase(qpos, 2);
    for (const char* prefix : {"VCryptoPP", "Vstd", "Vnlohmann", "Vgoogle"}) {
        size_t vp;
        while ((vp = result.find(prefix)) != std::string::npos) {
            if (vp == 0 || result[vp-1] == ':' || result[vp-1] == '_')
                result.erase(vp, 1);
            else break;
        }
    }
    size_t dp;
    while ((dp = result.find("$0A")) != std::string::npos)
        result.replace(dp, 3, "Enc");
    while ((dp = result.find("$00")) != std::string::npos)
        result.replace(dp, 3, "Dec");
    while ((dp = result.find("H__")) != std::string::npos)
        result.erase(dp, 3);
    while ((dp = result.find("W4")) != std::string::npos)
        result.erase(dp, 2);
    if (result.size() > 80)
        result = result.substr(0, 77) + "...";

    return result;
}

std::vector<RTTIClass> parseRTTI(const PEFile& pe, uint64_t imageBase) {
    std::vector<RTTIClass> result;
    uint32_t sizeOfImage = pe.nt->OptionalHeader.SizeOfImage;

    struct TypeDesc { uint32_t rva; uint32_t nameOffset; std::string name; };
    std::vector<TypeDesc> typeDescs;

    for (WORD i = 0; i < pe.numSections; i++) {
        uint32_t rawOff = pe.sections[i].PointerToRawData;
        uint32_t rawSz = pe.sections[i].SizeOfRawData;
        uint32_t va = pe.sections[i].VirtualAddress;
        if (rawOff + rawSz > pe.data.size()) rawSz = (uint32_t)(pe.data.size() - rawOff);
        const char* data = (const char*)(pe.data.data() + rawOff);

        for (uint32_t pos = 0; pos + 10 < rawSz; pos++) {
            if (strncmp(data + pos, ".?AV", 4) != 0) continue;
            size_t len = strnlen(data + pos, rawSz - pos);
            if (len < 8 || len > 200) continue;
            std::string name(data + pos, len);
            if (name.find("@@") == std::string::npos) continue;

            uint32_t tdRVA = va + pos - 0x10;
            if (tdRVA < va) continue;
            typeDescs.push_back({tdRVA, va + pos, name});
            pos += (uint32_t)len;
        }
    }

    struct COLRef { uint32_t colRVA; uint32_t tdIdx; };
    std::vector<COLRef> cols;

    std::unordered_map<uint32_t, uint32_t> tdRVAtoIdx;
    for (uint32_t idx = 0; idx < typeDescs.size(); idx++)
        tdRVAtoIdx[typeDescs[idx].rva] = idx;

    for (WORD i = 0; i < pe.numSections; i++) {
        uint32_t rawOff = pe.sections[i].PointerToRawData;
        uint32_t rawSz = pe.sections[i].SizeOfRawData;
        uint32_t va = pe.sections[i].VirtualAddress;
        if (rawOff + rawSz > pe.data.size()) rawSz = (uint32_t)(pe.data.size() - rawOff);
        const uint8_t* data = pe.data.data() + rawOff;

        for (uint32_t pos = 0; pos + 24 <= rawSz; pos += 4) {
            uint32_t sig = *(uint32_t*)(data + pos);
            if (sig != 1) continue;

            uint32_t tdRVA = *(uint32_t*)(data + pos + 12);
            auto it = tdRVAtoIdx.find(tdRVA);
            if (it == tdRVAtoIdx.end()) continue;

            uint32_t selfRVA = *(uint32_t*)(data + pos + 20);
            uint32_t thisRVA = va + pos;
            if (selfRVA != thisRVA) continue;

            cols.push_back({thisRVA, it->second});
        }
    }

    std::unordered_map<uint32_t, uint32_t> colRVAtoIdx;
    for (uint32_t idx = 0; idx < cols.size(); idx++)
        colRVAtoIdx[cols[idx].colRVA] = idx;

    for (WORD i = 0; i < pe.numSections; i++) {
        uint32_t rawOff = pe.sections[i].PointerToRawData;
        uint32_t rawSz = pe.sections[i].SizeOfRawData;
        uint32_t va = pe.sections[i].VirtualAddress;
        if (rawOff + rawSz > pe.data.size()) rawSz = (uint32_t)(pe.data.size() - rawOff);
        const uint8_t* data = pe.data.data() + rawOff;

        for (uint32_t pos = 0; pos + 16 <= rawSz; pos += 8) {
            uint64_t colPtr = *(uint64_t*)(data + pos);
            if (colPtr < imageBase || colPtr >= imageBase + sizeOfImage) continue;
            uint32_t colRVA = (uint32_t)(colPtr - imageBase);
            auto it = colRVAtoIdx.find(colRVA);
            if (it == colRVAtoIdx.end()) continue;

            uint32_t vtableFileOff = rawOff + pos + 8;
            uint32_t vtableRVA = va + pos + 8;

            RTTIClass cls;
            cls.rawName = typeDescs[cols[it->second].tdIdx].name;
            cls.demangledName = demangleRTTI(cls.rawName);
            cls.vtableVA = imageBase + vtableRVA;

            for (int slot = 0; slot < 30; slot++) {
                uint32_t entryOff = vtableFileOff + slot * 8;
                if (entryOff + 8 > pe.data.size()) break;
                uint64_t funcVA = *(uint64_t*)(pe.data.data() + entryOff);
                if (funcVA < imageBase || funcVA >= imageBase + sizeOfImage) break;
                uint32_t funcRVA = (uint32_t)(funcVA - imageBase);
                int sec = pe.findSection(funcRVA);
                if (sec < 0 || !pe.isExecutableSection(sec)) break;
                cls.methodVAs.push_back(funcVA);
            }

            if (!cls.methodVAs.empty())
                result.push_back(cls);
        }
    }

    return result;
}

std::vector<InferredName> inferFunctionNames(const PEFile& pe, uint64_t imageBase,
    const std::vector<RipRelativeRef>& refs)
{
    std::vector<InferredName> result;
    uint32_t sizeOfImage = pe.nt->OptionalHeader.SizeOfImage;

    struct StrInfo { uint32_t strRVA; std::string value; };
    std::vector<StrInfo> strings;

    for (WORD i = 0; i < pe.numSections; i++) {
        char sn[9] = {}; memcpy(sn, pe.sections[i].Name, 8);
        if (strcmp(sn, ".rdata") != 0) continue;
        uint32_t rawOff = pe.sections[i].PointerToRawData;
        uint32_t rawSz = pe.sections[i].SizeOfRawData;
        uint32_t va = pe.sections[i].VirtualAddress;
        if (rawOff + rawSz > pe.data.size()) rawSz = (uint32_t)(pe.data.size() - rawOff);
        const char* d = (const char*)(pe.data.data() + rawOff);

        for (uint32_t pos = 0; pos + 8 < rawSz; pos++) {
            if (d[pos] < 0x20 || d[pos] > 0x7E) continue;
            size_t slen = strnlen(d + pos, std::min(rawSz - pos, (uint32_t)120));
            if (slen < 8 || slen > 80) continue;
            bool valid = true;
            for (size_t k = 0; k < slen; k++)
                if (d[pos+k] < 0x20 || d[pos+k] > 0x7E) { valid = false; break; }
            if (!valid) continue;

            std::string s(d + pos, slen);
            if (s.find("Error") != std::string::npos ||
                s.find("Failed") != std::string::npos ||
                s.find("Invalid") != std::string::npos ||
                s.find("cannot") != std::string::npos ||
                s.find("unable") != std::string::npos) {
                strings.push_back({va + pos, s});
            }
            pos += (uint32_t)slen;
        }
    }

    std::map<uint32_t, std::vector<uint32_t>> strToRefs;
    for (auto& ref : refs) {
        if (ref.isLea && ref.targetRVA < sizeOfImage)
            strToRefs[ref.targetRVA].push_back(ref.instrRVA);
    }

    for (auto& si : strings) {
        auto it = strToRefs.find(si.strRVA);
        if (it == strToRefs.end() || it->second.size() != 1) continue;
        uint32_t instrRVA = it->second[0];
        std::string fname = si.value.substr(0, 40);
        for (auto& c : fname) {
            if (c == ' ' || c == ':' || c == '(' || c == ')' || c == '\'' ||
                c == '"' || c == '\\' || c == '/' || c == ',' || c == '.')
                c = '_';
        }
        while (!fname.empty() && fname.back() == '_') fname.pop_back();
        if (fname.size() >= 4)
            result.push_back({imageBase + instrRVA, "ref_" + fname, true});
    }

    for (WORD i = 0; i < pe.numSections; i++) {
        char sn[9] = {}; memcpy(sn, pe.sections[i].Name, 8);
        if (strcmp(sn, ".text") != 0) continue;
        uint32_t rawOff = pe.sections[i].PointerToRawData;
        uint32_t rawSz = pe.sections[i].SizeOfRawData;
        uint32_t va = pe.sections[i].VirtualAddress;
        if (rawOff + rawSz > pe.data.size()) break;
        const uint8_t* code = pe.data.data() + rawOff;

        for (uint32_t pos = 0; pos + 20 <= rawSz; pos++) {
            if (code[pos] == 0x48 && code[pos+1] == 0x3B && code[pos+2] == 0x0D &&
                code[pos+7] == 0x75) {
                if (pos == 0 || code[pos-1] == 0xCC || code[pos-1] == 0xC3) {
                    result.push_back({imageBase + va + pos, "__security_check_cookie", true});
                    break;
                }
            }
        }
    }

    return result;
}

uint32_t flattenJmpChains(PEFile& pe, SectionFilter filter) {
    uint32_t flattened = 0;

    for (WORD i = 0; i < pe.numSections; i++) {
        if (!(pe.sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
        if (filter) {
            char name[9] = {};
            memcpy(name, pe.sections[i].Name, 8);
            if (!filter(name)) continue;
        }

        uint32_t rawOff = pe.sections[i].PointerToRawData;
        uint32_t rawSz = pe.sections[i].SizeOfRawData;
        uint32_t va = pe.sections[i].VirtualAddress;
        if (rawOff + rawSz > pe.data.size()) rawSz = (uint32_t)(pe.data.size() - rawOff);
        uint8_t* code = pe.data.data() + rawOff;

        for (uint32_t pos = 0; pos + 5 <= rawSz; pos++) {
            if (code[pos] != 0xE9) continue;

            int32_t disp = *(int32_t*)(code + pos + 1);
            uint32_t targetRVA = va + pos + 5 + disp;
            uint32_t finalRVA = targetRVA;
            int hops = 0;

            while (hops < 16) {
                uint32_t fOff = pe.rvaToOffset(finalRVA);
                if (!fOff || fOff + 5 > pe.data.size()) break;
                if (pe.data[fOff] != 0xE9) break;
                int32_t nd = *(int32_t*)(pe.data.data() + fOff + 1);
                uint32_t next = finalRVA + 5 + nd;
                if (next == finalRVA) break;
                finalRVA = next;
                hops++;
            }

            if (hops > 0 && finalRVA != targetRVA) {
                int32_t newDisp = (int32_t)(finalRVA - (va + pos + 5));
                *(int32_t*)(code + pos + 1) = newDisp;
                flattened++;
            }
        }
    }
    return flattened;
}

std::vector<ChainedFunc> importChainBFS(const PEFile& pe, uint64_t imageBase,
    const std::vector<std::pair<uint32_t, std::string>>& seeds, int maxDepth) {
    std::vector<ChainedFunc> result;
    uint32_t sizeOfImage = pe.nt->OptionalHeader.SizeOfImage;

    std::unordered_map<uint32_t, std::vector<uint32_t>> callerMap;
    for (WORD si = 0; si < pe.numSections; si++) {
        if (!(pe.sections[si].Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
        uint32_t rawOff = pe.sections[si].PointerToRawData;
        uint32_t rawSz = pe.sections[si].SizeOfRawData;
        uint32_t secRVA = pe.sections[si].VirtualAddress;
        if (rawOff + rawSz > pe.data.size()) rawSz = (uint32_t)(pe.data.size() - rawOff);

        for (uint32_t p = 0; p + 5 <= rawSz; p++) {
            if (pe.data[rawOff + p] != 0xE8) continue;
            int32_t d = *(int32_t*)(pe.data.data() + rawOff + p + 1);
            uint32_t target = secRVA + p + 5 + d;
            if (target < sizeOfImage)
                callerMap[target].push_back(secRVA + p);
        }
    }

    auto findFuncStart = [&](uint32_t rva) -> uint32_t {
        uint32_t off = pe.rvaToOffset(rva);
        if (!off) return rva;
        for (uint32_t bk = 1; bk < 4096 && off > bk; bk++) {
            uint8_t b = pe.data[off - bk];
            if (b == 0xCC || b == 0xC3) return rva - bk + 1;
        }
        return rva;
    };

    struct QEntry { uint32_t rva; std::string name; int depth; };
    std::vector<QEntry> queue;
    std::set<uint32_t> visited;

    for (auto& [rva, name] : seeds) {
        queue.push_back({rva, name, 0});
        visited.insert(rva);
    }

    for (size_t qi = 0; qi < queue.size(); qi++) {
        auto& entry = queue[qi];
        if (entry.depth >= maxDepth) continue;

        auto it = callerMap.find(entry.rva);
        if (it == callerMap.end()) continue;

        for (uint32_t callerRVA : it->second) {
            uint32_t funcRVA = findFuncStart(callerRVA);
            if (visited.count(funcRVA)) continue;
            visited.insert(funcRVA);

            std::string name = entry.name + "_chain_" + std::to_string(entry.depth + 1);
            result.push_back({funcRVA, name, entry.depth + 1});
            queue.push_back({funcRVA, name, entry.depth + 1});
        }
    }

    return result;
}

} // namespace pefix
