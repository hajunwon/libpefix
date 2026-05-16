#include <pefix/xrefs.h>

namespace pefix {

static bool opcodeHasModRM_1byte(uint8_t op) {
    uint8_t col = op & 0x07;
    if (op <= 0x3F) {
        if (col <= 3) return true;
        return false;
    }
    switch (op) {
        case 0x88: case 0x89: case 0x8A: case 0x8B:
        case 0x8C: case 0x8E: case 0x8D:
        case 0x84: case 0x85: case 0x86: case 0x87:
        case 0x8F:
        case 0xC6: case 0xC7:
        case 0xC0: case 0xC1: case 0xD0: case 0xD1: case 0xD2: case 0xD3:
        case 0x80: case 0x81: case 0x82: case 0x83:
        case 0x69: case 0x6B: case 0x63:
        case 0xF6: case 0xF7: case 0xFE: case 0xFF:
        case 0xD8: case 0xD9: case 0xDA: case 0xDB:
        case 0xDC: case 0xDD: case 0xDE: case 0xDF:
        case 0x62:
            return true;
        default:
            return false;
    }
}

static int immSize_1byte(uint8_t op, bool has66, bool /*rexW*/) {
    switch (op) {
        case 0x69: return has66 ? 2 : 4;
        case 0x6B: return 1;
        case 0x80: case 0x82: return 1;
        case 0x81: return has66 ? 2 : 4;
        case 0x83: return 1;
        case 0xC0: case 0xC1: return 1;
        case 0xC6: return 1;
        case 0xC7: return has66 ? 2 : 4;
        case 0xF6: return 1;
        case 0xF7: return has66 ? 2 : 4;
        default: return 0;
    }
}

static bool opcodeHasModRM_2byte(uint8_t op2) {
    switch (op2) {
        case 0x05: case 0x06: case 0x07: case 0x08: case 0x09: case 0x0B:
        case 0x30: case 0x31: case 0x32: case 0x33: case 0x34: case 0x35:
        case 0x36: case 0x37:
        case 0x77:
        case 0xA0: case 0xA1: case 0xA8: case 0xA9:
        case 0xC8: case 0xC9: case 0xCA: case 0xCB:
        case 0xCC: case 0xCD: case 0xCE: case 0xCF:
            return false;
        default:
            return true;
    }
}

static int immSize_2byte(uint8_t op2, bool /*has66*/) {
    if (op2 >= 0x70 && op2 <= 0x73) return 1;
    if (op2 == 0xC2) return 1;
    if (op2 == 0xC4) return 1;
    if (op2 == 0xC5) return 1;
    if (op2 == 0xC6) return 1;
    if (op2 == 0xBA) return 1;
    if (op2 == 0xA4 || op2 == 0xAC) return 1;
    return 0;
}

static void scanForRipRelative(
    const uint8_t* code, uint32_t codeSize,
    uint32_t sectionRVA, uint64_t imageBase,
    std::vector<RipRelativeRef>& refs)
{
    uint32_t pos = 0;

    while (pos < codeSize) {
        uint32_t instrStart = pos;
        uint32_t instrRVA = sectionRVA + pos;

        bool has66 = false;
        bool has67 = false; (void)has67;
        bool hasF2 = false; (void)hasF2;
        bool hasF3 = false; (void)hasF3;
        uint8_t rex = 0;

        while (pos < codeSize) {
            uint8_t b = code[pos];
            if (b == 0x66) { has66 = true; pos++; }
            else if (b == 0x67) { has67 = true; pos++; }
            else if (b == 0xF2) { hasF2 = true; pos++; }
            else if (b == 0xF3) { hasF3 = true; pos++; }
            else if (b == 0xF0) { pos++; }
            else if (b == 0x2E || b == 0x3E || b == 0x26 || b == 0x36 ||
                     b == 0x64 || b == 0x65) { pos++; }
            else break;
        }

        if (pos >= codeSize) break;

        if (code[pos] >= 0x40 && code[pos] <= 0x4F) {
            rex = code[pos];
            pos++;
        }

        if (pos >= codeSize) break;

        uint8_t op1 = code[pos++];
        bool hasModRM = false;
        int immSz = 0;
        bool is2byte = false;
        bool is3byte38 = false;
        bool is3byte3A = false;
        uint8_t op2 = 0;
        uint8_t op3 = 0; (void)op3;

        // VEX/EVEX -- skip
        if (op1 == 0xC4 || op1 == 0xC5 || op1 == 0x62) {
            pos = instrStart + 1;
            continue;
        }

        if (op1 == 0x0F) {
            if (pos >= codeSize) break;
            op2 = code[pos++];

            if (op2 == 0x38) {
                if (pos >= codeSize) break;
                op3 = code[pos++];
                is3byte38 = true;
                hasModRM = true;
                immSz = 0;
            } else if (op2 == 0x3A) {
                if (pos >= codeSize) break;
                op3 = code[pos++];
                is3byte3A = true;
                hasModRM = true;
                immSz = 1;
            } else {
                is2byte = true;
                hasModRM = opcodeHasModRM_2byte(op2);
                immSz = immSize_2byte(op2, has66);
            }
        } else {
            hasModRM = opcodeHasModRM_1byte(op1);
            immSz = immSize_1byte(op1, has66, (rex & 0x08) != 0);
        }

        if (!hasModRM) {
            pos = instrStart + 1;
            continue;
        }

        if (pos >= codeSize) break;
        uint8_t modrm = code[pos];
        uint8_t mod = modrm >> 6;
        uint8_t reg = (modrm >> 3) & 0x07;
        uint8_t rm = modrm & 0x07;

        (void)rex;
        pos++;

        // SIB byte
        if (mod != 3 && rm == 4) {
            if (pos >= codeSize) break;
            uint8_t sib = code[pos++];
            uint8_t sibBase = sib & 0x07;

            int dispSz = 0;
            if (mod == 0 && sibBase == 5) dispSz = 4;
            else if (mod == 1) dispSz = 1;
            else if (mod == 2) dispSz = 4;

            pos += dispSz;

            if (!is2byte && !is3byte38 && !is3byte3A && (op1 == 0xF6 || op1 == 0xF7)) {
                if (reg == 0 || reg == 1) pos += immSz;
            } else {
                pos += immSz;
            }
            continue;
        }

        // RIP-relative: mod=00, rm=101
        if (mod == 0 && rm == 5) {
            uint32_t dispFileOffset = pos;
            if (pos + 4 > codeSize) break;

            int32_t disp = *(int32_t*)(code + pos);
            pos += 4;

            if (!is2byte && !is3byte38 && !is3byte3A && (op1 == 0xF6 || op1 == 0xF7)) {
                if (reg == 0 || reg == 1) pos += immSz;
            } else {
                pos += immSz;
            }

            uint32_t instrLen = pos - instrStart;
            uint64_t nextInsnVA = imageBase + instrRVA + instrLen;
            uint64_t targetVA = nextInsnVA + (int64_t)disp;
            uint32_t targetRVA = (uint32_t)(targetVA - imageBase);

            bool isCall = (!is2byte && !is3byte38 && !is3byte3A && op1 == 0xFF && reg == 2);
            bool isJmp = (!is2byte && !is3byte38 && !is3byte3A && op1 == 0xFF && reg == 4);
            bool isLea = (!is2byte && !is3byte38 && !is3byte3A && op1 == 0x8D);

            RipRelativeRef ref;
            ref.instrRVA = instrRVA;
            ref.instrLen = instrLen;
            ref.dispOffset = (sectionRVA + dispFileOffset) - instrRVA;
            ref.displacement = disp;
            ref.targetVA = targetVA;
            ref.targetRVA = targetRVA;
            ref.isCall = isCall;
            ref.isJmp = isJmp;
            ref.isLea = isLea;
            refs.push_back(ref);
            continue;
        }

        int dispSz = 0;
        if (mod == 1) dispSz = 1;
        else if (mod == 2) dispSz = 4;

        pos += dispSz;

        if (!is2byte && !is3byte38 && !is3byte3A && (op1 == 0xF6 || op1 == 0xF7)) {
            if (reg == 0 || reg == 1) pos += immSz;
        } else {
            pos += immSz;
        }
    }
}

std::vector<RipRelativeRef> scanRipRelativeRefs(const PEFile& pe, uint64_t imageBase) {
    std::vector<RipRelativeRef> allRefs;

    for (WORD i = 0; i < pe.numSections; i++) {
        if (!(pe.sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE))
            continue;

        uint32_t rawOff = pe.sections[i].PointerToRawData;
        uint32_t rawSz = pe.sections[i].SizeOfRawData;
        uint32_t va = pe.sections[i].VirtualAddress;

        if (rawOff + rawSz > pe.data.size())
            rawSz = (uint32_t)(pe.data.size() - rawOff);

        char name[9] = {};
        memcpy(name, pe.sections[i].Name, 8);
        printf("    Scanning section [%s] (VA=0x%X, size=0x%X)...\n", name, va, rawSz);

        size_t before = allRefs.size();
        scanForRipRelative(pe.data.data() + rawOff, rawSz, va, imageBase, allRefs);
        printf("      Found %zu RIP-relative references\n", allRefs.size() - before);
    }

    return allRefs;
}

std::vector<PointerRef> resolvePointerChains(const PEFile& pe, uint64_t imageBase) {
    std::vector<PointerRef> result;
    uint32_t sizeOfImage = pe.nt->OptionalHeader.SizeOfImage;

    for (WORD i = 0; i < pe.numSections; i++) {
        char name[9] = {};
        memcpy(name, pe.sections[i].Name, 8);

        bool isData = (strcmp(name, ".rdata") == 0 || strcmp(name, ".data") == 0);
        if (!isData) continue;

        uint32_t rawOff = pe.sections[i].PointerToRawData;
        uint32_t rawSz = pe.sections[i].SizeOfRawData;
        uint32_t va = pe.sections[i].VirtualAddress;
        if (rawOff + rawSz > pe.data.size()) rawSz = (uint32_t)(pe.data.size() - rawOff);

        size_t before = result.size();
        for (uint32_t pos = 0; pos + 8 <= rawSz; pos += 8) {
            uint64_t val = *(uint64_t*)(pe.data.data() + rawOff + pos);
            if (val < imageBase || val >= imageBase + sizeOfImage) continue;
            if (val == 0 || val == imageBase) continue;

            uint32_t targetRVA = (uint32_t)(val - imageBase);
            uint32_t ptrRVA = va + pos;
            if (targetRVA == ptrRVA) continue;

            result.push_back({ptrRVA, targetRVA});
        }
        printf("    [%s] %zu pointers\n", name, result.size() - before);
    }

    return result;
}

} // namespace pefix
