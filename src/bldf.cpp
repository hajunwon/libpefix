#include <pefix/bldf.h>
#include <pefix/log.h>
#include <algorithm>
#include <chrono>
#include <cstring>
#include <unordered_map>

namespace pefix {

namespace {

// ----- length tables shared with xrefs.cpp (kept local to avoid cross-TU
// coupling on a private helper). Any new opcode added here must stay in sync. -----

bool opcodeHasModRM_1byte(uint8_t op) {
    uint8_t col = op & 0x07;
    if (op <= 0x3F) return col <= 3;
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

int immSize_1byte(uint8_t op, bool has66, bool /*rexW*/) {
    switch (op) {
    case 0x69: return has66 ? 2 : 4;
    case 0x6B: return 1;
    case 0x80: case 0x82: case 0x83: return 1;
    case 0x81: return has66 ? 2 : 4;
    case 0xC0: case 0xC1: return 1;
    case 0xC6: return 1;
    case 0xC7: return has66 ? 2 : 4;
    case 0xF6: return 1;
    case 0xF7: return has66 ? 2 : 4;
    default: return 0;
    }
}

bool opcodeHasModRM_2byte(uint8_t op2) {
    switch (op2) {
    case 0x05: case 0x06: case 0x07: case 0x08: case 0x09: case 0x0B:
    case 0x30: case 0x31: case 0x32: case 0x33: case 0x34: case 0x35:
    case 0x36: case 0x37:
    case 0x77:
    case 0x80: case 0x81: case 0x82: case 0x83: case 0x84: case 0x85: case 0x86: case 0x87:
    case 0x88: case 0x89: case 0x8A: case 0x8B: case 0x8C: case 0x8D: case 0x8E: case 0x8F:
    case 0xA0: case 0xA1: case 0xA8: case 0xA9:
    case 0xC8: case 0xC9: case 0xCA: case 0xCB:
    case 0xCC: case 0xCD: case 0xCE: case 0xCF:
        return false;
    default:
        return true;
    }
}

int immSize_2byte(uint8_t op2, bool /*has66*/) {
    if (op2 >= 0x70 && op2 <= 0x73) return 1;
    if (op2 == 0xBA || op2 == 0xA4 || op2 == 0xAC) return 1;
    if (op2 == 0xC2 || op2 == 0xC4 || op2 == 0xC5 || op2 == 0xC6) return 1;
    return 0;
}

int noModRMOperandSize_1byte(uint8_t op, bool has66, bool rexW) {
    if (op == 0x04 || op == 0x0C || op == 0x14 || op == 0x1C ||
        op == 0x24 || op == 0x2C || op == 0x34 || op == 0x3C) return 1;
    if (op == 0x05 || op == 0x0D || op == 0x15 || op == 0x1D ||
        op == 0x25 || op == 0x2D || op == 0x35 || op == 0x3D) return has66 ? 2 : 4;
    if (op == 0x68) return has66 ? 2 : 4;
    if (op == 0x6A) return 1;
    if (op >= 0x70 && op <= 0x7F) return 1;
    if (op >= 0xA0 && op <= 0xA3) return 8;
    if (op == 0xA8) return 1;
    if (op == 0xA9) return has66 ? 2 : 4;
    if (op >= 0xB0 && op <= 0xB7) return 1;
    if (op >= 0xB8 && op <= 0xBF) return rexW ? 8 : (has66 ? 2 : 4);
    if (op == 0xC2 || op == 0xCA) return 2;
    if (op == 0xC8) return 3;
    if (op == 0xCD) return 1;
    if (op >= 0xE0 && op <= 0xE3) return 1;
    if (op >= 0xE4 && op <= 0xE7) return 1;
    if (op == 0xE8 || op == 0xE9) return 4;
    if (op == 0xEB) return 1;
    return 0;
}

int noModRMOperandSize_2byte(uint8_t op2, bool /*has66*/) {
    if (op2 >= 0x80 && op2 <= 0x8F) return 4;
    return 0;
}

bool isPrintable(uint8_t b) {
    return (b >= 0x20 && b <= 0x7E) || b == 0x09 || b == 0x0A || b == 0x0D;
}

// Decode one instruction. Returns length consumed, or 0 if decode fails.
// When the instruction is `mov [r/m], imm8/16/32` (Group 11 /0 with mod != 3),
// fills *outStore* and sets *outIsStore* to true.
uint32_t decodeInstr(const uint8_t* code, uint32_t avail, uint32_t instrRVA,
                      bool allowQwordMov, bool& outIsStore, ByteStore& outStore) {
    outIsStore = false;
    if (avail == 0) return 0;
    uint32_t pos = 0;

    bool has66 = false;
    uint8_t rex = 0;

    while (pos < avail) {
        uint8_t b = code[pos];
        if (b == 0x66) { has66 = true; pos++; continue; }
        if (b == 0x67 || b == 0xF2 || b == 0xF3 || b == 0xF0) { pos++; continue; }
        if (b == 0x2E || b == 0x3E || b == 0x26 || b == 0x36 ||
            b == 0x64 || b == 0x65) { pos++; continue; }
        break;
    }
    if (pos >= avail) return 0;

    if (code[pos] >= 0x40 && code[pos] <= 0x4F) {
        rex = code[pos];
        pos++;
    }
    if (pos >= avail) return 0;

    uint8_t op1 = code[pos++];
    if (op1 == 0xC4 || op1 == 0xC5 || op1 == 0x62) return 0;  // VEX/EVEX  - give up

    bool is2byte = false, is3byte38 = false, is3byte3A = false;
    uint8_t op2 = 0;
    bool hasModRM;
    int immSz;

    if (op1 == 0x0F) {
        if (pos >= avail) return 0;
        op2 = code[pos++];
        if (op2 == 0x38) {
            if (pos >= avail) return 0;
            (void)code[pos++];
            is3byte38 = true; hasModRM = true; immSz = 0;
        } else if (op2 == 0x3A) {
            if (pos >= avail) return 0;
            (void)code[pos++];
            is3byte3A = true; hasModRM = true; immSz = 1;
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
        int operandLen = is2byte
            ? noModRMOperandSize_2byte(op2, has66)
            : (is3byte38 || is3byte3A) ? 0
            : noModRMOperandSize_1byte(op1, has66, (rex & 0x08) != 0);
        if (operandLen == 0) return 0;
        if (pos + operandLen > avail) return 0;
        return pos + operandLen;
    }

    if (pos >= avail) return 0;
    uint8_t modrm = code[pos++];
    uint8_t mod = modrm >> 6;
    uint8_t reg = (modrm >> 3) & 0x7;
    uint8_t rm = modrm & 0x7;

    // Group 11 /0 mov immediate at this point requires reg=0; remember and decode.
    bool isMovImm = !is2byte && !is3byte38 && !is3byte3A && (op1 == 0xC6 || op1 == 0xC7);
    bool isStoreCandidate = isMovImm && reg == 0 && mod != 3;

    uint8_t baseReg = 0xFF;
    int32_t disp = 0;

    if (mod != 3 && rm == 4) {
        if (pos >= avail) return 0;
        uint8_t sib = code[pos++];
        uint8_t index = (sib >> 3) & 0x7;
        uint8_t base = sib & 0x7;
        int dispSz = 0;
        if (mod == 0 && base == 5) dispSz = 4;
        else if (mod == 1) dispSz = 1;
        else if (mod == 2) dispSz = 4;
        if (pos + dispSz > avail) return 0;
        if (isStoreCandidate) {
            // Skip stores that use an index*scale form  - the spec only models
            // pure base+disp buffer builds.
            if (index != 4 || (mod == 0 && base == 5)) {
                isStoreCandidate = false;
            } else {
                baseReg = base | ((rex & 0x01) ? 8 : 0);
                if (dispSz == 1) disp = (int8_t)code[pos];
                else if (dispSz == 4) memcpy(&disp, code + pos, 4);
            }
        }
        pos += dispSz;
        // Group 11 special case: F6/F7 reg=0/1 take imm  - others don't. C6/C7 always do.
        if (op1 == 0xF6 || op1 == 0xF7) {
            if (reg == 0 || reg == 1) {
                if (pos + immSz > avail) return 0;
                pos += immSz;
            }
        } else {
            if (pos + immSz > avail) return 0;
            if (isStoreCandidate) {
                uint64_t v = 0;
                if (immSz == 1) v = code[pos];
                else if (immSz == 2) { uint16_t t; memcpy(&t, code + pos, 2); v = t; }
                else if (immSz == 4) {
                    if ((rex & 0x08) && op1 == 0xC7) {
                        int32_t t; memcpy(&t, code + pos, 4); v = (uint64_t)(int64_t)t;
                    } else {
                        uint32_t t; memcpy(&t, code + pos, 4); v = t;
                    }
                }
                uint8_t opSize;
                if (op1 == 0xC6) opSize = 1;
                else if (has66) opSize = 2;
                else if (rex & 0x08) opSize = 8;
                else opSize = 4;
                if (opSize != 8 || allowQwordMov) {
                    outStore.instrRVA = instrRVA;
                    outStore.baseReg = baseReg;
                    outStore.baseOffset = disp;
                    outStore.value = v;
                    outStore.size = opSize;
                    outIsStore = true;
                }
            }
            pos += immSz;
        }
        return pos;
    }

    // RIP-relative form  - not a store we care about, but still need length.
    if (mod == 0 && rm == 5) {
        if (pos + 4 > avail) return 0;
        pos += 4;
        if (op1 == 0xF6 || op1 == 0xF7) {
            if (reg == 0 || reg == 1) {
                if (pos + immSz > avail) return 0;
                pos += immSz;
            }
        } else {
            if (pos + immSz > avail) return 0;
            pos += immSz;
        }
        return pos;
    }

    int dispSz = 0;
    if (mod == 1) dispSz = 1;
    else if (mod == 2) dispSz = 4;
    if (pos + dispSz > avail) return 0;
    if (isStoreCandidate) {
        baseReg = rm | ((rex & 0x01) ? 8 : 0);
        if (dispSz == 1)      disp = (int8_t)code[pos];
        else if (dispSz == 4) memcpy(&disp, code + pos, 4);
    }
    pos += dispSz;

    if (op1 == 0xF6 || op1 == 0xF7) {
        if (reg == 0 || reg == 1) {
            if (pos + immSz > avail) return 0;
            pos += immSz;
        }
    } else {
        if (pos + immSz > avail) return 0;
        if (isStoreCandidate) {
            uint64_t v = 0;
            if (immSz == 1) v = code[pos];
            else if (immSz == 2) { uint16_t t; memcpy(&t, code + pos, 2); v = t; }
            else if (immSz == 4) {
                if ((rex & 0x08) && op1 == 0xC7) {
                    int32_t t; memcpy(&t, code + pos, 4); v = (uint64_t)(int64_t)t;
                } else {
                    uint32_t t; memcpy(&t, code + pos, 4); v = t;
                }
            }
            uint8_t opSize;
            if (op1 == 0xC6) opSize = 1;
            else if (has66) opSize = 2;
            else if (rex & 0x08) opSize = 8;
            else opSize = 4;
            if (opSize != 8 || allowQwordMov) {
                outStore.instrRVA = instrRVA;
                outStore.baseReg = baseReg;
                outStore.baseOffset = disp;
                outStore.value = v;
                outStore.size = opSize;
                outIsStore = true;
            }
        }
        pos += immSz;
    }
    return pos;
}

} // namespace

BldfResult extractByteConcatStrings(const PEFile& pe,
                                     const std::vector<FunctionBoundary>& funcs,
                                     const BldfConfig& cfg) {
    auto t0 = std::chrono::high_resolution_clock::now();
    BldfResult result;
    BldfStats& st = result.stats;
    if (!pe.nt) return result;

    struct Group {
        uint8_t baseReg;
        int32_t minOff;
        int32_t maxOff;
        std::vector<ByteStore> stores;
    };

    for (const FunctionBoundary& fb : funcs) {
        if (fb.endRVA <= fb.startRVA) continue;
        uint32_t fileOff = pe.rvaToOffset(fb.startRVA);
        if (!fileOff || fileOff >= pe.data.size()) continue;
        uint32_t bytes = fb.endRVA - fb.startRVA;
        if (fileOff + bytes > pe.data.size())
            bytes = (uint32_t)pe.data.size() - fileOff;
        ++st.funcsScanned;

        std::vector<ByteStore> stores;
        const uint8_t* base = pe.data.data() + fileOff;
        uint32_t pos = 0;
        while (pos < bytes) {
            bool isStore = false;
            ByteStore bs;
            uint32_t len = decodeInstr(base + pos, bytes - pos, fb.startRVA + pos,
                                        cfg.allowQwordMov, isStore, bs);
            if (len == 0) { pos += 1; continue; }
            if (isStore) stores.push_back(bs);
            pos += len;
        }
        st.storesFound += (uint32_t)stores.size();

        std::vector<Group> groups;
        for (auto& bs : stores) {
            int32_t end = bs.baseOffset + bs.size;
            bool placed = false;
            if (!groups.empty()) {
                Group& g = groups.back();
                if (g.baseReg == bs.baseReg) {
                    int32_t gap = bs.baseOffset - g.maxOff;
                    bool adjacent = gap >= 0 && gap <= (int32_t)cfg.maxGap;
                    bool overlap = cfg.allowOverwrite &&
                                    bs.baseOffset >= g.minOff &&
                                    bs.baseOffset < g.maxOff;
                    if (adjacent || overlap) {
                        g.stores.push_back(bs);
                        if (bs.baseOffset < g.minOff) g.minOff = bs.baseOffset;
                        if (end > g.maxOff) g.maxOff = end;
                        placed = true;
                    }
                }
            }
            if (!placed) {
                Group g;
                g.baseReg = bs.baseReg;
                g.minOff = bs.baseOffset;
                g.maxOff = end;
                g.stores.push_back(bs);
                groups.push_back(std::move(g));
            }
        }
        st.groupsBuilt += (uint32_t)groups.size();

        for (auto& g : groups) {
            if (g.maxOff <= g.minOff) continue;
            uint32_t bufLen = (uint32_t)(g.maxOff - g.minOff);
            if (bufLen < cfg.minLength) continue;
            if (bufLen > cfg.maxBufferBytes) continue;

            std::vector<uint8_t> buf(bufLen, 0);
            for (auto& s : g.stores) {
                for (uint8_t i = 0; i < s.size; ++i) {
                    int32_t idx = s.baseOffset + (int32_t)i - g.minOff;
                    if (idx < 0 || idx >= (int32_t)bufLen) continue;
                    buf[(uint32_t)idx] = (uint8_t)((s.value >> (i * 8)) & 0xFFu);
                }
            }

            uint32_t effective = bufLen;
            while (effective > 0 && buf[effective - 1] == 0) --effective;
            if (effective < cfg.minLength) continue;

            bool ok = true;
            for (uint32_t i = 0; i < effective; ++i) {
                if (!isPrintable(buf[i])) { ok = false; break; }
            }
            if (!ok) continue;

            ConcatString cs;
            cs.funcRVA = fb.startRVA;
            cs.firstStoreRVA = g.stores.front().instrRVA;
            cs.lastStoreRVA = g.stores.back().instrRVA;
            cs.bufferBaseReg = g.baseReg;
            cs.bufferBaseOff = g.minOff;
            cs.onStack = (g.baseReg == 4 /*RSP*/ || g.baseReg == 5 /*RBP*/);
            cs.rawBytes = std::move(buf);
            cs.content.assign((const char*)cs.rawBytes.data(), effective);
            result.strings.push_back(std::move(cs));
            ++st.stringsReconstructed;
        }
    }

    auto t1 = std::chrono::high_resolution_clock::now();
    st.durationMs = (uint32_t)std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();

    log::ok("BLDF: scanned %u funcs, %u stores, %u groups, %u strings, %ums",
            st.funcsScanned, st.storesFound, st.groupsBuilt,
            st.stringsReconstructed, st.durationMs);

    return result;
}

std::vector<ConcatStringRdataLink>
matchConcatStringsToRdata(const PEFile& pe, const BldfResult& res) {
    std::vector<ConcatStringRdataLink> links;
    if (!pe.nt || res.strings.empty()) return links;

    uint32_t rdStart = 0, rdEnd = 0, rdRaw = 0;
    for (WORD i = 0; i < pe.numSections; ++i) {
        char name[9] = {};
        memcpy(name, pe.sections[i].Name, 8);
        if (strcmp(name, ".rdata") == 0) {
            rdStart = pe.sections[i].VirtualAddress;
            rdEnd = rdStart + pe.sections[i].Misc.VirtualSize;
            rdRaw = pe.sections[i].PointerToRawData;
            break;
        }
    }
    if (!rdStart) return links;

    uint32_t rdSize = rdEnd - rdStart;
    if (rdRaw + rdSize > pe.data.size()) rdSize = (uint32_t)pe.data.size() - rdRaw;
    const uint8_t* rd = pe.data.data() + rdRaw;

    std::unordered_map<uint32_t, std::vector<uint32_t>> firstQuad;
    bool atStart = true;
    for (uint32_t i = 0; i < rdSize; ++i) {
        if (atStart && isPrintable(rd[i])) {
            if (i + 4 <= rdSize) {
                uint32_t key;
                memcpy(&key, rd + i, 4);
                firstQuad[key].push_back(i);
            }
            atStart = false;
        }
        if (rd[i] == 0) atStart = true;
    }

    for (auto& cs : res.strings) {
        if (cs.content.size() < 4) continue;
        uint32_t key;
        memcpy(&key, cs.content.data(), 4);
        auto it = firstQuad.find(key);
        if (it == firstQuad.end()) continue;
        for (uint32_t off : it->second) {
            uint32_t end = off;
            while (end < rdSize && rd[end] != 0) ++end;
            uint32_t rdLen = end - off;
            if (rdLen == cs.content.size() &&
                memcmp(rd + off, cs.content.data(), rdLen) == 0) {
                links.push_back({&cs, rdStart + off});
            }
        }
    }
    return links;
}

} // namespace pefix
