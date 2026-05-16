#pragma once
#include <pefix/x86_64/ir.h>
#include <pefix/pe.h>
#include <cstdint>
#include <set>

namespace pefix {

class Disasm {
public:
    Disasm(const PEFile& pe, uint64_t imageBase);

    // Decode a single instruction at the given file offset.
    // Returns instruction length (0 on failure).
    uint32_t decodeOne(uint32_t fileOffset, uint64_t va, Instr& out);

    // Build CFG starting from an entry RVA.
    bool buildCFG(uint32_t entryRVA, Func& func);

private:
    const PEFile& pe_;
    uint64_t imageBase_;
    uint32_t sizeOfImage_;

    uint32_t rvaToOffset(uint32_t rva) const;
    bool isInImage(uint64_t va) const;

    struct DecodeCtx {
        const uint8_t* code;
        uint32_t maxLen;
        uint32_t pos;
        uint64_t va;
        bool hasREX;
        uint8_t rex;
        bool has66;
        bool hasF2;
        bool hasF3;
        bool has67;
        bool rexW() const { return hasREX && (rex & 0x08); }
        bool rexR() const { return hasREX && (rex & 0x04); }
        bool rexX() const { return hasREX && (rex & 0x02); }
        bool rexB() const { return hasREX && (rex & 0x01); }
    };

    void parsePrefixes(DecodeCtx& ctx);
    Value decodeModRM(DecodeCtx& ctx, Width width, Reg& regOp);
    Width operandWidth(const DecodeCtx& ctx, bool defaultIs8 = false);
};

} // namespace pefix
