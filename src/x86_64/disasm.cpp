#include <pefix/x86_64/disasm.h>
#include <cstring>
#include <algorithm>
#include <cstdio>

namespace pefix {

Disasm::Disasm(const PEFile& pe, uint64_t imageBase)
    : pe_(pe), imageBase_(imageBase) {
    sizeOfImage_ = pe_.nt->OptionalHeader.SizeOfImage;
}

uint32_t Disasm::rvaToOffset(uint32_t rva) const {
    return pe_.rvaToOffset(rva);
}

bool Disasm::isInImage(uint64_t va) const {
    return va >= imageBase_ && va < imageBase_ + sizeOfImage_;
}

// Prefix parser

void Disasm::parsePrefixes(DecodeCtx& ctx) {
    ctx.hasREX = false; ctx.rex = 0;
    ctx.has66 = ctx.hasF2 = ctx.hasF3 = ctx.has67 = false;

    while (ctx.pos < ctx.maxLen) {
        uint8_t b = ctx.code[ctx.pos];
        switch (b) {
        case 0x66: ctx.has66 = true; ctx.pos++; continue;
        case 0x67: ctx.has67 = true; ctx.pos++; continue;
        case 0xF2: ctx.hasF2 = true; ctx.pos++; continue;
        case 0xF3: ctx.hasF3 = true; ctx.pos++; continue;
        case 0xF0: case 0x2E: case 0x3E: case 0x26: case 0x36: case 0x64: case 0x65:
            ctx.pos++; continue;
        default:
            if (b >= 0x40 && b <= 0x4F) {
                ctx.hasREX = true;
                ctx.rex = b;
                ctx.pos++;
                continue;
            }
            return;
        }
    }
}

Width Disasm::operandWidth(const DecodeCtx& ctx, bool defaultIs8) {
    if (defaultIs8) return Width::W8;
    if (ctx.rexW()) return Width::W64;
    if (ctx.has66) return Width::W16;
    return Width::W32;
}

// ModRM decoder

Value Disasm::decodeModRM(DecodeCtx& ctx, Width width, Reg& regOp) {
    if (ctx.pos >= ctx.maxLen) return Value::None();
    uint8_t modrm = ctx.code[ctx.pos++];
    uint8_t mod = (modrm >> 6) & 3;
    uint8_t reg = (modrm >> 3) & 7;
    uint8_t rm  = modrm & 7;

    if (ctx.rexR()) reg |= 8;
    if (ctx.rexB()) rm |= 8;
    regOp = gpr(reg);

    if (mod == 3) {
        return Value::Reg(gpr(rm), width);
    }

    Reg base = Reg::NONE;
    Reg index = Reg::NONE;
    uint8_t scale = 0;
    int64_t disp = 0;

    bool hasSIB = ((rm & 7) == 4) && mod != 3;

    if (hasSIB) {
        if (ctx.pos >= ctx.maxLen) return Value::None();
        uint8_t sib = ctx.code[ctx.pos++];
        uint8_t ss = (sib >> 6) & 3;
        uint8_t idx = (sib >> 3) & 7;
        uint8_t bas = sib & 7;
        if (ctx.rexX()) idx |= 8;
        if (ctx.rexB()) bas |= 8;

        scale = 1 << ss;
        if (idx != 4) index = gpr(idx);
        if (mod == 0 && (bas & 7) == 5) {
            if (ctx.pos + 4 > ctx.maxLen) return Value::None();
            disp = *(int32_t*)(ctx.code + ctx.pos);
            ctx.pos += 4;
        } else {
            base = gpr(bas);
        }
    } else if (mod == 0 && (rm & 7) == 5) {
        // RIP-relative
        if (ctx.pos + 4 > ctx.maxLen) return Value::None();
        int32_t rip_disp = *(int32_t*)(ctx.code + ctx.pos);
        ctx.pos += 4;
        base = Reg::RIP;
        disp = rip_disp;
    } else {
        base = gpr(rm);
    }

    if (mod == 1) {
        if (ctx.pos >= ctx.maxLen) return Value::None();
        disp = (int8_t)ctx.code[ctx.pos++];
    } else if (mod == 2) {
        if (ctx.pos + 4 > ctx.maxLen) return Value::None();
        disp = *(int32_t*)(ctx.code + ctx.pos);
        ctx.pos += 4;
    }

    return Value::Mem(base, disp, index, scale, width);
}

// Single instruction decoder

uint32_t Disasm::decodeOne(uint32_t fileOffset, uint64_t va, Instr& out) {
    if (fileOffset >= pe_.data.size()) return 0;
    uint32_t maxLen = (uint32_t)std::min((size_t)15, pe_.data.size() - fileOffset);
    const uint8_t* code = pe_.data.data() + fileOffset;

    DecodeCtx ctx;
    ctx.code = code;
    ctx.maxLen = maxLen;
    ctx.pos = 0;
    ctx.va = va;

    parsePrefixes(ctx);
    if (ctx.pos >= maxLen) return 0;

    out = Instr{};
    out.addr = va;

    uint8_t op1 = code[ctx.pos++];
    Width width;
    Reg regOp;
    Value rm;

    // Two-byte opcode escape
    if (op1 == 0x0F) {
        if (ctx.pos >= maxLen) return 0;
        uint8_t op2 = code[ctx.pos++];

        // JCC near (0F 80-8F)
        if (op2 >= 0x80 && op2 <= 0x8F) {
            if (ctx.pos + 4 > maxLen) return 0;
            int32_t disp = *(int32_t*)(code + ctx.pos);
            ctx.pos += 4;
            out.rawLen = ctx.pos;
            out.op = Op::JCC;
            out.cc = (CC)(op2 & 0x0F);
            out.dst = Value::Label(va + ctx.pos + disp);
            out.flagsRead = FLAG_ALL;
            return ctx.pos;
        }
        // CMOV (0F 40-4F)
        if (op2 >= 0x40 && op2 <= 0x4F) {
            width = operandWidth(ctx);
            rm = decodeModRM(ctx, width, regOp);
            out.rawLen = ctx.pos;
            out.op = Op::CMOV;
            out.cc = (CC)(op2 & 0x0F);
            out.dst = Value::Reg(regOp, width);
            out.src1 = rm;
            out.flagsRead = FLAG_ALL;
            return ctx.pos;
        }
        // SETcc (0F 90-9F)
        if (op2 >= 0x90 && op2 <= 0x9F) {
            rm = decodeModRM(ctx, Width::W8, regOp);
            out.rawLen = ctx.pos;
            out.op = Op::SETcc;
            out.cc = (CC)(op2 & 0x0F);
            out.dst = rm;
            out.flagsRead = FLAG_ALL;
            return ctx.pos;
        }
        // MOVZX (0F B6/B7)
        if (op2 == 0xB6 || op2 == 0xB7) {
            Width srcW = (op2 == 0xB6) ? Width::W8 : Width::W16;
            width = operandWidth(ctx);
            rm = decodeModRM(ctx, srcW, regOp);
            out.rawLen = ctx.pos;
            out.op = Op::MOVZX;
            out.dst = Value::Reg(regOp, width);
            out.src1 = rm;
            return ctx.pos;
        }
        // MOVSX (0F BE/BF)
        if (op2 == 0xBE || op2 == 0xBF) {
            Width srcW = (op2 == 0xBE) ? Width::W8 : Width::W16;
            width = operandWidth(ctx);
            rm = decodeModRM(ctx, srcW, regOp);
            out.rawLen = ctx.pos;
            out.op = Op::MOVSX;
            out.dst = Value::Reg(regOp, width);
            out.src1 = rm;
            return ctx.pos;
        }
        // IMUL reg, rm (0F AF)
        if (op2 == 0xAF) {
            width = operandWidth(ctx);
            rm = decodeModRM(ctx, width, regOp);
            out.rawLen = ctx.pos;
            out.op = Op::IMUL;
            out.dst = Value::Reg(regOp, width);
            out.src1 = Value::Reg(regOp, width);
            out.src2 = rm;
            out.flagsWritten = FLAG_ALL;
            return ctx.pos;
        }
        // BT rm, reg (0F A3)
        if (op2 == 0xA3) {
            width = operandWidth(ctx);
            rm = decodeModRM(ctx, width, regOp);
            out.rawLen = ctx.pos;
            out.op = Op::BT;
            out.src1 = rm;
            out.src2 = Value::Reg(regOp, width);
            out.flagsWritten = FLAG_CF;
            return ctx.pos;
        }
        // BT rm, imm8 (0F BA /4)
        if (op2 == 0xBA) {
            width = operandWidth(ctx);
            rm = decodeModRM(ctx, width, regOp);
            uint8_t ext = (uint16_t)regOp & 7;
            if (ctx.pos >= maxLen) return 0;
            uint8_t imm8 = code[ctx.pos++];
            out.rawLen = ctx.pos;
            if (ext == 4) out.op = Op::BT;
            else if (ext == 5) out.op = Op::BTS;
            else if (ext == 6) out.op = Op::BTR;
            else { out.op = Op::UNDEF; return ctx.pos; }
            out.src1 = rm;
            out.src2 = Value::Imm(imm8, Width::W8);
            out.flagsWritten = FLAG_CF;
            return ctx.pos;
        }
        // BSWAP (0F C8+rd)
        if (op2 >= 0xC8 && op2 <= 0xCF) {
            uint8_t rd = op2 - 0xC8;
            if (ctx.rexB()) rd |= 8;
            width = ctx.rexW() ? Width::W64 : Width::W32;
            out.rawLen = ctx.pos;
            out.op = Op::BSWAP;
            out.dst = Value::Reg(gpr(rd), width);
            return ctx.pos;
        }
        // NOP with ModRM (0F 1F /0)
        if (op2 == 0x1F) {
            rm = decodeModRM(ctx, Width::W32, regOp);
            out.rawLen = ctx.pos;
            out.op = Op::NOP;
            return ctx.pos;
        }

        out.op = Op::UNDEF;
        out.rawLen = ctx.pos;
        return ctx.pos;
    }


    // NOP (90)
    if (op1 == 0x90 && !ctx.hasREX) {
        out.op = Op::NOP;
        out.rawLen = ctx.pos;
        return ctx.pos;
    }

    // INT3 (CC)
    if (op1 == 0xCC) {
        out.op = Op::INT3;
        out.rawLen = ctx.pos;
        return ctx.pos;
    }

    // RET (C3)
    if (op1 == 0xC3) {
        out.op = Op::RET;
        out.rawLen = ctx.pos;
        return ctx.pos;
    }
    // RET imm16 (C2)
    if (op1 == 0xC2) {
        if (ctx.pos + 2 > maxLen) return 0;
        uint16_t imm16 = *(uint16_t*)(code + ctx.pos);
        ctx.pos += 2;
        out.op = Op::RET;
        out.src1 = Value::Imm(imm16, Width::W16);
        out.rawLen = ctx.pos;
        return ctx.pos;
    }

    // PUSH reg (50-57)
    if (op1 >= 0x50 && op1 <= 0x57) {
        uint8_t rd = op1 - 0x50;
        if (ctx.rexB()) rd |= 8;
        out.op = Op::PUSH;
        out.src1 = Value::Reg(gpr(rd), Width::W64);
        out.rawLen = ctx.pos;
        return ctx.pos;
    }
    // POP reg (58-5F)
    if (op1 >= 0x58 && op1 <= 0x5F) {
        uint8_t rd = op1 - 0x58;
        if (ctx.rexB()) rd |= 8;
        out.op = Op::POP;
        out.dst = Value::Reg(gpr(rd), Width::W64);
        out.rawLen = ctx.pos;
        return ctx.pos;
    }

    // PUSH imm32 (68), PUSH imm8 (6A)
    if (op1 == 0x68) {
        if (ctx.pos + 4 > maxLen) return 0;
        int32_t imm = *(int32_t*)(code + ctx.pos); ctx.pos += 4;
        out.op = Op::PUSH;
        out.src1 = Value::Imm(imm, Width::W64);
        out.rawLen = ctx.pos;
        return ctx.pos;
    }
    if (op1 == 0x6A) {
        if (ctx.pos >= maxLen) return 0;
        int8_t imm = (int8_t)code[ctx.pos++];
        out.op = Op::PUSH;
        out.src1 = Value::Imm(imm, Width::W64);
        out.rawLen = ctx.pos;
        return ctx.pos;
    }

    // MOV reg, imm (B8-BF)
    if (op1 >= 0xB8 && op1 <= 0xBF) {
        uint8_t rd = op1 - 0xB8;
        if (ctx.rexB()) rd |= 8;
        width = ctx.rexW() ? Width::W64 : Width::W32;
        int immSz = (width == Width::W64) ? 8 : 4;
        if (ctx.pos + immSz > maxLen) return 0;
        int64_t imm;
        if (immSz == 8) imm = *(int64_t*)(code + ctx.pos);
        else imm = (int64_t)*(int32_t*)(code + ctx.pos);
        ctx.pos += immSz;
        out.op = Op::MOV;
        out.dst = Value::Reg(gpr(rd), width);
        out.src1 = Value::Imm(imm, width);
        out.rawLen = ctx.pos;
        return ctx.pos;
    }
    // MOV r8, imm8 (B0-B7)
    if (op1 >= 0xB0 && op1 <= 0xB7) {
        uint8_t rd = op1 - 0xB0;
        if (ctx.rexB()) rd |= 8;
        if (ctx.pos >= maxLen) return 0;
        uint8_t imm = code[ctx.pos++];
        out.op = Op::MOV;
        out.dst = Value::Reg(gpr(rd), Width::W8);
        out.src1 = Value::Imm(imm, Width::W8);
        out.rawLen = ctx.pos;
        return ctx.pos;
    }

    // JMP rel32 (E9)
    if (op1 == 0xE9) {
        if (ctx.pos + 4 > maxLen) return 0;
        int32_t disp = *(int32_t*)(code + ctx.pos);
        ctx.pos += 4;
        out.op = Op::JMP;
        out.dst = Value::Label(va + ctx.pos + disp);
        out.rawLen = ctx.pos;
        return ctx.pos;
    }
    // JMP rel8 (EB)
    if (op1 == 0xEB) {
        if (ctx.pos >= maxLen) return 0;
        int8_t disp = (int8_t)code[ctx.pos++];
        out.op = Op::JMP;
        out.dst = Value::Label(va + ctx.pos + disp);
        out.rawLen = ctx.pos;
        return ctx.pos;
    }

    // JCC short (70-7F)
    if (op1 >= 0x70 && op1 <= 0x7F) {
        if (ctx.pos >= maxLen) return 0;
        int8_t disp = (int8_t)code[ctx.pos++];
        out.op = Op::JCC;
        out.cc = (CC)(op1 & 0x0F);
        out.dst = Value::Label(va + ctx.pos + disp);
        out.flagsRead = FLAG_ALL;
        out.rawLen = ctx.pos;
        return ctx.pos;
    }

    // CALL rel32 (E8)
    if (op1 == 0xE8) {
        if (ctx.pos + 4 > maxLen) return 0;
        int32_t disp = *(int32_t*)(code + ctx.pos);
        ctx.pos += 4;
        out.op = Op::CALL;
        out.dst = Value::Label(va + ctx.pos + disp);
        out.rawLen = ctx.pos;
        return ctx.pos;
    }

    // LEA (8D)
    if (op1 == 0x8D) {
        width = operandWidth(ctx);
        rm = decodeModRM(ctx, width, regOp);
        out.op = Op::LEA;
        out.dst = Value::Reg(regOp, width);
        out.src1 = rm;
        out.rawLen = ctx.pos;
        return ctx.pos;
    }

    // MOV variants (88-8B)
    if (op1 >= 0x88 && op1 <= 0x8B) {
        bool is8bit = !(op1 & 1);
        bool dir = (op1 & 2);
        width = is8bit ? Width::W8 : operandWidth(ctx);
        rm = decodeModRM(ctx, width, regOp);
        out.op = Op::MOV;
        if (dir) {
            out.dst = Value::Reg(regOp, width);
            out.src1 = rm;
        } else {
            out.dst = rm;
            out.src1 = Value::Reg(regOp, width);
        }
        out.rawLen = ctx.pos;
        return ctx.pos;
    }

    // Arithmetic: ADD/OR/ADC/SBB/AND/SUB/XOR/CMP with r/m
    {
        static const Op arithOps[] = { Op::ADD, Op::OR, Op::UNDEF, Op::UNDEF,
                                          Op::AND, Op::SUB, Op::XOR, Op::CMP };
        uint8_t row = op1 >> 3;
        uint8_t col = op1 & 7;
        if (row < 8 && col <= 3) {
            Op aop = arithOps[row];
            if (aop != Op::UNDEF) {
                bool is8bit = !(col & 1);
                bool dir = (col & 2);
                width = is8bit ? Width::W8 : operandWidth(ctx);
                rm = decodeModRM(ctx, width, regOp);
                out.op = aop;
                out.flagsWritten = FLAG_ALL;
                if (dir) {
                    out.dst = Value::Reg(regOp, width);
                    out.src1 = Value::Reg(regOp, width);
                    out.src2 = rm;
                } else {
                    out.dst = rm;
                    out.src1 = rm;
                    out.src2 = Value::Reg(regOp, width);
                }
                if (aop == Op::CMP) { out.dst = Value::None(); }
                out.rawLen = ctx.pos;
                return ctx.pos;
            }
        }
    }

    // Accumulator-immediate
    {
        static const Op accOps[] = { Op::ADD, Op::OR, Op::UNDEF, Op::UNDEF,
                                        Op::AND, Op::SUB, Op::XOR, Op::CMP };
        uint8_t row = op1 >> 3;
        uint8_t col = op1 & 7;
        if (row < 8 && (col == 4 || col == 5)) {
            Op aop = accOps[row];
            if (aop != Op::UNDEF) {
                bool is8bit = (col == 4);
                width = is8bit ? Width::W8 : operandWidth(ctx);
                int64_t imm;
                if (is8bit) {
                    if (ctx.pos >= maxLen) return 0;
                    imm = (int8_t)code[ctx.pos++];
                } else if (ctx.has66) {
                    if (ctx.pos + 2 > maxLen) return 0;
                    imm = (int16_t)*(int16_t*)(code + ctx.pos); ctx.pos += 2;
                } else {
                    if (ctx.pos + 4 > maxLen) return 0;
                    imm = (int32_t)*(int32_t*)(code + ctx.pos); ctx.pos += 4;
                }
                Reg accReg = Reg::RAX;
                out.op = aop;
                out.flagsWritten = FLAG_ALL;
                out.dst = Value::Reg(accReg, width);
                out.src1 = Value::Reg(accReg, width);
                out.src2 = Value::Imm(imm, width);
                if (aop == Op::CMP) out.dst = Value::None();
                out.rawLen = ctx.pos;
                return ctx.pos;
            }
        }
    }
    // TEST AL/RAX, imm (A8/A9)
    if (op1 == 0xA8 || op1 == 0xA9) {
        bool is8 = (op1 == 0xA8);
        width = is8 ? Width::W8 : operandWidth(ctx);
        int64_t imm;
        if (is8) {
            if (ctx.pos >= maxLen) return 0;
            imm = (int8_t)code[ctx.pos++];
        } else if (ctx.has66) {
            if (ctx.pos + 2 > maxLen) return 0;
            imm = (int16_t)*(int16_t*)(code + ctx.pos); ctx.pos += 2;
        } else {
            if (ctx.pos + 4 > maxLen) return 0;
            imm = (int32_t)*(int32_t*)(code + ctx.pos); ctx.pos += 4;
        }
        out.op = Op::TEST;
        out.src1 = Value::Reg(Reg::RAX, width);
        out.src2 = Value::Imm(imm, width);
        out.flagsWritten = FLAG_ALL;
        out.rawLen = ctx.pos;
        return ctx.pos;
    }

    // Group 1: 80-83 (ADD/OR/ADC/SBB/AND/SUB/XOR/CMP rm, imm)
    if (op1 >= 0x80 && op1 <= 0x83) {
        static const Op g1ops[] = { Op::ADD, Op::OR, Op::UNDEF, Op::UNDEF,
                                       Op::AND, Op::SUB, Op::XOR, Op::CMP };
        bool is8bit = (op1 == 0x80 || op1 == 0x82);
        bool isImm8 = (op1 == 0x83 || op1 == 0x80 || op1 == 0x82);
        width = is8bit ? Width::W8 : operandWidth(ctx);
        rm = decodeModRM(ctx, width, regOp);
        uint8_t ext = (uint16_t)regOp & 7;
        Op gop = g1ops[ext];
        int64_t imm;
        if (isImm8) {
            if (ctx.pos >= maxLen) return 0;
            imm = (int8_t)code[ctx.pos++];
        } else {
            if (ctx.has66) {
                if (ctx.pos + 2 > maxLen) return 0;
                imm = (int16_t)*(int16_t*)(code + ctx.pos); ctx.pos += 2;
            } else {
                if (ctx.pos + 4 > maxLen) return 0;
                imm = (int32_t)*(int32_t*)(code + ctx.pos); ctx.pos += 4;
            }
        }
        out.op = (gop != Op::UNDEF) ? gop : Op::UNDEF;
        out.flagsWritten = FLAG_ALL;
        out.src1 = rm;
        out.src2 = Value::Imm(imm, width);
        if (gop == Op::CMP) out.dst = Value::None();
        else out.dst = rm;
        out.rawLen = ctx.pos;
        return ctx.pos;
    }

    // TEST rm, reg (84/85)
    if (op1 == 0x84 || op1 == 0x85) {
        width = (op1 == 0x84) ? Width::W8 : operandWidth(ctx);
        rm = decodeModRM(ctx, width, regOp);
        out.op = Op::TEST;
        out.src1 = rm;
        out.src2 = Value::Reg(regOp, width);
        out.flagsWritten = FLAG_ALL;
        out.rawLen = ctx.pos;
        return ctx.pos;
    }

    // XCHG (86/87)
    if (op1 == 0x86 || op1 == 0x87) {
        width = (op1 == 0x86) ? Width::W8 : operandWidth(ctx);
        rm = decodeModRM(ctx, width, regOp);
        out.op = Op::XCHG;
        out.dst = Value::Reg(regOp, width);
        out.src1 = rm;
        out.rawLen = ctx.pos;
        return ctx.pos;
    }

    // IMUL reg, rm, imm32 (69) / imm8 (6B)
    if (op1 == 0x69 || op1 == 0x6B) {
        width = operandWidth(ctx);
        rm = decodeModRM(ctx, width, regOp);
        int64_t imm;
        if (op1 == 0x6B) {
            if (ctx.pos >= maxLen) return 0;
            imm = (int8_t)code[ctx.pos++];
        } else {
            if (ctx.has66) {
                if (ctx.pos + 2 > maxLen) return 0;
                imm = (int16_t)*(int16_t*)(code + ctx.pos); ctx.pos += 2;
            } else {
                if (ctx.pos + 4 > maxLen) return 0;
                imm = (int32_t)*(int32_t*)(code + ctx.pos); ctx.pos += 4;
            }
        }
        out.op = Op::IMUL;
        out.dst = Value::Reg(regOp, width);
        out.src1 = rm;
        out.src2 = Value::Imm(imm, width);
        out.flagsWritten = FLAG_ALL;
        out.rawLen = ctx.pos;
        return ctx.pos;
    }

    // MOVSXD (63)
    if (op1 == 0x63) {
        width = operandWidth(ctx);
        rm = decodeModRM(ctx, Width::W32, regOp);
        out.op = Op::MOVSX;
        out.dst = Value::Reg(regOp, width);
        out.src1 = rm;
        out.rawLen = ctx.pos;
        return ctx.pos;
    }

    // Group 3: F6/F7 (TEST/NOT/NEG/MUL/IMUL/DIV/IDIV)
    if (op1 == 0xF6 || op1 == 0xF7) {
        width = (op1 == 0xF6) ? Width::W8 : operandWidth(ctx);
        rm = decodeModRM(ctx, width, regOp);
        uint8_t ext = (uint16_t)regOp & 7;
        switch (ext) {
        case 0: {
            int64_t imm;
            if (width == Width::W8) {
                if (ctx.pos >= maxLen) return 0;
                imm = (int8_t)code[ctx.pos++];
            } else if (ctx.has66) {
                if (ctx.pos + 2 > maxLen) return 0;
                imm = (int16_t)*(int16_t*)(code + ctx.pos); ctx.pos += 2;
            } else {
                if (ctx.pos + 4 > maxLen) return 0;
                imm = (int32_t)*(int32_t*)(code + ctx.pos); ctx.pos += 4;
            }
            out.op = Op::TEST;
            out.src1 = rm;
            out.src2 = Value::Imm(imm, width);
            out.flagsWritten = FLAG_ALL;
            break;
        }
        case 2: out.op = Op::NOT; out.dst = rm; out.src1 = rm; break;
        case 3: out.op = Op::NEG; out.dst = rm; out.src1 = rm; out.flagsWritten = FLAG_ALL; break;
        case 4: out.op = Op::MUL; out.src1 = rm; out.flagsWritten = FLAG_ALL; break;
        case 5: out.op = Op::IMUL; out.src1 = rm; out.flagsWritten = FLAG_ALL; break;
        case 6: out.op = Op::DIV; out.src1 = rm; out.flagsWritten = FLAG_ALL; break;
        case 7: out.op = Op::IDIV; out.src1 = rm; out.flagsWritten = FLAG_ALL; break;
        default: out.op = Op::UNDEF; break;
        }
        out.rawLen = ctx.pos;
        return ctx.pos;
    }

    // Group 5: FF (INC/DEC/CALL/JMP/PUSH rm)
    if (op1 == 0xFF) {
        width = operandWidth(ctx);
        rm = decodeModRM(ctx, width, regOp);
        uint8_t ext = (uint16_t)regOp & 7;
        switch (ext) {
        case 0: out.op = Op::INC; out.dst = rm; out.src1 = rm; out.flagsWritten = FLAG_ALL & ~FLAG_CF; break;
        case 1: out.op = Op::DEC; out.dst = rm; out.src1 = rm; out.flagsWritten = FLAG_ALL & ~FLAG_CF; break;
        case 2: out.op = Op::CALL; out.dst = rm; break;
        case 4: out.op = Op::JMP; out.dst = rm; break;
        case 6: out.op = Op::PUSH; out.src1 = rm; break;
        default: out.op = Op::UNDEF; break;
        }
        out.rawLen = ctx.pos;
        return ctx.pos;
    }

    // Shift group: C0/C1 (rm, imm8), D0/D1 (rm, 1), D2/D3 (rm, CL)
    if (op1 == 0xC0 || op1 == 0xC1 || op1 == 0xD0 || op1 == 0xD1 || op1 == 0xD2 || op1 == 0xD3) {
        static const Op shiftOps[] = { Op::ROL, Op::ROR, Op::UNDEF, Op::UNDEF,
                                          Op::SHL, Op::SHR, Op::UNDEF, Op::SAR };
        bool is8bit = !(op1 & 1);
        width = is8bit ? Width::W8 : operandWidth(ctx);
        rm = decodeModRM(ctx, width, regOp);
        uint8_t ext = (uint16_t)regOp & 7;
        out.op = shiftOps[ext];
        out.dst = rm;
        out.src1 = rm;
        if (op1 == 0xC0 || op1 == 0xC1) {
            if (ctx.pos >= maxLen) return 0;
            out.src2 = Value::Imm(code[ctx.pos++], Width::W8);
        } else if (op1 == 0xD0 || op1 == 0xD1) {
            out.src2 = Value::Imm(1, Width::W8);
        } else {
            out.src2 = Value::Reg(Reg::RCX, Width::W8);
        }
        out.flagsWritten = FLAG_ALL;
        out.rawLen = ctx.pos;
        return ctx.pos;
    }

    // POP rm (8F /0)
    if (op1 == 0x8F) {
        rm = decodeModRM(ctx, Width::W64, regOp);
        uint8_t ext = (uint16_t)regOp & 7;
        if (ext == 0) {
            if (rm.isMem()) {
                out.op = Op::POP;
                out.dst = rm;
            } else {
                out.op = Op::POP;
                out.dst = rm;
            }
        } else {
            out.op = Op::UNDEF;
        }
        out.rawLen = ctx.pos;
        return ctx.pos;
    }

    // MOV rm, imm (C6/C7)
    if (op1 == 0xC6 || op1 == 0xC7) {
        bool is8 = (op1 == 0xC6);
        width = is8 ? Width::W8 : operandWidth(ctx);
        rm = decodeModRM(ctx, width, regOp);
        int64_t imm;
        if (is8) {
            if (ctx.pos >= maxLen) return 0;
            imm = (int8_t)code[ctx.pos++];
        } else if (ctx.has66) {
            if (ctx.pos + 2 > maxLen) return 0;
            imm = (int16_t)*(int16_t*)(code + ctx.pos); ctx.pos += 2;
        } else {
            if (ctx.pos + 4 > maxLen) return 0;
            imm = (int32_t)*(int32_t*)(code + ctx.pos); ctx.pos += 4;
        }
        out.op = Op::MOV;
        out.dst = rm;
        out.src1 = Value::Imm(imm, width);
        out.rawLen = ctx.pos;
        return ctx.pos;
    }

    // CDQ (99) / CQO (48 99)
    if (op1 == 0x99) {
        out.op = ctx.rexW() ? Op::CQO : Op::CDQ;
        out.rawLen = ctx.pos;
        return ctx.pos;
    }

    // LEAVE (C9)
    if (op1 == 0xC9) {
        out.op = Op::LEAVE;
        out.rawLen = ctx.pos;
        return ctx.pos;
    }

    out.op = Op::UNDEF;
    out.rawLen = 1;
    return 1;
}

// CFG Builder

bool Disasm::buildCFG(uint32_t entryRVA, Func& func) {
    func = Func{};
    func.entryAddr = imageBase_ + entryRVA;

    std::set<uint32_t> visited;
    std::vector<uint32_t> worklist;
    worklist.push_back(entryRVA);

    while (!worklist.empty() && func.blocks.size() < 256) {
        uint32_t rva = worklist.back();
        worklist.pop_back();
        if (visited.count(rva)) continue;
        visited.insert(rva);

        uint32_t off = rvaToOffset(rva);
        if (!off) continue;

        Block block;
        block.startAddr = imageBase_ + rva;
        uint32_t curRVA = rva;

        while (func.blocks.size() < 256) {
            uint32_t curOff = rvaToOffset(curRVA);
            if (!curOff) break;

            Instr instr;
            uint64_t curVA = imageBase_ + curRVA;
            uint32_t len = decodeOne(curOff, curVA, instr);
            if (len == 0) break;

            // Resolve RIP-relative to absolute
            if (instr.src1.isMem() && instr.src1.reg == Reg::RIP) {
                instr.src1.reg = Reg::NONE;
                instr.src1.imm = (int64_t)curVA + len + instr.src1.imm;
            }
            if (instr.dst.isMem() && instr.dst.reg == Reg::RIP) {
                instr.dst.reg = Reg::NONE;
                instr.dst.imm = (int64_t)curVA + len + instr.dst.imm;
            }

            block.instrs.push_back(instr);
            curRVA += len;

            if (instr.op == Op::JMP) {
                if (instr.dst.kind == Value::LABEL) {
                    uint64_t targetVA = instr.dst.imm;
                    if (isInImage(targetVA)) {
                        uint32_t targetRVA = (uint32_t)(targetVA - imageBase_);
                        worklist.push_back(targetRVA);
                    }
                }
                break;
            }
            if (instr.op == Op::JCC) {
                if (instr.dst.kind == Value::LABEL) {
                    uint64_t takenVA = instr.dst.imm;
                    if (isInImage(takenVA)) {
                        uint32_t takenRVA = (uint32_t)(takenVA - imageBase_);
                        worklist.push_back(takenRVA);
                    }
                }
                worklist.push_back(curRVA);
                break;
            }
            if (instr.op == Op::RET || instr.op == Op::INT3 || instr.op == Op::UD2) break;
            if (instr.op == Op::CALL && instr.dst.kind == Value::LABEL)
                func.callTargets.push_back(instr.dst.imm);

            if (block.instrs.size() > 5000) break;
        }

        block.endAddr = imageBase_ + curRVA;
        uint32_t blockIdx = (uint32_t)func.blocks.size();
        func.addrToBlock[block.startAddr] = blockIdx;
        func.blocks.push_back(std::move(block));
    }

    // Wire up edges
    for (uint32_t i = 0; i < func.blocks.size(); i++) {
        auto& blk = func.blocks[i];
        if (blk.instrs.empty()) continue;
        auto& last = blk.instrs.back();
        if (last.op == Op::JMP && last.dst.kind == Value::LABEL) {
            auto it = func.addrToBlock.find(last.dst.imm);
            if (it != func.addrToBlock.end()) blk.succs.push_back(it->second);
        }
        if (last.op == Op::JCC) {
            if (last.dst.kind == Value::LABEL) {
                auto it = func.addrToBlock.find(last.dst.imm);
                if (it != func.addrToBlock.end()) blk.succs.push_back(it->second);
            }
            auto itF = func.addrToBlock.find(blk.endAddr);
            if (itF != func.addrToBlock.end()) blk.succs.push_back(itF->second);
        }
    }

    if (func.blocks.empty()) return false;

    // Compute predecessors
    for (uint32_t i = 0; i < func.blocks.size(); i++) {
        for (uint32_t s : func.blocks[i].succs) {
            if (s < func.blocks.size())
                func.blocks[s].preds.push_back(i);
        }
    }

    // Detect frame size from first SUB RSP, imm
    for (auto& instr : func.blocks[0].instrs) {
        if (instr.op == Op::SUB && instr.dst.isReg() &&
            instr.dst.reg == Reg::RSP && instr.src2.isImm()) {
            func.frameSize = (int32_t)instr.src2.imm;
            break;
        }
    }

    return true;
}

} // namespace pefix
