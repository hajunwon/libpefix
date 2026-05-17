#include <pefix/pefix.h>
#include <pefix/log.h>
#include "cli.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>

static void cli_sink(int level, const char* msg) {
    char buf[8192];
    size_t n = strlen(msg);
    if (n >= sizeof(buf)) n = sizeof(buf) - 1;
    memcpy(buf, msg, n);
    buf[n] = 0;
    while (n && buf[n - 1] == '\n') buf[--n] = 0;
    switch (level) {
        case pefix::log::OK:     cli::ok("%s", buf);     break;
        case pefix::log::FAIL:   cli::fail("%s", buf);   break;
        case pefix::log::WARN:   cli::warn("%s", buf);   break;
        case pefix::log::INFO:   cli::info("%s", buf);   break;
        case pefix::log::DETAIL: cli::detail("%s", buf); break;
        default:                 fputs(buf, stdout); fputc('\n', stdout); break;
    }
}

static void printUsage(const char* exe) {
    printf("pefix -- PE analysis toolkit for dumped/obfuscated x86-64 binaries\n\n");
    printf("Usage: %s <input.exe> [options]\n\n", exe);
    printf("Options:\n");
    printf("  -o <output.exe>     Output path (default: <input>_fixed.exe)\n");
    printf("  -b <hex>            Set ImageBase (auto-detected from PE header if omitted)\n");
    printf("  --all               Apply all safe fixups (recover + patch-eb-ff + xrefs)\n");
    printf("  --xrefs             Scan RIP-relative references\n");
    printf("  --exports <file>    Add synthetic exports from file (name=RVA per line)\n");
    printf("  --coff <file>       Embed COFF symbols from file (name=RVA per line)\n");
    printf("  --recover           Recover hidden sections (gaps in section layout)\n");
    printf("  --patch-eb-ff       Patch EB FF anti-disassembly patterns with NOPs\n");
    printf("  --trace <rva>       Static trace from RVA (hex), print calls\n");
    printf("  --cfg <rva>         Build CFG from RVA (hex), print block summary\n");
    printf("  --dry-run           Analyze only, do not write output\n");
    printf("  --verbose           Detailed output\n");
    printf("\nWith no options, --all is applied by default.\n\n");
}

static std::vector<pefix::NamedAddress> loadNameFile(const char* path, uint64_t imageBase) {
    std::vector<pefix::NamedAddress> entries;
    FILE* f = nullptr;
    fopen_s(&f, path, "r");
    if (!f) {
        printf("[!] Cannot open: %s\n", path);
        return entries;
    }
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        // Format: name=RVA (hex, no 0x prefix required)
        char* eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        char* name = line;
        char* rvaStr = eq + 1;
        // Trim whitespace
        while (*name == ' ' || *name == '\t') name++;
        while (*rvaStr == ' ' || *rvaStr == '\t') rvaStr++;
        char* end = rvaStr + strlen(rvaStr) - 1;
        while (end > rvaStr && (*end == '\n' || *end == '\r' || *end == ' ')) *end-- = '\0';

        uint32_t rva = (uint32_t)strtoull(rvaStr, nullptr, 16);
        if (rva == 0 || strlen(name) == 0) continue;
        entries.push_back({imageBase + rva, std::string(name)});
    }
    fclose(f);
    return entries;
}

static std::vector<pefix::CoffSymEntry> loadCoffFile(const char* path, const pefix::PEFile& pe) {
    std::vector<pefix::CoffSymEntry> syms;
    FILE* f = nullptr;
    fopen_s(&f, path, "r");
    if (!f) {
        printf("[!] Cannot open: %s\n", path);
        return syms;
    }
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        char* eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        char* name = line;
        char* rvaStr = eq + 1;
        while (*name == ' ' || *name == '\t') name++;
        while (*rvaStr == ' ' || *rvaStr == '\t') rvaStr++;
        char* end = rvaStr + strlen(rvaStr) - 1;
        while (end > rvaStr && (*end == '\n' || *end == '\r' || *end == ' ')) *end-- = '\0';

        uint32_t rva = (uint32_t)strtoull(rvaStr, nullptr, 16);
        if (rva == 0 || strlen(name) == 0) continue;

        int secIdx = pe.findSection(rva);
        if (secIdx < 0) continue;

        pefix::CoffSymEntry e;
        e.rva = rva;
        e.sectionIndex = (uint16_t)(secIdx + 1);
        e.name = name;
        e.isFunction = true;
        syms.push_back(e);
    }
    fclose(f);
    return syms;
}

static int patchEbFf(pefix::PEFile& pe) {
    int patched = 0;
    for (WORD i = 0; i < pe.numSections; i++) {
        if (!(pe.sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE))
            continue;
        uint32_t rawOff = pe.sections[i].PointerToRawData;
        uint32_t rawSz = pe.sections[i].SizeOfRawData;
        if (rawOff + rawSz > pe.data.size())
            rawSz = (uint32_t)(pe.data.size() - rawOff);

        uint8_t* code = pe.data.data() + rawOff;
        for (uint32_t j = 0; j + 1 < rawSz; j++) {
            if (code[j] == 0xEB && code[j + 1] == 0xFF) {
                // Replace with two NOPs
                code[j] = 0x90;
                code[j + 1] = 0x90;
                patched++;
            }
        }
    }
    return patched;
}

int main(int argc, char* argv[]) {
    pefix::log::set_sink(cli_sink);
    if (argc < 2) {
        printUsage(argv[0]);
        return 1;
    }

    const char* inputPath = argv[1];
    const char* outputPath = nullptr;
    uint64_t imageBase = 0;
    bool doAll = false;
    bool doXrefs = false;
    const char* exportsFile = nullptr;
    const char* coffFile = nullptr;
    bool doRecover = false;
    bool doPatchEbFf = false;
    bool dryRun = false;
    uint32_t traceRVA = 0;
    bool doTrace = false;
    uint32_t cfgRVA = 0;
    bool doCfg = false;
    bool hasOptions = false;

    for (int i = 2; i < argc; i++) {
        hasOptions = true;
        if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            outputPath = argv[++i];
        } else if (strcmp(argv[i], "-b") == 0 && i + 1 < argc) {
            imageBase = strtoull(argv[++i], nullptr, 16);
        } else if (strcmp(argv[i], "--all") == 0) {
            doAll = true;
        } else if (strcmp(argv[i], "--xrefs") == 0) {
            doXrefs = true;
        } else if (strcmp(argv[i], "--exports") == 0 && i + 1 < argc) {
            exportsFile = argv[++i];
        } else if (strcmp(argv[i], "--coff") == 0 && i + 1 < argc) {
            coffFile = argv[++i];
        } else if (strcmp(argv[i], "--recover") == 0) {
            doRecover = true;
        } else if (strcmp(argv[i], "--patch-eb-ff") == 0) {
            doPatchEbFf = true;
        } else if (strcmp(argv[i], "--dry-run") == 0) {
            dryRun = true;
        } else if (strcmp(argv[i], "--trace") == 0 && i + 1 < argc) {
            traceRVA = (uint32_t)strtoull(argv[++i], nullptr, 16);
            doTrace = true;
        } else if (strcmp(argv[i], "--cfg") == 0 && i + 1 < argc) {
            cfgRVA = (uint32_t)strtoull(argv[++i], nullptr, 16);
            doCfg = true;
        } else if (strcmp(argv[i], "--verbose") == 0) {
            // reserved
        } else {
            printf("[!] Unknown option: %s\n", argv[i]);
            printUsage(argv[0]);
            return 1;
        }
    }

    // No options specified → apply --all by default
    if (!hasOptions) doAll = true;
    if (doAll) {
        doRecover = true;
        doPatchEbFf = true;
        doXrefs = true;
    }

    // Auto-generate output path if not specified
    std::string autoOutput;
    if (!outputPath && !dryRun) {
        autoOutput = inputPath;
        auto dot = autoOutput.rfind('.');
        if (dot != std::string::npos)
            autoOutput = autoOutput.substr(0, dot) + "_fixed" + autoOutput.substr(dot);
        else
            autoOutput += "_fixed.exe";
        outputPath = autoOutput.c_str();
    }

    pefix::PEFile pe;
    cli::info("Loading: %s", inputPath);
    if (!pe.load(inputPath)) {
        cli::fail("Failed to load PE file.");
        return 1;
    }
    cli::ok("PE loaded: %zu bytes, %u sections", pe.data.size(), pe.numSections);

    if (imageBase == 0)
        imageBase = pe.nt->OptionalHeader.ImageBase;
    else
        pe.nt->OptionalHeader.ImageBase = imageBase;
    cli::info("ImageBase: 0x%llX", (unsigned long long)imageBase);

    bool modified = false;

    if (doRecover) {
        int n = pefix::recoverHiddenSections(pe);
        if (n > 0) { cli::ok("Recovered %d hidden sections", n); modified = true; }
    }

    if (doPatchEbFf) {
        int n = patchEbFf(pe);
        if (n > 0) { cli::ok("Patched %d EB FF anti-disasm", n); modified = true; }
    }

    if (doXrefs) {
        auto refs = pefix::scanRipRelativeRefs(pe, imageBase);
        cli::ok("RIP-relative references: %zu", refs.size());

        uint32_t calls = 0, jmps = 0, leas = 0, loads = 0;
        for (auto& r : refs) {
            if (r.isCall) calls++;
            else if (r.isJmp) jmps++;
            else if (r.isLea) leas++;
            else loads++;
        }
        cli::detail("Calls=%u  Jmps=%u  LEAs=%u  Loads=%u", calls, jmps, leas, loads);

        auto rttiClasses = pefix::parseRTTI(pe, imageBase);
        if (!rttiClasses.empty())
            cli::ok("RTTI: %zu classes with vtables", rttiClasses.size());

        auto inferred = pefix::inferFunctionNames(pe, imageBase, refs);
        if (!inferred.empty())
            cli::ok("Inferred %zu function names", inferred.size());
    }

    if (exportsFile) {
        auto entries = loadNameFile(exportsFile, imageBase);
        if (!entries.empty()) {
            pefix::addSyntheticExports(pe, imageBase, entries);
            cli::ok("Added %zu synthetic exports", entries.size());
            modified = true;
        }
    }

    if (coffFile) {
        auto syms = loadCoffFile(coffFile, pe);
        if (!syms.empty()) {
            pefix::embedCoffSymbols(pe, imageBase, syms);
            cli::ok("Embedded %zu COFF symbols", syms.size());
            modified = true;
        }
    }

    if (doTrace) {
        cli::info("Static trace from RVA 0x%X", traceRVA);
        pefix::Tracer tracer(pe, imageBase);
        auto tr = tracer.trace(traceRVA);
        cli::ok("Trace: %llu steps, %zu calls",
               (unsigned long long)tr.stepsExecuted, tr.calls.size());
        cli::detail("Stop: %s", tr.stopReason.c_str());
        for (auto& c : tr.calls) {
            cli::detail("CALL 0x%llX from 0x%llX  [0x%llX, 0x%llX, 0x%llX, 0x%llX]",
                   (unsigned long long)c.targetVA, (unsigned long long)c.callerVA,
                   (unsigned long long)c.args[0], (unsigned long long)c.args[1],
                   (unsigned long long)c.args[2], (unsigned long long)c.args[3]);
        }
    }

    if (doCfg) {
        cli::info("Building CFG from RVA 0x%X", cfgRVA);
        pefix::Disasm disasm(pe, imageBase);
        pefix::Func func;
        if (disasm.buildCFG(cfgRVA, func)) {
            cli::ok("CFG: %zu blocks, %u instructions, frame=%d",
                   func.blocks.size(), func.totalInstrs(), func.frameSize);
            for (size_t i = 0; i < func.blocks.size(); i++) {
                auto& b = func.blocks[i];
                cli::detail("Block %zu: 0x%llX - 0x%llX (%zu instrs)",
                       i, (unsigned long long)b.startAddr, (unsigned long long)b.endAddr,
                       b.instrs.size());
            }
        } else {
            cli::fail("CFG build failed");
        }
    }

    if (modified) {
        if (!outputPath) {
            static char defaultOut[512];
            const char* dot = strrchr(inputPath, '.');
            if (dot) {
                size_t baseLen = dot - inputPath;
                memcpy(defaultOut, inputPath, baseLen);
                sprintf_s(defaultOut + baseLen, sizeof(defaultOut) - baseLen, "_fixed%s", dot);
            } else {
                sprintf_s(defaultOut, "%s_fixed", inputPath);
            }
            outputPath = defaultOut;
        }
        if (pe.save(outputPath)) {
            cli::ok("Saved: %s (%zu bytes)", outputPath, pe.data.size());
        } else {
            cli::fail("Failed to save: %s", outputPath);
            return 1;
        }
    }

    return 0;
}
