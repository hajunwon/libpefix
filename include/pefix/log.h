#pragma once
#include <cstdarg>

namespace pefix::log {

enum Level { OK = 0, FAIL, WARN, INFO, DETAIL, RAW };

// Receives a fully formatted message (no trailing newline for RAW; one for others).
using Sink = void(*)(int level, const char* message);

void set_sink(Sink sink);   // pass nullptr to restore default (plain stdout)

void ok(const char* fmt, ...);
void fail(const char* fmt, ...);
void warn(const char* fmt, ...);
void info(const char* fmt, ...);
void detail(const char* fmt, ...);
void raw(const char* fmt, ...);   // no prefix, no auto-newline — drop-in printf

} // namespace pefix::log
