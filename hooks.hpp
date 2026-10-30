#pragma once
#include <stdint.h>
#include <stddef.h>
#include <setjmp.h>
#include <signal.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OFFSET_LUAU_COMPILE 0x0
#define OFFSET_LUAU_LOAD 0x44bc110
#define OFFSET_LUA_PCALL 0x4490fec
#define OFFSET_LUA_NEWTHREAD 0x448df3c
#define OFFSET_LUA_SANDBOXTHREAD 0x1a12ad4

typedef char* (*luau_compile_t)(const char* source, size_t source_size, void* options, size_t* bytecode_size);
typedef int (*luau_load_t)(void* L, const char* chunkname, const char* data, size_t size, int env);
typedef int (*lua_pcall_t)(void* L, int nargs, int nresults, int errfunc);
typedef void* (*lua_newthread_t)(void* L);
typedef void (*luaL_sandboxthread_t)(void* L);

extern void* g_live_L;
extern void* g_script_context;
extern sigjmp_buf hook_jump_buffer;
extern volatile sig_atomic_t in_hook_exec;

void SetupHooks(void);
uintptr_t get_robloxlib_base(void);
void ExecuteLuauBytecode(const char* source, size_t size);
void hook_signal_handler(int sig);
bool safe_read(void* address, void* buffer, size_t size);

#ifdef __cplusplus
}
#endif

// Inline helpers usable from any TU
static inline uintptr_t spork_strip_pac(uintptr_t p) {
    return p & 0x0000FFFFFFFFFFFFULL;
}
static inline bool spork_is_valid_ptr(uintptr_t p) {
    return p > 0x100000000ULL && p < 0x0000FFFFFFFFFFFFULL;
}
