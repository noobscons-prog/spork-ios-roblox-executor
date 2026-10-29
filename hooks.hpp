#pragma once
#include <stdint.h>
#include <setjmp.h>
#include <signal.h>

#ifdef __cplusplus
extern "C" {
#endif

// ⚠️ luau_compile is NOT in your dump. Leave this at 0x0 for now.
// The code will use the pre-compiled bytecode fallback to prevent a crash.
#define OFFSET_LUAU_COMPILE 0x0 

// Exact offsets from your dump (Roblox 2.744.0.1077)
#define OFFSET_LUAU_LOAD 0x44bc110
#define OFFSET_LUA_PCALL 0x4490fec
#define OFFSET_LUA_NEWTHREAD 0x448df3c
#define OFFSET_LUA_SANDBOXTHREAD 0x1a12ad4

typedef char* (*luau_compile_t)(const char* source, size_t source_size, void* options, size_t* bytecode_size);

extern void* g_live_L;
extern sigjmp_buf hook_jump_buffer;
extern volatile sig_atomic_t in_hook_exec;

void SetupHooks(void);
uintptr_t get_robloxlib_base(void);
void ExecuteLuauBytecode(const char* source, size_t size);
void hook_signal_handler(int sig);

#ifdef __cplusplus
}
#endif
