#pragma once
#include <stdint.h>
#include <setjmp.h>
#include <signal.h>

#ifdef __cplusplus
extern "C" {
#endif

// ⚠️ PUT YOUR ACTUAL OFFSET HERE LATER (I used a dummy 0x0 for now)
#define OFFSET_LUAU_COMPILE 0x0 

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
