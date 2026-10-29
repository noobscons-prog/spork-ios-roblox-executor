#pragma once
#include <stdint.h>
#include <setjmp.h>
#include <signal.h>

#ifdef __cplusplus
extern "C" {
#endif

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
