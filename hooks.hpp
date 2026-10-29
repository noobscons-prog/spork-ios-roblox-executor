#pragma once
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

extern void* g_live_L;
void SetupHooks(void);
uintptr_t get_robloxlib_base(void);
void ExecuteLuauBytecode(const char* source, size_t size);

#ifdef __cplusplus
}
#endif
