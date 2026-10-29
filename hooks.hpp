#pragma once
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

extern void* g_live_L;
void SetupHooks(void);
uintptr_t get_robloxlib_base(void); // Added this line

#ifdef __cplusplus
}
#endif
