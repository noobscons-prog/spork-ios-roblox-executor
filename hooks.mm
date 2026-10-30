#import "hooks.hpp"
#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <string.h>
#import <mach/mach.h>
#import <mach/vm_map.h>
#import <libkern/OSCacheControl.h>

#define OFFSET_LUAU_LOAD 0x44bc110

void* g_live_L = NULL;

extern void SporkLog(NSString *format, ...);
extern void ExecuteLuauBytecode(const char* source, size_t size);
extern const char* g_gui_script;

uintptr_t get_robloxlib_base(void) {
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (name && strstr(name, "RobloxLib")) return (uintptr_t)_dyld_get_image_header(i);
    }
    return 0;
}

static uint8_t* trampoline_load = NULL;
static bool g_is_executing = false;

int my_luau_load_hook(void* L, const char* chunkname, const char* data, size_t size, int env) {
    // Capture the real L the moment Roblox loads a script
    if (!g_live_L && L && !g_is_executing) {
        g_live_L = L;
        SporkLog(@"CAPTURED REAL L from luau_load: %p", L);
        
        // Dispatch to background to prevent iOS Watchdog kill (WaitForChild yields)
        dispatch_async(dispatch_get_main_queue(), ^{
            SporkLog(@"Executing GUI payload...");
            ExecuteLuauBytecode(g_gui_script, strlen(g_gui_script));
        });
    }
    
    // Call the original luau_load via our trampoline
    typedef int (*orig_load_t)(void*, const char*, const char*, size_t, int);
    orig_load_t orig = (orig_load_t)trampoline_load;
    return orig(L, chunkname, data, size, env);
}

void install_hook(uintptr_t target, void* hook_func) {
    kern_return_t kr;
    vm_address_t page = target & ~0x3FFF;
    
    kr = vm_protect(mach_task_self(), page, 0x4000, false, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) {
        SporkLog(@"vm_protect RW failed: %d", kr);
        return;
    }

    vm_address_t tramp_mem = 0;
    kr = vm_allocate(mach_task_self(), &tramp_mem, 0x4000, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        SporkLog(@"vm_allocate failed: %d", kr);
        return;
    }
    vm_protect(mach_task_self(), tramp_mem, 0x4000, false, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);

    uint8_t* tramp = (uint8_t*)tramp_mem;
    
    // Manual byte copy (No memcpy, as requested)
    for (int i = 0; i < 16; i++) tramp[i] = ((uint8_t*)target)[i];
    
    // Append absolute jump back to target+16
    tramp[16] = 0x50; tramp[17] = 0x00; tramp[18] = 0x00; tramp[19] = 0x58; // ldr x16, 8
    tramp[20] = 0x00; tramp[21] = 0x02; tramp[22] = 0x1F; tramp[23] = 0xD6; // br x16
    *(uintptr_t*)(tramp + 24) = target + 16;

    // Patch target with absolute jump to our C hook
    uint8_t patch[16];
    patch[0] = 0x50; patch[1] = 0x00; patch[2] = 0x00; patch[3] = 0x58; // ldr x16, 8
    patch[4] = 0x00; patch[5] = 0x02; patch[6] = 0x1F; patch[7] = 0xD6; // br x16
    *(uintptr_t*)(patch + 8) = (uintptr_t)hook_func;

    for (int i = 0; i < 16; i++) ((uint8_t*)target)[i] = patch[i];
    
    vm_protect(mach_task_self(), page, 0x4000, false, VM_PROT_READ | VM_PROT_EXECUTE);
    
    sys_icache_invalidate((void*)target, 16);
    sys_icache_invalidate(tramp, 32);
    
    trampoline_load = tramp;
    SporkLog(@"Inline hook installed on luau_load successfully.");
}

void SetupHooks(void) {
    uintptr_t base = get_robloxlib_base();
    if (!base) { SporkLog(@"RobloxLib not found."); return; }

    SporkLog(@"Installing inline hook on luau_load @ 0x%lx", (unsigned long)(base + OFFSET_LUAU_LOAD));
    install_hook(base + OFFSET_LUAU_LOAD, (void*)my_luau_load_hook);
}
