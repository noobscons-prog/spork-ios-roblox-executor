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
    if (!g_live_L && L && !g_is_executing) {
        g_live_L = L;
        SporkLog(@"CAPTURED REAL L from luau_load: %p", L);
        
        dispatch_async(dispatch_get_main_queue(), ^{
            SporkLog(@"Executing GUI payload...");
            ExecuteLuauBytecode(g_gui_script, strlen(g_gui_script));
        });
    }
    
    typedef int (*orig_load_t)(void*, const char*, const char*, size_t, int);
    orig_load_t orig = (orig_load_t)trampoline_load;
    return orig(L, chunkname, data, size, env);
}

void install_hook(uintptr_t target_addr, void* hook_func) {
    kern_return_t kr;
    uintptr_t target = target_addr & 0x0000FFFFFFFFFFFF;
    uintptr_t page = target & ~0x3FFF;
    
    SporkLog(@"Hooking 0x%lx, page 0x%lx", target, page);
    
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
    
    // 1. Copy original 24 bytes
    for (int i = 0; i < 24; i++) tramp[i] = ((uint8_t*)target)[i];
    
    // 2. Append jump back to target+24
    uint8_t jump_back[16] = {
        0x3F, 0x43, 0xC1, 0xDA, // xpaci x16 (strip PAC)
        0x50, 0x00, 0x00, 0x58, // ldr x16, #8 (load jump address)
        0x00, 0x02, 0x1F, 0xD6, // br x16
        0, 0, 0, 0
    };
    for (int i = 0; i < 16; i++) tramp[24 + i] = jump_back[i];
    *(uintptr_t*)(tramp + 24 + 8) = target + 24;

    // 3. Prepare patch (Exactly 24 bytes)
    uint8_t patch[24] = {
        0x3F, 0x43, 0xC1, 0xDA, // xpaci x16
        0x50, 0x00, 0x00, 0x58, // ldr x16, #8
        0x00, 0x02, 0x1F, 0xD6, // br x16
        0, 0, 0, 0, 0, 0, 0, 0, // 8-byte target address placeholder
        0x1F, 0x20, 0x03, 0xD5  // nop (Padding to 24 bytes)
    };
    // Write our C function pointer into the payload
    *(uintptr_t*)(patch + 12) = (uintptr_t)hook_func;

    // 4. Apply patch to memory
    for (int i = 0; i < 24; i++) ((uint8_t*)target)[i] = patch[i];
    
    // 5. Flush caches & restore RX protection
    vm_protect(mach_task_self(), page, 0x4000, false, VM_PROT_READ | VM_PROT_EXECUTE);
    sys_icache_invalidate((void*)target, 24);
    sys_icache_invalidate(tramp, 40);
    
    trampoline_load = tramp;
    SporkLog(@"Inline hook installed safely.");
}

void SetupHooks(void) {
    SporkLog(@"SetupHooks starting...");
    uintptr_t base = get_robloxlib_base();
    if (!base) { SporkLog(@"RobloxLib not found."); return; }

    install_hook(base + OFFSET_LUAU_LOAD, (void*)my_luau_load_hook);
}
