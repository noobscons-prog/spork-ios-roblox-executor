#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <string.h>
#import <mach/mach.h>
#import <mach/vm_map.h>
#import <libkern/OSCacheControl.h>

// Exact Offsets from your dump
#define OFFSET_LUA_GETTOP         0x448e048
#define OFFSET_LUA_STATE_TOP      0x70
#define OFFSET_LUA_STATE_BASE     0x58

void* g_live_L = NULL;

extern void SporkLog(NSString *format, ...);

uintptr_t get_robloxlib_base(void) {
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (name && strstr(name, "RobloxLib")) return (uintptr_t)_dyld_get_image_header(i);
    }
    return 0;
}

// FAST hook: No syscalls, purely direct memory reads
int my_lua_gettop(void* L) {
    if (!g_live_L && L) {
        g_live_L = L;
        SporkLog(@"STOLE lua_State via lua_gettop: %p", L);
    }
    // Direct memory access using dumped offsets
    uintptr_t top = *(uintptr_t*)((uintptr_t)L + OFFSET_LUA_STATE_TOP);
    uintptr_t base = *(uintptr_t*)((uintptr_t)L + OFFSET_LUA_STATE_BASE);
    return (int)((top - base) / 16);
}

void SetupHooks(void) {
    uintptr_t base = get_robloxlib_base();
    if (!base) {
        SporkLog(@"Hooks: RobloxLib base not found.");
        return;
    }
    
    void* target = (void*)(base + OFFSET_LUA_GETTOP);
    uint64_t my_func_addr = (uint64_t)my_lua_gettop;
    
    // ARM64 patch: ldr x16, #8 ; br x16 ; <address>
    uint32_t patch[4] = {
        0x58000050, 
        0xD61F0200, 
        (uint32_t)(my_func_addr & 0xFFFFFFFF), 
        (uint32_t)(my_func_addr >> 32)
    };
    
    uintptr_t page = (uintptr_t)target & ~0xFFF;
    
    // VM_PROT_COPY is required on iOS 15+ to bypass Code Signing Enforcement (CSE)
    kern_return_t kr = vm_protect(mach_task_self(), (vm_address_t)page, 0x4000, false, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    
    if (kr == KERN_SUCCESS) {
        // Write the patch
        memcpy(target, patch, 16);
        
        // CRITICAL: Flush the CPU instruction cache so the CPU doesn't execute the old cached instructions
        sys_icache_invalidate(target, 16);
        
        // Restore execution-only protection
        vm_protect(mach_task_self(), (vm_address_t)page, 0x4000, false, VM_PROT_READ | VM_PROT_EXECUTE);
        
        SporkLog(@"Successfully hooked lua_gettop (CSE Bypassed).");
    } else {
        SporkLog(@"vm_protect failed: %d", kr);
    }
}
