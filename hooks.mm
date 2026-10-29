#import "hooks.hpp"
#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <string.h>
#import <mach/mach.h>
#import <mach/vm_map.h>
#import <libkern/OSCacheControl.h>

#define OFFSET_LUA_GETTOP         0x448e048
#define OFFSET_LUA_STATE_TOP      0x70
#define OFFSET_LUA_STATE_BASE     0x58

void* g_live_L = NULL;
sigjmp_buf hook_jump_buffer;
volatile sig_atomic_t in_hook_exec = 0;

extern void SporkLog(NSString *format, ...);

void hook_signal_handler(int sig) {
    if (in_hook_exec) siglongjmp(hook_jump_buffer, sig);
}

uintptr_t get_robloxlib_base(void) {
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (name && strstr(name, "RobloxLib")) return (uintptr_t)_dyld_get_image_header(i);
    }
    return 0;
}

// NO LOGGING HERE. MUST BE EXTREMELY FAST.
int my_lua_gettop(void* L) {
    if (!g_live_L && L) {
        g_live_L = L;
    }
    uintptr_t top = *(uintptr_t*)((uintptr_t)L + OFFSET_LUA_STATE_TOP);
    uintptr_t base = *(uintptr_t*)((uintptr_t)L + OFFSET_LUA_STATE_BASE);
    return (int)((top - base) / 16);
}

void SetupHooks(void) {
    signal(SIGSEGV, hook_signal_handler);
    signal(SIGBUS, hook_signal_handler);

    uintptr_t base = get_robloxlib_base();
    if (!base) { SporkLog(@"RobloxLib not found."); return; }

    void* target = (void*)(base + OFFSET_LUA_GETTOP);
    uint64_t my_func_addr = (uint64_t)my_lua_gettop;
    
    uint32_t patch[4] = {0x58000050, 0xD61F0200, (uint32_t)(my_func_addr & 0xFFFFFFFF), (uint32_t)(my_func_addr >> 32)};
    
    // iOS 16+ uses 16KB pages (~0x3FFF)
    uintptr_t page = (uintptr_t)target & ~0x3FFF;
    
    SporkLog(@"Attempting to patch lua_gettop...");
    
    // Catch the CSE crash during memcpy!
    in_hook_exec = 1;
    int sig = sigsetjmp(hook_jump_buffer, 1);
    
    if (sig == 0) {
        kern_return_t kr = vm_protect(mach_task_self(), (vm_address_t)page, 0x4000, false, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
        
        if (kr == KERN_SUCCESS) {
            memcpy(target, patch, 16);
            sys_icache_invalidate(target, 16); // Flush cache
            vm_protect(mach_task_self(), (vm_address_t)page, 0x4000, false, VM_PROT_READ | VM_PROT_EXECUTE);
            in_hook_exec = 0;
            SporkLog(@"Successfully patched lua_gettop.");
        } else {
            in_hook_exec = 0;
            SporkLog(@"vm_protect failed: %d", kr);
        }
    } else {
        in_hook_exec = 0;
        SporkLog(@"CSE blocked the patch (Signal %d).", sig);
    }
}
