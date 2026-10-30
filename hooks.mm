#import "hooks.hpp"
#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <string.h>
#import <mach/mach.h>
#import <mach/vm_map.h>
#import <libkern/OSCacheControl.h>

#define OFFSET_LUA_PCALL 0x4490fec

void* g_live_L = NULL;
sigjmp_buf hook_jump_buffer;
volatile sig_atomic_t in_hook_exec = 0;

extern void SporkLog(NSString *format, ...);
extern void ExecuteLuauBytecode(const char* source, size_t size);
extern const char* g_gui_script; // From Tweak.xm

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

bool safe_read(void* address, void* buffer, size_t size) {
    uintptr_t addr = spork_strip_pac((uintptr_t)address);
    if (addr < 0x100000000) return false;
    vm_size_t out_size;
    kern_return_t kr = vm_read_overwrite(mach_task_self(),
                                         (vm_address_t)addr,
                                         (vm_size_t)size,
                                         (vm_address_t)buffer,
                                         &out_size);
    return (kr == KERN_SUCCESS && out_size == size);
}

static uint8_t* trampoline_pcall = NULL;

// This function runs EVERY time Roblox calls lua_pcall (which is constantly)
int my_lua_pcall_hook(void* L, int nargs, int nresults, int errfunc) {
    // Capture the real L on the very first call
    if (!g_live_L && L) {
        g_live_L = L;
        SporkLog(@"CAPTURED REAL L from lua_pcall: %p", L);
        
        // Trigger GUI injection on the main thread
        dispatch_async(dispatch_get_main_queue(), ^{
            SporkLog(@"Executing GUI payload...");
            ExecuteLuauBytecode(g_gui_script, strlen(g_gui_script));
        });
    }
    
    // Call the original lua_pcall via our trampoline
    typedef int (*orig_pcall_t)(void*, int, int, int);
    orig_pcall_t orig = (orig_pcall_t)trampoline_pcall;
    return orig(L, nargs, nresults, errfunc);
}

void install_hook(uintptr_t target, void* hook_func) {
    kern_return_t kr;
    vm_address_t page = target & ~0x3FFF;
    
    // Make the code page writable
    kr = vm_protect(mach_task_self(), page, 0x4000, false, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) {
        SporkLog(@"vm_protect RW failed: %d", kr);
        return;
    }

    // Allocate executable memory for our trampoline
    vm_address_t tramp_mem = 0;
    kr = vm_allocate(mach_task_self(), &tramp_mem, 0x4000, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) return;
    vm_protect(mach_task_self(), tramp_mem, 0x4000, false, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);

    uint8_t* tramp = (uint8_t*)tramp_mem;
    
    // Manual byte copy of original 16 bytes (4 instructions)
    for (int i = 0; i < 16; i++) {
        tramp[i] = ((uint8_t*)target)[i];
    }
    
    // Append absolute jump back to target+16
    tramp[16] = 0x50; tramp[17] = 0x00; tramp[18] = 0x00; tramp[19] = 0x58; // ldr x16, 8
    tramp[20] = 0x00; tramp[21] = 0x02; tramp[22] = 0x1F; tramp[23] = 0xD6; // br x16
    *(uintptr_t*)(tramp + 24) = target + 16;

    // Patch target with absolute jump to our C hook
    uint8_t patch[16];
    patch[0] = 0x50; patch[1] = 0x00; patch[2] = 0x00; patch[3] = 0x58; // ldr x16, 8
    patch[4] = 0x00; patch[5] = 0x02; patch[6] = 0x1F; patch[7] = 0xD6; // br x16
    *(uintptr_t*)(patch + 8) = (uintptr_t)hook_func;

    for (int i = 0; i < 16; i++) {
        ((uint8_t*)target)[i] = patch[i];
    }
    
    // Restore read-execute protection
    vm_protect(mach_task_self(), page, 0x4000, false, VM_PROT_READ | VM_PROT_EXECUTE);
    
    // Flush instruction cache
    sys_icache_invalidate((void*)target, 16);
    sys_icache_invalidate(tramp, 32);
    
    trampoline_pcall = tramp;
    SporkLog(@"Inline hook installed successfully.");
}

void SetupHooks(void) {
    signal(SIGSEGV, hook_signal_handler);
    signal(SIGBUS,  hook_signal_handler);

    uintptr_t base = get_robloxlib_base();
    if (!base) { SporkLog(@"RobloxLib not found."); return; }

    SporkLog(@"Installing inline hook on lua_pcall @ 0x%lx", (unsigned long)(base + OFFSET_LUA_PCALL));
    install_hook(base + OFFSET_LUA_PCALL, (void*)my_lua_pcall_hook);
}
