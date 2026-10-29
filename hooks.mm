#import "hooks.hpp"
#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <string.h>
#import <mach/mach.h>
#import <mach/vm_map.h>
#import <mach/mach_vm.h> // <-- Added for mach_vm_write
#import <libkern/OSCacheControl.h>

// Explicit declaration just in case the SDK hides it
extern kern_return_t mach_vm_write(vm_map_t target_task, mach_vm_address_t address, vm_offset_t data, mach_msg_type_number_t dataCnt);

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
    uint64_t my_func_addr = (uint64_t)my_lua_gettop & 0x0000000FFFFFFFFF; // Strip PAC
    
    uint32_t patch[4] = {0x58000050, 0xD61F0200, (uint32_t)(my_func_addr & 0xFFFFFFFF), (uint32_t)(my_func_addr >> 32)};
    uintptr_t page = (uintptr_t)target & ~0x3FFF;
    
    SporkLog(@"Patching lua_gettop at %p", target);
    
    in_hook_exec = 1;
    int sig = sigsetjmp(hook_jump_buffer, 1);
    
    if (sig == 0) {
        kern_return_t kr = vm_protect(mach_task_self(), (vm_address_t)page, 0x4000, false, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
        SporkLog(@"vm_protect returned: %d", kr);
        
        if (kr == KERN_SUCCESS) {
            // Use mach_vm_write instead of memcpy to bypass CSE
            kern_return_t wr = mach_vm_write(mach_task_self(), (mach_vm_address_t)target, (vm_offset_t)patch, (mach_msg_type_number_t)16);
            SporkLog(@"mach_vm_write returned: %d", wr);
            
            sys_icache_invalidate(target, 16);
            vm_protect(mach_task_self(), (vm_address_t)page, 0x4000, false, VM_PROT_READ | VM_PROT_EXECUTE);
            in_hook_exec = 0;
            SporkLog(@"Successfully patched lua_gettop.");
        } else {
            in_hook_exec = 0;
            SporkLog(@"vm_protect failed.");
        }
    } else {
        in_hook_exec = 0;
        SporkLog(@"CSE blocked the patch (Signal %d).", sig);
    }
}
