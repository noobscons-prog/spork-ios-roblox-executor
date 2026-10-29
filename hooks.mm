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

extern void SporkLog(NSString *format, ...);

uintptr_t get_robloxlib_base(void) {
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (name && strstr(name, "RobloxLib")) return (uintptr_t)_dyld_get_image_header(i);
    }
    return 0;
}

// Thread-safe hook function (no syscalls, just memory reads)
int my_lua_gettop(void* L) {
    if (!L) return 0;
    
    // Atomically set g_live_L so multiple threads don't clash
    void* expected = NULL;
    __atomic_compare_exchange_n(&g_live_L, &expected, L, false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
    
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
    
    uint32_t patch[4] = {
        0x58000050, 
        0xD61F0200, 
        (uint32_t)(my_func_addr & 0xFFFFFFFF), 
        (uint32_t)(my_func_addr >> 32)
    };
    
    uintptr_t page = (uintptr_t)target & ~0xFFF;
    
    // 1. Suspend all other threads to prevent race conditions
    thread_act_array_t threads;
    mach_msg_type_number_t thread_count;
    task_threads(mach_task_self(), &threads, &thread_count);
    
    thread_t current_thread = mach_thread_self();
    for (mach_msg_type_number_t i = 0; i < thread_count; i++) {
        if (threads[i] != current_thread) {
            thread_suspend(threads[i]);
        }
    }
    
    // 2. Patch memory
    kern_return_t kr = vm_protect(mach_task_self(), (vm_address_t)page, 0x4000, false, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    
    if (kr == KERN_SUCCESS) {
        memcpy(target, patch, 16);
        sys_icache_invalidate(target, 16); // Flush CPU cache
        vm_protect(mach_task_self(), (vm_address_t)page, 0x4000, false, VM_PROT_READ | VM_PROT_EXECUTE);
        SporkLog(@"Successfully hooked lua_gettop.");
    } else {
        SporkLog(@"vm_protect failed: %d", kr);
    }
    
    // 3. Resume all threads
    for (mach_msg_type_number_t i = 0; i < thread_count; i++) {
        if (threads[i] != current_thread) {
            thread_resume(threads[i]);
        }
        mach_port_deallocate(mach_task_self(), threads[i]);
    }
    vm_deallocate(mach_task_self(), (vm_address_t)threads, sizeof(thread_t) * thread_count);
}
