#import "hooks.hpp"
#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <string.h>
#import <mach/mach.h>
#import <mach/vm_map.h>
#import <libkern/OSCacheControl.h>

void* g_live_L = NULL;
sigjmp_buf hook_jump_buffer;
volatile sig_atomic_t in_hook_exec = 0;

extern void SporkLog(NSString *format, ...);
extern void ExecuteLuauBytecode(const char* source, size_t size);
extern const char* g_gui_script;

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

void SetupHooks(void) {
    signal(SIGSEGV, hook_signal_handler);
    signal(SIGBUS,  hook_signal_handler);

    uintptr_t base = get_robloxlib_base();
    if (!base) { SporkLog(@"RobloxLib not found."); return; }

    SporkLog(@"Using direct offsets from dump...");

    // Method 1: get_global_state -> mainthread (Instant and 100% accurate)
    typedef void* (*get_gs_t)();
    get_gs_t get_gs = (get_gs_t)(base + 0x19ce768);
    void* gs = get_gs();
    
    if (gs) {
        uintptr_t L = 0;
        // global_State::mainthread is at 0x1A0
        if (safe_read((void*)((uintptr_t)gs + 0x1A0), &L, 8)) {
            L = spork_strip_pac(L);
            if (spork_is_valid_ptr(L)) {
                g_live_L = (void*)L;
                SporkLog(@"Found L via get_global_state(): %p", L);
            }
        }
    }

    // Method 2: get_scriptcontext -> scan for L (Fallback)
    if (!g_live_L) {
        typedef void* (*get_sc_t)();
        get_sc_t get_sc = (get_sc_t)(base + 0x19cc48c);
        void* sc = get_sc();
        
        if (sc) {
            SporkLog(@"Found ScriptContext via get_scriptcontext(): %p", sc);
            // Scan SC for a valid lua_State using exact dumped offsets (0x78 -> 0x1A0)
            for (size_t i = 0; i < 0x8000; i += 8) {
                uintptr_t cand = 0;
                if (!safe_read((char*)sc + i, &cand, 8)) continue;
                cand = spork_strip_pac(cand);
                if (!spork_is_valid_ptr(cand)) continue;

                uintptr_t cand_gs = 0;
                if (safe_read((void*)(cand + 0x78), &cand_gs, 8)) {
                    cand_gs = spork_strip_pac(cand_gs);
                    if (spork_is_valid_ptr(cand_gs)) {
                        uintptr_t mt = 0;
                        if (safe_read((void*)(cand_gs + 0x1A0), &mt, 8) && spork_strip_pac(mt) == cand) {
                            g_live_L = (void*)cand;
                            SporkLog(@"Found canonical L via get_scriptcontext: %p", cand);
                            break;
                        }
                    }
                }
            }
        }
    }

    if (g_live_L) {
        SporkLog(@"SUCCESS: g_live_L is set! Auto-injecting GUI in 3 seconds...");
        
        // Wait 3 seconds so the game finishes loading before we inject, preventing a race condition.
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            ExecuteLuauBytecode(g_gui_script, strlen(g_gui_script));
        });
    } else {
        SporkLog(@"ERROR: Could not find lua_State.");
    }
}
