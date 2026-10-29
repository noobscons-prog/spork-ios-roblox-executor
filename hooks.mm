#import "hooks.hpp"
#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <string.h>
#import <mach/mach.h>
#import <mach/vm_map.h>
#import <signal.h>
#import <setjmp.h>

#define OFFSET_TASKSCHEDULER      0x6a6d7c0
#define OFFSET_TS_JOBS_START      0xd0
#define OFFSET_TS_JOBS_END        0xd8
#define OFFSET_JOB_SCRIPT_CTX     0x1b0
#define OFFSET_GET_GLOBAL_STATE   0x19ce768
#define OFFSET_MAINTHREAD         0x1a0

#define STRIP_PAC(ptr) ((uintptr_t)(ptr) & 0x0000000FFFFFFFFF)

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

bool safe_read(void* address, void* buffer, size_t size) {
    uintptr_t addr = STRIP_PAC(address);
    if (addr < 0x100000000) return false; 
    vm_size_t out_size;
    kern_return_t kr = vm_read_overwrite(mach_task_self(), (vm_address_t)addr, (vm_size_t)size, (vm_address_t)buffer, &out_size);
    return (kr == KERN_SUCCESS && out_size == size);
}

// Crash handler for get_global_state
static sigjmp_buf hook_jump_buffer;
static volatile sig_atomic_t in_hook_exec = 0;

void hook_signal_handler(int sig) {
    if (in_hook_exec) siglongjmp(hook_jump_buffer, sig);
}

typedef void* (*get_global_state_t)(void* sc, int* identity, void** script);

void SetupHooks(void) {
    signal(SIGSEGV, hook_signal_handler);
    signal(SIGBUS, hook_signal_handler);

    uintptr_t base = get_robloxlib_base();
    if (!base) { SporkLog(@"RobloxLib not found."); return; }

    void* task_scheduler = NULL;
    if (!safe_read((void*)(base + OFFSET_TASKSCHEDULER), &task_scheduler, 8)) { SporkLog(@"TaskScheduler failed."); return; }
    task_scheduler = (void*)STRIP_PAC(task_scheduler);

    uintptr_t start = 0, end = 0;
    safe_read((char*)task_scheduler + OFFSET_TS_JOBS_START, &start, 8);
    safe_read((char*)task_scheduler + OFFSET_TS_JOBS_END, &end, 8);
    start = STRIP_PAC(start); end = STRIP_PAC(end);

    SporkLog(@"Scanning ALL Jobs for Lua VM...");
    
    get_global_state_t get_gs = (get_global_state_t)(base + OFFSET_GET_GLOBAL_STATE);

    for (uintptr_t ptr = start; ptr < end; ptr += 0x10) {
        void* j = NULL;
        if (!safe_read((void*)ptr, &j, 8) || !j) continue;
        uintptr_t stripped_j = STRIP_PAC(j);
        
        void* script_context = NULL;
        if (!safe_read((char*)stripped_j + OFFSET_JOB_SCRIPT_CTX, &script_context, 8) || !script_context) {
            continue; // Job has no ScriptContext, skip it
        }
        
        script_context = (void*)STRIP_PAC(script_context);

        int id = 0; 
        void* script = NULL;
        
        in_hook_exec = 1;
        int sig = sigsetjmp(hook_jump_buffer, 1);
        
        if (sig == 0) {
            void* global_state = get_gs(script_context, &id, &script);
            in_hook_exec = 0;
            
            if (global_state) {
                safe_read((char*)global_state + OFFSET_MAINTHREAD, &g_live_L, 8);
                if (g_live_L) {
                    SporkLog(@"SUCCESS! Found VM via Job at %p | lua_State: %p", j, g_live_L);
                    ExecuteLuauBytecode("print(\"testing\")", 15);
                    return; // Stop scanning, we found it!
                }
            }
        } else {
            in_hook_exec = 0;
            // Crash caught, this script_context wasn't the right one. Continue to next job.
        }
    }

    SporkLog(@"Failed to find a valid Lua VM in any job.");
}
