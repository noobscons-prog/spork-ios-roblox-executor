#import "hooks.hpp"
#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <string.h>
#import <mach/mach.h>
#import <mach/vm_map.h>

#define OFFSET_TASKSCHEDULER      0x6a6d7c0
#define OFFSET_TS_JOBS_START      0xd0
#define OFFSET_TS_JOBS_END        0xd8
#define OFFSET_JOB_NAME           0x18
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

void SetupHooks(void) {
    uintptr_t base = get_robloxlib_base();
    if (!base) { SporkLog(@"RobloxLib not found."); return; }

    void* task_scheduler = NULL;
    if (!safe_read((void*)(base + OFFSET_TASKSCHEDULER), &task_scheduler, 8)) { SporkLog(@"TaskScheduler failed."); return; }
    task_scheduler = (void*)STRIP_PAC(task_scheduler);

    uintptr_t start = 0, end = 0;
    safe_read((char*)task_scheduler + OFFSET_TS_JOBS_START, &start, 8);
    safe_read((char*)task_scheduler + OFFSET_TS_JOBS_END, &end, 8);
    start = STRIP_PAC(start); end = STRIP_PAC(end);

    SporkLog(@"Scanning Jobs...");
    void* script_context = NULL;

    // Iterate through all jobs
    for (uintptr_t ptr = start; ptr < end; ptr += 0x10) {
        void* j = NULL;
        if (!safe_read((void*)ptr, &j, 8) || !j) continue;
        uintptr_t stripped_j = STRIP_PAC(j);
        
        char job_name[64] = {0};
        safe_read((char*)stripped_j + OFFSET_JOB_NAME, job_name, 23);

        // Log jobs so you can see what the game is using
        if (strlen(job_name) > 2) {
            SporkLog(@"Job: %s", job_name);
        }

        // Look for WaitingHybridScriptsJob
        if (strcmp(job_name, "WaitingHybridScriptsJob") == 0) {
            SporkLog(@"Found WaitingHybridScriptsJob!");
            if (safe_read((char*)stripped_j + OFFSET_JOB_SCRIPT_CTX, &script_context, 8) && script_context) {
                script_context = (void*)STRIP_PAC(script_context);
                break;
            }
        }
    }

    if (!script_context) {
        SporkLog(@"ScriptContext not found.");
        return;
    }

    SporkLog(@"Found SC: %p. Calling get_global_state...", script_context);

    // Call get_global_state with 3 args
    typedef void* (*get_global_state_t)(void* sc, int* identity, void** script);
    get_global_state_t get_gs = (get_global_state_t)(base + OFFSET_GET_GLOBAL_STATE);
    
    int id = 0; 
    void* script = NULL;
    
    void* global_state = get_gs(script_context, &id, &script);
    
    if (global_state) {
        safe_read((char*)global_state + OFFSET_MAINTHREAD, &g_live_L, 8);
        if (g_live_L) {
            SporkLog(@"SUCCESS! Stole lua_State: %p", g_live_L);
            // Automatically test execution!
            ExecuteLuauBytecode("print(\"testing\")", 15);
        } else {
            SporkLog(@"Failed to read mainthread");
        }
    } else {
        SporkLog(@"get_global_state returned NULL");
    }
}
