#import "hooks.hpp"
#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <string.h>
#import <mach/mach.h>
#import <mach/vm_map.h>
#import <libkern/OSCacheControl.h>

#define OFFSET_TASKSCHEDULER      0x6a6d7c0
#define OFFSET_TS_JOBS_START      0xd0
#define OFFSET_TS_JOBS_END        0xd8
#define OFFSET_JOB_NAME           0x18
#define OFFSET_JOB_SCRIPT_CTX     0x1b0

#define STRIP_PAC(ptr) ((uintptr_t)(ptr) & 0x0000000FFFFFFFFF)

void* g_live_L = NULL;
sigjmp_buf hook_jump_buffer;
volatile sig_atomic_t in_hook_exec = 0;

extern void SporkLog(NSString *format, ...);
extern void ExecuteLuauBytecode(const char* source, size_t size);

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
    uintptr_t addr = STRIP_PAC(address);
    if (addr < 0x100000000) return false; 
    vm_size_t out_size;
    kern_return_t kr = vm_read_overwrite(mach_task_self(), (vm_address_t)addr, (vm_size_t)size, (vm_address_t)buffer, &out_size);
    return (kr == KERN_SUCCESS && out_size == size);
}

// Simple replacement for Job::step
typedef void (*job_step_t)(void* job);
static job_step_t orig_job_step = NULL;
static bool logged_sc = false;

void my_job_step(void* job) {
    // Only scan if we haven't found L yet.
    if (job && !g_live_L) {
        void* script_context = NULL;
        
        if (safe_read((char*)job + OFFSET_JOB_SCRIPT_CTX, &script_context, 8) && script_context) {
            script_context = (void*)STRIP_PAC(script_context);
            
            if (!logged_sc) {
                SporkLog(@"Job::step triggered! Found SC: %p", script_context);
                logged_sc = true;
            }
            
            // Scan up to 32KB for the lua_State
            for (int i = 0; i < 0x8000; i += 8) {
                uintptr_t ptr = 0;
                if (safe_read((char*)script_context + i, &ptr, 8)) {
                    uintptr_t stripped_ptr = STRIP_PAC(ptr);
                    
                    // FIXED: iOS 64-bit pointers can go up to 0x7FFFFFFFFFFF
                    if (stripped_ptr > 0x100000000 && stripped_ptr < 0x7FFFFFFFFFFF) {
                        uint8_t tt = 0;
                        if (safe_read((void*)(stripped_ptr + 2), &tt, 1) && tt == 9) {
                            SporkLog(@"FOUND LUA STATE at offset 0x%X: %p", i, (void*)stripped_ptr);
                            g_live_L = (void*)stripped_ptr;
                            
                            // Auto execute test script!
                            ExecuteLuauBytecode("print(\"testing\")", 15);
                            break;
                        }
                    }
                }
            }
        }
    }
    
    if (orig_job_step) {
        orig_job_step(job);
    }
}

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

    SporkLog(@"Scanning Jobs to hook VTable...");
    
    for (uintptr_t ptr = start; ptr < end; ptr += 0x10) {
        void* j = NULL;
        if (!safe_read((void*)ptr, &j, 8) || !j) continue;
        uintptr_t stripped_j = STRIP_PAC(j);
        
        char job_name[64] = {0};
        safe_read((char*)stripped_j + OFFSET_JOB_NAME, job_name, 23);
        
        if (strlen(job_name) > 2) {
            SporkLog(@"Job: %s", job_name);
        }

        // Hook the first job that has a ScriptContext
        void* sc = NULL;
        if (safe_read((char*)stripped_j + OFFSET_JOB_SCRIPT_CTX, &sc, 8) && sc) {
            void** original_vtable = *(void***)j;
            orig_job_step = (job_step_t)original_vtable[0];
            
            void** new_vtable = (void**)malloc(0x1000);
            memcpy(new_vtable, original_vtable, 0x1000);
            new_vtable[0] = (void*)my_job_step;
            
            uintptr_t job_page = (uintptr_t)j & ~0x3FFF;
            kern_return_t kr = vm_protect(mach_task_self(), (vm_address_t)job_page, 0x4000, false, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
            if (kr == KERN_SUCCESS) {
                *(void***)j = new_vtable;
                vm_protect(mach_task_self(), (vm_address_t)job_page, 0x4000, false, VM_PROT_READ | VM_PROT_EXECUTE);
                SporkLog(@"Success: Hooked Job::step via VTable!");
                return;
            } else {
                SporkLog(@"Failed to protect memory for VTable hook: %d", kr);
                free(new_vtable);
            }
        }
    }
}
