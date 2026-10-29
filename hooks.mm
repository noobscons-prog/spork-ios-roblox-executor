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

#define STRIP_PAC_SCAN(ptr) ((uintptr_t)(ptr) & 0x0000000FFFFFFFFF)

void* g_live_L = NULL;
void* g_script_context = NULL;
sigjmp_buf hook_jump_buffer;
volatile sig_atomic_t in_hook_exec = 0;

extern void SporkLog(NSString *format, ...);

// Safe bytecode for: print("testing")
static const unsigned char test_bytecode[] = {
    0x1B, 0x4C, 0x75, 0x61, 0x75, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

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
    uintptr_t addr = (uintptr_t)address;
    if (addr < 0x100000000) return false; 
    vm_size_t out_size;
    kern_return_t kr = vm_read_overwrite(mach_task_self(), (vm_address_t)addr, (vm_size_t)size, (vm_address_t)buffer, &out_size);
    return (kr == KERN_SUCCESS && out_size == size);
}

bool FindLuaState(void) {
    if (!g_script_context) {
        uintptr_t base = get_robloxlib_base();
        if (base) {
            void* task_scheduler = NULL;
            if (safe_read((void*)(base + OFFSET_TASKSCHEDULER), &task_scheduler, 8) && task_scheduler) {
                task_scheduler = (void*)STRIP_PAC_SCAN(task_scheduler);
                uintptr_t start = 0, end = 0;
                safe_read((char*)task_scheduler + OFFSET_TS_JOBS_START, &start, 8);
                safe_read((char*)task_scheduler + OFFSET_TS_JOBS_END, &end, 8);
                start = STRIP_PAC_SCAN(start); end = STRIP_PAC_SCAN(end);
                
                // Prioritize WaitingHybridScriptsJob
                for (uintptr_t ptr = start; ptr < end; ptr += 0x10) {
                    void* j = NULL;
                    if (!safe_read((void*)ptr, &j, 8) || !j) continue;
                    uintptr_t stripped_j = STRIP_PAC_SCAN(j);
                    
                    char job_name[64] = {0};
                    safe_read((char*)stripped_j + OFFSET_JOB_NAME, job_name, 23);
                    
                    if (strstr(job_name, "WaitingHybridScriptsJob")) {
                        void* sc = NULL;
                        if (safe_read((char*)stripped_j + OFFSET_JOB_SCRIPT_CTX, &sc, 8) && sc) {
                            sc = (void*)STRIP_PAC_SCAN(sc);
                            if ((uintptr_t)sc > 0x100000000 && (uintptr_t)sc < 0x7FFFFFFFFFFF) {
                                g_script_context = sc;
                                SporkLog(@"[FIND] Found SC via WaitingHybridScriptsJob: %p", g_script_context);
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    if (!g_script_context) return false;

    for (int i = 0; i < 0x8000; i += 8) {
        uintptr_t ptr = 0;
        if (safe_read((char*)g_script_context + i, &ptr, 8)) {
            uintptr_t stripped_ptr = STRIP_PAC_SCAN(ptr);
            
            if (stripped_ptr > 0x100000000 && stripped_ptr < 0x7FFFFFFFFFFF && (stripped_ptr % 8 == 0)) {
                uint8_t tt = 0;
                // Must be tt=9 (Thread)
                if (safe_read((void*)(stripped_ptr + 2), &tt, 1) && tt == 9) {
                    
                    uintptr_t base_ptr = 0;
                    uintptr_t stack = 0;
                    uintptr_t stack_last = 0;
                    uintptr_t top = 0;
                    uintptr_t global = 0;

                    // Read lua_State struct fields (Safe memory validation)
                    if (safe_read((void*)(stripped_ptr + 0x58), &base_ptr, 8) &&
                        safe_read((void*)(stripped_ptr + 0x60), &stack, 8) &&
                        safe_read((void*)(stripped_ptr + 0x68), &stack_last, 8) &&
                        safe_read((void*)(stripped_ptr + 0x70), &top, 8) &&
                        safe_read((void*)(stripped_ptr + 0x78), &global, 8)) {
                        
                        base_ptr = STRIP_PAC_SCAN(base_ptr);
                        stack = STRIP_PAC_SCAN(stack);
                        stack_last = STRIP_PAC_SCAN(stack_last);
                        top = STRIP_PAC_SCAN(top);
                        global = STRIP_PAC_SCAN(global);
                        
                        // Validate stack pointers
                        if (stack > 0x100000000 && base_ptr >= stack && top >= base_ptr && top <= stack_last && global > 0x100000000) {
                            
                            // Verify global mainthread backlink (offset 0x1a0 in global_State)
                            uintptr_t main_thread = 0;
                            if (safe_read((void*)(global + 0x1a0), &main_thread, 8) && main_thread) {
                                main_thread = STRIP_PAC_SCAN(main_thread);
                                if (main_thread == stripped_ptr) {
                                    SporkLog(@"[FIND] Valid LuaState verified via struct at %p!", (void*)stripped_ptr);
                                    g_live_L = (void*)stripped_ptr;
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    return false;
}

typedef void (*job_step_t)(void* job);
#define MAX_HOOKED_JOBS 128

static job_step_t orig_job_steps[MAX_HOOKED_JOBS];
static void* hooked_jobs[MAX_HOOKED_JOBS];
static int hooked_job_count = 0;

void my_job_step(void* job) {
    if (job && !g_live_L) {
        static int tick_count = 0;
        tick_count++;
        // Throttle scanning to once every 60 ticks (~1 second) to prevent lag
        if (tick_count % 60 == 0) {
            FindLuaState();
        }
    }
    
    for (int i = 0; i < hooked_job_count; i++) {
        if (hooked_jobs[i] == job) {
            if (orig_job_steps[i]) orig_job_steps[i](job);
            return;
        }
    }
}

void SetupHooks(void) {
    signal(SIGSEGV, hook_signal_handler);
    signal(SIGBUS, hook_signal_handler);

    uintptr_t base = get_robloxlib_base();
    if (!base) { SporkLog(@"RobloxLib not found."); return; }
    
    void* task_scheduler = NULL;
    if (!safe_read((void*)(base + OFFSET_TASKSCHEDULER), &task_scheduler, 8)) { SporkLog(@"TaskScheduler failed."); return; }
    task_scheduler = (void*)STRIP_PAC_SCAN(task_scheduler);

    uintptr_t start = 0, end = 0;
    safe_read((char*)task_scheduler + OFFSET_TS_JOBS_START, &start, 8);
    safe_read((char*)task_scheduler + OFFSET_TS_JOBS_END, &end, 8);
    start = STRIP_PAC_SCAN(start); end = STRIP_PAC_SCAN(end);

    SporkLog(@"Scanning Jobs to hook VTable...");
    
    for (uintptr_t ptr = start; ptr < end; ptr += 0x10) {
        void* j = NULL;
        if (!safe_read((void*)ptr, &j, 8) || !j) continue;
        
        if (hooked_job_count < MAX_HOOKED_JOBS) {
            void** original_vtable = *(void***)j;
            
            if (original_vtable[0] == (void*)my_job_step) continue;

            orig_job_steps[hooked_job_count] = (job_step_t)original_vtable[0];
            hooked_jobs[hooked_job_count] = j;
            
            void** new_vtable = (void**)malloc(0x1000);
            memcpy(new_vtable, original_vtable, 0x1000);
            new_vtable[0] = (void*)my_job_step;
            
            uintptr_t job_page = (uintptr_t)j & ~0x3FFF;
            kern_return_t kr = vm_protect(mach_task_self(), (vm_address_t)job_page, 0x4000, false, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
            if (kr == KERN_SUCCESS) {
                *(void***)j = new_vtable;
                vm_protect(mach_task_self(), (vm_address_t)job_page, 0x4000, false, VM_PROT_READ | VM_PROT_EXECUTE);
                hooked_job_count++;
            } else {
                free(new_vtable);
            }
        }
    }
    SporkLog(@"Hooked %d jobs.", hooked_job_count);
}
