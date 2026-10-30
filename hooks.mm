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

// STRICT: Only accepts canonical Roblox lua_State layout.
// L+0x78 -> global_State
// global_State+0x1a0 -> back to L
static bool is_canonical_L(uintptr_t cand) {
    uintptr_t gs = 0;
    // 1. Read global_State pointer
    if (!safe_read((void*)(cand + 0x78), &gs, 8)) return false;
    gs = spork_strip_pac(gs);
    
    // 2. Validate global_State pointer
    if (!spork_is_valid_ptr(gs)) return false;
    if (gs == cand) return false; // Reject self-loops
    if ((gs >> 48) == 0x99) return false; // Reject NaN sentinels (like 0x99999999999a)
    
    // 3. Read mainthread pointer from global_State
    uintptr_t mt = 0;
    if (!safe_read((void*)(gs + 0x1a0), &mt, 8)) return false;
    
    // 4. Must point back to original candidate
    return spork_strip_pac(mt) == cand;
}

static uintptr_t scan_region_for_L(uintptr_t base, size_t range, const char *label) {
    for (size_t i = 0; i < range; i += 8) {
        uintptr_t cand = 0;
        if (!safe_read((char*)base + i, &cand, 8)) continue;
        cand = spork_strip_pac(cand);
        if (!spork_is_valid_ptr(cand)) continue;
        
        if (is_canonical_L(cand)) {
            SporkLog(@"FOUND L: %p [%s+0x%zx]", (void*)cand, label, i);
            return cand;
        }
    }
    return 0;
}

typedef void (*job_step_t)(void* job);
static job_step_t orig_job_step = NULL;
static int g_tick_count = 0;
static int g_last_scan_tick = -999999;
static int g_scan_attempt = 0;
static bool g_given_up = false;

void my_job_step(void *job) {
    g_tick_count++;

    // Rate limit to once per ~5 seconds (300 ticks) to avoid lag
    if (job && !g_live_L && !g_given_up && (g_tick_count - g_last_scan_tick > 300)) {
        g_last_scan_tick = g_tick_count;
        g_scan_attempt++;
        SporkLog(@"=== Scan attempt %d (tick %d) ===", g_scan_attempt, g_tick_count);

        uintptr_t found = 0;

        // 1. Scan job+0x1b0 (ScriptContext)
        uintptr_t sc = 0;
        if (safe_read((char*)job + 0x1b0, &sc, 8)) {
            sc = spork_strip_pac(sc);
            if (spork_is_valid_ptr(sc)) {
                SporkLog(@"Scanning SC at job+0x1b0 -> 0x%lx", (unsigned long)sc);
                found = scan_region_for_L(sc, 0x8000, "SC(0x1b0)");
            }
        }

        // 2. Scan job+0x188 (DataModel / alternate SC)
        if (!found) {
            uintptr_t sc2 = 0;
            if (safe_read((char*)job + 0x188, &sc2, 8)) {
                sc2 = spork_strip_pac(sc2);
                if (spork_is_valid_ptr(sc2) && sc2 != sc) {
                    SporkLog(@"Scanning SC at job+0x188 -> 0x%lx", (unsigned long)sc2);
                    found = scan_region_for_L(sc2, 0x8000, "SC(0x188)");
                }
            }
        }

        // 3. Fallback: Check job's own pointer fields (excluding SELF at 0x08/0x10)
        if (!found) {
            for (int off = 0x18; off < 0x400 && !found; off += 8) {
                if (off == 0x1b0 || off == 0x188) continue; // Already checked
                uintptr_t p = 0;
                if (!safe_read((char*)job + off, &p, 8)) continue;
                p = spork_strip_pac(p);
                if (!spork_is_valid_ptr(p)) continue;
                if (is_canonical_L(p)) {
                    SporkLog(@"FOUND L: %p [job+0x%x direct]", (void*)p, off);
                    found = p;
                }
            }
        }

        if (found) {
            g_live_L = (void*)found;
            SporkLog(@"Set g_live_L = %p", g_live_L);
            // Tweak.xm handles the execution and crash catching
            ExecuteLuauBytecode("print(\"testing from Spork\")", 27);
            
            if (!g_live_L) {
                SporkLog(@"Execution failed. Giving up.");
                g_given_up = true;
            }
        } else if (g_scan_attempt >= 5) {
            SporkLog(@"Giving up after %d attempts.", g_scan_attempt);
            g_given_up = true;
        }
    }

    if (orig_job_step) orig_job_step(job);
}

void SetupHooks(void) {
    signal(SIGSEGV, hook_signal_handler);
    signal(SIGBUS,  hook_signal_handler);

    uintptr_t base = get_robloxlib_base();
    if (!base) { SporkLog(@"RobloxLib not found."); return; }

    void *task_scheduler = NULL;
    if (!safe_read((void *)(base + OFFSET_TASKSCHEDULER), &task_scheduler, 8)) {
        SporkLog(@"TaskScheduler read failed."); return;
    }
    task_scheduler = (void *)spork_strip_pac((uintptr_t)task_scheduler);
    SporkLog(@"TaskScheduler @ %p", task_scheduler);

    uintptr_t start = 0, end = 0;
    safe_read((char *)task_scheduler + OFFSET_TS_JOBS_START, &start, 8);
    safe_read((char *)task_scheduler + OFFSET_TS_JOBS_END,   &end,   8);
    start = spork_strip_pac(start);
    end   = spork_strip_pac(end);

    SporkLog(@"Scanning Jobs for WaitingHybridScriptsJob...");

    static const int kNameOff[] = { 0x18, 0x20, 0x28, 0x10, 0x30, 0x38, 0x40, 0x08, 0x48, 0x50 };
    uintptr_t hybrid_jobs[8] = {0};
    int num_hybrid = 0;

    for (uintptr_t ptr = start; ptr + 8 <= end; ptr += 0x10) {
        void *j = NULL;
        if (!safe_read((void *)ptr, &j, 8) || !j) continue;
        uintptr_t sj = spork_strip_pac((uintptr_t)j);
        if (!spork_is_valid_ptr(sj)) continue;

        const char *name = NULL;
        for (size_t k = 0; k < sizeof(kNameOff)/sizeof(kNameOff[0]); k++) {
            uintptr_t raw = 0;
            if (!safe_read((char *)sj + kNameOff[k], &raw, 8)) continue;
            uintptr_t sp = spork_strip_pac(raw);
            if (!spork_is_valid_ptr(sp)) continue;
            char buf[96] = {0};
            if (!safe_read((void *)sp, buf, sizeof(buf) - 1)) continue;
            bool ok = true; int len = 0;
            for (int b = 0; b < 64; b++) {
                if (!buf[b]) break;
                if (buf[b] < 0x20 || buf[b] > 0x7e) { ok = false; break; }
                len++;
            }
            if (ok && len >= 4) { name = buf; break; }
        }
        if (!name) continue;

        if (strcmp(name, "WaitingHybridScriptsJob") == 0 && num_hybrid < 8) {
            hybrid_jobs[num_hybrid++] = sj;
            SporkLog(@"WaitingHybridScriptsJob[%d] @ %p", num_hybrid - 1, (void*)sj);
        }
    }

    if (num_hybrid == 0) {
        SporkLog(@"ERROR: no WaitingHybridScriptsJob found.");
        return;
    }

    uintptr_t hj = hybrid_jobs[num_hybrid - 1];
    SporkLog(@"Hooking vtable of WaitingHybridScriptsJob @ %p", (void*)hj);
    void **original_vtable = *(void ***)hj;
    orig_job_step = (job_step_t)original_vtable[0];
    void **new_vtable = (void **)malloc(0x1000);
    memcpy(new_vtable, original_vtable, 0x1000);
    new_vtable[0] = (void *)my_job_step;
    uintptr_t job_page = hj & ~0x3FFFULL;
    kern_return_t kr = vm_protect(mach_task_self(),
                                  (vm_address_t)job_page, 0x4000,
                                  false, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr == KERN_SUCCESS) {
        *(void ***)hj = new_vtable;
        vm_protect(mach_task_self(), (vm_address_t)job_page, 0x4000,
                   false, VM_PROT_READ | VM_PROT_EXECUTE);
        SporkLog(@"VTable hooked.");
    } else {
        SporkLog(@"vm_protect failed: %d", kr);
        free(new_vtable);
    }
}
