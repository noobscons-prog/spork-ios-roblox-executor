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

// ---- Canonical-only lua_State check -------------------------------------

static bool is_canonical_L(uintptr_t cand) {
    uintptr_t gs = 0;
    if (!safe_read((void*)(cand + 0x78), &gs, 8)) return false;
    gs = spork_strip_pac(gs);
    if (!spork_is_valid_ptr(gs)) return false;
    uintptr_t mt = 0;
    if (!safe_read((void*)(gs + 0x1a0), &mt, 8)) return false;
    return spork_strip_pac(mt) == cand;
}

static void *scan_region_for_canonical_L(uintptr_t region, size_t range,
                                         const char *label) {
    for (size_t i = 0; i < range; i += 8) {
        uintptr_t cand = 0;
        if (!safe_read((char*)region + i, &cand, 8)) continue;
        cand = spork_strip_pac(cand);
        if (!spork_is_valid_ptr(cand)) continue;
        if (is_canonical_L(cand)) {
            SporkLog(@"CANONICAL L: %s+0x%zx -> L=%p", label, i, (void*)cand);
            return (void*)cand;
        }
    }
    return NULL;
}

static void dump_object_fields(uintptr_t addr, size_t range, const char *label) {
    SporkLog(@"%s @ 0x%lx dump:", label, (unsigned long)addr);
    int shown = 0;
    for (size_t off = 0; off < range; off += 8) {
        uintptr_t v = 0;
        if (!safe_read((void*)(addr + off), &v, 8)) continue;
        uintptr_t sv = spork_strip_pac(v);
        if (spork_is_valid_ptr(sv)) {
            const char *tag = "";
            if (sv == addr) tag = " [SELF]";
            else if (sv > 0x10d000000 && sv < 0x120000000) tag = " [code]";
            SporkLog(@"  +0x%03zx = %p%s", off, (void*)sv, tag);
            if (++shown >= 32) { SporkLog(@"  ...truncated"); break; }
        }
    }
}

// ---- Deep search from one job ------------------------------------------

static void *find_L_from_job(uintptr_t job) {
    // A) Is L directly reachable in the job struct?
    SporkLog(@"-- Checking job region directly --");
    void *L = scan_region_for_canonical_L(job, 0x400, "job");
    if (L) return L;

    // B) Try each plausible SC pointer at job+0x100..0x400
    SporkLog(@"-- Scanning job+0x100..0x400 for SC candidates --");
    for (int off = 0x100; off < 0x400; off += 8) {
        uintptr_t sc = 0;
        if (!safe_read((char*)job + off, &sc, 8)) continue;
        sc = spork_strip_pac(sc);
        if (!spork_is_valid_ptr(sc)) continue;

        // Sanity: SC should have a vtable-like first word
        uintptr_t vt = 0;
        if (!safe_read((void*)sc, &vt, 8)) continue;
        vt = spork_strip_pac(vt);
        if (!spork_is_valid_ptr(vt)) continue;

        // Scan this candidate SC for canonical L
        char label[32];
        snprintf(label, sizeof(label), "job+0x%x", off);
        L = scan_region_for_canonical_L(sc, 0x10000, label);
        if (L) {
            SporkLog(@"FOUND SC at job+0x%x, real L=%p", off, L);
            return L;
        }
    }
    return NULL;
}

// ---- Vtable hook --------------------------------------------------------

typedef void (*job_step_t)(void* job);
static job_step_t orig_job_step = NULL;
static bool g_did_initial_scan = false;
static bool g_given_up = false;

void my_job_step(void *job) {
    if (job && !g_live_L && !g_did_initial_scan && !g_given_up) {
        g_did_initial_scan = true;

        SporkLog(@"my_job_step fired. Probing job @ %p", job);
        dump_object_fields((uintptr_t)job, 0x200, "job");

        void *L = find_L_from_job((uintptr_t)job);
        if (L) {
            g_live_L = L;
            SporkLog(@"Set g_live_L = %p (verified canonical)", L);
            SporkLog(@"Auto-testing execution...");
            ExecuteLuauBytecode("print(\"testing from Spork\")", 27);
            if (!g_live_L) {
                SporkLog(@"L cleared after failure. Giving up auto-scan.");
                g_given_up = true;
            }
            return;
        }
        SporkLog(@"No canonical L found in this job. Will retry next tick.");
        g_did_initial_scan = false;
    }
    if (orig_job_step) orig_job_step(job);
}

// ---- Setup --------------------------------------------------------------

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

    // Quick shot: maybe L is directly inside TaskScheduler
    SporkLog(@"-- Quick scan: TaskScheduler for L --");
    void *quick_L = scan_region_for_canonical_L((uintptr_t)task_scheduler, 0x400, "ts");
    if (quick_L) {
        g_live_L = quick_L;
        SporkLog(@"Found L inside TaskScheduler! L=%p", quick_L);
        ExecuteLuauBytecode("print(\"testing from Spork\")", 27);
        return;
    }

    uintptr_t start = 0, end = 0;
    safe_read((char *)task_scheduler + OFFSET_TS_JOBS_START, &start, 8);
    safe_read((char *)task_scheduler + OFFSET_TS_JOBS_END,   &end,   8);
    start = spork_strip_pac(start);
    end   = spork_strip_pac(end);

    SporkLog(@"Scanning Jobs (auto-detecting name offset)...");

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

        if (strcmp(name, "WaitingHybridScriptsJob") == 0) {
            if (num_hybrid < 8) {
                hybrid_jobs[num_hybrid++] = sj;
                SporkLog(@"WaitingHybridScriptsJob[%d] @ %p", num_hybrid - 1, (void*)sj);
            }
        }
    }

    if (num_hybrid == 0) {
        SporkLog(@"ERROR: no WaitingHybridScriptsJob instances found.");
        return;
    }

    // Try each candidate job synchronously (we're in the game thread)
    for (int i = 0; i < num_hybrid; i++) {
        SporkLog(@"=== Trying job[%d] @ %p ===", i, (void*)hybrid_jobs[i]);
        void *L = find_L_from_job(hybrid_jobs[i]);
        if (L) {
            g_live_L = L;
            SporkLog(@"Set g_live_L = %p (job[%d] canonical)", L, i);
            ExecuteLuauBytecode("print(\"testing from Spork\")", 27);
            if (g_live_L) {
                SporkLog(@"SUCCESS via job[%d]. Hooking vtable anyway for future.", i);
            }
            break;
        }
    }

    // Hook vtable of the LAST WaitingHybridScriptsJob (used as backup trigger)
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
        SporkLog(@"VTable hooked on last WaitingHybridScriptsJob.");
    } else {
        SporkLog(@"vm_protect failed: %d", kr);
        free(new_vtable);
    }
}
