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

// These are HINTS only — real values are discovered at runtime
#define OFFSET_JOB_SCRIPT_CTX_HINT 0x1b0

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

// 48-bit mask — was 36-bit before (0x0000000FFFFFFFFF), which silently
// truncated any pointer above ~68 GB. That is a common iOS lua_State range.
#define STRIP_PAC(ptr) ((uintptr_t)(ptr) & 0x0000FFFFFFFFFFFFULL)

static inline bool is_valid_ptr(uintptr_t p) {
    return p > 0x100000000ULL && p < 0x0000FFFFFFFFFFFFULL;
}

bool safe_read(void* address, void* buffer, size_t size) {
    uintptr_t addr = STRIP_PAC(address);
    if (addr < 0x100000000) return false;
    vm_size_t out_size;
    kern_return_t kr = vm_read_overwrite(mach_task_self(),
                                         (vm_address_t)addr,
                                         (vm_size_t)size,
                                         (vm_address_t)buffer,
                                         &out_size);
    return (kr == KERN_SUCCESS && out_size == size);
}

// --- Auto-discovery helpers ------------------------------------------------

// Try to interpret `p` as a lua_State. On success, writes the *actual*
// offsets used by this build into out_ls / out_gs and returns true.
static bool try_find_ls_gs(uintptr_t p, int *out_ls, int *out_gs) {
    static const int kLs[] = { 0x78, 0x70, 0x80, 0x68, 0x88, 0x60, 0x90, 0x58, 0x98, 0x50 };
    static const int kGs[] = { 0x1a0, 0x1b8, 0x1c0, 0x1a8, 0x1b0, 0x1d0, 0x198,
                               0x190, 0x1e0, 0x1e8, 0x1f0, 0x188, 0x180 };
    for (size_t i = 0; i < sizeof(kLs)/sizeof(kLs[0]); i++) {
        uintptr_t gs = 0;
        if (!safe_read((void *)(p + kLs[i]), &gs, 8)) continue;
        gs = STRIP_PAC(gs);
        if (!is_valid_ptr(gs)) continue;
        for (size_t j = 0; j < sizeof(kGs)/sizeof(kGs[0]); j++) {
            uintptr_t mt = 0;
            if (!safe_read((void *)(gs + kGs[j]), &mt, 8)) continue;
            mt = STRIP_PAC(mt);
            if (mt != p) continue;      // global_State::mainthread must point back to L
            *out_ls = kLs[i];
            *out_gs = kGs[j];
            return true;
        }
    }
    return false;
}

// Walk a ScriptContext-sized object looking for a valid lua_State.
static void *scan_sc_for_lua_state(uintptr_t sc, int sc_off) {
    for (int i = 0; i < 0x8000; i += 8) {
        uintptr_t cand = 0;
        if (!safe_read((char *)sc + i, &cand, 8)) continue;
        cand = STRIP_PAC(cand);
        if (!is_valid_ptr(cand)) continue;
        int ls_off = 0, gs_off = 0;
        if (try_find_ls_gs(cand, &ls_off, &gs_off)) {
            SporkLog(@"FOUND L: SC+0x%x (sc@job+0x%x) -> L=%p (ls=0x%x gs=0x%x)",
                     i, sc_off, (void *)cand, ls_off, gs_off);
            return (void *)cand;
        }
    }
    return NULL;
}

// --- Vtable hook -----------------------------------------------------------

typedef void (*job_step_t)(void* job);
static job_step_t orig_job_step = NULL;
static bool g_did_initial_scan = false;

void my_job_step(void *job) {
    if (job && !g_live_L && !g_did_initial_scan) {
        g_did_initial_scan = true;

        // Try a range of plausible Job->ScriptContext offsets.
        static const int kSc[] = { 0x1b0, 0x1a8, 0x1b8, 0x1c0, 0x1a0, 0x1d0,
                                   0x1e0, 0x198, 0x190, 0x1e8, 0x1f0, 0x188,
                                   0x1d8, 0x1f8, 0x208, 0x178, 0x170, 0x168 };
        for (size_t k = 0; k < sizeof(kSc)/sizeof(kSc[0]); k++) {
            uintptr_t sc = 0;
            if (!safe_read((char *)job + kSc[k], &sc, 8)) continue;
            sc = STRIP_PAC(sc);
            if (!is_valid_ptr(sc)) continue;

            SporkLog(@"Trying SC candidate at job+0x%x -> %p", kSc[k], (void *)sc);
            void *L = scan_sc_for_lua_state(sc, kSc[k]);
            if (L) {
                g_live_L = L;
                SporkLog(@"Triggering test execution on L=%p", L);
                ExecuteLuauBytecode("print(\"testing from Spork\")", 27);
                return;   // orig_job_step called by caller? No — we're the hook.
            }
        }
        if (!g_live_L) {
            SporkLog(@"No L in any SC candidate — will retry next tick.");
            g_did_initial_scan = false;   // allow retry next frame
        }
    }

    if (orig_job_step) orig_job_step(job);
}

// --- Entry point -----------------------------------------------------------

void SetupHooks(void) {
    signal(SIGSEGV, hook_signal_handler);
    signal(SIGBUS,  hook_signal_handler);

    uintptr_t base = get_robloxlib_base();
    if (!base) { SporkLog(@"RobloxLib not found."); return; }

    void *task_scheduler = NULL;
    if (!safe_read((void *)(base + OFFSET_TASKSCHEDULER), &task_scheduler, 8)) {
        SporkLog(@"TaskScheduler read failed."); return;
    }
    task_scheduler = (void *)STRIP_PAC(task_scheduler);

    uintptr_t start = 0, end = 0;
    safe_read((char *)task_scheduler + OFFSET_TS_JOBS_START, &start, 8);
    safe_read((char *)task_scheduler + OFFSET_TS_JOBS_END,   &end,   8);
    start = STRIP_PAC(start);
    end   = STRIP_PAC(end);

    SporkLog(@"Scanning Jobs (auto-detecting name offset)...");

    static const int kNameOff[] = { 0x18, 0x20, 0x28, 0x10, 0x30, 0x38, 0x40, 0x08, 0x48, 0x50 };
    uintptr_t detected_job = 0;
    char detected_name[128] = {0};
    int detected_name_off = -1;

    for (uintptr_t ptr = start; ptr + 8 <= end; ptr += 0x10) {
        void *j = NULL;
        if (!safe_read((void *)ptr, &j, 8) || !j) continue;
        uintptr_t sj = STRIP_PAC(j);
        if (!is_valid_ptr(sj)) continue;

        // Find the job's name via the first offset that yields printable ASCII.
        const char *name = NULL;
        int name_off = -1;
        for (size_t k = 0; k < sizeof(kNameOff)/sizeof(kNameOff[0]); k++) {
            uintptr_t raw = 0;
            if (!safe_read((char *)sj + kNameOff[k], &raw, 8)) continue;
            uintptr_t sp = STRIP_PAC(raw);
            if (!is_valid_ptr(sp)) continue;
            char buf[96] = {0};
            if (!safe_read((void *)sp, buf, sizeof(buf) - 1)) continue;
            bool ok = true; int len = 0;
            for (int b = 0; b < 64; b++) {
                if (!buf[b]) break;
                if (buf[b] < 0x20 || buf[b] > 0x7e) { ok = false; break; }
                len++;
            }
            if (ok && len >= 4) { name = buf; name_off = kNameOff[k]; break; }
        }
        if (!name) continue;

        SporkLog(@"Job: '%s' @ %p (name+0x%x)", name, (void *)sj, name_off);

        if (strcmp(name, "WaitingHybridScriptsJob") == 0) {
            strncpy(detected_name, name, sizeof(detected_name) - 1);
            detected_name_off = name_off;
            detected_job = sj;
            // don't break — keep logging so you can see every job name
        }
    }

    if (detected_job == 0) {
        SporkLog(@"ERROR: WaitingHybridScriptsJob not found. Names printed above are the real names on this build — adjust filter.");
        return;
    }

    SporkLog(@"Hooking '%s' @ %p (name+0x%x)",
             detected_name, (void *)detected_job, detected_name_off);

    void **original_vtable = *(void ***)detected_job;
    orig_job_step = (job_step_t)original_vtable[0];

    void **new_vtable = (void **)malloc(0x1000);
    memcpy(new_vtable, original_vtable, 0x1000);
    new_vtable[0] = (void *)my_job_step;

    uintptr_t job_page = detected_job & ~0x3FFFULL;
    kern_return_t kr = vm_protect(mach_task_self(),
                                  (vm_address_t)job_page, 0x4000,
                                  false, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr == KERN_SUCCESS) {
        *(void ***)detected_job = new_vtable;
        vm_protect(mach_task_self(), (vm_address_t)job_page, 0x4000,
                   false, VM_PROT_READ | VM_PROT_EXECUTE);
        SporkLog(@"VTable hooked on WaitingHybridScriptsJob.");
    } else {
        SporkLog(@"vm_protect failed: %d", kr);
        free(new_vtable);
    }
}
