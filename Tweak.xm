#import <UIKit/UIKit.h>
#import <mach-o/dyld.h>
#import <string.h>
#import <mach/mach.h>
#import <mach/vm_map.h>
#import <stdlib.h>
#import <signal.h>
#import <setjmp.h>
#import "SporkUI.h"

// --- Exact Offsets from your 2.744.0.1077 dump ---
#define OFFSET_TASKSCHEDULER      0x6a6d7c0
#define OFFSET_TS_JOBS_START      0xd0
#define OFFSET_TS_JOBS_END        0xd8
#define OFFSET_JOB_NAME           0x18
#define OFFSET_JOB_SCRIPT_CTX     0x1b0

#define OFFSET_GET_GLOBAL_STATE   0x19ce768 // Fallback signature

#define OFFSET_LUA_GETTOP         0x448e048
#define OFFSET_LUAU_LOAD          0x44bc110
#define OFFSET_LUA_PCALL          0x4490fec
#define OFFSET_LUA_NEWTHREAD      0x448df3c
#define OFFSET_LUAL_SANDBOXTHREAD 0x1a12ad4

#define OFFSET_LUA_STATE_TOP      0x70
#define OFFSET_LUA_STATE_BASE     0x58

#define STRIP_PAC(ptr) ((uintptr_t)(ptr) & 0x0000000FFFFFFFFF)

bool g_is_injected = true;
int g_execution_method = 1;
NSMutableArray<NSString *> *g_logs = nil;
void* g_live_L = NULL;

// Crash Handler
static sigjmp_buf hook_jump_buffer;
static volatile sig_atomic_t in_hook_exec = 0;
void hook_signal_handler(int sig) {
    if (in_hook_exec) siglongjmp(hook_jump_buffer, sig);
}

// Logging
void SporkLog(NSString *format, ...) {
    va_list args;
    va_start(args, format);
    NSString *msg = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);
    if (!g_logs) g_logs = [NSMutableArray array];
    NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
    [formatter setDateFormat:@"HH:mm:ss"];
    NSString *logLine = [NSString stringWithFormat:@"[%@] %@", [formatter stringFromDate:[NSDate date]], msg];
    [g_logs addObject:logLine];
    NSLog(@"[Spork] %@", msg);
    dispatch_async(dispatch_get_main_queue(), ^{
        [[NSNotificationCenter defaultCenter] postNotificationName:@"SporkLogUpdated" object:nil];
    });
}

bool safe_read(void* address, void* buffer, size_t size) {
    uintptr_t addr = STRIP_PAC(address);
    if (addr < 0x100000000) return false; 
    vm_size_t out_size;
    kern_return_t kr = vm_read_overwrite(mach_task_self(), (vm_address_t)addr, (vm_size_t)size, (vm_address_t)buffer, &out_size);
    return (kr == KERN_SUCCESS && out_size == size);
}

uintptr_t get_robloxlib_base(void) {
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (name && strstr(name, "RobloxLib")) return (uintptr_t)_dyld_get_image_header(i);
    }
    return 0;
}

// ---------------------------------------------------------
// 1. Find the "Ugc" Job
// ---------------------------------------------------------
void* FindUgcScriptContext(uintptr_t base) {
    void* task_scheduler = NULL;
    if (!safe_read((void*)(base + OFFSET_TASKSCHEDULER), &task_scheduler, 8)) return NULL;
    task_scheduler = (void*)STRIP_PAC(task_scheduler);

    uintptr_t start = 0, end = 0;
    safe_read((char*)task_scheduler + OFFSET_TS_JOBS_START, &start, 8);
    safe_read((char*)task_scheduler + OFFSET_TS_JOBS_END, &end, 8);
    start = STRIP_PAC(start); end = STRIP_PAC(end);

    for (uintptr_t ptr = start; ptr < end; ptr += 0x10) {
        void* j = NULL;
        if (!safe_read((void*)ptr, &j, 8) || !j) continue;
        uintptr_t stripped_j = STRIP_PAC(j);
        
        // Read the job name (std::string at +0x18)
        char job_name[64] = {0};
        safe_read((char*)stripped_j + OFFSET_JOB_NAME, job_name, 23); // SSO inline read

        if (strcmp(job_name, "Ugc") == 0) {
            SporkLog(@"Found 'Ugc' Job at %p!", j);
            void* sc = NULL;
            if (safe_read((char*)stripped_j + OFFSET_JOB_SCRIPT_CTX, &sc, 8) && sc) {
                return (void*)STRIP_PAC(sc);
            }
        }
    }
    return NULL;
}

// ---------------------------------------------------------
// 2. Fallback lua_gettop Inline Hook (VM_PROT_COPY)
// ---------------------------------------------------------
int my_lua_gettop(void* L) {
    if (!g_live_L && L) {
        g_live_L = L;
        SporkLog(@"STOLE lua_State via lua_gettop: %p", L);
    }
    uintptr_t top = 0, base = 0;
    safe_read((char*)L + OFFSET_LUA_STATE_TOP, &top, 8);
    safe_read((char*)L + OFFSET_LUA_STATE_BASE, &base, 8);
    return (int)((top - base) / 16);
}

void SetupInlineHook(uintptr_t base) {
    void* target = (void*)(base + OFFSET_LUA_GETTOP);
    uint64_t my_func_addr = (uint64_t)my_lua_gettop;
    
    uint32_t patch[4] = {0x58000050, 0xD61F0200, (uint32_t)(my_func_addr & 0xFFFFFFFF), (uint32_t)(my_func_addr >> 32)};
    uintptr_t page = (uintptr_t)target & ~0xFFF;
    
    // THE FIX: VM_PROT_COPY bypasses iOS Code Signing Enforcement
    kern_return_t kr = mach_vm_protect(mach_task_self(), (mach_vm_address_t)page, 0x4000, false, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr == KERN_SUCCESS) {
        memcpy(target, patch, 16);
        mach_vm_protect(mach_task_self(), (mach_vm_address_t)page, 0x4000, false, VM_PROT_READ | VM_PROT_EXECUTE);
        SporkLog(@"Fallback: Patched lua_gettop (CSE Bypassed).");
    } else {
        SporkLog(@"Fallback: mach_vm_protect failed: %d", kr);
    }
}

// ---------------------------------------------------------
// 3. Injection & Execution
// ---------------------------------------------------------
typedef void* (*get_global_state_t)(void* sc, int* identity, void** script);

void InjectExecutor(void) {
    uintptr_t base = get_robloxlib_base();
    if (!base) return;

    void* sc = FindUgcScriptContext(base);
    if (sc) {
        SporkLog(@"Found Ugc ScriptContext: %p", sc);
        
        // Try get_global_state on the Ugc context
        get_global_state_t get_gs = (get_global_state_t)(base + OFFSET_GET_GLOBAL_STATE);
        int id = 0; void* script = NULL;
        
        in_hook_exec = 1;
        int sig = sigsetjmp(hook_jump_buffer, 1);
        if (sig == 0) {
            void* L = get_gs(sc, &id, &script);
            in_hook_exec = 0;
            if (L) {
                g_live_L = L;
                SporkLog(@"SUCCESS! Got lua_State via Ugc: %p", L);
                return; // We have it!
            }
        } else {
            in_hook_exec = 0;
            SporkLog(@"get_global_state crashed (Signal %d). Falling back to hook.", sig);
        }
    } else {
        SporkLog(@"Could not find 'Ugc' job. Falling back to hook.");
    }
    
    // If we reach here, get_global_state failed. Use the inline hook.
    SetupInlineHook(base);
}

typedef int (*lua_pcall_t)(void* L, int nargs, int nresults, int errfunc);
typedef int (*luau_load_t)(void* L, const char* chunkname, const char* data, size_t size, int env);
typedef void* (*lua_newthread_t)(void* L);
typedef void (*luaL_sandboxthread_t)(void* L);

void ExecuteLuauBytecode(const char* source, size_t size) {
    if (!g_live_L) {
        SporkLog(@"L is NULL. Wait for the game to load.");
        return;
    }
    
    uintptr_t base = get_robloxlib_base();
    luau_load_t luau_load = (luau_load_t)(base + OFFSET_LUAU_LOAD);
    lua_pcall_t lua_pcall = (lua_pcall_t)(base + OFFSET_LUA_PCALL);
    lua_newthread_t lua_newthread = (lua_newthread_t)(base + OFFSET_LUA_NEWTHREAD);
    luaL_sandboxthread_t luaL_sandboxthread = (luaL_sandboxthread_t)(base + OFFSET_LUAL_SANDBOXTHREAD);
    
    SporkLog(@"Executing script on L: %p", g_live_L);
    
    in_hook_exec = 1;
    int sig = sigsetjmp(hook_jump_buffer, 1);
    if (sig == 0) {
        void* new_L = lua_newthread(g_live_L);
        if (new_L) {
            luaL_sandboxthread(new_L);
            int status = luau_load(new_L, "SporkScript", source, size, 0);
            if (status == 0) {
                lua_pcall(new_L, 0, 0, 0);
                SporkLog(@"Executed successfully!");
            } else {
                SporkLog(@"luau_load failed. Status: %d", status);
            }
        }
        in_hook_exec = 0;
    } else {
        in_hook_exec = 0;
        SporkLog(@"HOOK CRASH CAUGHT: Signal %d", sig);
    }
}

// ---------------------------------------------------------
// UI & INIT
// ---------------------------------------------------------
@interface PassThroughWindow : UIWindow
@property (nonatomic, weak) UIView *interactableView1;
@property (nonatomic, weak) UIView *interactableView2;
@end

@implementation PassThroughWindow
- (UIView *)hitTest:(CGPoint)point withEvent:(UIEvent *)event {
    UIView *hitView = [super hitTest:point withEvent:event];
    if (self.interactableView1 && !self.interactableView1.hidden) {
        CGPoint point1 = [self.interactableView1 convertPoint:point fromView:self];
        if ([self.interactableView1 pointInside:point1 withEvent:event]) return hitView;
    }
    if (self.interactableView2 && !self.interactableView2.hidden) {
        CGPoint point2 = [self.interactableView2 convertPoint:point fromView:self];
        if ([self.interactableView2 pointInside:point2 withEvent:event]) return hitView;
    }
    return nil; 
}
@end

static PassThroughWindow *overlayWindow = nil;

__attribute__((constructor))
static void init() {
    signal(SIGSEGV, hook_signal_handler);
    signal(SIGBUS, hook_signal_handler);

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        if (overlayWindow) return; 

        UIWindowScene *activeScene = nil;
        for (UIScene *scene in [UIApplication sharedApplication].connectedScenes) {
            if ([scene isKindOfClass:[UIWindowScene class]]) {
                activeScene = (UIWindowScene *)scene;
                break;
            }
        }

        if (activeScene) {
            overlayWindow = [[PassThroughWindow alloc] initWithWindowScene:activeScene];
        } else {
            overlayWindow = [[PassThroughWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
        }

        overlayWindow.frame = [UIScreen mainScreen].bounds;
        overlayWindow.windowLevel = UIWindowLevelAlert + 1000;
        overlayWindow.backgroundColor = [UIColor clearColor];
        
        SporkViewController *vc = [[SporkViewController alloc] init];
        overlayWindow.rootViewController = vc;
        overlayWindow.hidden = NO;
        [overlayWindow makeKeyAndVisible];
        
        overlayWindow.interactableView1 = vc.mainContainer;
        overlayWindow.interactableView2 = vc.floatingButton;
        
        // Wait a few seconds for the game to load its jobs, then inject
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            InjectExecutor();
        });
    });
}
