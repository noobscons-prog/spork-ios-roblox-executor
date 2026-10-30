#import <UIKit/UIKit.h>
#import <signal.h>
#import <setjmp.h>
#import <string.h>
#import <Foundation/Foundation.h>
#import "SporkUI.h"
#import "hooks.hpp"

// safe_read is defined (non-static) in hooks.mm
extern bool safe_read(void* address, void* buffer, size_t size);

bool g_is_injected = true;
int g_execution_method = 1;
NSMutableArray<NSString *> *g_logs = nil;

static NSString *getLogPath() {
    NSString *logsDir = @"/var/mobile/Documents/SporkLogs";
    if (![[NSFileManager defaultManager] fileExistsAtPath:logsDir]) {
        [[NSFileManager defaultManager] createDirectoryAtPath:logsDir withIntermediateDirectories:YES attributes:nil error:nil];
    }
    return [logsDir stringByAppendingPathComponent:@"execution_logs.txt"];
}

void SporkLog(NSString *format, ...) {
    va_list args;
    va_start(args, format);
    NSString *msg = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);

    NSLog(@"[Spork] %@", msg);

    NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
    [formatter setDateFormat:@"HH:mm:ss"];
    NSString *logLine = [NSString stringWithFormat:@"[%@] %@\n", [formatter stringFromDate:[NSDate date]], msg];

    NSString *path = getLogPath();
    NSFileHandle *fileHandle = [NSFileHandle fileHandleForWritingAtPath:path];
    if (fileHandle) {
        [fileHandle seekToEndOfFile];
        [fileHandle writeData:[logLine dataUsingEncoding:NSUTF8StringEncoding]];
        [fileHandle closeFile];
    } else {
        [logLine writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil];
    }

    dispatch_async(dispatch_get_main_queue(), ^{
        if (!g_logs) g_logs = [NSMutableArray array];
        [g_logs addObject:[logLine stringByTrimmingCharactersInSet:[NSCharacterSet newlineCharacterSet]]];
        [[NSNotificationCenter defaultCenter] postNotificationName:@"SporkLogUpdated" object:nil];
    });
}

typedef int  (*lua_pcall_t)(void* L, int nargs, int nresults, int errfunc);
typedef int  (*luau_load_t)(void* L, const char* chunkname, const char* data, size_t size, int env);
typedef void* (*lua_newthread_t)(void* L);
typedef void (*luaL_sandboxthread_t)(void* L);

void ExecuteLuauBytecode(const char* source, size_t size) {
    if (!g_live_L) {
        SporkLog(@"L is NULL. Wait for game.");
        return;
    }

    uintptr_t base = get_robloxlib_base();
    luau_load_t          luau_load          = (luau_load_t)(base + 0x44bc110);
    lua_pcall_t          lua_pcall          = (lua_pcall_t)(base + 0x4490fec);
    lua_newthread_t      lua_newthread      = (lua_newthread_t)(base + 0x448df3c);
    luaL_sandboxthread_t luaL_sandboxthread = (luaL_sandboxthread_t)(base + 0x1a12ad4);

    SporkLog(@"Exec: L=%p base=0x%lx size=%zu", g_live_L, (unsigned long)base, size);

    // Preflight: ARM64 function prologue of lua_newthread should look like
    // stp x29, x30, [sp, #-16]!  →  FD 7B BF A9
    uint8_t nb[8] = {0};
    if (safe_read((void*)(uintptr_t)lua_newthread, nb, sizeof(nb))) {
        bool ok = (nb[0] == 0xFD && nb[1] == 0x7B);
        SporkLog(@"newthread @ %p: %02x %02x %02x %02x %02x %02x %02x %02x %s",
                 lua_newthread,
                 nb[0], nb[1], nb[2], nb[3], nb[4], nb[5], nb[6], nb[7],
                 ok ? "(prologue OK)" : "(SUSPICIOUS — offset may be wrong)");
    }

    // ===== Attempt 1: newthread → sandbox → load → pcall =====
    SporkLog(@"--- Attempt 1: newthread + sandbox + load + pcall ---");
    in_hook_exec = 1;
    int sig = sigsetjmp(hook_jump_buffer, 1);
    if (sig == 0) {
        void* new_L = lua_newthread(g_live_L);
        SporkLog(@"newthread -> %p", new_L);
        if (new_L) {
            luaL_sandboxthread(new_L);
            int status = luau_load(new_L, "SporkScript", source, size, 0);
            SporkLog(@"luau_load status=%d", status);
            if (status == 0) {
                int ret = lua_pcall(new_L, 0, 0, 0);
                SporkLog(@"pcall ret=%d", ret);
                if (ret == 0) {
                    SporkLog(@"SUCCESS (attempt 1): script executed!");
                    in_hook_exec = 0;
                    return;
                }
            }
        } else {
            SporkLog(@"lua_newthread returned NULL — offset 0x448df3c may be wrong.");
        }
        in_hook_exec = 0;
        SporkLog(@"Attempt 1 did not crash — offsets are valid but call returned an error. Not retrying.");
        return;
    }

    // Attempt 1 crashed
    in_hook_exec = 0;
    SporkLog(@"Attempt 1 CRASHED (signal %d) — trying direct-load fallback", sig);

    // ===== Attempt 2: luau_load directly on g_live_L → pcall =====
    SporkLog(@"--- Attempt 2: direct luau_load on L + pcall ---");
    in_hook_exec = 1;
    sig = sigsetjmp(hook_jump_buffer, 1);
    if (sig == 0) {
        int status = luau_load(g_live_L, "SporkScript", source, size, 0);
        SporkLog(@"luau_load(direct) status=%d", status);
        if (status == 0) {
            int ret = lua_pcall(g_live_L, 0, 0, 0);
            SporkLog(@"pcall(direct) ret=%d", ret);
            if (ret == 0) {
                SporkLog(@"SUCCESS (attempt 2): script executed!");
                in_hook_exec = 0;
                return;
            }
        }
        in_hook_exec = 0;
        return;
    }

    // Attempt 2 crashed
    in_hook_exec = 0;
    SporkLog(@"Attempt 2 CRASHED (signal %d) — giving up. Clearing g_live_L.", sig);
    g_live_L = NULL;
}

// --- Everything below this line is UNCHANGED from your original Tweak.xm ---

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
    SporkLog(@"Spork injected. Starting UI...");

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(6.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
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

        SporkLog(@"UI loaded. Waiting 2 seconds before hooking...");

        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            SporkLog(@"Starting SetupHooks...");
            SetupHooks();
        });
    });
}
