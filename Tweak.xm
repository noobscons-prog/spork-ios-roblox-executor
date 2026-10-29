#import <UIKit/UIKit.h>
#import <signal.h>
#import <setjmp.h>
#import <Foundation/Foundation.h>
#import "SporkUI.h"
#import "hooks.hpp"

bool g_is_injected = true;
int g_execution_method = 1;
NSMutableArray<NSString *> *g_logs = nil;

static NSString *getLogPath(NSString *filename) {
    NSString *documents = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *logsDir = [documents stringByAppendingPathComponent:@"SporkLogs"];
    if (![[NSFileManager defaultManager] fileExistsAtPath:logsDir]) {
        [[NSFileManager defaultManager] createDirectoryAtPath:logsDir withIntermediateDirectories:YES attributes:nil error:nil];
    }
    return [logsDir stringByAppendingPathComponent:filename];
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
    
    NSString *path = getLogPath(@"execution_logs.txt");
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

void uncaught_exception_handler(NSException *exception) {
    NSString *crashLog = [NSString stringWithFormat:@"CRASH: %@\nReason: %@\nStack: %@\n", exception.name, exception.reason, exception.callStackSymbols];
    NSString *path = getLogPath(@"crash_logs.txt");
    [crashLog writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil];
    SporkLog(@"App crashed: %@", exception.name);
}

typedef int (*lua_pcall_t)(void* L, int nargs, int nresults, int errfunc);
typedef int (*luau_load_t)(void* L, const char* chunkname, const char* data, size_t size, int env);
typedef void* (*lua_newthread_t)(void* L);
typedef void (*luaL_sandboxthread_t)(void* L);

void ExecuteLuauBytecode(const char* source, size_t size) {
    if (!g_live_L) {
        SporkLog(@"L is NULL. Wait for game.");
        return;
    }
    
    uintptr_t base = get_robloxlib_base();
    luau_load_t luau_load = (luau_load_t)(base + 0x44bc110);
    lua_pcall_t lua_pcall = (lua_pcall_t)(base + 0x4490fec);
    lua_newthread_t lua_newthread = (lua_newthread_t)(base + 0x448df3c);
    luaL_sandboxthread_t luaL_sandboxthread = (luaL_sandboxthread_t)(base + 0x1a12ad4);
    
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
        SporkLog(@"CRASH CAUGHT during execution: Signal %d", sig);
    }
}

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
    NSSetUncaughtExceptionHandler(&uncaught_exception_handler);
    
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
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
        
        SporkLog(@"UI loaded. Waiting 3 seconds for game to stabilize...");
        
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            SporkLog(@"Starting setup hooks...");
            SetupHooks();
            
            [NSTimer scheduledTimerWithTimeInterval:1.0 repeats:YES block:^(NSTimer * _Nonnull timer) {
                if (g_live_L) {
                    SporkLog(@"SUCCESS! Stole lua_State: %p", g_live_L);
                    [timer invalidate];
                    ExecuteLuauBytecode("print(\"testing\")", 15);
                }
            }];
        });
    });
}
