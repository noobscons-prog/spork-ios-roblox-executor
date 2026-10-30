#import <UIKit/UIKit.h>
#import <signal.h>
#import <setjmp.h>
#import <string.h>
#import <Foundation/Foundation.h>
#import "SporkUI.h"
#import "hooks.hpp"

extern bool safe_read(void* address, void* buffer, size_t size);

bool g_is_injected = true;
int g_execution_method = 1;
NSMutableArray<NSString *> *g_logs = nil;

const char* g_gui_script = 
    "local ScreenGui = Instance.new('ScreenGui') "
    "local Main = Instance.new('Frame') "
    "local TextBox = Instance.new('TextBox') "
    "local Execute = Instance.new('TextButton') "
    "local Title = Instance.new('TextLabel') "
    "ScreenGui.Parent = game:GetService('Players').LocalPlayer:WaitForChild('PlayerGui') "
    "ScreenGui.Name = 'SporkGUI' "
    "Main.Parent = ScreenGui "
    "Main.Size = UDim2.new(0, 300, 0, 200) "
    "Main.Position = UDim2.new(0.5, -150, 0.5, -100) "
    "Main.BackgroundColor3 = Color3.fromRGB(30, 30, 30) "
    "Main.BorderSizePixel = 0 "
    "Title.Parent = Main "
    "Title.Size = UDim2.new(1, 0, 0, 30) "
    "Title.BackgroundColor3 = Color3.fromRGB(40, 40, 40) "
    "Title.Text = 'Spork In-Game' "
    "Title.TextColor3 = Color3.fromRGB(255, 255, 255) "
    "Title.Font = Enum.Font.SourceSansBold "
    "TextBox.Parent = Main "
    "TextBox.Size = UDim2.new(1, -20, 1, -80) "
    "TextBox.Position = UDim2.new(0, 10, 0, 40) "
    "TextBox.BackgroundColor3 = Color3.fromRGB(20, 20, 20) "
    "TextBox.TextColor3 = Color3.fromRGB(0, 255, 0) "
    "TextBox.MultiLine = true "
    "Execute.Parent = Main "
    "Execute.Size = UDim2.new(1, -20, 0, 30) "
    "Execute.Position = UDim2.new(0, 10, 1, -40) "
    "Execute.BackgroundColor3 = Color3.fromRGB(0, 120, 255) "
    "Execute.Text = 'Execute' "
    "Execute.TextColor3 = Color3.fromRGB(255, 255, 255) "
    "Execute.MouseButton1Click:Connect(function() "
    "local func, err = loadstring(TextBox.Text) "
    "if func then pcall(func) else TextBox.Text = 'Error: ' .. tostring(err) end "
    "end) "
    "print('Spork GUI injected successfully!')";

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

    // Direct execution, no sigsetjmp
    void* new_L = lua_newthread(g_live_L);
    if (new_L) {
        luaL_sandboxthread(new_L);
        int status = luau_load(new_L, "SporkScript", source, size, 0);
        if (status == 0) {
            int ret = lua_pcall(new_L, 0, 0, 0);
            SporkLog(@"pcall ret=%d", ret);
            if (ret == 0) {
                SporkLog(@"SUCCESS: script executed!");
            }
        } else {
            SporkLog(@"luau_load failed. Status: %d", status);
        }
    } else {
        SporkLog(@"lua_newthread returned NULL.");
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
