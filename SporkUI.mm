#import "SporkUI.h"
#import <Foundation/Foundation.h>

extern void ExecuteLuauBytecode(const char* source, size_t size);
extern void* g_live_L;
extern int g_execution_method;

// Custom Button for Squish Effect
@interface SporkButton : UIButton
@end
@implementation SporkButton
- (void)touchesBegan:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event {
    [super touchesBegan:touches withEvent:event];
    [UIView animateWithDuration:0.1 animations:^{ self.transform = CGAffineTransformMakeScale(0.92, 0.92); }];
}
- (void)touchesEnded:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event {
    [super touchesEnded:touches withEvent:event];
    [UIView animateWithDuration:0.4 delay:0 usingSpringWithDamping:0.5 initialSpringVelocity:1.0 options:UIViewAnimationOptionAllowUserInteraction animations:^{ self.transform = CGAffineTransformIdentity; } completion:nil];
}
- (void)touchesCancelled:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event {
    [super touchesCancelled:touches withEvent:event];
    [UIView animateWithDuration:0.4 delay:0 usingSpringWithDamping:0.5 initialSpringVelocity:1.0 options:UIViewAnimationOptionAllowUserInteraction animations:^{ self.transform = CGAffineTransformIdentity; } completion:nil];
}
@end

@interface SporkViewController ()
@property (nonatomic, strong, readwrite) UIView *mainContainer;
@property (nonatomic, strong, readwrite) UIButton *floatingButton;
@property (nonatomic, strong) UIView *topBar;
@property (nonatomic, strong) UIView *contentContainer;
@property (nonatomic, strong) UIView *sidebar;
@property (nonatomic, strong) UIView *selectionIndicator;
@property (nonatomic, strong) NSArray *sidebarButtons;

@property (nonatomic, strong) UIView *editorTabView;
@property (nonatomic, strong) UIView *homeTabView;
@property (nonatomic, strong) UIView *hacksTabView;
@property (nonatomic, strong) UIView *logsTabView;

@property (nonatomic, strong) UITextView *scriptEditor;
@property (nonatomic, strong) UITextView *logsTextView;
@property (nonatomic, strong) UILabel *tabLabel;
@property (nonatomic) NSInteger tabCounter;

@property (nonatomic, strong) SporkButton *injectBtn;
@property (nonatomic, strong) UILabel *statusLabel;
@property (nonatomic, strong) UILabel *methodLabel;
@end

@implementation SporkViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor clearColor];
    self.tabCounter = 1;
    g_execution_method = 1; 
    [self setupMainContainer];
    [self setupTopBar];
    [self setupSidebar];
    [self setupEditorTab];
    [self setupHomeTab];
    [self setupHacksTab];
    [self setupLogsTab];
    [self setupFloatingButton];
    
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(updateLogs) name:@"SporkLogUpdated" object:nil];
    [self switchTab:1]; 
}

- (void)updateLogs {
    if (self.logsTextView && g_logs) {
        self.logsTextView.text = [g_logs componentsJoinedByString:@"\n"];
        if (self.logsTextView.text.length > 0) {
            NSRange bottom = NSMakeRange(self.logsTextView.text.length - 1, 1);
            [self.logsTextView scrollRangeToVisible:bottom];
        }
    }
}

// ... [Keep all your setup functions (setupMainContainer, setupTopBar, etc.) the same as before] ...

- (void)setupEditorTab {
    [self setupContentContainer];
    self.editorTabView = [[UIView alloc] init];
    self.editorTabView.translatesAutoresizingMaskIntoConstraints = NO;
    [self.contentContainer addSubview:self.editorTabView];
    
    UIView *tabHeader = [[UIView alloc] init];
    tabHeader.translatesAutoresizingMaskIntoConstraints = NO;
    tabHeader.backgroundColor = [UIColor colorWithRed:0.15 green:0.15 blue:0.15 alpha:1.0];
    tabHeader.layer.cornerRadius = 8;
    tabHeader.layer.maskedCorners = kCALayerMinXMinYCorner | kCALayerMaxXMinYCorner;
    [self.editorTabView addSubview:tabHeader];

    self.tabLabel = [[UILabel alloc] init];
    self.tabLabel.translatesAutoresizingMaskIntoConstraints = NO;
    self.tabLabel.text = @"Script 1  x";
    self.tabLabel.textColor = [UIColor whiteColor];
    self.tabLabel.font = [UIFont systemFontOfSize:12];
    [tabHeader addSubview:self.tabLabel];

    self.scriptEditor = [[UITextView alloc] init];
    self.scriptEditor.translatesAutoresizingMaskIntoConstraints = NO;
    self.scriptEditor.backgroundColor = [UIColor colorWithRed:0.08 green:0.08 blue:0.08 alpha:1.0];
    self.scriptEditor.textColor = [UIColor colorWithRed:0.8 green:0.8 blue:0.8 alpha:1.0];
    self.scriptEditor.font = [UIFont fontWithName:@"Menlo" size:12];
    self.scriptEditor.text = @"print(\"Hello from Spork!\")";
    self.scriptEditor.layer.cornerRadius = 8;
    self.scriptEditor.layer.maskedCorners = kCALayerMinXMaxYCorner | kCALayerMaxXMaxYCorner;
    [self.editorTabView addSubview:self.scriptEditor];

    UIView *actionBar = [[UIView alloc] init];
    actionBar.translatesAutoresizingMaskIntoConstraints = NO;
    [self.editorTabView addSubview:actionBar];

    UIStackView *btnStack = [[UIStackView alloc] init];
    btnStack.translatesAutoresizingMaskIntoConstraints = NO;
    btnStack.axis = UILayoutConstraintAxisHorizontal;
    btnStack.spacing = 8;
    btnStack.distribution = UIStackViewDistributionFillEqually;
    [actionBar addSubview:btnStack];

    // ADDED BASE64 DECODE BUTTON
    NSArray *btnTitles = @[@"Execute", @"Clear", @"Copy", @"Paste", @"B64 Decode"];
    for (int i = 0; i < btnTitles.count; i++) {
        SporkButton *btn = [SporkButton buttonWithType:UIButtonTypeSystem];
        [btn setTitle:btnTitles[i] forState:UIControlStateNormal];
        [btn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        btn.titleLabel.font = [UIFont boldSystemFontOfSize:11];
        btn.backgroundColor = (i == 0) ? [UIColor colorWithRed:0.0 green:0.5 blue:1.0 alpha:1.0] : [UIColor colorWithWhite:0.2 alpha:1.0];
        btn.layer.cornerRadius = 6;
        
        if (i == 0) [btn addTarget:self action:@selector(executeScriptAction) forControlEvents:UIControlEventTouchUpInside];
        if (i == 1) [btn addTarget:self action:@selector(clearAction) forControlEvents:UIControlEventTouchUpInside];
        if (i == 2) [btn addTarget:self action:@selector(copyAction) forControlEvents:UIControlEventTouchUpInside];
        if (i == 3) [btn addTarget:self action:@selector(pasteAction) forControlEvents:UIControlEventTouchUpInside];
        if (i == 4) [btn addTarget:self action:@selector(decodeBase64Action) forControlEvents:UIControlEventTouchUpInside];
        
        [btnStack addArrangedSubview:btn];
    }

    [NSLayoutConstraint activateConstraints:@[
        [self.editorTabView.topAnchor constraintEqualToAnchor:self.contentContainer.topAnchor constant:15],
        [self.editorTabView.leadingAnchor constraintEqualToAnchor:self.contentContainer.leadingAnchor constant:15],
        [self.editorTabView.trailingAnchor constraintEqualToAnchor:self.contentContainer.trailingAnchor constant:-15],
        [self.editorTabView.bottomAnchor constraintEqualToAnchor:self.contentContainer.bottomAnchor constant:-15],
        [tabHeader.topAnchor constraintEqualToAnchor:self.editorTabView.topAnchor],
        [tabHeader.leadingAnchor constraintEqualToAnchor:self.editorTabView.leadingAnchor],
        [tabHeader.trailingAnchor constraintEqualToAnchor:self.editorTabView.trailingAnchor],
        [tabHeader.heightAnchor constraintEqualToConstant:30],
        [self.tabLabel.leadingAnchor constraintEqualToAnchor:tabHeader.leadingAnchor constant:10],
        [self.tabLabel.centerYAnchor constraintEqualToAnchor:tabHeader.centerYAnchor],
        [self.scriptEditor.topAnchor constraintEqualToAnchor:tabHeader.bottomAnchor],
        [self.scriptEditor.leadingAnchor constraintEqualToAnchor:tabHeader.leadingAnchor],
        [self.scriptEditor.trailingAnchor constraintEqualToAnchor:tabHeader.trailingAnchor],
        [self.scriptEditor.bottomAnchor constraintEqualToAnchor:actionBar.topAnchor constant:-10],
        [actionBar.leadingAnchor constraintEqualToAnchor:tabHeader.leadingAnchor],
        [actionBar.trailingAnchor constraintEqualToAnchor:tabHeader.trailingAnchor],
        [actionBar.bottomAnchor constraintEqualToAnchor:self.editorTabView.bottomAnchor],
        [actionBar.heightAnchor constraintEqualToConstant:35],
        [btnStack.leadingAnchor constraintEqualToAnchor:actionBar.leadingAnchor],
        [btnStack.trailingAnchor constraintEqualToAnchor:actionBar.trailingAnchor],
        [btnStack.topAnchor constraintEqualToAnchor:actionBar.topAnchor],
        [btnStack.bottomAnchor constraintEqualToAnchor:actionBar.bottomAnchor]
    ]];
}

// --- ADDED BASE64 DECODE IMPLEMENTATION ---
- (void)decodeBase64Action {
    NSString *b64String = self.scriptEditor.text;
    b64String = [b64String stringByReplacingOccurrencesOfString:@"\n" withString:@""];
    b64String = [b64String stringByReplacingOccurrencesOfString:@"\r" withString:@""];
    b64String = [b64String stringByReplacingOccurrencesOfString:@" " withString:@""];
    
    NSData *decodedData = [[NSData alloc] initWithBase64EncodedString:b64String options:0];
    if (decodedData) {
        NSString *decodedString = [[NSString alloc] initWithData:decodedData encoding:NSUTF8StringEncoding];
        if (decodedString) {
            self.scriptEditor.text = decodedString;
            UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Success" message:@"Base64 Decoded!" preferredStyle:UIAlertControllerStyleAlert];
            [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
            [self presentViewController:alert animated:YES completion:nil];
        } else {
            self.scriptEditor.text = @"[Decode Error: Result is not UTF8 text]";
        }
    } else {
        self.scriptEditor.text = @"[Decode Error: Invalid Base64]";
    }
}

// ... [Keep the rest of the UI methods the same] ...
