#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN

@interface ZTFloatingButton : UIButton
+ (instancetype)sharedButton;
- (void)attachToWindow:(UIWindow *)window;
- (void)show;
- (void)hide;
@end

@interface ZTFloatingWindow : UIWindow
+ (instancetype)sharedWindow;
- (void)show;
- (void)hide;
@end

@interface ZTMenuManager : NSObject
+ (instancetype)sharedManager;
- (void)setupInAppMenu;
- (void)tryAttachFloatingButton;
- (void)showColdBootBanner;
- (void)presentMainMenuFrom:(nullable UIViewController *)presentingVC;
- (void)showPreRegDiagnosticFrom:(UIViewController *)top;
- (void)showIdleSocketRadarFrom:(UIViewController *)top;
- (void)showAdvancedSettingsFrom:(UIViewController *)top;
- (void)showHardwareSpoofSettingsFrom:(UIViewController *)top;
- (void)startAutoUSWipeSequenceFrom:(UIViewController *)top;
- (void)startAutoVNWipeSequenceFrom:(UIViewController *)top;
- (void)confirmDeepWipeFrom:(UIViewController *)top;
- (void)promptSmartAutoWipeFrom:(UIViewController *)top;
- (void)performInAppDeepWipe;
- (void)performInAppDeepWipeWithRegion:(NSString *)region;
- (void)performInAppDeepWipeWithRegion:(NSString *)region preferredCarrier:(nullable NSString *)preferredCarrier currentIP:(nullable NSString *)currentIP;
- (void)performInAppDeepWipeWithRegion:(NSString *)region preferredCarrier:(nullable NSString *)preferredCarrier currentIP:(nullable NSString *)currentIP targetTimeZone:(nullable NSString *)targetTimeZone;
- (void)startInAppDeepWipeSequenceWithRegion:(NSString *)targetRegion preferredCarrier:(nullable NSString *)preferredCarrier from:(UIViewController *)top;
@end

#ifdef __cplusplus
extern "C" {
#endif

UIViewController * _Nullable ZTGetTopViewController(void);

#ifdef __cplusplus
}
#endif

NS_ASSUME_NONNULL_END
