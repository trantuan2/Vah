#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <UserNotifications/UserNotifications.h>
#import <objc/runtime.h>
#import <Security/Security.h>
#import <CommonCrypto/CommonDigest.h>
#import <CFNetwork/CFNetwork.h>
#import <SystemConfiguration/CaptiveNetwork.h>
#import <mach-o/dyld.h>
#import <sys/sysctl.h>
#import <sys/utsname.h>
#import <sys/stat.h>
#import <sys/mount.h>
#import <sys/statvfs.h>
#import <sys/attr.h>
#import <ifaddrs.h>
#import <net/if.h>
#import <sys/socket.h>
#import <netinet/in.h>
#import <arpa/inet.h>
#import <CoreTelephony/CTCarrier.h>
#import <CoreTelephony/CTTelephonyNetworkInfo.h>
#import <fcntl.h>
#import <unistd.h>
#import <stdlib.h>
#import <string.h>
#import <errno.h>
#import <stdarg.h>
#import <stdio.h>
#import <dlfcn.h>
#import <time.h>
#import <mach/mach_time.h>
#import <pthread.h>
#import "fishhook.h"
#import "Config.h"
#import "SecurityManager.h"
#import "FloatingMenu.h"
#import "DeviceProfilePool.h"

__attribute__((visibility("default"))) void zt_reset_runtime_counters(void);
__attribute__((visibility("default"))) NSInteger zt_get_last_centralized_status(void);
__attribute__((visibility("default"))) NSString *zt_get_last_centralized_did(void);
__attribute__((visibility("default"))) NSInteger zt_get_qos_error_count(void);
__attribute__((visibility("default"))) int zt_get_masked_ifaddrs(struct ifaddrs **ifap);
__attribute__((visibility("default"))) void zt_log_audit(NSString *category, NSString *detail);

static void (*dynamic_MSHookFunction)(void *symbol, void *replace, void **result) = NULL;
#if __has_feature(ptrauth_calls)
#import <ptrauth.h>
#endif

static inline void *strip_pac_ptr(const void *ptr) {
    if (!ptr) return NULL;
#if __has_feature(ptrauth_calls)
    return ptrauth_strip((void *)ptr, ptrauth_key_asia);
#elif defined(__arm64e__)
    void *ret = (void *)ptr;
    asm volatile("xpaci %0" : "+r"(ret));
    return ret;
#else
    return (void *)((uintptr_t)ptr & 0x00007FFFFFFFFFFFULL);
#endif
}

static int (*orig_dladdr)(const void *addr, Dl_info *info) = NULL;

static inline int raw_dladdr(const void *addr, Dl_info *info) {
    if (!addr) return 0;
    const void *clean_addr = strip_pac_ptr(addr);
    return orig_dladdr ? orig_dladdr(clean_addr, info) : dladdr(clean_addr, info);
}

static inline void universal_hook_c_function(const char *name, void *symbol, void *replace, void **result) {
    void *ms_orig = NULL;
    if (dynamic_MSHookFunction && symbol) {
        dynamic_MSHookFunction(symbol, replace, &ms_orig);
    }
    if (ms_orig != NULL) {
        if (result) *result = ms_orig;
        // MSHookFunction đã patch trực tiếp prologue của symbol.
        // Khi chạy bổ sung rebind_symbols cho các bảng GOT/LAZY, truyền NULL cho replaced
        // để fishhook KHÔNG ghi đè *result bằng địa chỉ symbol đã bị patch (tránh đệ quy vô tận)!
        if (name) {
            struct rebinding r = { name, replace, NULL };
            rebind_symbols(&r, 1);
        }
    } else {
        // MSHookFunction không có sẵn (Sideload/Clone) hoặc từ chối patch syscall stub 12-byte:
        // Dùng fishhook rebind toàn bộ GOT/PLT và lưu con trỏ hàm gốc chính xác vào *result!
        void *fh_orig = NULL;
        if (name) {
            struct rebinding r = { name, replace, &fh_orig };
            rebind_symbols(&r, 1);
        }
        if (result) {
            *result = (fh_orig != NULL && fh_orig != replace) ? fh_orig : symbol;
        }
    }
}

static inline BOOL is_tweak_active(void) {
    static __thread BOOL s_in_active_check = NO;
    if (s_in_active_check) return NO;
    s_in_active_check = YES;
    // Chỉ fake khi tweak bật VÀ đã từng cấu hình profile (đã có key và đã từng bấm wipe)
    // Khi hết hạn, profile vẫn được đóng băng giữ nguyên để bảo vệ tài khoản, không rớt về máy thật!
    BOOL active = [ZTSettings sharedSettings].enabled && [ZTSettings sharedSettings].hasConfiguredProfile;
    s_in_active_check = NO;
    return active;
}

static int s_is_orig = -1;
static inline BOOL is_original_zalo_app(void) {
    if (s_is_orig != -1) return (s_is_orig == 1);
    
    NSString *bundleId = nil;
    NSDictionary *info = [[NSBundle mainBundle] infoDictionary];
    if (info && [info isKindOfClass:[NSDictionary class]]) {
        bundleId = info[@"CFBundleIdentifier"];
    }
    if (!bundleId) {
        CFBundleRef mb = CFBundleGetMainBundle();
        if (mb) {
            CFStringRef cbid = CFBundleGetIdentifier(mb);
            if (cbid) bundleId = (__bridge NSString *)cbid;
        }
    }
    if (bundleId && bundleId.length > 0) {
        if ([bundleId isEqualToString:@"vn.com.vng.zingalo"] ||
            [bundleId isEqualToString:@"com.vng.zalo"] ||
            [bundleId isEqualToString:@"com.zing.zalo"]) {
            s_is_orig = 1;
            return YES;
        } else {
            s_is_orig = 0;
            return NO;
        }
    }
    
    const char *pname = getprogname();
    if (pname && (strstr(pname, "Zalo") != NULL || strstr(pname, "zingalo") != NULL)) {
        return YES; // Tạm thời coi là bản gốc trong lúc runtime đang khởi tạo
    }
    return YES; // Mặc định an toàn bảo vệ APNs thật
}

static inline __attribute__((unused)) BOOL has_system_preferenceloader(void) {
    static int s_has_pl = -1;
    if (s_has_pl != -1) return (s_has_pl == 1);
    const char *paths[] = {
        "/Library/PreferenceLoader/Preferences",
        "/var/jb/Library/PreferenceLoader/Preferences",
        "/var/jb/usr/lib",
        NULL
    };
    for (int i = 0; paths[i] != NULL; i++) {
        if (access(paths[i], F_OK) == 0) {
            s_has_pl = 1;
            return YES;
        }
    }
    s_has_pl = 0;
    return NO;
}

static inline BOOL is_device_jailbroken(void) {
#if defined(THEOS_PACKAGE_SCHEME_ROOTHIDE) || defined(THEOS_PACKAGE_SCHEME_ROOTLESS)
    return YES;
#endif
    if (dlsym(RTLD_DEFAULT, "jbrand") != NULL ||
        dlsym(RTLD_DEFAULT, "jbroot") != NULL ||
        dlsym(RTLD_DEFAULT, "roothide_check_path") != NULL ||
        dlsym(RTLD_DEFAULT, "MSHookFunction") != NULL ||
        dlsym(RTLD_DEFAULT, "ellekit_hook_c_function") != NULL ||
        dlsym(RTLD_DEFAULT, "cydia_substitute_hook_functions") != NULL ||
        getenv("JB_ROOT_PATH") != NULL ||
        getenv("ROOTHIDE_JB_ROOT_PATH") != NULL ||
        [[NSFileManager defaultManager] fileExistsAtPath:@"/var/jb"]) {
        return YES;
    }

    Dl_info info;
    if (raw_dladdr((const void *)is_device_jailbroken, &info) && info.dli_fname) {
        NSString *dpath = [NSString stringWithUTF8String:info.dli_fname];
        NSString *appBundle = [[NSBundle mainBundle] bundlePath];
        if (appBundle && ![dpath hasPrefix:appBundle]) {
            return YES; // Nạp từ ngoài App Bundle -> Chắc chắn là môi trường Jailbreak!
        }
    }
    return NO;
}

static inline BOOL is_zalo_caller(const void *addr0) {
    if (!addr0) return NO;
    Dl_info info0;
    if (raw_dladdr(addr0, &info0) && info0.dli_fname) {
        const char *f0 = info0.dli_fname;
        if ((strstr(f0, ".app/") != NULL || strstr(f0, "/Zalo.app") != NULL) &&
            strstr(f0, "Zalotweak") == NULL &&
            strstr(f0, "roothide") == NULL &&
            strstr(f0, "Substrate") == NULL &&
            strstr(f0, "ellekit") == NULL) {
            return YES;
        }
    }
    return NO;
}

static inline BOOL __attribute__((unused)) is_zalo_or_tweak_caller(const void *addr0, const void *addr1) {
    if (is_zalo_caller(addr0) || is_zalo_caller(addr1)) return YES;
    const void *addrs[2] = {addr0, addr1};
    for (int i = 0; i < 2; i++) {
        if (!addrs[i]) continue;
        Dl_info info0;
        if (raw_dladdr(addrs[i], &info0) && info0.dli_fname) {
            const char *f0 = info0.dli_fname;
            if (strstr(f0, "Zalotweak") != NULL) {
                return YES;
            }
        }
    }
    return NO;
}

static inline BOOL __attribute__((unused)) is_network_system_caller(const void *addr) {
    if (!addr) return NO;
    Dl_info info;
    if (raw_dladdr(addr, &info) && info.dli_fname) {
        const char *f = info.dli_fname;
        if (strstr(f, "CFNetwork") != NULL ||
            strstr(f, "libnetwork") != NULL ||
            strstr(f, "Network.framework") != NULL ||
            strstr(f, "CoreTelephony") != NULL ||
            strstr(f, "SystemConfiguration") != NULL) {
            return YES;
        }
    }
    return NO;
}

static inline BOOL __attribute__((unused)) is_system_caller(const void *addr0, const void *addr1) {
    const void *addrs[2] = {addr0, addr1};
    for (int i = 0; i < 2; i++) {
        if (!addrs[i]) continue;
        Dl_info info;
        if (raw_dladdr(addrs[i], &info) && info.dli_fname) {
            const char *fname = info.dli_fname;
            if (strstr(fname, "/System/Library/") != NULL ||
                strstr(fname, "/usr/lib/") != NULL ||
                strstr(fname, "CFNetwork") != NULL ||
                strstr(fname, "Network") != NULL ||
                strstr(fname, "libnetwork") != NULL ||
                strstr(fname, "CoreTelephony") != NULL ||
                strstr(fname, "UserNotifications") != NULL ||
                strstr(fname, "CoreFoundation") != NULL ||
                strstr(fname, "Foundation") != NULL ||
                strstr(fname, "Security") != NULL ||
                strstr(fname, "SystemConfiguration") != NULL ||
                strstr(fname, "Substrate") != NULL ||
                strstr(fname, "ellekit") != NULL ||
                strstr(fname, "ElleKit") != NULL ||
                strstr(fname, "roothide") != NULL ||
                strstr(fname, "Zalotweak") != NULL) {
                return YES;
            }
        }
    }
    return NO;
}

#define MAX_RADAR_CALLERS 256
static void *s_radar_logged_addrs[MAX_RADAR_CALLERS];
static int s_radar_logged_count = 0;
static pthread_mutex_t s_radar_lock = PTHREAD_MUTEX_INITIALIZER;

static BOOL should_log_radar_caller(void *addr) {
    if (!addr) return NO;
    pthread_mutex_lock(&s_radar_lock);
    for (int i = 0; i < s_radar_logged_count; i++) {
        if (s_radar_logged_addrs[i] == addr) {
            pthread_mutex_unlock(&s_radar_lock);
            return NO;
        }
    }
    if (s_radar_logged_count < MAX_RADAR_CALLERS) {
        s_radar_logged_addrs[s_radar_logged_count++] = addr;
    }
    pthread_mutex_unlock(&s_radar_lock);
    return YES;
}

static NSString *format_caller_info(void *addr) {
    if (!addr) return @"(unknown)";
    Dl_info info;
    if (raw_dladdr(addr, &info)) {
        const char *fname = info.dli_fname ? (strrchr(info.dli_fname, '/') ? strrchr(info.dli_fname, '/') + 1 : info.dli_fname) : "unknown";
        const char *sname = info.dli_sname ?: "unknown_sym";
        ptrdiff_t offset = (const char *)addr - (const char *)(info.dli_saddr ?: info.dli_fbase);
        return [NSString stringWithFormat:@"%s`%s + 0x%lx (%p)", fname, sname, (long)offset, addr];
    }
    return [NSString stringWithFormat:@"%p", addr];
}

static void zt_reset_radar_cache(void) {
    pthread_mutex_lock(&s_radar_lock);
    s_radar_logged_count = 0;
    pthread_mutex_unlock(&s_radar_lock);
}

#define GLOBAL_PREFS_PATH @"/var/mobile/Library/Preferences/com.sonhu.zalotweak.plist"
#define GLOBAL_AUDIT_LOG_PATH @"/var/mobile/Library/Preferences/ZaloAudit.log"

static NSString *get_roothide_prefs_path(void) {
    typedef const char* (*jbroot_fn_t)(const char*);
    jbroot_fn_t jbroot_fn = (jbroot_fn_t)dlsym(RTLD_DEFAULT, "jbroot");
    if (jbroot_fn) {
        const char *p = jbroot_fn("/var/mobile/Library/Preferences/com.sonhu.zalotweak.plist");
        if (p) return [NSString stringWithUTF8String:p];
    }
    return GLOBAL_PREFS_PATH;
}

static inline BOOL has_active_session_in_sandbox(void) {
    NSString *home = NSHomeDirectory();
    if (!home) return NO;
    NSString *zaloPref = [home stringByAppendingPathComponent:@"Library/Preferences/vn.com.vng.zingalo.plist"];
    if ([[NSFileManager defaultManager] fileExistsAtPath:zaloPref]) {
        NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:zaloPref];
        if (d && (d[@"kSessionUid"] || d[@"kSessionKey"])) {
            return YES;
        }
    }
    return NO;
}

// Tìm đường dẫn file cấu hình tối ưu để vượt rào Sandbox
static NSString *getConfigPath(void) {
    NSString *home = NSHomeDirectory();
    if (home) {
        NSString *containerPref = [home stringByAppendingPathComponent:@"Library/Preferences/com.sonhu.zalotweak.plist"];
        NSFileManager *fm = [NSFileManager defaultManager];

        // Luôn kiểm tra các ứng viên toàn cục từ Cài Đặt (Roothide / Rootless / jbroot) xem có bản ghi mới hơn không
        NSString *rhPath = get_roothide_prefs_path();
        NSArray *globalCandidates = @[
            rhPath,
            GLOBAL_PREFS_PATH,
            @"/var/jb/var/mobile/Library/Preferences/com.sonhu.zalotweak.plist",
            @"/private/var/mobile/Library/Preferences/com.sonhu.zalotweak.plist"
        ];

        NSDate *localDate = nil;
        NSDictionary *localDict = nil;
        uint64_t localWipeTS = 0;
        BOOL localNeedsWipe = NO;
        BOOL justRestored = NO;
        if ([fm fileExistsAtPath:containerPref]) {
            NSDictionary *localAttrs = [fm attributesOfItemAtPath:containerPref error:nil];
            localDate = localAttrs[NSFileModificationDate];
            localDict = [NSDictionary dictionaryWithContentsOfFile:containerPref];
            localWipeTS = [localDict[@"lastWipedTimestamp"] unsignedLongLongValue];
            localNeedsWipe = [localDict[@"needsNewProfile"] boolValue] || [localDict[@"needsSandboxPurge"] boolValue] || [localDict[@"needsKeychainPurge"] boolValue];
            justRestored = [localDict[@"justRestoredBackup"] boolValue];
        }

        // BẢO VỆ TUYỆT ĐỐI CHO TÀI KHOẢN KHI RESTORE:
        // Chỉ hủy cờ wipe nếu vừa thực sự Restore từ Backup (justRestoredBackup = YES)
        // hoặc khi containerPref KHÔNG yêu cầu wipe nhưng đã có phiên đăng nhập hợp lệ.
        BOOL hasSession = has_active_session_in_sandbox();
        if (justRestored && [fm fileExistsAtPath:containerPref]) {
            NSMutableDictionary *m = [NSMutableDictionary dictionaryWithContentsOfFile:containerPref];
            if (m) {
                m[@"needsNewProfile"] = @(NO);
                m[@"needsSandboxPurge"] = @(NO);
                m[@"needsKeychainPurge"] = @(NO);
                [m writeToFile:containerPref atomically:YES];
                [m writeToFile:GLOBAL_PREFS_PATH atomically:YES];
            }
            return containerPref;
        }
        if (hasSession && !localNeedsWipe && [fm fileExistsAtPath:containerPref]) {
            return containerPref;
        }

        // Nếu containerPref đang giữ cờ chờ Cold-Boot Wipe, tuyệt đối không lấy bản global cũ đè lên!
        if (!localNeedsWipe) {
            for (NSString *candidate in globalCandidates) {
                if ([fm fileExistsAtPath:candidate]) {
                    NSDictionary *candAttrs = [fm attributesOfItemAtPath:candidate error:nil];
                    NSDate *candDate = candAttrs[NSFileModificationDate];
                    if (!localDate || (candDate && [candDate compare:localDate] == NSOrderedDescending)) {
                        NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:candidate];
                        uint64_t candWipeTS = [d[@"lastWipedTimestamp"] unsignedLongLongValue];
                        if (d && d.count > 0 && candWipeTS >= localWipeTS) {
                            [fm createDirectoryAtPath:[containerPref stringByDeletingLastPathComponent] withIntermediateDirectories:YES attributes:nil error:nil];
                            [d writeToFile:containerPref atomically:YES];
                            chmod([containerPref UTF8String], 0666);
                            return containerPref;
                        }
                    }
                }
            }
        }

        if ([fm fileExistsAtPath:containerPref]) {
            return containerPref;
        }

        NSString *containerDoc = [home stringByAppendingPathComponent:@"Documents/com.sonhu.zalotweak.plist"];
        if ([fm fileExistsAtPath:containerDoc]) {
            return containerDoc;
        }

        // Khi file chưa tồn tại (lần đầu chạy), luôn trả về containerPref
        return containerPref;
    }

    NSString *groupBase = @"/var/mobile/Containers/Shared/AppGroup";
    NSArray *subdirs = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:groupBase error:nil];
    for (NSString *uuid in subdirs) {
        NSString *metaPath = [groupBase stringByAppendingPathComponent:[NSString stringWithFormat:@"%@/.com.apple.mobile_container_manager.metadata.plist", uuid]];
        NSDictionary *meta = [NSDictionary dictionaryWithContentsOfFile:metaPath];
        NSString *identifier = meta[@"MCMMetadataIdentifier"];
        if ([identifier containsString:@"zalo"] || [identifier containsString:@"vng"]) {
            NSString *groupPref = [groupBase stringByAppendingPathComponent:[NSString stringWithFormat:@"%@/com.sonhu.zalotweak.plist", uuid]];
            if ([[NSFileManager defaultManager] fileExistsAtPath:groupPref]) {
                return groupPref;
            }
        }
    }

    return GLOBAL_PREFS_PATH;
}

static int (*orig_sysctlbyname)(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) = NULL;
static NSString *s_true_hardware_machine = nil;

static NSString *get_real_hardware_machine(void) {
    if (s_true_hardware_machine && s_true_hardware_machine.length > 0) {
        return s_true_hardware_machine;
    }
    char buf[64] = {0};
    size_t size = sizeof(buf);
    if (orig_sysctlbyname) {
        orig_sysctlbyname("hw.machine", buf, &size, NULL, 0);
    } else {
        sysctlbyname("hw.machine", buf, &size, NULL, 0);
    }
    if (strlen(buf) > 0) {
        s_true_hardware_machine = [NSString stringWithUTF8String:buf];
        [ZTDeviceProfile setRealHardwareMachine:s_true_hardware_machine];
        return s_true_hardware_machine;
    }
    struct utsname u;
    if (uname(&u) == 0 && strlen(u.machine) > 0) {
        s_true_hardware_machine = [NSString stringWithUTF8String:u.machine];
        [ZTDeviceProfile setRealHardwareMachine:s_true_hardware_machine];
        return s_true_hardware_machine;
    }
    s_true_hardware_machine = @"iPhone14,5";
    [ZTDeviceProfile setRealHardwareMachine:s_true_hardware_machine];
    return s_true_hardware_machine;
}

static NSString *get_real_hardware_model(void) {
    char buf[64] = {0};
    size_t size = sizeof(buf);
    if (orig_sysctlbyname) {
        orig_sysctlbyname("hw.model", buf, &size, NULL, 0);
    } else {
        sysctlbyname("hw.model", buf, &size, NULL, 0);
    }
    if (strlen(buf) > 0) {
        return [NSString stringWithUTF8String:buf];
    }
    return @"D17AP";
}

static NSString *get_real_os_version(void) {
    char buf[64] = {0};
    size_t size = sizeof(buf);
    if (orig_sysctlbyname) {
        orig_sysctlbyname("kern.osversion", buf, &size, NULL, 0);
    } else {
        sysctlbyname("kern.osversion", buf, &size, NULL, 0);
    }
    if (strlen(buf) > 0) {
        return [NSString stringWithUTF8String:buf];
    }
    return @"21F90";
}

static NSString *get_real_product_version(void) {
    NSDictionary *dict = [NSDictionary dictionaryWithContentsOfFile:@"/System/Library/CoreServices/SystemVersion.plist"];
    if (dict && dict[@"ProductVersion"]) {
        return [dict[@"ProductVersion"] copy];
    }
    return @"15.8.3";
}

static __attribute__((unused)) uint64_t get_real_disk_total_size(void) {
    NSDictionary *attrs = [[NSFileManager defaultManager] attributesOfFileSystemForPath:NSHomeDirectory() error:nil];
    NSNumber *total = attrs[NSFileSystemSize];
    if (total && [total unsignedLongLongValue] > 0) {
        return [total unsignedLongLongValue];
    }
    return 128000000000ULL;
}
// Forward declaration - hàm logAudit được định nghĩa ở phần sau
static void logAudit(NSString *category, NSString *detail);

static BOOL s_session_profile_locked = NO;

@implementation ZTSettings

+ (instancetype)sharedSettings {
    static ZTSettings *instance = nil;
    if (instance) return instance;
    static BOOL s_initializing = NO;
    if (s_initializing) return instance;
    s_initializing = YES;
    instance = [[ZTSettings alloc] init];
    [instance loadSettings];
    s_session_profile_locked = YES;
    s_initializing = NO;
    return instance;
}

static void purge_directory_recursively_safely(NSString *targetPath) {
    if (!targetPath || targetPath.length == 0) return;
    NSFileManager *fm = [NSFileManager defaultManager];
    BOOL isDir = NO;
    if (![fm fileExistsAtPath:targetPath isDirectory:&isDir]) return;

    NSString *lower = [targetPath lowercaseString];
    if ([lower hasSuffix:@".adbk"] ||
        [lower containsString:@"appsmanager"] ||
        [lower containsString:@"com.sonhu.zalotweak"] ||
        [lower containsString:@"splashboard"] ||
        [lower containsString:@"saved application state"] ||
        [lower containsString:@"zaloaudit.log"] ||
        [lower containsString:@"zalotraffic.har"]) {
        return;
    }

    if (!isDir) {
        [fm removeItemAtPath:targetPath error:nil];
        return;
    }

    NSArray *contents = [fm contentsOfDirectoryAtPath:targetPath error:nil];
    for (NSString *sub in contents) {
        NSString *subLower = [sub lowercaseString];
        if ([subLower hasSuffix:@".adbk"] ||
            [subLower containsString:@"appsmanager"] ||
            [subLower containsString:@"com.sonhu.zalotweak"] ||
            [subLower containsString:@"splashboard"] ||
            [subLower containsString:@"saved application state"] ||
            [subLower isEqualToString:@"zaloaudit.log"] ||
            [subLower isEqualToString:@"zalotraffic.har"]) {
            continue;
        }
        NSString *fullSub = [targetPath stringByAppendingPathComponent:sub];
        purge_directory_recursively_safely(fullSub);
    }
    // Không xoá chính thư mục gốc Library, Documents, tmp hoặc Application Support
    NSString *lastComp = [targetPath lastPathComponent];
    if (![lastComp isEqualToString:@"Library"] &&
        ![lastComp isEqualToString:@"Documents"] &&
        ![lastComp isEqualToString:@"tmp"] &&
        ![lastComp isEqualToString:@"Application Support"]) {
        [fm removeItemAtPath:targetPath error:nil];
    }
}

static BOOL s_is_cold_boot_phase = YES;

static void clear_all_network_caches(void) {
    [[NSURLCache sharedURLCache] removeAllCachedResponses];
    NSHTTPCookieStorage *cookieStorage = [NSHTTPCookieStorage sharedHTTPCookieStorage];
    for (NSHTTPCookie *cookie in [cookieStorage cookies]) {
        [cookieStorage deleteCookie:cookie];
    }
    if ([NSURLSessionConfiguration respondsToSelector:@selector(defaultSessionConfiguration)]) {
        NSURLSessionConfiguration *def = [NSURLSessionConfiguration defaultSessionConfiguration];
        [def.URLCache removeAllCachedResponses];
        if (def.HTTPCookieStorage) {
            for (NSHTTPCookie *c in [def.HTTPCookieStorage cookies]) {
                [def.HTTPCookieStorage deleteCookie:c];
            }
        }
    }
}

static BOOL s_logged_c_bid = NO;
static BOOL s_logged_c_info_bid = NO;

static void reset_audit_log_on_wipe(NSString *machine, NSString *idfv) {
    s_logged_c_bid = NO;
    s_logged_c_info_bid = NO;
    zt_reset_runtime_counters();
    zt_reset_radar_cache();

    NSString *home = NSHomeDirectory();
    if (!home) return;
    NSString *docDir = [home stringByAppendingPathComponent:@"Documents"];
    NSString *auditPath = [docDir stringByAppendingPathComponent:@"ZaloAudit.log"];
    NSString *harPath = [docDir stringByAppendingPathComponent:@"ZaloTraffic.har"];

    NSFileManager *fm = [NSFileManager defaultManager];
    [fm removeItemAtPath:harPath error:nil];

    NSDateFormatter *df = [[NSDateFormatter alloc] init];
    [df setDateFormat:@"yyyy-MM-dd HH:mm:ss"];
    NSString *timeStr = [df stringFromDate:[NSDate date]];

    NSString *appType = is_original_zalo_app() ? @"Zalo Gốc (vn.com.vng.zingalo)" : @"Zalo Clone (Đã bẻ hướng C-layer & APNs Token)";

    NSString *header = [NSString stringWithFormat:
        @"================================================================================\n"
        @"🚀 [SYSTEM-INIT] === BẮT ĐẦU PHIÊN AUDIT MỚI SAU DEEP WIPE ===\n"
        @"🕒 Thời gian kích hoạt: %@\n"
        @"📱 Thiết bị: %@ | IDFV: %@\n"
        @"📦 Gói Ứng Dụng: %@\n"
        @"================================================================================\n\n",
        timeStr, machine ?: @"iPhone", idfv ?: @"N/A", appType];

    [header writeToFile:auditPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
    chmod([auditPath UTF8String], 0666);

    if (is_device_jailbroken()) {
        [header writeToFile:GLOBAL_AUDIT_LOG_PATH atomically:YES encoding:NSUTF8StringEncoding error:nil];
        chmod([GLOBAL_AUDIT_LOG_PATH UTF8String], 0666);
    }
}

static void purge_all_zalo_keychain_safely(void) {
    NSArray *secClasses = @[
        (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecClassInternetPassword,
        (__bridge id)kSecClassCertificate,
        (__bridge id)kSecClassKey,
        (__bridge id)kSecClassIdentity
    ];

    // 1. Quét liệt kê toàn bộ item thực tế qua SecItemCopyMatching để lấy đúng kSecAttrAccessGroup có tiền tố <TeamID>. thật của Apple và xóa đích danh từng mục
    for (id secClass in secClasses) {
        NSDictionary *enumQuery = @{
            (__bridge id)kSecClass: secClass,
            (__bridge id)kSecAttrSynchronizable: (__bridge id)kSecAttrSynchronizableAny,
            (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitAll,
            (__bridge id)kSecReturnAttributes: @YES
        };
        CFTypeRef result = NULL;
        OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)enumQuery, &result);
        if (status == errSecSuccess && result) {
            NSArray *items = (CFGetTypeID(result) == CFArrayGetTypeID()) ? (__bridge NSArray *)result : @[(__bridge id)result];
            for (NSDictionary *item in items) {
                if (![item isKindOfClass:[NSDictionary class]]) continue;
                NSMutableDictionary *delQ = [NSMutableDictionary dictionary];
                delQ[(__bridge id)kSecClass] = secClass;
                if (item[(__bridge id)kSecAttrAccessGroup]) delQ[(__bridge id)kSecAttrAccessGroup] = item[(__bridge id)kSecAttrAccessGroup];
                if (item[(__bridge id)kSecAttrService]) delQ[(__bridge id)kSecAttrService] = item[(__bridge id)kSecAttrService];
                if (item[(__bridge id)kSecAttrAccount]) delQ[(__bridge id)kSecAttrAccount] = item[(__bridge id)kSecAttrAccount];
                delQ[(__bridge id)kSecAttrSynchronizable] = (__bridge id)kSecAttrSynchronizableAny;
                SecItemDelete((__bridge CFDictionaryRef)delQ);

                [delQ removeObjectForKey:(__bridge id)kSecAttrSynchronizable];
                SecItemDelete((__bridge CFDictionaryRef)delQ);
            }
        }
        if (result) CFRelease(result);
    }

    // 2. Xóa đích danh các key định danh thiết bị & lịch sử tài khoản cốt lõi của Zalo (kZAIDForDevice, kZAIDS4UserDevices...) trên mọi Access Group hợp lệ
    NSArray *targetAccounts = @[
        @"kZAIDForDevice",
        @"kZAIDS4UserDevices",
        @"kZADeviceId",
        @"zalo_device_id",
        @"zcid",
        @"kSessionKey",
        @"kSessionUid"
    ];
    for (NSString *acc in targetAccounts) {
        NSDictionary *accQ1 = @{
            (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
            (__bridge id)kSecAttrAccount: acc,
            (__bridge id)kSecAttrSynchronizable: (__bridge id)kSecAttrSynchronizableAny
        };
        SecItemDelete((__bridge CFDictionaryRef)accQ1);

        NSDictionary *accQ2 = @{
            (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
            (__bridge id)kSecAttrAccount: acc
        };
        SecItemDelete((__bridge CFDictionaryRef)accQ2);
    }

    // 3. Quét xóa diện rộng theo từng SecClass
    for (id secClass in secClasses) {
        NSMutableDictionary *broadQ = [NSMutableDictionary dictionary];
        broadQ[(__bridge id)kSecClass] = secClass;
        broadQ[(__bridge id)kSecAttrSynchronizable] = (__bridge id)kSecAttrSynchronizableAny;
        SecItemDelete((__bridge CFDictionaryRef)broadQ);

        [broadQ removeObjectForKey:(__bridge id)kSecAttrSynchronizable];
        SecItemDelete((__bridge CFDictionaryRef)broadQ);
    }
    NSLog(@"[ZaloAudit] [COLD-BOOT] 🔑 Đã dọn dẹp sạch toàn bộ Keychain (bao gồm kZAIDForDevice & kZAIDS4UserDevices) của Zalo!");
}

static void __attribute__((unused)) purge_webkit_data_safely(void) {
    Class wkClass = NSClassFromString(@"WKWebsiteDataStore");
    if (wkClass && [wkClass respondsToSelector:@selector(allWebsiteDataTypes)] && [wkClass respondsToSelector:@selector(defaultDataStore)]) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
        id types = [wkClass performSelector:@selector(allWebsiteDataTypes)];
        id dataStore = [wkClass performSelector:@selector(defaultDataStore)];
        if (dataStore && [dataStore respondsToSelector:@selector(removeDataOfTypes:modifiedSince:completionHandler:)]) {
            NSDate *dateFrom = [NSDate dateWithTimeIntervalSince1970:0];
            typedef void (*RemoveDataFunc)(id, SEL, id, NSDate *, void (^)(void));
            SEL sel = @selector(removeDataOfTypes:modifiedSince:completionHandler:);
            RemoveDataFunc fn = (RemoveDataFunc)[dataStore methodForSelector:sel];
            if (fn) {
                fn(dataStore, sel, types, dateFrom, ^{});
            }
        }
#pragma clang diagnostic pop
    }
}

static void purge_entire_sandbox_safely(void) {
    NSString *home = NSHomeDirectory();
    if (!home || home.length < 5) return;
    NSFileManager *fm = [NSFileManager defaultManager];

    NSLog(@"[ZaloAudit] [COLD-BOOT] 🧹 Bắt đầu dọn dẹp sạch toàn bộ Sandbox tại Cold-Boot (App chưa khóa file)...");

    // 1. Quét sạch toàn bộ Keychain của Zalo để không bị dính vết vi phạm của tài khoản cũ
    purge_all_zalo_keychain_safely();

    // 2. Tuyệt đối KHÔNG gọi [UIPasteboard generalPasteboard] và purge_webkit_data_safely() tại %ctor!
    // Vì %ctor chạy trước hàm main() và UIApplicationMain(), việc gọi UIKit UI Server hoặc WebKit
    // Process Pool lúc này là nguyên nhân hàng đầu gây crash SIGABRT/SIGSEGV!
    // Việc xóa Clipboard và WebKit DataStore đã được thực hiện an toàn ngay lúc bấm Deep Wipe trong app.

    // 3. Xóa sạch dữ liệu in-memory của NSUserDefaults các App Suites & standardUserDefaults
    NSArray *suitesToPurge = @[
        @"group.vn.com.vng.zingalo",
        @"group.noti.vn.com.vng.zingalo",
        @"group.zsettings",
        @"group.com.vng.zalo",
        @"group.com.zing.zalo",
        @"com.zing.zalo.chatMigrateStore",
        @"vn.com.vng.zingalo.zalosdk",
        @"com.zing.zalo",
        @"vn.com.vng.zingalo"
    ];
    for (NSString *suite in suitesToPurge) {
        NSUserDefaults *ud = [[NSUserDefaults alloc] initWithSuiteName:suite];
        if (ud && ud != [NSUserDefaults standardUserDefaults]) {
            NSDictionary *d = [ud dictionaryRepresentation];
            for (NSString *k in d.allKeys) {
                if ([k.lowercaseString containsString:@"zalotweak"] || [k hasPrefix:@"ZT_"]) continue;
                [ud removeObjectForKey:k];
            }
            [ud synchronize];
        }
    }
    NSUserDefaults *stdUD = [NSUserDefaults standardUserDefaults];
    NSDictionary *stdDict = [stdUD dictionaryRepresentation];
    for (NSString *k in stdDict.allKeys) {
        if ([k.lowercaseString containsString:@"zalotweak"] || [k hasPrefix:@"ZT_"]) continue;
        [stdUD removeObjectForKey:k];
    }
    NSString *bundleId = [[NSBundle mainBundle] bundleIdentifier];
    if (bundleId && bundleId.length > 0 && ![bundleId.lowercaseString containsString:@"zalotweak"]) {
        [stdUD removePersistentDomainForName:bundleId];
    }
    [stdUD removePersistentDomainForName:@"vn.com.vng.zingalo"];
    [stdUD synchronize];
    CFPreferencesAppSynchronize(kCFPreferencesCurrentApplication);

    // 5. Xả sạch cache mạng bộ nhớ RAM
    clear_all_network_caches();

    NSString *docDir = [home stringByAppendingPathComponent:@"Documents"];
    NSString *libDir = [home stringByAppendingPathComponent:@"Library"];
    NSString *tmpDir = [home stringByAppendingPathComponent:@"tmp"];

    // 6. Quét dọn triệt để Documents và tmp
    purge_directory_recursively_safely(docDir);
    purge_directory_recursively_safely(tmpDir);

    // 7. Quét dọn toàn bộ các thư mục con trong Library (WebKit, Caches, Application Support, HTTPStorages, Cookies...)
    NSArray *libItems = [fm contentsOfDirectoryAtPath:libDir error:nil];
    for (NSString *item in libItems) {
        NSString *lower = [item lowercaseString];
        if ([lower containsString:@"com.sonhu.zalotweak"]) continue;
        if ([lower containsString:@"splashboard"] || [lower containsString:@"saved application state"]) continue;

        NSString *subDir = [libDir stringByAppendingPathComponent:item];
        if ([lower isEqualToString:@"preferences"]) {
            // Preferences: chỉ xóa các file plist của app và zalo, giữ lại cấu hình tweak
            NSArray *pItems = [fm contentsOfDirectoryAtPath:subDir error:nil];
            for (NSString *pItem in pItems) {
                if ([pItem.lowercaseString containsString:@"com.sonhu.zalotweak"]) continue;
                [fm removeItemAtPath:[subDir stringByAppendingPathComponent:pItem] error:nil];
            }
        } else {
            purge_directory_recursively_safely(subDir);
        }
    }

    // 8. Quét dọn Shared App Groups (nếu có quyền truy cập nhóm)
    NSArray *groupNames = @[
        @"group.vn.com.vng.zingalo",
        @"group.noti.vn.com.vng.zingalo",
        @"group.zsettings",
        @"group.com.vng.zalo",
        @"group.com.zing.zalo"
    ];
    for (NSString *grp in groupNames) {
        NSURL *groupURL = [fm containerURLForSecurityApplicationGroupIdentifier:grp];
        if (groupURL) {
            NSString *groupPath = [groupURL path];
            purge_directory_recursively_safely(groupPath);
        }
    }

    // Quét sâu bổ sung trực tiếp vào đường dẫn vật lý AppGroup trên hệ thống (Rootful + Rootless Roothide/Dopamine)
    NSArray *physicalGroupBases = @[
        @"/private/var/mobile/Containers/Shared/AppGroup",
        @"/var/mobile/Containers/Shared/AppGroup",
        @"/var/jb/var/mobile/Containers/Shared/AppGroup",
        @"/private/var/jb/var/mobile/Containers/Shared/AppGroup"
    ];
    NSMutableSet *scannedPhysicalGroups = [NSMutableSet set];
    for (NSString *base in physicalGroupBases) {
        BOOL isDir = NO;
        if (![fm fileExistsAtPath:base isDirectory:&isDir] || !isDir) continue;
        NSArray *subDirs = [fm contentsOfDirectoryAtPath:base error:nil];
        for (NSString *uuidDir in subDirs) {
            NSString *fullGroupDir = [base stringByAppendingPathComponent:uuidDir];
            if ([scannedPhysicalGroups containsObject:fullGroupDir]) continue;
            [scannedPhysicalGroups addObject:fullGroupDir];

            NSString *metaPlist = [fullGroupDir stringByAppendingPathComponent:@".com.apple.mobile_container_manager.metadata.plist"];
            if (![fm fileExistsAtPath:metaPlist]) {
                metaPlist = [fullGroupDir stringByAppendingPathComponent:@"metadata.plist"];
            }
            if ([fm fileExistsAtPath:metaPlist]) {
                NSDictionary *meta = [NSDictionary dictionaryWithContentsOfFile:metaPlist];
                NSString *ident = meta[@"MCMMetadataIdentifier"] ?: meta[@"CFBundleIdentifier"];
                if (ident && [ident isKindOfClass:[NSString class]]) {
                    NSString *lowIdent = [ident lowercaseString];
                    if ([lowIdent containsString:@"zalo"] || [lowIdent containsString:@"zingalo"] || [lowIdent containsString:@"zsettings"]) {
                        NSLog(@"[ZaloTweak-AppGroup] 🧹 [COLD-BOOT] Quét sạch vật lý App Group: %@ (ID: %@)", fullGroupDir, ident);
                        NSArray *gItems = [fm contentsOfDirectoryAtPath:fullGroupDir error:nil];
                        for (NSString *gItem in gItems) {
                            if ([gItem containsString:@"metadata.plist"]) continue; // Bảo toàn metadata gốc của iOS
                            purge_directory_recursively_safely([fullGroupDir stringByAppendingPathComponent:gItem]);
                        }
                    }
                }
            }
        }
    }

    // 9. Tái tạo sẵn khung thư mục rỗng chuẩn để Zalo không bị crash I/O khi nạp
    [fm createDirectoryAtPath:docDir withIntermediateDirectories:YES attributes:nil error:nil];
    [fm createDirectoryAtPath:tmpDir withIntermediateDirectories:YES attributes:nil error:nil];
    [fm createDirectoryAtPath:[libDir stringByAppendingPathComponent:@"Preferences"] withIntermediateDirectories:YES attributes:nil error:nil];
    [fm createDirectoryAtPath:[libDir stringByAppendingPathComponent:@"Caches"] withIntermediateDirectories:YES attributes:nil error:nil];
    [fm createDirectoryAtPath:[libDir stringByAppendingPathComponent:@"WebKit"] withIntermediateDirectories:YES attributes:nil error:nil];
    [fm createDirectoryAtPath:[libDir stringByAppendingPathComponent:@"HTTPStorages"] withIntermediateDirectories:YES attributes:nil error:nil];
    [fm createDirectoryAtPath:[libDir stringByAppendingPathComponent:@"Application Support/KVCore/Device"] withIntermediateDirectories:YES attributes:nil error:nil];

    NSLog(@"[ZaloAudit] [COLD-BOOT] ✅ Hoàn tất dọn dẹp sạch toàn bộ Sandbox, Keychain & WebKit!");
}

- (void)loadSettings {
    NSString *path = getConfigPath();
    NSDictionary *dict = [NSDictionary dictionaryWithContentsOfFile:path];
    if (s_session_profile_locked) {
        // Atomic Session Profile: Khi phiên đang hoạt động, chỉ cập nhật cờ hiển thị UI, tuyệt đối KHÔNG ghi đè thông số phần cứng / OS / MNO
        if (dict) {
            if (dict[@"showFloatingMenu"] != nil) {
                self.showFloatingMenu = [dict[@"showFloatingMenu"] boolValue];
            }
            if (dict[@"enableAuditLog"] != nil) {
                self.enableAuditLog = [dict[@"enableAuditLog"] boolValue];
            }
        }
        return;
    }
    if (!dict) {
        CFPreferencesAppSynchronize(CFSTR("com.sonhu.zalotweak"));
        CFDictionaryRef cfDict = CFPreferencesCopyMultiple(NULL, CFSTR("com.sonhu.zalotweak"), kCFPreferencesCurrentUser, kCFPreferencesAnyHost);
        if (cfDict) {
            dict = [NSDictionary dictionaryWithDictionary:(__bridge NSDictionary *)cfDict];
            CFRelease(cfDict);
            if (dict.count > 0) {
                // Tự động lưu bản sao vào container Sandbox để các lần sau đọc siêu tốc
                NSString *home = NSHomeDirectory();
                if (home) {
                    NSString *localPref = [home stringByAppendingPathComponent:@"Library/Preferences/com.sonhu.zalotweak.plist"];
                    [[NSFileManager defaultManager] createDirectoryAtPath:[localPref stringByDeletingLastPathComponent] withIntermediateDirectories:YES attributes:nil error:nil];
                    [dict writeToFile:localPref atomically:YES];
                }
            }
        }
    }
    if (dict) {
        self.enabled = [dict[@"enabled"] boolValue];
        self.hasConfiguredProfile = [dict[@"hasConfiguredProfile"] boolValue];
        self.proxyEnabled = [dict[@"proxyEnabled"] boolValue];
        self.proxyType = dict[@"proxyType"] ?: @"HTTP";
        self.proxyHost = dict[@"proxyHost"] ?: @"";
        self.proxyPort = [dict[@"proxyPort"] unsignedShortValue];
        self.proxyUser = dict[@"proxyUser"] ?: @"";
        self.proxyPass = dict[@"proxyPass"] ?: @"";
        self.centralizedDid = dict[@"centralizedDid"] ?: @"";
        self.currentAPNsToken = dict[@"currentAPNsToken"] ?: @"";
        self.lastWipedAPNsToken = dict[@"lastWipedAPNsToken"] ?: @"";
        self.lastKnownAPNsToken = dict[@"lastKnownAPNsToken"] ?: @"";
        self.apnsRotatedStatus = dict[@"apnsRotatedStatus"] ?: @"";

        self.deviceMachine = dict[@"deviceMachine"] ?: get_real_hardware_machine();
        self.deviceModel = dict[@"deviceModel"] ?: get_real_hardware_model();
        self.deviceName = dict[@"deviceName"] ?: @"iPhone";
        self.systemVersion = dict[@"systemVersion"] ?: get_real_product_version();
        self.kernOsVersion = dict[@"kernOsVersion"] ?: get_real_os_version();
        self.ncpu = [dict[@"ncpu"] unsignedIntValue] ?: (uint32_t)[[NSProcessInfo processInfo] activeProcessorCount];
        self.memsize = [dict[@"memsize"] unsignedLongLongValue] ?: [[NSProcessInfo processInfo] physicalMemory];
        CGFloat defW = 375.0, defH = 667.0, defS = 2.0;
        [ZTDeviceProfile getScreenDimensionsForMachine:self.deviceMachine width:&defW height:&defH scale:&defS];
        self.screenWidth = [dict[@"screenWidth"] doubleValue] ?: defW;
        self.screenHeight = [dict[@"screenHeight"] doubleValue] ?: defH;
        self.screenScale = [dict[@"screenScale"] doubleValue] ?: defS;
        self.bootTimeSec = [dict[@"bootTimeSec"] unsignedLongLongValue] ?: 0;
        self.birthTimeSec = [dict[@"birthTimeSec"] unsignedLongLongValue] ?: 0;
        self.deltaVarSec = [dict[@"deltaVarSec"] unsignedIntValue] ?: 0;
        self.deltaMobileSec = [dict[@"deltaMobileSec"] unsignedIntValue] ?: 0;
        self.deltaSandboxSec = [dict[@"deltaSandboxSec"] unsignedIntValue] ?: 0;
        self.autoSyncTimezoneWithIP = dict[@"autoSyncTimezoneWithIP"] != nil ? [dict[@"autoSyncTimezoneWithIP"] boolValue] : YES;
        self.enableFakeTimeZone = dict[@"enableFakeTimeZone"] != nil ? [dict[@"enableFakeTimeZone"] boolValue] : NO;
        self.bootSessionUUID = dict[@"bootSessionUUID"] ?: @"";
        self.spoofedIDFV = dict[@"spoofedIDFV"] ?: (self.hasConfiguredProfile ? [[NSUUID UUID] UUIDString] : @"");
        self.spoofedIDFA = dict[@"spoofedIDFA"] ?: @"00000000-0000-0000-0000-000000000000";
        self.profileId = dict[@"profileId"] ?: (self.hasConfiguredProfile ? [[NSUUID UUID] UUIDString] : @"");
        self.diskTotalSize = (dict[@"diskTotalSize"] != nil) ? [dict[@"diskTotalSize"] unsignedLongLongValue] : 0ULL;
        self.diskFreeSize = (dict[@"diskFreeSize"] != nil) ? [dict[@"diskFreeSize"] unsignedLongLongValue] : 0ULL;
        self.enableAuditLog = [dict[@"enableAuditLog"] boolValue];
        self.lastWipedIDFV = dict[@"lastWipedIDFV"] ?: @"";
        self.lastWipedIP = dict[@"lastWipedIP"] ?: @"";
        self.lastWipedTimestamp = [dict[@"lastWipedTimestamp"] unsignedLongLongValue] ?: 0;
        self.carrierName = dict[@"carrierName"] ?: @"Viettel";
        self.carrierMCC = dict[@"carrierMCC"] ?: @"452";
        self.carrierMNC = dict[@"carrierMNC"] ?: @"04";
        self.carrierCountryCode = dict[@"carrierCountryCode"] ?: @"vn";
        self.batteryLevel = [dict[@"batteryLevel"] floatValue] ?: 0.85f;
        self.batteryState = [dict[@"batteryState"] integerValue] ?: 1;
        self.regionMode = dict[@"regionMode"] ?: @"VN";
        self.preferredCarrier = dict[@"preferredCarrier"] ?: @"";
        self.l2cacheSize = [dict[@"l2cacheSize"] unsignedLongLongValue] ?: 3145728ULL;
        if ([self.regionMode isEqualToString:@"US"] || [self.regionMode isEqualToString:@"US_STUDENT"]) {
            self.localeIdentifier = dict[@"localeIdentifier"] ?: @"en_US";
            self.timeZoneName = dict[@"timeZoneName"] ?: @"America/New_York";
            self.preferredLanguages = dict[@"preferredLanguages"] ?: @[@"en-US"];
        } else if ([self.regionMode isEqualToString:@"PL"]) {
            self.localeIdentifier = dict[@"localeIdentifier"] ?: @"pl_PL";
            self.timeZoneName = dict[@"timeZoneName"] ?: @"Europe/Warsaw";
            self.preferredLanguages = dict[@"preferredLanguages"] ?: @[@"pl-PL", @"en-PL"];
        } else {
            self.localeIdentifier = dict[@"localeIdentifier"] ?: @"vi_VN";
            self.timeZoneName = dict[@"timeZoneName"] ?: ([NSTimeZone systemTimeZone].name ?: @"Asia/Ho_Chi_Minh");
            self.preferredLanguages = dict[@"preferredLanguages"] ?: @[@"vi-VN", @"en-VN"];
        }
        self.darwinKernelRelease = dict[@"darwinKernelRelease"] ?: @"";
        self.spoofedSerial = dict[@"spoofedSerial"] ?: @"";
        self.spoofedWifiMAC = dict[@"spoofedWifiMAC"] ?: @"";
        self.spoofedBluetoothMAC = dict[@"spoofedBluetoothMAC"] ?: @"";
        self.spoofedScreenSize = dict[@"spoofedScreenSize"] ?: @"";
        self.currentZCID = dict[@"currentZCID"] ?: @"";
        self.lastWipedZCID = dict[@"lastWipedZCID"] ?: @"";
        self.currentVoIPToken = dict[@"currentVoIPToken"] ?: @"";
        self.spoofedVoIPToken = dict[@"spoofedVoIPToken"] ?: @"";
        self.lastWipedVoIPToken = dict[@"lastWipedVoIPToken"] ?: @"";
        self.spoofContinuousCPUClock = (dict[@"spoofContinuousCPUClock"] != nil) ? [dict[@"spoofContinuousCPUClock"] boolValue] : YES;
        self.spoofVoIPPushToken = (dict[@"spoofVoIPPushToken"] != nil) ? [dict[@"spoofVoIPPushToken"] boolValue] : NO;
        self.resetTCCPromptOnWipe = (dict[@"resetTCCPromptOnWipe"] != nil) ? [dict[@"resetTCCPromptOnWipe"] boolValue] : YES;
        self.contactsPermissionDetermined = [dict[@"contactsPermissionDetermined"] boolValue];
        self.notificationPermissionDetermined = [dict[@"notificationPermissionDetermined"] boolValue];
        self.photosPermissionDetermined = [dict[@"photosPermissionDetermined"] boolValue];
        self.cameraPermissionDetermined = [dict[@"cameraPermissionDetermined"] boolValue];
        self.micPermissionDetermined = [dict[@"micPermissionDetermined"] boolValue];
        self.locationPermissionDetermined = [dict[@"locationPermissionDetermined"] boolValue];
        if (self.spoofedVoIPToken.length == 0 && self.hasConfiguredProfile) {
            unsigned char voipBytes[32];
            arc4random_buf(voipBytes, sizeof(voipBytes));
            NSMutableString *vHex = [NSMutableString stringWithCapacity:64];
            for (int i = 0; i < 32; i++) {
                [vHex appendFormat:@"%02x", voipBytes[i]];
            }
            self.spoofedVoIPToken = [vHex copy];
        }

        BOOL isAppExtension = [[NSBundle mainBundle].bundlePath containsString:@".appex"];
        if (isAppExtension) {
            self.showFloatingMenu = NO;
        } else if (dict[@"showFloatingMenu"] != nil) {
            self.showFloatingMenu = [dict[@"showFloatingMenu"] boolValue];
        } else {
            self.showFloatingMenu = YES; // Mặc định luôn hiện nút nổi để thuận tiện thao tác
        }

        self.needsNewProfile = [dict[@"needsNewProfile"] boolValue];
        self.needsSandboxPurge = [dict[@"needsSandboxPurge"] boolValue];
        BOOL justRestoredBackup = [dict[@"justRestoredBackup"] boolValue];
        if (justRestoredBackup) {
            logAudit(@"SYSTEM-INIT", @"[COLD-BOOT] 🛡️ Phát hiện cờ vừa Restore từ Backup (justRestoredBackup=YES) -> Bảo vệ nguyên vẹn phiên đăng nhập & hồ sơ máy!");
            self.needsNewProfile = NO;
            self.needsSandboxPurge = NO;
            NSMutableDictionary *m = [dict mutableCopy];
            m[@"justRestoredBackup"] = @(NO);
            m[@"needsNewProfile"] = @(NO);
            m[@"needsSandboxPurge"] = @(NO);
            m[@"needsKeychainPurge"] = @(NO);
            [m writeToFile:path atomically:YES];
            [m writeToFile:GLOBAL_PREFS_PATH atomically:YES];
            [self saveSettings];
        } else if (self.needsNewProfile || self.needsSandboxPurge) {
            if (s_is_cold_boot_phase) {
                if (ZTSecurityCheckLicenseFast()) {
                    logAudit(@"SYSTEM-INIT", @"[COLD-BOOT] 🧹 Phát hiện cờ yêu cầu máy mới / dọn sạch sau Deep Wipe -> Khởi động dọn sạch 100% Sandbox & Keychain...");
                    purge_entire_sandbox_safely();
                    BOOL willGenProfile = self.needsNewProfile;
                    self.needsNewProfile = NO;
                    self.needsSandboxPurge = NO;
                    self.justGeneratedColdBoot = YES;
                    if (dict[@"showFloatingMenu"] != nil) {
                        self.showFloatingMenu = [dict[@"showFloatingMenu"] boolValue];
                    } else {
                        self.showFloatingMenu = YES;
                    }
                    self.regionMode = dict[@"regionMode"] ?: (self.regionMode ?: @"VN");
                    self.preferredCarrier = dict[@"preferredCarrier"] ?: @"";
                    if (self.currentZCID.length > 0) {
                        self.lastWipedZCID = self.currentZCID;
                    }
                    if (self.currentVoIPToken.length > 0) {
                        self.lastWipedVoIPToken = self.currentVoIPToken;
                    }
                    self.currentZCID = @"";
                    self.currentVoIPToken = @"";
                    self.spoofedVoIPToken = @"";
                    self.centralizedDid = @"";
                    if (willGenProfile) {
                        // Cấp ngay Profile mới tinh đồng bộ theo vòng đời máy và vùng địa lý (chỉ khi được yêu cầu)
                        [self generateNewProfile];
                    }
                    NSMutableDictionary *cleanFlags = [NSMutableDictionary dictionaryWithContentsOfFile:path] ?: [NSMutableDictionary dictionary];
                    cleanFlags[@"needsKeychainPurge"] = @(NO);
                    cleanFlags[@"needsSandboxPurge"] = @(NO);
                    cleanFlags[@"needsNewProfile"] = @(NO);
                    cleanFlags[@"justRestoredBackup"] = @(NO);
                    [cleanFlags writeToFile:path atomically:YES];
                    [cleanFlags writeToFile:GLOBAL_PREFS_PATH atomically:YES];
                    [self saveSettings];
                    reset_audit_log_on_wipe(self.deviceMachine, self.spoofedIDFV);
                    return;
                } else {
                    logAudit(@"SYSTEM-INIT", @"[COLD-BOOT] Chưa có bản quyền hợp lệ -> Từ chối cấp Profile mới!");
                    self.needsNewProfile = NO;
                    self.needsSandboxPurge = NO;
                    [self saveSettings];
                }
            } else {
                // Đang trong runtime của app, bảo toàn cờ để dành cho Cold-Boot thực sự khi khởi động lại!
                return;
            }
        }

        if (self.hasConfiguredProfile && (!dict[@"spoofedIDFV"] || !dict[@"spoofedIDFA"] || !dict[@"profileId"] || self.bootTimeSec == 0 || self.birthTimeSec == 0 || self.spoofedSerial.length == 0)) {
            if (self.spoofedSerial.length == 0) {
                extern NSString *generate_random_serial(void);
                extern NSString *generate_random_mac(void);
                self.spoofedSerial = generate_random_serial();
                self.spoofedWifiMAC = generate_random_mac();
                self.spoofedBluetoothMAC = generate_random_mac();
            }
            if (self.bootTimeSec == 0) {
                uint32_t randomOffset = 86400 + (arc4random_uniform(345600)) + arc4random_uniform(59);
                self.bootTimeSec = (uint64_t)[[NSDate date] timeIntervalSince1970] - randomOffset;
                self.bootSessionUUID = [[NSUUID UUID] UUIDString];
            }
            if (self.birthTimeSec == 0) {
                uint64_t launch = 1632441600ULL;
                self.birthTimeSec = launch + arc4random_uniform(90000000ULL);
                if (self.birthTimeSec >= self.bootTimeSec) {
                    self.birthTimeSec = self.bootTimeSec - (86400ULL * 30ULL + arc4random_uniform(86400 * 180) + arc4random_uniform(3599));
                }
            }
            [self saveSettings];
        }
    } else {
        self.enabled = YES;
        self.showFloatingMenu = YES;
        self.hasConfiguredProfile = NO; // MỚI CÀI ĐẶT: CHƯA CẤU HÌNH -> KHÔNG FAKE MÁY NGAY!
        self.enableAuditLog = NO;
        self.lastWipedIDFV = @"";
        self.lastWipedIP = @"";
        self.lastWipedTimestamp = 0;
        self.regionMode = @"VN";
        self.needsNewProfile = NO;
        self.needsSandboxPurge = NO;
        self.proxyEnabled = NO;
        self.proxyType = @"HTTP";
        self.proxyHost = @"";
        self.proxyPort = 0;
        self.proxyUser = @"";
        self.proxyPass = @"";
        self.centralizedDid = @"";
        self.currentAPNsToken = @"";
        self.lastWipedAPNsToken = @"";
        self.lastKnownAPNsToken = @"";
        self.apnsRotatedStatus = @"";
        self.spoofedSerial = @"";
        self.spoofedWifiMAC = @"";
        self.spoofedBluetoothMAC = @"";
        self.spoofedIDFV = @"";
        self.profileId = @"";
        // Giữ 100% thông số máy thật:
        self.deviceMachine = get_real_hardware_machine();
        self.deviceModel = get_real_hardware_model();
        self.deviceName = @"iPhone";
        self.systemVersion = get_real_product_version();
        self.kernOsVersion = get_real_os_version();
        self.ncpu = (uint32_t)[[NSProcessInfo processInfo] activeProcessorCount];
        self.memsize = [[NSProcessInfo processInfo] physicalMemory];
        CGFloat defW = 375.0, defH = 667.0, defS = 2.0;
        [ZTDeviceProfile getScreenDimensionsForMachine:self.deviceMachine width:&defW height:&defH scale:&defS];
        self.screenWidth = defW;
        self.screenHeight = defH;
        self.screenScale = defS;
        self.bootTimeSec = 0;
        self.birthTimeSec = 0;
        self.autoSyncTimezoneWithIP = YES;
        self.bootSessionUUID = @"";
        self.carrierName = @"Viettel";
        self.carrierMCC = @"452";
        self.carrierMNC = @"04";
        self.carrierCountryCode = @"vn";
        self.batteryLevel = 0.85f;
        self.batteryState = 1;
        BOOL isAppExtension = [[NSBundle mainBundle].bundlePath containsString:@".appex"];
        if (isAppExtension) {
            self.showFloatingMenu = NO;
        }
        [self saveSettings];
    }
}

- (void)saveSettings {
    NSString *path = getConfigPath();
    NSMutableDictionary *dict = [NSMutableDictionary dictionaryWithContentsOfFile:path] ?: [NSMutableDictionary dictionary];
    dict[@"enabled"] = @(self.enabled);
    dict[@"enableAuditLog"] = @(self.enableAuditLog);
    dict[@"hasConfiguredProfile"] = @(self.hasConfiguredProfile);
    dict[@"proxyEnabled"] = @(self.proxyEnabled);
    dict[@"proxyType"] = self.proxyType ?: @"HTTP";
    dict[@"proxyHost"] = self.proxyHost ?: @"";
    dict[@"proxyPort"] = @(self.proxyPort);
    dict[@"proxyUser"] = self.proxyUser ?: @"";
    dict[@"proxyPass"] = self.proxyPass ?: @"";
    if (self.centralizedDid) dict[@"centralizedDid"] = self.centralizedDid;
    if (self.currentAPNsToken) dict[@"currentAPNsToken"] = self.currentAPNsToken;
    if (self.lastWipedAPNsToken) dict[@"lastWipedAPNsToken"] = self.lastWipedAPNsToken;
    if (self.lastKnownAPNsToken) dict[@"lastKnownAPNsToken"] = self.lastKnownAPNsToken;
    if (self.apnsRotatedStatus) dict[@"apnsRotatedStatus"] = self.apnsRotatedStatus;
    dict[@"deviceMachine"] = self.deviceMachine;
    dict[@"deviceModel"] = self.deviceModel;
    dict[@"deviceName"] = self.deviceName;
    dict[@"systemVersion"] = self.systemVersion;
    dict[@"kernOsVersion"] = self.kernOsVersion;
    if (self.darwinKernelRelease) dict[@"darwinKernelRelease"] = self.darwinKernelRelease;
    dict[@"ncpu"] = @(self.ncpu);
    dict[@"memsize"] = @(self.memsize);
    dict[@"screenWidth"] = @(self.screenWidth);
    dict[@"screenHeight"] = @(self.screenHeight);
    dict[@"screenScale"] = @(self.screenScale);
    dict[@"bootTimeSec"] = @(self.bootTimeSec);
    dict[@"birthTimeSec"] = @(self.birthTimeSec);
    dict[@"deltaVarSec"] = @(self.deltaVarSec);
    dict[@"deltaMobileSec"] = @(self.deltaMobileSec);
    dict[@"deltaSandboxSec"] = @(self.deltaSandboxSec);
    dict[@"autoSyncTimezoneWithIP"] = @(self.autoSyncTimezoneWithIP);
    dict[@"enableFakeTimeZone"] = @(self.enableFakeTimeZone);
    dict[@"bootSessionUUID"] = self.bootSessionUUID ?: @"";
    dict[@"spoofedIDFV"] = self.spoofedIDFV;
    dict[@"spoofedIDFA"] = self.spoofedIDFA ?: @"00000000-0000-0000-0000-000000000000";
    dict[@"profileId"] = self.profileId;
    dict[@"diskTotalSize"] = @(self.diskTotalSize);
    dict[@"diskFreeSize"] = @(self.diskFreeSize);
    dict[@"carrierName"] = self.carrierName ?: @"Viettel";
    dict[@"carrierMCC"] = self.carrierMCC ?: @"452";
    dict[@"carrierMNC"] = self.carrierMNC ?: @"04";
    dict[@"carrierCountryCode"] = self.carrierCountryCode ?: @"vn";
    dict[@"batteryLevel"] = @(self.batteryLevel);
    dict[@"batteryState"] = @(self.batteryState);
    dict[@"regionMode"] = self.regionMode ?: @"VN";
    if (self.preferredCarrier) dict[@"preferredCarrier"] = self.preferredCarrier;
    dict[@"l2cacheSize"] = @(self.l2cacheSize);
    dict[@"localeIdentifier"] = self.localeIdentifier ?: @"vi_VN";
    dict[@"timeZoneName"] = self.timeZoneName ?: @"Asia/Ho_Chi_Minh";
    if (self.preferredLanguages) dict[@"preferredLanguages"] = self.preferredLanguages;
    dict[@"showFloatingMenu"] = @(self.showFloatingMenu);
    dict[@"needsNewProfile"] = @(self.needsNewProfile);
    dict[@"needsSandboxPurge"] = @(self.needsSandboxPurge);
    if (self.spoofedSerial) dict[@"spoofedSerial"] = self.spoofedSerial;
    if (self.spoofedWifiMAC) dict[@"spoofedWifiMAC"] = self.spoofedWifiMAC;
    if (self.spoofedBluetoothMAC) dict[@"spoofedBluetoothMAC"] = self.spoofedBluetoothMAC;
    if (self.spoofedScreenSize) dict[@"spoofedScreenSize"] = self.spoofedScreenSize;
    if (self.currentZCID) dict[@"currentZCID"] = self.currentZCID;
    if (self.lastWipedZCID) dict[@"lastWipedZCID"] = self.lastWipedZCID;
    if (self.currentVoIPToken) dict[@"currentVoIPToken"] = self.currentVoIPToken;
    if (self.spoofedVoIPToken) dict[@"spoofedVoIPToken"] = self.spoofedVoIPToken;
    if (self.lastWipedVoIPToken) dict[@"lastWipedVoIPToken"] = self.lastWipedVoIPToken;
    dict[@"spoofContinuousCPUClock"] = @(self.spoofContinuousCPUClock);
    dict[@"spoofVoIPPushToken"] = @(self.spoofVoIPPushToken);
    dict[@"resetTCCPromptOnWipe"] = @(self.resetTCCPromptOnWipe);
    dict[@"contactsPermissionDetermined"] = @(self.contactsPermissionDetermined);
    dict[@"notificationPermissionDetermined"] = @(self.notificationPermissionDetermined);
    dict[@"photosPermissionDetermined"] = @(self.photosPermissionDetermined);
    dict[@"cameraPermissionDetermined"] = @(self.cameraPermissionDetermined);
    dict[@"micPermissionDetermined"] = @(self.micPermissionDetermined);
    dict[@"locationPermissionDetermined"] = @(self.locationPermissionDetermined);
    if (self.lastWipedIDFV) dict[@"lastWipedIDFV"] = self.lastWipedIDFV;
    if (self.lastWipedIP) dict[@"lastWipedIP"] = self.lastWipedIP;
    dict[@"lastWipedTimestamp"] = @(self.lastWipedTimestamp);

    [[NSFileManager defaultManager] createDirectoryAtPath:[path stringByDeletingLastPathComponent] withIntermediateDirectories:YES attributes:nil error:nil];
    [dict writeToFile:path atomically:YES];
    chmod([path UTF8String], 0666);

    NSString *home = NSHomeDirectory();
    if (home) {
        NSString *localPref = [home stringByAppendingPathComponent:@"Library/Preferences/com.sonhu.zalotweak.plist"];
        [[NSFileManager defaultManager] createDirectoryAtPath:[localPref stringByDeletingLastPathComponent] withIntermediateDirectories:YES attributes:nil error:nil];
        [dict writeToFile:localPref atomically:YES];
        chmod([localPref UTF8String], 0666);
        NSString *localDoc = [home stringByAppendingPathComponent:@"Documents/com.sonhu.zalotweak.plist"];
        [[NSFileManager defaultManager] createDirectoryAtPath:[localDoc stringByDeletingLastPathComponent] withIntermediateDirectories:YES attributes:nil error:nil];
        [dict writeToFile:localDoc atomically:YES];
        chmod([localDoc UTF8String], 0666);
    }

    if (is_device_jailbroken()) {
        NSString *rhPath = get_roothide_prefs_path();
        if (rhPath) {
            [[NSFileManager defaultManager] createDirectoryAtPath:[rhPath stringByDeletingLastPathComponent] withIntermediateDirectories:YES attributes:nil error:nil];
            [dict writeToFile:rhPath atomically:YES];
            chmod([rhPath UTF8String], 0666);
        }
        [dict writeToFile:GLOBAL_PREFS_PATH atomically:YES];
        chmod([GLOBAL_PREFS_PATH UTF8String], 0666);
    }

    CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(),
                                         CFSTR("com.sonhu.zalotweak/settingschanged"),
                                         NULL, NULL, YES);
}

NSString *generate_random_serial(void) {
    return generate_apple_serial();
}

NSString *generate_random_mac(void) {
    return generate_apple_mac();
}

- (void)generateNewProfile {
    if (s_session_profile_locked && !self.isShuttingDownForDeepWipe) {
        logAudit(@"PROFILE-LOCK", @"🔒 [ATOMIC LOCK] Tiến trình đang hoạt động: Khóa cố định Profile, từ chối tạo mới trong cùng phiên!");
        return;
    }
    if (!ZTSecurityCheckLicenseFast()) {
        logAudit(@"SECURITY", @"[AUTH] ❌ Từ chối cấp Profile: Chưa kích hoạt bản quyền hợp lệ hoặc phát hiện can thiệp nhị phân!");
        return;
    }
    self.enabled = YES;
    self.hasConfiguredProfile = YES; // Kích hoạt cờ đã cấu hình profile
    // 1. Sinh profile thiết bị từ ngân hàng mẫu iPhone chuẩn phần cứng Apple khớp dòng máy thực tế
    ZTDeviceProfile *p = [ZTDeviceProfile generateRandomProfileForRegion:self.regionMode ?: @"VN"
                                                             baseMachine:get_real_hardware_machine()
                                                        preferredCarrier:self.preferredCarrier];

    self.deviceMachine = p.deviceMachine;
    self.deviceModel = p.deviceModel;
    self.ncpu = p.ncpu;
    self.memsize = p.memsize;
    self.screenWidth = p.screenWidth;
    self.screenHeight = p.screenHeight;
    self.screenScale = p.screenScale;
    self.systemVersion = p.systemVersion;
    self.kernOsVersion = p.kernOsVersion;
    self.darwinKernelRelease = p.darwinKernelRelease;
    self.diskTotalSize = p.diskTotalSize;
    self.diskFreeSize = p.diskFreeSize;
    self.deviceName = p.deviceName;
    self.carrierName = p.carrierName;
    self.carrierMCC = p.carrierMCC;
    self.carrierMNC = p.carrierMNC;
    self.carrierCountryCode = p.carrierCountryCode;
    if (p.actualCarrier.length > 0) {
        self.preferredCarrier = p.actualCarrier;
    }
    self.l2cacheSize = p.l2cacheSize;
    self.localeIdentifier = p.localeIdentifier;
    self.preferredLanguages = p.preferredLanguages;
    self.timeZoneName = p.timeZoneName;
    self.batteryLevel = p.batteryLevel;
    self.batteryState = p.batteryState;
    self.bootTimeSec = p.bootTimeSec;
    self.birthTimeSec = p.birthTimeSec;
    self.deltaVarSec = p.deltaVarSec;
    self.deltaMobileSec = p.deltaMobileSec;
    self.deltaSandboxSec = p.deltaSandboxSec;
    self.autoSyncTimezoneWithIP = YES;
    self.bootSessionUUID = p.bootSessionUUID;
    self.spoofedIDFV = p.spoofedIDFV;
    self.spoofedIDFA = p.spoofedIDFA;
    self.profileId = p.profileId;
    self.spoofedSerial = p.spoofedSerial;
    self.spoofedWifiMAC = p.spoofedWifiMAC;
    self.spoofedBluetoothMAC = p.spoofedBluetoothMAC;
    self.spoofedScreenSize = p.spoofedScreenSize ?: [NSString stringWithFormat:@"%.0fx%.0f", self.screenWidth * self.screenScale, self.screenHeight * self.screenScale];
    if (p.spoofedVoIPToken.length > 0) {
        self.spoofedVoIPToken = p.spoofedVoIPToken;
    }
    self.contactsPermissionDetermined = NO;
    self.notificationPermissionDetermined = NO;
    self.photosPermissionDetermined = NO;
    self.cameraPermissionDetermined = NO;
    self.micPermissionDetermined = NO;
    self.locationPermissionDetermined = NO;

    logAudit(@"DEVICE-GEN", [NSString stringWithFormat:@"Đã sinh máy ngẫu nhiên mới: %@ (%@) | iOS: %@ (%@) | RAM: %.1fGB | L2: %lluMB | Màn: %.0fx%.0f@%.0fx | Vùng: %@ (%@) | Tên: %@",
              self.deviceMachine, self.deviceModel, self.systemVersion, self.kernOsVersion,
              (double)self.memsize / (1024.0 * 1024.0 * 1024.0),
              self.l2cacheSize / (1024ULL * 1024ULL),
              self.screenWidth, self.screenHeight, self.screenScale,
              self.regionMode, self.localeIdentifier, self.deviceName]);

    [self saveSettings];
}

@end

// ==========================================
// HỆ THỐNG AUDIT LOG (KIỂM TOÁN HÀNH VI ZALO)
// ==========================================

static __attribute__((unused)) NSString *getAuditLogPath(void) {
    return @"/var/mobile/Documents/ZaloAudit.log";
}

static void append_data_to_file_safely(NSString *path, NSData *data) {
    if (!path || !data || data.length == 0) return;
    @try {
        NSFileHandle *handle = [NSFileHandle fileHandleForWritingAtPath:path];
        if (!handle) {
            NSString *parentDir = [path stringByDeletingLastPathComponent];
            [[NSFileManager defaultManager] createDirectoryAtPath:parentDir withIntermediateDirectories:YES attributes:nil error:nil];
            [[NSFileManager defaultManager] createFileAtPath:path contents:nil attributes:nil];
            chmod([path UTF8String], 0666);
            handle = [NSFileHandle fileHandleForWritingAtPath:path];
        }
        if (handle) {
            [handle seekToEndOfFile];
            [handle writeData:data];
            [handle closeFile];
        }
    } @catch (NSException *e) {}
}

static NSMutableSet *loggedAuditKeys = nil;
static dispatch_queue_t auditQueue = nil;
static dispatch_queue_t harQueue = nil;

static void flush_audit_and_har_queues_sync(void) {
    if (auditQueue) {
        dispatch_sync(auditQueue, ^{});
    }
    if (harQueue) {
        dispatch_sync(harQueue, ^{});
    }
}

__attribute__((visibility("default"))) void zt_flush_audit_and_har_queues_sync(void) {
    flush_audit_and_har_queues_sync();
}

static void handle_app_termination_event(const char *reason) {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        NSString *msg = [NSString stringWithFormat:@"⚠️ [LIFECYCLE-GUARD] Tiến trình đang đóng / thoát (%s) -> Đang xả toàn bộ dữ liệu log & HAR xuống ổ đĩa an toàn ✅", reason];
        logAudit(@"APP-LIFECYCLE", msg);
        flush_audit_and_har_queues_sync();
    });
}

static void zt_sig_handler(int sig) {
    char buf[64];
    snprintf(buf, sizeof(buf), "Signal %d", sig);
    handle_app_termination_event(buf);
    signal(sig, SIG_DFL);
    raise(sig);
}

static void zt_atexit_handler(void) {
    handle_app_termination_event("atexit");
}

static UIBackgroundTaskIdentifier s_bg_task_id;
static void renew_background_task_assertion(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        static dispatch_once_t s_bg_once;
        dispatch_once(&s_bg_once, ^{
            s_bg_task_id = UIBackgroundTaskInvalid;
        });
        UIApplication *app = [UIApplication sharedApplication];
        if (!app) return;
        if (s_bg_task_id != UIBackgroundTaskInvalid) {
            [app endBackgroundTask:s_bg_task_id];
            s_bg_task_id = UIBackgroundTaskInvalid;
        }
        s_bg_task_id = [app beginBackgroundTaskWithName:@"ZTBackgroundKeepAlive" expirationHandler:^{
            logAudit(@"BACKGROUND-GUARD", @"⏱️ Hết hạn Background Task -> Tự động gia hạn giữ tiến trình sống...");
            renew_background_task_assertion();
        }];
    });
}

static NSString *mask_sensitive_data(NSString *input) {
    if (!input || input.length == 0) return input;
    NSMutableString *str = [input mutableCopy];

    static NSRegularExpression *jwtRegex = nil;
    static NSRegularExpression *paramRegex = nil;
    static dispatch_once_t s_regexToken;
    dispatch_once(&s_regexToken, ^{
        jwtRegex = [NSRegularExpression regularExpressionWithPattern:@"\"(token|authToken|refreshToken|privateKey|sdkId|zaId)\"\\s*:\\s*\"([^\"]+)\"" options:0 error:nil];
        paramRegex = [NSRegularExpression regularExpressionWithPattern:@"(api_key|sig|sdkId|X-Goog-Api-Key)[=:\\s]+([a-zA-Z0-9_-]{12,})" options:0 error:nil];
    });

    // Mask JSON tokens & keys
    if (jwtRegex) {
        NSArray *matches = [jwtRegex matchesInString:str options:0 range:NSMakeRange(0, str.length)];
        for (NSTextCheckingResult *match in [matches reverseObjectEnumerator]) {
            NSRange valRange = [match rangeAtIndex:2];
            NSString *val = [str substringWithRange:valRange];
            if (val.length > 8) {
                NSString *masked = [NSString stringWithFormat:@"%@***%@", [val substringToIndex:4], [val substringFromIndex:val.length - 4]];
                [str replaceCharactersInRange:valRange withString:masked];
            }
        }
    }

    // Mask query & header params
    if (paramRegex) {
        NSArray *matches = [paramRegex matchesInString:str options:0 range:NSMakeRange(0, str.length)];
        for (NSTextCheckingResult *match in [matches reverseObjectEnumerator]) {
            NSRange valRange = [match rangeAtIndex:2];
            NSString *val = [str substringWithRange:valRange];
            if (val.length > 8) {
                NSString *masked = [NSString stringWithFormat:@"%@***", [val substringToIndex:6]];
                [str replaceCharactersInRange:valRange withString:masked];
            }
        }
    }

    return str;
}

static void logAudit(NSString *category, NSString *detail) {
    NSString *safeDetail = mask_sensitive_data(detail);

    // 1. Luôn in trực tiếp ra System Console để soi trực tiếp trên 3uTools Device Console
    NSLog(@"[ZaloAudit] [%@] %@", category, safeDetail);

    if (![ZTSettings sharedSettings].enableAuditLog) return;

    if (!auditQueue) {
        loggedAuditKeys = [[NSMutableSet alloc] init];
        auditQueue = dispatch_queue_create("com.sonhu.zalotweak.auditQueue", DISPATCH_QUEUE_SERIAL);
    }

    NSString *dedupKey = [NSString stringWithFormat:@"%@:%@", category, safeDetail];
    dispatch_async(auditQueue, ^{
        BOOL isNetworkEvent = [category containsString:@"HTTP"] || [category containsString:@"HAR"] || [category containsString:@"NET"];
        if (!isNetworkEvent) {
            if ([loggedAuditKeys containsObject:dedupKey]) {
                return;
            }
            [loggedAuditKeys addObject:dedupKey];
        }

        NSDateFormatter *df = [[NSDateFormatter alloc] init];
        [df setDateFormat:@"HH:mm:ss"];
        NSString *timeStr = [df stringFromDate:[NSDate date]];

        NSString *line = [NSString stringWithFormat:@"[%@] [PID:%d] [%@] %@\n", timeStr, getpid(), category, safeDetail];
        NSData *lineData = [line dataUsingEncoding:NSUTF8StringEncoding];

        // 1. Luôn ghi vào /var/mobile/Documents/ZaloAudit.log (vị trí toàn cục dễ kéo từ 3uTools/Filza)
        append_data_to_file_safely(@"/var/mobile/Documents/ZaloAudit.log", lineData);

        // 2. Ghi song song vào Documents của Sandbox hiện tại (đảm bảo không bao giờ mất log dù Sandbox chặn)
        NSString *home = NSHomeDirectory();
        if (home) {
            NSString *containerDoc = [home stringByAppendingPathComponent:@"Documents/ZaloAudit.log"];
            if (![containerDoc isEqualToString:@"/var/mobile/Documents/ZaloAudit.log"]) {
                append_data_to_file_safely(containerDoc, lineData);
            }
        }
    });
}

// ==========================================
// 1. TẦNG C API: sysctl, sysctlbyname & uname HOOKING
// ==========================================

static NSString *get_darwin_kernel_release(NSString *sysVer) {
    ZTSettings *s = [ZTSettings sharedSettings];
    if (s.darwinKernelRelease && s.darwinKernelRelease.length > 0) {
        return s.darwinKernelRelease;
    }
    if (!sysVer || sysVer.length == 0) return @"21.6.0";
    NSArray<NSString *> *components = [sysVer componentsSeparatedByString:@"."];
    if (components.count == 0) return @"21.6.0";
    NSInteger major = [components[0] integerValue];
    NSInteger minor = components.count > 1 ? [components[1] integerValue] : 0;
    NSInteger darwinMajor = major + 6;
    NSInteger darwinMinor = (major <= 16) ? 6 : minor;
    return [NSString stringWithFormat:@"%ld.%ld.0", (long)darwinMajor, (long)darwinMinor];
}

static inline uint32_t get_cpufamily_for_machine(NSString *machine) {
    if (!machine || machine.length == 0) return 0x608e83e3; // Default A10
    if ([machine hasPrefix:@"iPhone7,"]) return 0x37fc219f; // Apple A8
    if ([machine hasPrefix:@"iPhone8,"]) return 0x2c5558d6; // Apple A9
    if ([machine hasPrefix:@"iPhone9,"]) return 0x608e83e3; // Apple A10 Fusion
    if ([machine hasPrefix:@"iPhone10,"]) return 0xe81e7e1f; // Apple A11 Bionic
    if ([machine hasPrefix:@"iPhone11,"]) return 0x07d34b9f; // Apple A12 Bionic
    if ([machine hasPrefix:@"iPhone12,"]) return 0x462504d2; // Apple A13 Bionic
    if ([machine hasPrefix:@"iPhone13,"]) return 0x1b588bb3; // Apple A14 Bionic
    if ([machine hasPrefix:@"iPhone14,"]) {
        if ([machine isEqualToString:@"iPhone14,2"] || [machine isEqualToString:@"iPhone14,3"] ||
            [machine isEqualToString:@"iPhone14,4"] || [machine isEqualToString:@"iPhone14,5"] ||
            [machine isEqualToString:@"iPhone14,6"] || [machine isEqualToString:@"iPhone14,7"] ||
            [machine isEqualToString:@"iPhone14,8"]) {
            return 0xda33d83d; // Apple A15 Bionic
        }
        return 0x8765edea; // Apple A16 Bionic
    }
    if ([machine hasPrefix:@"iPhone15,"]) return 0x8765edea; // Apple A16 Bionic
    if ([machine hasPrefix:@"iPhone16,"]) return 0xfa33ffec; // Apple A17 Pro
    return 0x608e83e3; // fallback A10
}

static inline const char *get_cpu_brand_for_machine(NSString *machine) {
    if (!machine || machine.length == 0) return "Apple A10 Fusion";
    if ([machine hasPrefix:@"iPhone7,"]) return "Apple A8";
    if ([machine hasPrefix:@"iPhone8,"]) return "Apple A9";
    if ([machine hasPrefix:@"iPhone9,"]) return "Apple A10 Fusion";
    if ([machine hasPrefix:@"iPhone10,"]) return "Apple A11 Bionic";
    if ([machine hasPrefix:@"iPhone11,"]) return "Apple A12 Bionic";
    if ([machine hasPrefix:@"iPhone12,"]) return "Apple A13 Bionic";
    if ([machine hasPrefix:@"iPhone13,"]) return "Apple A14 Bionic";
    if ([machine hasPrefix:@"iPhone14,"]) return "Apple A15 Bionic";
    if ([machine hasPrefix:@"iPhone15,"]) return "Apple A16 Bionic";
    return "Apple A10 Fusion";
}

static inline const char *get_chip_code_for_machine(NSString *machine) {
    if (!machine || machine.length == 0) return "T8010";
    if ([machine hasPrefix:@"iPhone7,"]) return "T7000";
    if ([machine hasPrefix:@"iPhone8,"]) return "S8000";
    if ([machine hasPrefix:@"iPhone9,"]) return "T8010";
    if ([machine hasPrefix:@"iPhone10,"]) return "T8015";
    if ([machine hasPrefix:@"iPhone11,"]) return "T8020";
    if ([machine hasPrefix:@"iPhone12,"]) return "T8030";
    if ([machine hasPrefix:@"iPhone13,"]) return "T8101";
    if ([machine hasPrefix:@"iPhone14,"]) return "T8110";
    if ([machine hasPrefix:@"iPhone15,"]) return "T8120";
    return "T8010";
}

static inline NSString *get_apple_kernel_version_string(NSString *sysVer, NSString *machine) {
    NSString *darwinRelease = get_darwin_kernel_release(sysVer) ?: @"21.6.0";
    const char *chipCode = get_chip_code_for_machine(machine);
    
    NSString *xnuBuild = @"8020.240.14~1";
    NSString *buildDate = @"Mon Aug 22 20:19:51 PDT 2022";
    if ([sysVer hasPrefix:@"15.0"] || [sysVer hasPrefix:@"15.1"]) {
        xnuBuild = @"8019.41.5~1";
        buildDate = @"Sun Oct 10 22:27:08 PDT 2021";
    } else if ([sysVer hasPrefix:@"15.2"] || [sysVer hasPrefix:@"15.3"]) {
        xnuBuild = @"8019.80.24~1";
        buildDate = @"Sun Jan 9 23:28:01 PST 2022";
    } else if ([sysVer hasPrefix:@"15.4"]) {
        xnuBuild = @"8020.102.3~1";
        buildDate = @"Mon Feb 21 20:38:51 PST 2022";
    } else if ([sysVer hasPrefix:@"15.5"] || [sysVer hasPrefix:@"15.6"]) {
        xnuBuild = @"8020.140.41~1";
        buildDate = @"Mon Apr 25 21:18:03 PDT 2022";
    } else if ([sysVer hasPrefix:@"15.7"] || [sysVer hasPrefix:@"15.8"]) {
        xnuBuild = @"8020.240.14~1";
        buildDate = @"Mon Aug 22 20:19:51 PDT 2022";
    } else if ([sysVer hasPrefix:@"16."]) {
        xnuBuild = @"8792.81.3~2";
        buildDate = @"Mon Jan 16 00:54:15 PST 2023";
    } else if ([sysVer hasPrefix:@"17."]) {
        xnuBuild = @"10002.1.13~1";
        buildDate = @"Thu Aug 17 21:03:00 PDT 2023";
    }
    
    return [NSString stringWithFormat:@"Darwin Kernel Version %@: %@; root:xnu-%@/RELEASE_ARM64_%s",
            darwinRelease, buildDate, xnuBuild, chipCode];
}

static int (*orig_sysctl)(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) = NULL;
static int my_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    static __thread BOOL s_in_sysctl = NO;
    if (s_in_sysctl || !name || namelen < 2 || !is_tweak_active()) {
        return orig_sysctl ? orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen) : sysctl(name, namelen, oldp, oldlenp, newp, newlen);
    }
    s_in_sysctl = YES;

    ZTSettings *settings = [ZTSettings sharedSettings];

    if (name[0] == CTL_HW) {
        if (name[1] == HW_MACHINE) {
            const char *val = settings.deviceMachine.length > 0 ? [settings.deviceMachine UTF8String] : "iPhone9,3";
            size_t val_len = strlen(val) + 1;
            if (oldp && oldlenp) {
                size_t copy_len = (*oldlenp < val_len) ? *oldlenp : val_len;
                memcpy(oldp, val, copy_len);
            }
            if (oldlenp) *oldlenp = val_len;
            s_in_sysctl = NO;
            return 0;
        }
        if (name[1] == HW_MODEL) {
            const char *val = settings.deviceModel.length > 0 ? [settings.deviceModel UTF8String] : "D10AP";
            size_t val_len = strlen(val) + 1;
            if (oldp && oldlenp) {
                size_t copy_len = (*oldlenp < val_len) ? *oldlenp : val_len;
                memcpy(oldp, val, copy_len);
            }
            if (oldlenp) *oldlenp = val_len;
            s_in_sysctl = NO;
            return 0;
        }
        if (name[1] == HW_NCPU || name[1] == HW_AVAILCPU) {
            uint32_t cpu = settings.ncpu;
            if (oldp && oldlenp && *oldlenp >= sizeof(uint32_t)) {
                memcpy(oldp, &cpu, sizeof(uint32_t));
            }
            if (oldlenp) *oldlenp = sizeof(uint32_t);
            s_in_sysctl = NO;
            return 0;
        }
        if (name[1] == HW_MEMSIZE) {
            uint64_t ram = settings.memsize;
            if (oldp && oldlenp && *oldlenp >= sizeof(uint64_t)) {
                memcpy(oldp, &ram, sizeof(uint64_t));
            }
            if (oldlenp) *oldlenp = sizeof(uint64_t);
            s_in_sysctl = NO;
            return 0;
        }
        if (name[1] == HW_PHYSMEM) {
            uint32_t ram32 = (uint32_t)(settings.memsize > 0xFFFFFFFFULL ? 0xFFFFFFFFULL : settings.memsize);
            if (oldp && oldlenp && *oldlenp >= sizeof(uint32_t)) {
                memcpy(oldp, &ram32, sizeof(uint32_t));
            }
            if (oldlenp) *oldlenp = sizeof(uint32_t);
            s_in_sysctl = NO;
            return 0;
        }
        if (name[1] == HW_PAGESIZE) {
            uint32_t pagesize = 16384;
            if (oldp && oldlenp && *oldlenp >= sizeof(uint32_t)) {
                memcpy(oldp, &pagesize, sizeof(uint32_t));
            }
            if (oldlenp) *oldlenp = sizeof(uint32_t);
            s_in_sysctl = NO;
            return 0;
        }
#ifdef HW_L2CACHESIZE
        if (name[1] == HW_L2CACHESIZE) {
            uint64_t l2 = settings.l2cacheSize > 0 ? settings.l2cacheSize : 3145728ULL;
            if (oldp && oldlenp) {
                if (*oldlenp >= sizeof(uint64_t)) {
                    memcpy(oldp, &l2, sizeof(uint64_t));
                } else if (*oldlenp >= sizeof(uint32_t)) {
                    uint32_t l2_32 = (uint32_t)l2;
                    memcpy(oldp, &l2_32, sizeof(uint32_t));
                }
            }
            if (oldlenp) *oldlenp = sizeof(uint64_t);
            s_in_sysctl = NO;
            return 0;
        }
#endif
#ifndef HW_CPUFAMILY
#define HW_CPUFAMILY 104
#endif
#ifndef HW_CPUTYPE
#define HW_CPUTYPE 105
#endif
#ifndef HW_CPUSUBTYPE
#define HW_CPUSUBTYPE 106
#endif
        if (name[1] == HW_CPUFAMILY) {
            uint32_t fam = get_cpufamily_for_machine(settings.deviceMachine);
            if (oldp && oldlenp && *oldlenp >= sizeof(uint32_t)) {
                memcpy(oldp, &fam, sizeof(uint32_t));
            }
            if (oldlenp) *oldlenp = sizeof(uint32_t);
            s_in_sysctl = NO;
            return 0;
        }
        if (name[1] == HW_CPUTYPE) {
            cpu_type_t cputype = CPU_TYPE_ARM64;
            if (oldp && oldlenp && *oldlenp >= sizeof(cpu_type_t)) {
                memcpy(oldp, &cputype, sizeof(cpu_type_t));
            }
            if (oldlenp) *oldlenp = sizeof(cpu_type_t);
            s_in_sysctl = NO;
            return 0;
        }
        if (name[1] == HW_CPUSUBTYPE) {
            cpu_subtype_t subtype = (settings.ncpu >= 6 && ![settings.deviceMachine hasPrefix:@"iPhone10,"]) ? CPU_SUBTYPE_ARM64E : CPU_SUBTYPE_ARM64_V8;
            if (oldp && oldlenp && *oldlenp >= sizeof(cpu_subtype_t)) {
                memcpy(oldp, &subtype, sizeof(cpu_subtype_t));
            }
            if (oldlenp) *oldlenp = sizeof(cpu_subtype_t);
            s_in_sysctl = NO;
            return 0;
        }
    } else if (name[0] == CTL_KERN) {
#ifdef KERN_VERSION
        if (name[1] == KERN_VERSION) {
            NSString *kVer = get_apple_kernel_version_string(settings.systemVersion, settings.deviceMachine);
            const char *val = [kVer UTF8String];
            size_t val_len = strlen(val) + 1;
            if (oldp && oldlenp) {
                size_t copy_len = (*oldlenp < val_len) ? *oldlenp : val_len;
                memcpy(oldp, val, copy_len);
            }
            if (oldlenp) *oldlenp = val_len;
            s_in_sysctl = NO;
            return 0;
        }
#endif
        if (name[1] == KERN_BOOTTIME && settings.bootTimeSec > 0) {
            struct timeval bt;
            bt.tv_sec = (time_t)settings.bootTimeSec;
            bt.tv_usec = (suseconds_t)((settings.bootTimeSec * 2654435761ULL) % 1000000ULL);
            if (oldp && oldlenp && *oldlenp >= sizeof(struct timeval)) {
                memcpy(oldp, &bt, sizeof(struct timeval));
            }
            if (oldlenp) *oldlenp = sizeof(struct timeval);
            s_in_sysctl = NO;
            return 0;
        }
        if (name[1] == KERN_OSVERSION && settings.kernOsVersion.length > 0) {
            const char *val = [settings.kernOsVersion UTF8String];
            size_t val_len = strlen(val) + 1;
            if (oldp && oldlenp) {
                size_t copy_len = (*oldlenp < val_len) ? *oldlenp : val_len;
                memcpy(oldp, val, copy_len);
            }
            if (oldlenp) *oldlenp = val_len;
            s_in_sysctl = NO;
            return 0;
        }
#ifdef KERN_OSRELEASE
        if (name[1] == KERN_OSRELEASE) {
            NSString *releaseStr = get_darwin_kernel_release(settings.systemVersion);
            const char *val = [releaseStr UTF8String];
            size_t val_len = strlen(val) + 1;
            if (oldp && oldlenp) {
                size_t copy_len = (*oldlenp < val_len) ? *oldlenp : val_len;
                memcpy(oldp, val, copy_len);
            }
            if (oldlenp) *oldlenp = val_len;
            s_in_sysctl = NO;
            return 0;
        }
#endif
        if (name[1] == KERN_HOSTNAME && settings.deviceName.length > 0) {
            const char *val = [settings.deviceName UTF8String];
            size_t val_len = strlen(val) + 1;
            if (oldp && oldlenp) {
                size_t copy_len = (*oldlenp < val_len) ? *oldlenp : val_len;
                memcpy(oldp, val, copy_len);
            }
            if (oldlenp) *oldlenp = val_len;
            s_in_sysctl = NO;
            return 0;
        }
        if (namelen >= 3 && name[1] == KERN_PROC && name[2] == KERN_PROC_PID) {
            int ret = orig_sysctl ? orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen) : sysctl(name, namelen, oldp, oldlenp, newp, newlen);
            if (ret == 0 && oldp && oldlenp && *oldlenp >= sizeof(struct kinfo_proc)) {
                struct kinfo_proc *kp = (struct kinfo_proc *)oldp;
                kp->kp_proc.p_flag &= ~P_TRACED;
            }
            s_in_sysctl = NO;
            return ret;
        }
    }

    s_in_sysctl = NO;
    return orig_sysctl ? orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen) : sysctl(name, namelen, oldp, oldlenp, newp, newlen);
}

static int my_sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    static __thread BOOL s_in_sysctlbyname = NO;
    if (s_in_sysctlbyname || !name || !is_tweak_active()) {
        return orig_sysctlbyname ? orig_sysctlbyname(name, oldp, oldlenp, newp, newlen) : sysctlbyname(name, oldp, oldlenp, newp, newlen);
    }
    s_in_sysctlbyname = YES;

    ZTSettings *settings = [ZTSettings sharedSettings];

    if (strcmp(name, "hw.machine") == 0 || strcmp(name, "hw.product") == 0) {
        const char *val = settings.deviceMachine.length > 0 ? [settings.deviceMachine UTF8String] : "iPhone9,3";
        size_t val_len = strlen(val) + 1;
        if (oldp && oldlenp) {
            size_t copy_len = (*oldlenp < val_len) ? *oldlenp : val_len;
            memcpy(oldp, val, copy_len);
        }
        if (oldlenp) *oldlenp = val_len;
        s_in_sysctlbyname = NO;
        return 0;
    }

    if (strcmp(name, "hw.model") == 0) {
        const char *val = settings.deviceModel.length > 0 ? [settings.deviceModel UTF8String] : "D10AP";
        size_t val_len = strlen(val) + 1;
        if (oldp && oldlenp) {
            size_t copy_len = (*oldlenp < val_len) ? *oldlenp : val_len;
            memcpy(oldp, val, copy_len);
        }
        if (oldlenp) *oldlenp = val_len;
        s_in_sysctlbyname = NO;
        return 0;
    }

    if (strcmp(name, "kern.osproductversion") == 0) {
        const char *val = settings.systemVersion.length > 0 ? [settings.systemVersion UTF8String] : "15.7.2";
        size_t val_len = strlen(val) + 1;
        if (oldp && oldlenp) {
            size_t copy_len = (*oldlenp < val_len) ? *oldlenp : val_len;
            memcpy(oldp, val, copy_len);
        }
        if (oldlenp) *oldlenp = val_len;
        s_in_sysctlbyname = NO;
        return 0;
    }

    if (strcmp(name, "kern.osversion") == 0) {
        const char *val = settings.kernOsVersion.length > 0 ? [settings.kernOsVersion UTF8String] : "19H218";
        size_t val_len = strlen(val) + 1;
        if (oldp && oldlenp) {
            size_t copy_len = (*oldlenp < val_len) ? *oldlenp : val_len;
            memcpy(oldp, val, copy_len);
        }
        if (oldlenp) *oldlenp = val_len;
        s_in_sysctlbyname = NO;
        return 0;
    }

    if (strcmp(name, "kern.osrelease") == 0) {
        NSString *releaseStr = get_darwin_kernel_release(settings.systemVersion);
        const char *val = [releaseStr UTF8String];
        size_t val_len = strlen(val) + 1;
        if (oldp && oldlenp) {
            size_t copy_len = (*oldlenp < val_len) ? *oldlenp : val_len;
            memcpy(oldp, val, copy_len);
        }
        if (oldlenp) *oldlenp = val_len;
        s_in_sysctlbyname = NO;
        return 0;
    }

    if (strcmp(name, "kern.version") == 0) {
        NSString *kVer = get_apple_kernel_version_string(settings.systemVersion, settings.deviceMachine);
        const char *val = [kVer UTF8String];
        size_t val_len = strlen(val) + 1;
        if (oldp && oldlenp) {
            size_t copy_len = (*oldlenp < val_len) ? *oldlenp : val_len;
            memcpy(oldp, val, copy_len);
        }
        if (oldlenp) *oldlenp = val_len;
        s_in_sysctlbyname = NO;
        return 0;
    }

    if (strcmp(name, "hw.cpufamily") == 0) {
        uint32_t fam = get_cpufamily_for_machine(settings.deviceMachine);
        if (oldp && oldlenp && *oldlenp >= sizeof(uint32_t)) {
            memcpy(oldp, &fam, sizeof(uint32_t));
        }
        if (oldlenp) *oldlenp = sizeof(uint32_t);
        s_in_sysctlbyname = NO;
        return 0;
    }

    if (strcmp(name, "hw.cputype") == 0) {
        cpu_type_t cputype = CPU_TYPE_ARM64;
        if (oldp && oldlenp && *oldlenp >= sizeof(cpu_type_t)) {
            memcpy(oldp, &cputype, sizeof(cpu_type_t));
        }
        if (oldlenp) *oldlenp = sizeof(cpu_type_t);
        s_in_sysctlbyname = NO;
        return 0;
    }

    if (strcmp(name, "hw.cpusubtype") == 0) {
        cpu_subtype_t subtype = (settings.ncpu >= 6 && ![settings.deviceMachine hasPrefix:@"iPhone10,"]) ? CPU_SUBTYPE_ARM64E : CPU_SUBTYPE_ARM64_V8;
        if (oldp && oldlenp && *oldlenp >= sizeof(cpu_subtype_t)) {
            memcpy(oldp, &subtype, sizeof(cpu_subtype_t));
        }
        if (oldlenp) *oldlenp = sizeof(cpu_subtype_t);
        s_in_sysctlbyname = NO;
        return 0;
    }

    if (strcmp(name, "machdep.cpu.brand_string") == 0) {
        const char *brand = get_cpu_brand_for_machine(settings.deviceMachine);
        size_t b_len = strlen(brand) + 1;
        if (oldp && oldlenp) {
            size_t copy_len = (*oldlenp < b_len) ? *oldlenp : b_len;
            memcpy(oldp, brand, copy_len);
        }
        if (oldlenp) *oldlenp = b_len;
        s_in_sysctlbyname = NO;
        return 0;
    }

    if (strcmp(name, "hw.ncpu") == 0 ||
        strcmp(name, "hw.logicalcpu") == 0 ||
        strcmp(name, "hw.physicalcpu") == 0 ||
        strcmp(name, "hw.activecpu") == 0 ||
        strcmp(name, "hw.logicalcpu_max") == 0 ||
        strcmp(name, "hw.physicalcpu_max") == 0) {
        uint32_t cpu = settings.ncpu;
        if (oldp && oldlenp && *oldlenp >= sizeof(uint32_t)) {
            memcpy(oldp, &cpu, sizeof(uint32_t));
        }
        if (oldlenp) *oldlenp = sizeof(uint32_t);
        s_in_sysctlbyname = NO;
        return 0;
    }

    if (strcmp(name, "hw.memsize") == 0) {
        uint64_t ram = settings.memsize;
        if (oldp && oldlenp && *oldlenp >= sizeof(uint64_t)) {
            memcpy(oldp, &ram, sizeof(uint64_t));
        }
        if (oldlenp) *oldlenp = sizeof(uint64_t);
        s_in_sysctlbyname = NO;
        return 0;
    }

    if (strcmp(name, "hw.physmem") == 0) {
        uint32_t ram32 = (uint32_t)(settings.memsize > 0xFFFFFFFFULL ? 0xFFFFFFFFULL : settings.memsize);
        if (oldp && oldlenp && *oldlenp >= sizeof(uint32_t)) {
            memcpy(oldp, &ram32, sizeof(uint32_t));
        }
        if (oldlenp) *oldlenp = sizeof(uint32_t);
        s_in_sysctlbyname = NO;
        return 0;
    }

    if (strcmp(name, "hw.pagesize") == 0) {
        uint32_t pagesize = 16384;
        if (oldp && oldlenp && *oldlenp >= sizeof(uint32_t)) {
            memcpy(oldp, &pagesize, sizeof(uint32_t));
        }
        if (oldlenp) *oldlenp = sizeof(uint32_t);
        s_in_sysctlbyname = NO;
        return 0;
    }

    if (strcmp(name, "hw.l2cachesize") == 0) {
        uint64_t l2 = settings.l2cacheSize > 0 ? settings.l2cacheSize : 3145728ULL;
        if (oldp && oldlenp) {
            if (*oldlenp >= sizeof(uint64_t)) {
                memcpy(oldp, &l2, sizeof(uint64_t));
            } else if (*oldlenp >= sizeof(uint32_t)) {
                uint32_t l2_32 = (uint32_t)l2;
                memcpy(oldp, &l2_32, sizeof(uint32_t));
            }
        }
        if (oldlenp) *oldlenp = sizeof(uint64_t);
        s_in_sysctlbyname = NO;
        return 0;
    }

    if (strcmp(name, "sysctl.proc_translated") == 0) {
        int translated = 0;
        if (oldp && oldlenp && *oldlenp >= sizeof(int)) {
            memcpy(oldp, &translated, sizeof(int));
        }
        if (oldlenp) *oldlenp = sizeof(int);
        s_in_sysctlbyname = NO;
        return 0;
    }

    if (strcmp(name, "kern.boottime") == 0 && settings.bootTimeSec > 0) {
        struct timeval bt;
        bt.tv_sec = (time_t)settings.bootTimeSec;
        bt.tv_usec = (suseconds_t)((settings.bootTimeSec * 2654435761ULL) % 1000000ULL);
        if (oldp && oldlenp && *oldlenp >= sizeof(struct timeval)) {
            memcpy(oldp, &bt, sizeof(struct timeval));
        }
        if (oldlenp) *oldlenp = sizeof(struct timeval);
        s_in_sysctlbyname = NO;
        return 0;
    }

    if (strcmp(name, "kern.bootsessionuuid") == 0 && settings.bootSessionUUID.length > 0) {
        const char *val = settings.bootSessionUUID.length > 0 ? [settings.bootSessionUUID UTF8String] : "00000000-0000-0000-0000-000000000000";
        size_t val_len = strlen(val) + 1;
        if (oldp && oldlenp) {
            size_t copy_len = (*oldlenp < val_len) ? *oldlenp : val_len;
            memcpy(oldp, val, copy_len);
        }
        if (oldlenp) *oldlenp = val_len;
        s_in_sysctlbyname = NO;
        return 0;
    }

    if (strcmp(name, "kern.hostname") == 0 && settings.deviceName.length > 0) {
        const char *val = settings.deviceName.length > 0 ? [settings.deviceName UTF8String] : "iPhone";
        size_t val_len = strlen(val) + 1;
        if (oldp && oldlenp) {
            size_t copy_len = (*oldlenp < val_len) ? *oldlenp : val_len;
            memcpy(oldp, val, copy_len);
        }
        if (oldlenp) *oldlenp = val_len;
        s_in_sysctlbyname = NO;
        return 0;
    }

    if (strncmp(name, "hw.optional.arm.FEAT_", 21) == 0) {
        uint32_t supported = 0;
        if (strcmp(name, "hw.optional.arm.FEAT_AES") == 0 ||
            strcmp(name, "hw.optional.arm.FEAT_PMULL") == 0 ||
            strcmp(name, "hw.optional.arm.FEAT_SHA1") == 0 ||
            strcmp(name, "hw.optional.arm.FEAT_SHA256") == 0) {
            supported = 1;
        } else if (settings.ncpu >= 6) {
            if (strcmp(name, "hw.optional.arm.FEAT_DotProd") == 0 ||
                strcmp(name, "hw.optional.arm.FEAT_FP16") == 0) {
                supported = 1;
            }
        }
        if (oldp && oldlenp && *oldlenp >= sizeof(uint32_t)) {
            memcpy(oldp, &supported, sizeof(uint32_t));
        }
        if (oldlenp) *oldlenp = sizeof(uint32_t);
        s_in_sysctlbyname = NO;
        return 0;
    }

    s_in_sysctlbyname = NO;
    return orig_sysctlbyname ? orig_sysctlbyname(name, oldp, oldlenp, newp, newlen) : sysctlbyname(name, oldp, oldlenp, newp, newlen);
}

static int (*orig_uname)(struct utsname *buf);
static int my_uname(struct utsname *buf) {
    static __thread BOOL s_in_uname = NO;
    if (s_in_uname) return orig_uname ? orig_uname(buf) : uname(buf);
    s_in_uname = YES;
    int ret = orig_uname ? orig_uname(buf) : uname(buf);
    if (ret == 0 && is_tweak_active() && buf) {
        ZTSettings *settings = [ZTSettings sharedSettings];
        if (settings.deviceMachine.length > 0) {
            strlcpy(buf->machine, [settings.deviceMachine UTF8String], sizeof(buf->machine));
        }
        NSString *releaseStr = get_darwin_kernel_release(settings.systemVersion);
        if (releaseStr.length > 0) {
            strlcpy(buf->release, [releaseStr UTF8String], sizeof(buf->release));
            char verBuf[sizeof(buf->version)];
            snprintf(verBuf, sizeof(verBuf), "Darwin Kernel Version %s: root:xnu/RELEASE_ARM64", [releaseStr UTF8String]);
            strlcpy(buf->version, verBuf, sizeof(buf->version));
        }
    }
    s_in_uname = NO;
    return ret;
}

// ==========================================
// 2. TẦNG OBJECTIVE-C: UIDevice, UIScreen, NSProcessInfo, NSFileManager & UIApplication
// ==========================================

%hook UIDevice

- (NSUUID *)identifierForVendor {
    if (!is_tweak_active()) {
        NSUUID *origUUID = %orig;
        logAudit(@"IDFV-CHECK", [NSString stringWithFormat:@"identifierForVendor -> [CHƯA KÍCH HOẠT KEY / HẾT HẠN - TRẢ VỀ IDFV THẬT] %@", [origUUID UUIDString]]);
        return origUUID;
    }
    NSString *fake = [ZTSettings sharedSettings].spoofedIDFV;
    if (fake && fake.length > 0) {
        logAudit(@"IDFV-CHECK", [NSString stringWithFormat:@"identifierForVendor -> [ĐÃ FAKE IDFV AN TOÀN] %@", fake]);
        NSUUID *uuid = [[NSUUID alloc] initWithUUIDString:fake];
        if (uuid) return uuid;
    }
    return %orig;
}

- (NSString *)systemVersion {
    if (!is_tweak_active()) {
        return %orig;
    }
    return [ZTSettings sharedSettings].systemVersion;
}

- (NSString *)name {
    if (!is_tweak_active()) {
        return %orig;
    }
    NSString *sysVer = [ZTSettings sharedSettings].systemVersion;
    if (sysVer.length > 0) {
        NSInteger major = [[sysVer componentsSeparatedByString:@"."].firstObject integerValue];
        if (major >= 16) {
            return @"iPhone";
        }
    }
    return [ZTSettings sharedSettings].deviceName ?: @"iPhone";
}

- (NSString *)model {
    if (!is_tweak_active()) {
        return %orig;
    }
    return @"iPhone";
}

- (NSString *)localizedModel {
    if (!is_tweak_active()) {
        return %orig;
    }
    return @"iPhone";
}

static uint64_t s_battery_ref_time = 0;
static float s_battery_ref_level = 0.0f;
static dispatch_source_t s_battery_timer = NULL;

static float compute_live_battery_level(void) {
    ZTSettings *s = [ZTSettings sharedSettings];
    float base = s.batteryLevel;
    if (base <= 0.05f || base > 1.0f) {
        base = 0.85f;
        s.batteryLevel = base;
    }

    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint64_t nowSec = (uint64_t)tv.tv_sec;

    if (s_battery_ref_time == 0 || s_battery_ref_level <= 0.0f || fabsf(s_battery_ref_level - base) > 0.05f) {
        s_battery_ref_time = nowSec;
        s_battery_ref_level = base;
    }

    uint64_t elapsed = (nowSec >= s_battery_ref_time) ? (nowSec - s_battery_ref_time) : 0;
    // Tốc độ tiêu hao thực tế khi app Zalo đang chạy: ~6.5% mỗi giờ (tương đương 1% mỗi ~9.2 phút)
    float drain = (float)elapsed * (0.065f / 3600.0f);
    float current = s_battery_ref_level - drain;
    if (current < 0.15f) current = 0.15f; // Chặn đáy 15%, không xả sập nguồn
    if (current > 1.0f) current = 1.0f;
    current = roundf(current * 100.0f) / 100.0f;

    return current;
}

static void check_and_update_battery_drain(void) {
    if (!is_tweak_active()) return;
    ZTSettings *s = [ZTSettings sharedSettings];
    if (s.batteryState != 1) return; // Chỉ xả khi không cắm sạc (UIDeviceBatteryStateUnplugged = 1)

    float current = compute_live_battery_level();
    if (current < s.batteryLevel) {
        float oldLevel = s.batteryLevel;
        s.batteryLevel = current;
        struct timeval tv;
        gettimeofday(&tv, NULL);
        s_battery_ref_time = (uint64_t)tv.tv_sec;
        s_battery_ref_level = current;
        [s saveSettings];

        dispatch_async(dispatch_get_main_queue(), ^{
            [[NSNotificationCenter defaultCenter] postNotificationName:UIDeviceBatteryLevelDidChangeNotification
                                                                object:[UIDevice currentDevice]];
        });

        logAudit(@"BATTERY-DRAIN", [NSString stringWithFormat:@"🔋 [PIN TỰ NHIÊN] Tụt: %.0f%% -> %.0f%% (Xả ~6.5%%/h) | Đã phát UIDeviceBatteryLevelDidChangeNotification", oldLevel * 100.0f, current * 100.0f]);
    }
}

static void start_battery_drain_timer_if_needed(void) {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        dispatch_queue_t queue = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0);
        s_battery_timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, queue);
        if (s_battery_timer) {
            // Kiểm tra đều đặn mỗi 30 giây
            dispatch_source_set_timer(s_battery_timer,
                                      dispatch_time(DISPATCH_TIME_NOW, 30 * NSEC_PER_SEC),
                                      30 * NSEC_PER_SEC,
                                      5 * NSEC_PER_SEC);
            dispatch_source_set_event_handler(s_battery_timer, ^{
                check_and_update_battery_drain();
            });
            dispatch_resume(s_battery_timer);
        }
    });
}

- (float)batteryLevel {
    if (!is_tweak_active()) return %orig;
    start_battery_drain_timer_if_needed();
    check_and_update_battery_drain();
    float current = compute_live_battery_level();

    void *c0 = __builtin_return_address(0);
    if (is_zalo_caller(c0) && should_log_radar_caller(c0)) {
        logAudit(@"RADAR-SENSOR", [NSString stringWithFormat:@"🔋 Zalo đọc UIDevice.batteryLevel (%.2f) từ %@", current, format_caller_info(c0)]);
    }
    return current;
}

- (UIDeviceBatteryState)batteryState {
    if (!is_tweak_active()) return %orig;
    void *c0 = __builtin_return_address(0);
    if (is_zalo_caller(c0) && should_log_radar_caller(c0)) {
        logAudit(@"RADAR-SENSOR", [NSString stringWithFormat:@"🔋 Zalo đọc UIDevice.batteryState (%ld) từ %@", (long)[ZTSettings sharedSettings].batteryState, format_caller_info(c0)]);
    }
    return (UIDeviceBatteryState)[ZTSettings sharedSettings].batteryState;
}

- (BOOL)isBatteryMonitoringEnabled {
    return YES;
}

- (void)setBatteryMonitoringEnabled:(BOOL)enabled {
    %orig(YES);
}

%end

// ==========================================
// CHẶN ĐỌC FILE HỆ THỐNG SystemVersion.plist
// ==========================================
%hook NSDictionary

+ (NSDictionary *)dictionaryWithContentsOfFile:(NSString *)path {
    if (is_tweak_active() && path && [path isEqualToString:@"/System/Library/CoreServices/SystemVersion.plist"]) {
        ZTSettings *s = [ZTSettings sharedSettings];
        NSDictionary *orig = %orig;
        NSMutableDictionary *dict = orig ? [orig mutableCopy] : [NSMutableDictionary dictionary];
        if (s.systemVersion.length > 0) {
            dict[@"ProductVersion"] = s.systemVersion;
            dict[@"ProductUserVisibleVersion"] = s.systemVersion;
        }
        if (s.kernOsVersion.length > 0) {
            dict[@"ProductBuildVersion"] = s.kernOsVersion;
        }
        dict[@"ProductName"] = @"iPhone OS";
        return dict;
    }
    return %orig;
}

- (NSDictionary *)initWithContentsOfFile:(NSString *)path {
    if (is_tweak_active() && path && [path isEqualToString:@"/System/Library/CoreServices/SystemVersion.plist"]) {
        ZTSettings *s = [ZTSettings sharedSettings];
        NSDictionary *orig = %orig;
        NSMutableDictionary *dict = orig ? [orig mutableCopy] : [NSMutableDictionary dictionary];
        if (s.systemVersion.length > 0) {
            dict[@"ProductVersion"] = s.systemVersion;
            dict[@"ProductUserVisibleVersion"] = s.systemVersion;
        }
        if (s.kernOsVersion.length > 0) {
            dict[@"ProductBuildVersion"] = s.kernOsVersion;
        }
        dict[@"ProductName"] = @"iPhone OS";
        return dict;
    }
    return %orig;
}

%end

// ==========================================
// BẢO VỆ DANH TÍNH QUẢNG CÁO: IDFA & APP TRACKING
// ==========================================
%hook ASIdentifierManager

- (NSUUID *)advertisingIdentifier {
    if (!is_tweak_active()) {
        return %orig;
    }
    logAudit(@"IDFA-CHECK", @"advertisingIdentifier -> [CHUẨN APPLE ATT DENIED] 00000000-0000-0000-0000-000000000000");
    return [[NSUUID alloc] initWithUUIDString:@"00000000-0000-0000-0000-000000000000"];
}

- (BOOL)isAdvertisingTrackingEnabled {
    if (!is_tweak_active()) {
        return %orig;
    }
    return NO;
}

%end

%hook ATTrackingManager

+ (NSInteger)trackingAuthorizationStatus {
    if (!is_tweak_active()) {
        return %orig;
    }
    logAudit(@"TRACKING-CHECK", @"trackingAuthorizationStatus -> [ĐÃ CHẶN THEO DÕI - TRẢ VỀ DENIED (2)]");
    return 2; // ATTrackingManagerAuthorizationStatusDenied
}

+ (void)requestTrackingAuthorizationWithCompletionHandler:(void (^)(NSInteger status))completion {
    if (!is_tweak_active()) {
        %orig(completion);
        return;
    }
    logAudit(@"TRACKING-CHECK", @"requestTrackingAuthorization -> [TỰ ĐỘNG TRẢ VỀ DENIED (2)]");
    if (completion) {
        completion(2);
    }
}

%end

// ==========================================
// BẢO VỆ CHỐNG CRASH SIRI INTENTS TRÊN APP CLONE / SIDELOAD
// (Khắc phục triệt để lỗi thiếu Entitlement com.apple.developer.siri)
// ==========================================
@interface INPreferences : NSObject
@end

%hook INPreferences

+ (NSInteger)siriAuthorizationStatus {
    logAudit(@"SIRI-FIX", @"[INPreferences siriAuthorizationStatus] -> [CHẶN CRASH: TRẢ VỀ DENIED (2)]");
    return 2; // INSiriAuthorizationStatusDenied
}

+ (void)requestSiriAuthorization:(void (^)(NSInteger status))completion {
    logAudit(@"SIRI-FIX", @"[INPreferences requestSiriAuthorization] -> [CHẶN CRASH: TỰ ĐỘNG DENIED (2)]");
    if (completion) {
        completion(2);
    }
}

+ (NSString *)siriLanguageCode {
    return @"vi-VN";
}

- (id)init {
    logAudit(@"SIRI-FIX", @"[INPreferences init] -> [CHẶN CRASH: TRẢ VỀ NIL]");
    return nil;
}

%end

@interface CNContactStore : NSObject
+ (NSInteger)authorizationStatusForEntityType:(NSInteger)entityType;
- (void)requestAccessForEntityType:(NSInteger)entityType completionHandler:(void (^)(BOOL granted, NSError *error))handler;
@end

%hook CNContactStore

+ (NSInteger)authorizationStatusForEntityType:(NSInteger)entityType {
    if (is_tweak_active()) {
        ZTSettings *s = [ZTSettings sharedSettings];
        if (s.resetTCCPromptOnWipe && !s.contactsPermissionDetermined) {
            void *c0 = __builtin_return_address(0);
            if (is_zalo_caller(c0)) {
                logAudit(@"TCC-CONTACTS", @"👥 Zalo kiểm tra quyền Danh Bạ (CNContactStore) -> [TRẢ VỀ NotDetermined (0) để iOS hiện popup xin quyền như máy mới]");
                return 0; // CNAuthorizationStatusNotDetermined
            }
        }
    }
    return %orig;
}

- (void)requestAccessForEntityType:(NSInteger)entityType completionHandler:(void (^)(BOOL granted, NSError *error))handler {
    if (is_tweak_active()) {
        ZTSettings *s = [ZTSettings sharedSettings];
        s.contactsPermissionDetermined = YES;
        [s saveSettings];
        logAudit(@"TCC-CONTACTS", @"👥 Zalo yêu cầu cấp quyền Danh Bạ (requestAccess) -> [Đã kích hoạt dialog xin quyền hệ thống Apple]");
    }
    %orig(entityType, handler);
}

%end

static CFIndex (*orig_ABAddressBookGetAuthorizationStatus)(void);
static CFIndex my_ABAddressBookGetAuthorizationStatus(void) {
    if (is_tweak_active()) {
        ZTSettings *s = [ZTSettings sharedSettings];
        if (s.resetTCCPromptOnWipe && !s.contactsPermissionDetermined) {
            void *c0 = __builtin_return_address(0);
            if (is_zalo_caller(c0)) {
                logAudit(@"TCC-CONTACTS", @"👥 Zalo kiểm tra quyền Danh Bạ (AddressBook C-API) -> [TRẢ VỀ kABAuthorizationStatusNotDetermined (0)]");
                return 0; // kABAuthorizationStatusNotDetermined
            }
        }
    }
    return orig_ABAddressBookGetAuthorizationStatus ? orig_ABAddressBookGetAuthorizationStatus() : 0;
}

// (Đã chuyển toàn bộ cơ chế Reset Quyền Thông Báo xuống TCC.db & UserNotifications tầng hệ thống, không can thiệp hook UNNotificationSettings để bảo toàn luồng đăng ký APNs của Apple)

// ==========================================
// HOOK TCC: PHOTOS (PHPhotoLibrary)
// Giả lập chưa hỏi quyền Thư viện ảnh sau khi Wipe
// ==========================================
@interface PHPhotoLibrary : NSObject
+ (NSInteger)authorizationStatus;
+ (NSInteger)authorizationStatusForAccessLevel:(NSInteger)accessLevel;
+ (void)requestAuthorization:(void (^)(NSInteger status))handler;
+ (void)requestAuthorizationForAccessLevel:(NSInteger)accessLevel handler:(void (^)(NSInteger status))handler;
@end

%hook PHPhotoLibrary

+ (NSInteger)authorizationStatus {
    if (is_tweak_active()) {
        ZTSettings *s = [ZTSettings sharedSettings];
        if (s.resetTCCPromptOnWipe && !s.photosPermissionDetermined) {
            void *c0 = __builtin_return_address(0);
            if (is_zalo_caller(c0)) {
                logAudit(@"TCC-PHOTOS", @"🖼️ Zalo kiểm tra quyền Thư Viện Ảnh (PHPhotoLibrary authorizationStatus) -> [TRẢ VỀ NotDetermined (0)]");
                return 0; // PHAuthorizationStatusNotDetermined
            }
        }
    }
    return %orig;
}

+ (NSInteger)authorizationStatusForAccessLevel:(NSInteger)accessLevel {
    if (is_tweak_active()) {
        ZTSettings *s = [ZTSettings sharedSettings];
        if (s.resetTCCPromptOnWipe && !s.photosPermissionDetermined) {
            void *c0 = __builtin_return_address(0);
            if (is_zalo_caller(c0)) {
                logAudit(@"TCC-PHOTOS", [NSString stringWithFormat:@"🖼️ Zalo kiểm tra quyền Thư Viện Ảnh (authorizationStatusForAccessLevel: %ld) -> [TRẢ VỀ NotDetermined (0)]", (long)accessLevel]);
                return 0; // PHAuthorizationStatusNotDetermined
            }
        }
    }
    return %orig(accessLevel);
}

+ (void)requestAuthorization:(void (^)(NSInteger status))handler {
    if (is_tweak_active()) {
        ZTSettings *s = [ZTSettings sharedSettings];
        s.photosPermissionDetermined = YES;
        [s saveSettings];
        logAudit(@"TCC-PHOTOS", @"🖼️ Zalo yêu cầu cấp quyền Thư Viện Ảnh (requestAuthorization) -> [Kích hoạt dialog Apple thật]");
    }
    %orig(handler);
}

+ (void)requestAuthorizationForAccessLevel:(NSInteger)accessLevel handler:(void (^)(NSInteger status))handler {
    if (is_tweak_active()) {
        ZTSettings *s = [ZTSettings sharedSettings];
        s.photosPermissionDetermined = YES;
        [s saveSettings];
        logAudit(@"TCC-PHOTOS", [NSString stringWithFormat:@"🖼️ Zalo yêu cầu cấp quyền Thư Viện Ảnh (requestAuthorizationForAccessLevel: %ld) -> [Kích hoạt dialog Apple thật]", (long)accessLevel]);
    }
    %orig(accessLevel, handler);
}

%end

// ==========================================
// HOOK TCC: CAMERA & MICROPHONE (AVCaptureDevice)
// Giả lập chưa hỏi quyền Camera / Mic sau khi Wipe
// ==========================================
@interface AVCaptureDevice : NSObject
+ (NSInteger)authorizationStatusForMediaType:(NSString *)mediaType;
+ (void)requestAccessForMediaType:(NSString *)mediaType completionHandler:(void (^)(BOOL granted))handler;
@end

%hook AVCaptureDevice

+ (NSInteger)authorizationStatusForMediaType:(NSString *)mediaType {
    if (is_tweak_active()) {
        ZTSettings *s = [ZTSettings sharedSettings];
        if (s.resetTCCPromptOnWipe) {
            void *c0 = __builtin_return_address(0);
            if (is_zalo_caller(c0)) {
                if ([mediaType isEqualToString:@"vide"] || [mediaType isEqualToString:@"AVMediaTypeVideo"]) {
                    if (!s.cameraPermissionDetermined) {
                        logAudit(@"TCC-CAMERA", @"📷 Zalo kiểm tra quyền Camera (AVCaptureDevice) -> [TRẢ VỀ NotDetermined (0)]");
                        return 0; // AVAuthorizationStatusNotDetermined
                    }
                } else if ([mediaType isEqualToString:@"soun"] || [mediaType isEqualToString:@"AVMediaTypeAudio"]) {
                    if (!s.micPermissionDetermined) {
                        logAudit(@"TCC-MIC", @"🎙️ Zalo kiểm tra quyền Micro (AVCaptureDevice) -> [TRẢ VỀ NotDetermined (0)]");
                        return 0; // AVAuthorizationStatusNotDetermined
                    }
                }
            }
        }
    }
    return %orig(mediaType);
}

+ (void)requestAccessForMediaType:(NSString *)mediaType completionHandler:(void (^)(BOOL granted))handler {
    if (is_tweak_active()) {
        ZTSettings *s = [ZTSettings sharedSettings];
        if ([mediaType isEqualToString:@"vide"] || [mediaType isEqualToString:@"AVMediaTypeVideo"]) {
            s.cameraPermissionDetermined = YES;
            logAudit(@"TCC-CAMERA", @"📷 Zalo yêu cầu cấp quyền Camera (requestAccess) -> [Kích hoạt dialog Apple thật]");
        } else if ([mediaType isEqualToString:@"soun"] || [mediaType isEqualToString:@"AVMediaTypeAudio"]) {
            s.micPermissionDetermined = YES;
            logAudit(@"TCC-MIC", @"🎙️ Zalo yêu cầu cấp quyền Micro (requestAccess) -> [Kích hoạt dialog Apple thật]");
        }
        [s saveSettings];
    }
    %orig(mediaType, handler);
}

%end

// ==========================================
// HOOK TCC: LOCATION (CLLocationManager)
// Giả lập chưa hỏi quyền Vị Trí sau khi Wipe
// ==========================================
@interface CLLocationManager : NSObject
+ (NSInteger)authorizationStatus;
- (NSInteger)authorizationStatus;
- (void)requestWhenInUseAuthorization;
- (void)requestAlwaysAuthorization;
@end

%hook CLLocationManager

+ (NSInteger)authorizationStatus {
    if (is_tweak_active()) {
        ZTSettings *s = [ZTSettings sharedSettings];
        if (s.resetTCCPromptOnWipe && !s.locationPermissionDetermined) {
            void *c0 = __builtin_return_address(0);
            if (is_zalo_caller(c0)) {
                logAudit(@"TCC-LOCATION", @"📍 Zalo kiểm tra quyền Vị Trí (+authorizationStatus) -> [TRẢ VỀ kCLAuthorizationStatusNotDetermined (0)]");
                return 0; // kCLAuthorizationStatusNotDetermined
            }
        }
    }
    return %orig;
}

- (NSInteger)authorizationStatus {
    if (is_tweak_active()) {
        ZTSettings *s = [ZTSettings sharedSettings];
        if (s.resetTCCPromptOnWipe && !s.locationPermissionDetermined) {
            void *c0 = __builtin_return_address(0);
            if (is_zalo_caller(c0)) {
                logAudit(@"TCC-LOCATION", @"📍 Zalo kiểm tra quyền Vị Trí (-authorizationStatus) -> [TRẢ VỀ kCLAuthorizationStatusNotDetermined (0)]");
                return 0; // kCLAuthorizationStatusNotDetermined
            }
        }
    }
    return %orig;
}

- (void)requestWhenInUseAuthorization {
    if (is_tweak_active()) {
        ZTSettings *s = [ZTSettings sharedSettings];
        s.locationPermissionDetermined = YES;
        [s saveSettings];
        logAudit(@"TCC-LOCATION", @"📍 Zalo yêu cầu quyền Vị Trí (requestWhenInUseAuthorization) -> [Kích hoạt dialog Apple thật]");
    }
    %orig;
}

- (void)requestAlwaysAuthorization {
    if (is_tweak_active()) {
        ZTSettings *s = [ZTSettings sharedSettings];
        s.locationPermissionDetermined = YES;
        [s saveSettings];
        logAudit(@"TCC-LOCATION", @"📍 Zalo yêu cầu quyền Vị Trí (requestAlwaysAuthorization) -> [Kích hoạt dialog Apple thật]");
    }
    %orig;
}

%end

@interface INVocabulary : NSObject
@end

%hook INVocabulary

+ (id)sharedVocabulary {
    logAudit(@"SIRI-FIX", @"[INVocabulary sharedVocabulary] -> [CHẶN CRASH: TRẢ VỀ NIL]");
    return nil;
}

- (void)setVocabularyStrings:(NSOrderedSet *)vocabularyStrings ofType:(NSInteger)type {
    // Bỏ qua để tránh crash
}

- (void)removeAllVocabularyStrings {
    // Bỏ qua để tránh crash
}

%end

// ==========================================
// GIẢ LẬP NHÀ MẠNG VIỄN THÔNG (CARRIER INFO)
// ==========================================
%hook CTCarrier

- (NSString *)carrierName {
    if (!is_tweak_active()) return %orig;
    return [ZTSettings sharedSettings].carrierName ?: @"Viettel";
}

- (NSString *)mobileCountryCode {
    if (!is_tweak_active()) return %orig;
    return [ZTSettings sharedSettings].carrierMCC ?: @"452";
}

- (NSString *)mobileNetworkCode {
    if (!is_tweak_active()) return %orig;
    return [ZTSettings sharedSettings].carrierMNC ?: @"04";
}

- (NSString *)isoCountryCode {
    if (!is_tweak_active()) return %orig;
    NSString *iso = [ZTSettings sharedSettings].carrierCountryCode;
    return (iso.length > 0) ? iso : nil;
}

- (BOOL)allowsVOIP {
    return YES;
}

%end

@interface ZTFakeCarrier : NSObject
@property (nonatomic, copy) NSString *carrierName;
@property (nonatomic, copy) NSString *mobileCountryCode;
@property (nonatomic, copy) NSString *mobileNetworkCode;
@property (nonatomic, copy) NSString *isoCountryCode;
@property (nonatomic, assign) BOOL allowsVOIP;
@end

@implementation ZTFakeCarrier
@dynamic carrierName, mobileCountryCode, mobileNetworkCode, isoCountryCode, allowsVOIP;

- (NSString *)carrierName {
    return [ZTSettings sharedSettings].carrierName ?: @"Viettel";
}
- (NSString *)mobileCountryCode {
    return [ZTSettings sharedSettings].carrierMCC ?: @"452";
}
- (NSString *)mobileNetworkCode {
    return [ZTSettings sharedSettings].carrierMNC ?: @"04";
}
- (NSString *)isoCountryCode {
    NSString *iso = [ZTSettings sharedSettings].carrierCountryCode;
    return (iso.length > 0) ? iso : nil;
}
- (BOOL)allowsVOIP {
    return YES;
}
- (BOOL)isKindOfClass:(Class)aClass {
    if (aClass == NSClassFromString(@"CTCarrier")) return YES;
    return [super isKindOfClass:aClass];
}
- (BOOL)respondsToSelector:(SEL)aSelector {
    if (aSelector == @selector(carrierName) ||
        aSelector == @selector(mobileCountryCode) ||
        aSelector == @selector(mobileNetworkCode) ||
        aSelector == @selector(isoCountryCode) ||
        aSelector == @selector(allowsVOIP)) {
        return YES;
    }
    return [super respondsToSelector:aSelector];
}
@end

static CTCarrier *get_fake_carrier(void) {
    static CTCarrier *s_fake = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        Class ctCls = NSClassFromString(@"CTCarrier");
        if (ctCls) {
            @try {
                s_fake = (CTCarrier *)class_createInstance(ctCls, 0);
            } @catch (NSException *e) {}
        }
        if (!s_fake) {
            s_fake = (CTCarrier *)[[ZTFakeCarrier alloc] init];
        }
    });
    return s_fake;
}

%hook CTTelephonyNetworkInfo

- (NSString *)dataServiceIdentifier {
    if (!is_tweak_active()) return %orig;
    return @"0000000100000001";
}

- (CTCarrier *)subscriberCellularProvider {
    if (!is_tweak_active()) return %orig;
    CTCarrier *c = get_fake_carrier();
    return c ?: %orig;
}

- (NSDictionary *)serviceSubscriberCellularProviders {
    if (!is_tweak_active()) return %orig;
    CTCarrier *c = get_fake_carrier();
    if (c) {
        NSDictionary *origDict = %orig;
        if (origDict && origDict.count > 0) {
            NSMutableDictionary *mut = [NSMutableDictionary dictionaryWithCapacity:origDict.count + 1];
            for (id key in origDict.allKeys) {
                mut[key] = c;
            }
            mut[@"0000000100000001"] = c;
            return mut;
        }
        return @{@"0000000100000001": c};
    }
    return %orig;
}

- (NSDictionary *)serviceCurrentRadioAccessTechnology {
    if (!is_tweak_active()) return %orig;
    NSDictionary *origDict = %orig;
    if (origDict && origDict.count > 0) {
        NSMutableDictionary *mut = [NSMutableDictionary dictionaryWithCapacity:origDict.count + 1];
        for (id key in origDict.allKeys) {
            mut[key] = @"CTRadioAccessTechnologyLTE";
        }
        mut[@"0000000100000001"] = @"CTRadioAccessTechnologyLTE";
        return mut;
    }
    return @{@"0000000100000001": @"CTRadioAccessTechnologyLTE"};
}

- (NSString *)currentRadioAccessTechnology {
    if (!is_tweak_active()) return %orig;
    return @"CTRadioAccessTechnologyLTE";
}

%end

// ==========================================
// ĐỒNG BỘ VÙNG / QUỐC GIA: NSLocale (Múi Giờ NSTimeZone Thu Thập Thật Từ Máy)
// ==========================================

static NSLocale *s_cachedLocale = nil;
static __thread BOOL s_in_locale_hook = NO;

static void update_cached_locale_and_tz(void) {
    if (s_in_locale_hook) return;
    s_in_locale_hook = YES;
    NSString *locId = [ZTSettings sharedSettings].localeIdentifier ?: @"vi_VN";
    s_cachedLocale = [NSLocale localeWithLocaleIdentifier:locId];
    s_in_locale_hook = NO;
}

%hook NSLocale

+ (NSLocale *)currentLocale {
    if (!is_tweak_active() || s_in_locale_hook) return %orig;
    s_in_locale_hook = YES;
    if (!s_cachedLocale) {
        update_cached_locale_and_tz();
    }
    NSLocale *res = s_cachedLocale ?: %orig;
    if ([ZTSettings sharedSettings].enableAuditLog) {
        logAudit(@"LOCALE-CHECK", [NSString stringWithFormat:@"Zalo đọc NSLocale currentLocale -> [TRẢ VỀ %@]", [ZTSettings sharedSettings].localeIdentifier ?: @"vi_VN"]);
    }
    s_in_locale_hook = NO;
    return res;
}

+ (NSLocale *)autoupdatingCurrentLocale {
    if (!is_tweak_active() || s_in_locale_hook) return %orig;
    s_in_locale_hook = YES;
    if (!s_cachedLocale) {
        update_cached_locale_and_tz();
    }
    NSLocale *res = s_cachedLocale ?: %orig;
    if ([ZTSettings sharedSettings].enableAuditLog) {
        logAudit(@"LOCALE-CHECK", [NSString stringWithFormat:@"Zalo đọc NSLocale autoupdatingCurrentLocale -> [TRẢ VỀ %@]", [ZTSettings sharedSettings].localeIdentifier ?: @"vi_VN"]);
    }
    s_in_locale_hook = NO;
    return res;
}

+ (NSArray<NSString *> *)preferredLanguages {
    if (!is_tweak_active() || s_in_locale_hook) return %orig;
    s_in_locale_hook = YES;
    NSArray *langs = [ZTSettings sharedSettings].preferredLanguages;
    NSArray *res = (langs && langs.count > 0) ? langs : @[@"vi-VN", @"en-VN"];
    if ([ZTSettings sharedSettings].enableAuditLog) {
        logAudit(@"LOCALE-CHECK", [NSString stringWithFormat:@"Zalo đọc preferredLanguages -> [TRẢ VỀ %@]", [res componentsJoinedByString:@", "]]);
    }
    s_in_locale_hook = NO;
    return res;
}

%end

// ==========================================
// ĐỒNG BỘ BÀN PHÍM / INPUT MODES: UITextInputMode
// ==========================================

%hook UITextInputMode

- (NSString *)primaryLanguage {
    if (!is_tweak_active()) return %orig;
    void *c0 = __builtin_return_address(0);
    if (is_zalo_caller(c0)) {
        NSArray *langs = [ZTSettings sharedSettings].preferredLanguages;
        if (!langs || langs.count == 0) {
            langs = @[@"vi-VN", @"en-US"];
        }
        NSArray *modes = [UITextInputMode activeInputModes];
        NSUInteger idx = [modes indexOfObject:self];
        if (idx != NSNotFound && idx < langs.count) {
            return langs[idx];
        }
        return langs.firstObject;
    }
    return %orig;
}

+ (NSArray *)activeInputModes {
    NSArray *orig = %orig;
    if (!is_tweak_active()) return orig;
    void *c0 = __builtin_return_address(0);
    if (is_zalo_caller(c0) && [ZTSettings sharedSettings].enableAuditLog) {
        logAudit(@"RADAR-KEYBOARD", [NSString stringWithFormat:@"Zalo đọc UITextInputMode activeInputModes (count=%lu)", (unsigned long)(orig ? orig.count : 0)]);
    }
    return orig;
}

%end

// Bảo toàn 100% thuộc tính hiển thị vật lý của UIScreen (bounds, nativeBounds, scale) để UIKit & Metal
// render chuẩn xác, không bị lỗi buffer mismatch. Thông số màn hình fake được cung cấp qua MGCopyAnswer & Headers.

static __attribute__((unused)) uint64_t seconds_to_mach_ticks(double seconds) {
    mach_timebase_info_data_t tb;
    mach_timebase_info(&tb);
    if (tb.numer == 0 || tb.denom == 0) {
        tb.numer = 125;
        tb.denom = 3;
    }
    double nanos = seconds * 1000000000.0;
    return (uint64_t)((nanos * (double)tb.denom) / (double)tb.numer);
}

static inline double mach_ticks_to_signed_seconds(int64_t ticks) {
    mach_timebase_info_data_t tb;
    mach_timebase_info(&tb);
    if (tb.numer == 0 || tb.denom == 0) {
        tb.numer = 125;
        tb.denom = 3;
    }
    return ((double)ticks * (double)tb.numer) / ((double)tb.denom * 1000000000.0);
}

static __attribute__((unused)) inline double mach_ticks_to_seconds(uint64_t ticks) {
    return mach_ticks_to_signed_seconds((int64_t)ticks);
}

// Đồng bộ Uptime với kern.boottime tự nhiên (now - boottime >= systemUptime, chênh lệch là thời gian máy ngủ)
static void get_consistent_uptimes(double *outContUptime, double *outAwakeUptime) {
    uint64_t bootSec = [ZTSettings sharedSettings].bootTimeSec;
    struct timeval tv;
    gettimeofday(&tv, NULL);
    double now = (double)tv.tv_sec + ((double)tv.tv_usec / 1000000.0);

    double contSec = 0.0;
    if (bootSec > 0 && now > (double)bootSec) {
        contSec = now - (double)bootSec;
    } else {
        contSec = 43200.0; // 12h mặc định
    }

    // Thời gian ngủ tự nhiên của máy phân bổ đa dạng theo thói quen người dùng (từ 25% đến 68% tổng thời gian máy bật)
    double sleepRatio = 0.25 + (double)((bootSec * 2654435761ULL) % 430ULL) / 1000.0;
    double awakeSec = contSec * (1.0 - sleepRatio);
    if (awakeSec < 60.0) awakeSec = 60.0;

    if (outContUptime) *outContUptime = contSec;
    if (outAwakeUptime) *outAwakeUptime = awakeSec;
}

static int (*orig_clock_gettime)(clockid_t clk_id, struct timespec *tp);
static int my_clock_gettime(clockid_t clk_id, struct timespec *tp) {
    return orig_clock_gettime ? orig_clock_gettime(clk_id, tp) : clock_gettime(clk_id, tp);
}

static inline uint64_t raw_hardware_arm64_ticks(void) {
#if defined(__arm64__) || defined(__aarch64__)
    uint64_t val;
    __asm__ volatile("mrs %0, cntvct_el0" : "=r"(val));
    return val;
#else
    return orig_mach_continuous_time ? orig_mach_continuous_time() : mach_continuous_time();
#endif
}

static int64_t s_mach_cont_offset = 0;
static int64_t s_mach_abs_offset = 0;
static uint64_t s_last_mach_boot_sec = 0;
static BOOL s_last_mach_enabled = NO;
static __thread BOOL s_in_mach_hook = NO;

static uint64_t (*orig_mach_continuous_time)(void);
static uint64_t (*orig_mach_absolute_time)(void);

static void update_mach_clock_offsets(void) {
    ZTSettings *s = [ZTSettings sharedSettings];
    double contSec = 0.0, awakeSec = 0.0;
    get_consistent_uptimes(&contSec, &awakeSec);

    uint64_t targetContTicks = seconds_to_mach_ticks(contSec);
    uint64_t targetAbsTicks = seconds_to_mach_ticks(awakeSec);

    uint64_t realCont = raw_hardware_arm64_ticks();

    s_mach_cont_offset = (int64_t)targetContTicks - (int64_t)realCont;
    s_mach_abs_offset = (int64_t)targetAbsTicks - (int64_t)realCont;
    s_last_mach_boot_sec = s.bootTimeSec;
    s_last_mach_enabled = s.spoofContinuousCPUClock;
}

static uint64_t my_mach_continuous_time(void) {
    uint64_t realTicks = raw_hardware_arm64_ticks();
    if (!is_tweak_active() || s_in_mach_hook) {
        return (orig_mach_continuous_time && orig_mach_continuous_time != (void *)my_mach_continuous_time) ? orig_mach_continuous_time() : realTicks;
    }
    void *c0 = __builtin_return_address(0);
    if (!is_zalo_caller(c0)) {
        return (orig_mach_continuous_time && orig_mach_continuous_time != (void *)my_mach_continuous_time) ? orig_mach_continuous_time() : realTicks;
    }
    s_in_mach_hook = YES;
    ZTSettings *s = [ZTSettings sharedSettings];
    if (s.spoofContinuousCPUClock && s.bootTimeSec > 0) {
        if (s_mach_cont_offset == 0 || s_last_mach_boot_sec != s.bootTimeSec || s_last_mach_enabled != s.spoofContinuousCPUClock) {
            update_mach_clock_offsets();
        }
        s_in_mach_hook = NO;
        return (uint64_t)((int64_t)realTicks + s_mach_cont_offset);
    }
    s_last_mach_enabled = s.spoofContinuousCPUClock;
    s_in_mach_hook = NO;
    return (orig_mach_continuous_time && orig_mach_continuous_time != (void *)my_mach_continuous_time) ? orig_mach_continuous_time() : realTicks;
}

static uint64_t my_mach_absolute_time(void) {
    uint64_t realTicks = raw_hardware_arm64_ticks();
    if (!is_tweak_active() || s_in_mach_hook) {
        return (orig_mach_absolute_time && orig_mach_absolute_time != (void *)my_mach_absolute_time) ? orig_mach_absolute_time() : realTicks;
    }
    void *c0 = __builtin_return_address(0);
    if (!is_zalo_caller(c0)) {
        return (orig_mach_absolute_time && orig_mach_absolute_time != (void *)my_mach_absolute_time) ? orig_mach_absolute_time() : realTicks;
    }
    s_in_mach_hook = YES;
    ZTSettings *s = [ZTSettings sharedSettings];
    if (s.spoofContinuousCPUClock && s.bootTimeSec > 0) {
        if (s_mach_abs_offset == 0 || s_last_mach_boot_sec != s.bootTimeSec || s_last_mach_enabled != s.spoofContinuousCPUClock) {
            update_mach_clock_offsets();
        }
        uint64_t absVal = (uint64_t)((int64_t)realTicks + s_mach_abs_offset);
        // Đảm bảo bất biến Apple Darwin Kernel: mach_continuous_time() >= mach_absolute_time()
        uint64_t contVal = (uint64_t)((int64_t)realTicks + s_mach_cont_offset);
        if (absVal > contVal) {
            absVal = contVal;
        }
        s_in_mach_hook = NO;
        return absVal;
    }
    s_last_mach_enabled = s.spoofContinuousCPUClock;
    s_in_mach_hook = NO;
    return (orig_mach_absolute_time && orig_mach_absolute_time != (void *)my_mach_absolute_time) ? orig_mach_absolute_time() : realTicks;
}


#ifndef PT_DENY_ATTACH
#define PT_DENY_ATTACH 31
#endif
static int (*orig_ptrace)(int request, pid_t pid, caddr_t addr, int data);
static int my_ptrace(int request, pid_t pid, caddr_t addr, int data) {
    if (request == PT_DENY_ATTACH && is_tweak_active()) {
        void *c0 = __builtin_return_address(0);
        logAudit(@"RADAR-SECURITY", [NSString stringWithFormat:@"🛡️ Zalo gọi ptrace(PT_DENY_ATTACH) từ %@ -> [ĐÃ CHẶN AN TOÀN]", format_caller_info(c0)]);
        return 0;
    }
    return orig_ptrace ? orig_ptrace(request, pid, addr, data) : 0;
}

static pid_t (*orig_getppid)(void);
static pid_t my_getppid(void) {
    pid_t ret = orig_getppid ? orig_getppid() : getppid();
    if (is_tweak_active()) {
        void *c0 = __builtin_return_address(0);
        if (is_zalo_caller(c0) && should_log_radar_caller(c0)) {
            logAudit(@"RADAR-SECURITY", [NSString stringWithFormat:@"🛡️ Zalo kiểm tra PID tiến trình cha (getppid=%d) từ %@ -> [CHUẨN HOÁ 1 (launchd)]", (int)ret, format_caller_info(c0)]);
            return 1;
        }
    }
    return ret;
}

static int (*orig_gethostname)(char *name, size_t len);
static int my_gethostname(char *name, size_t len) {
    int ret = orig_gethostname ? orig_gethostname(name, len) : gethostname(name, len);
    if (ret == 0 && name && is_tweak_active()) {
        void *c0 = __builtin_return_address(0);
        if (is_zalo_caller(c0) && should_log_radar_caller(c0)) {
            logAudit(@"RADAR-SYS", [NSString stringWithFormat:@"🏷️ Zalo đọc gethostname ('%s') từ %@", name, format_caller_info(c0)]);
        }
    }
    return ret;
}

%hook NSProcessInfo

- (NSString *)operatingSystemVersionString {
    if (!is_tweak_active()) return %orig;
    ZTSettings *s = [ZTSettings sharedSettings];
    if (s.systemVersion.length > 0 && s.kernOsVersion.length > 0) {
        return [NSString stringWithFormat:@"Version %@ (Build %@)", s.systemVersion, s.kernOsVersion];
    }
    return %orig;
}

- (NSOperatingSystemVersion)operatingSystemVersion {
    if (!is_tweak_active()) return %orig;
    ZTSettings *s = [ZTSettings sharedSettings];
    if (s.systemVersion.length > 0) {
        NSArray *components = [s.systemVersion componentsSeparatedByString:@"."];
        NSOperatingSystemVersion v;
        v.majorVersion = components.count > 0 ? [components[0] integerValue] : 18;
        v.minorVersion = components.count > 1 ? [components[1] integerValue] : 1;
        v.patchVersion = components.count > 2 ? [components[2] integerValue] : 0;
        return v;
    }
    return %orig;
}

- (NSTimeInterval)systemUptime {
    if (!is_tweak_active()) {
        return %orig;
    }
    double awakeUp = 0;
    get_consistent_uptimes(NULL, &awakeUp);
    return awakeUp;
}

%end

// ==========================================
// 3. TẦNG KEYCHAIN: PASS-THROUGH 100% NATIVE (CHỈ GHI LOG AUDIT KHI BẬT)
// Không sửa đổi query hay attributes để Zalo chính chủ đọc/ghi Keychain gốc tự nhiên 100%
// ==========================================

static NSString *format_sec_value_data(id valData) {
    if (!valData) return @"(nil)";
    @try {
        if ([valData isKindOfClass:[NSString class]]) return (NSString *)valData;
        if ([valData isKindOfClass:[NSNumber class]]) return [(NSNumber *)valData stringValue];
        if ([valData isKindOfClass:[NSData class]]) {
            NSData *d = (NSData *)valData;
            if (d.length == 0) return @"(empty data)";

            // 1. Thử giải mã chuỗi UTF-8 thông thường
            NSString *str = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
            if (str && str.length > 0) {
                NSCharacterSet *controlChars = [NSCharacterSet controlCharacterSet];
                NSRange r = [str rangeOfCharacterFromSet:controlChars];
                if (r.location == NSNotFound || r.location > 0) {
                    if (str.length > 150) {
                        return [NSString stringWithFormat:@"%@... (%lu chars)", [str substringToIndex:150], (unsigned long)str.length];
                    }
                    return str;
                }
            }

            // 2. Thử giải mã Property List (Dictionary / Array)
            id obj = nil;
            @try {
                obj = [NSPropertyListSerialization propertyListWithData:d options:0 format:NULL error:nil];
            } @catch (id ex) {}

            if (obj) {
                NSString *desc = [[obj description] stringByReplacingOccurrencesOfString:@"\n" withString:@" "];
                if (desc.length > 150) {
                    return [NSString stringWithFormat:@"[Plist] %@... (%lu chars)", [desc substringToIndex:150], (unsigned long)desc.length];
                }
                return [NSString stringWithFormat:@"[Plist] %@", desc];
            }

            // 3. Chuỗi nhị phân ngắn (Token / Key): in Base64
            if (d.length <= 48) {
                return [NSString stringWithFormat:@"[Base64] %@", [d base64EncodedStringWithOptions:0]];
            }
            return [NSString stringWithFormat:@"[Binary: %luB]", (unsigned long)d.length];
        }
        return [NSString stringWithFormat:@"%@", valData];
    } @catch (id ex) {
        if ([valData isKindOfClass:[NSData class]]) {
            return [NSString stringWithFormat:@"[RawData: %luB]", (unsigned long)[(NSData *)valData length]];
        }
        return @"(raw)";
    }
}

static OSStatus (*orig_SecItemCopyMatching)(CFDictionaryRef query, CFTypeRef *result);
static OSStatus my_SecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result) {
    OSStatus ret = orig_SecItemCopyMatching ? orig_SecItemCopyMatching(query, result) : SecItemCopyMatching(query, result);
    if (is_tweak_active() && [ZTSettings sharedSettings].enableAuditLog && query) {
        NSDictionary *qDict = (__bridge NSDictionary *)query;
        NSString *s = qDict[(__bridge id)kSecAttrService];
        NSString *a = qDict[(__bridge id)kSecAttrAccount];
        NSString *g = qDict[(__bridge id)kSecAttrAccessGroup];
        if (s || a) {
            logAudit(@"KEYCHAIN-READ", [NSString stringWithFormat:@"🔍 Zalo truy vấn Keychain: Service='%@' | Account='%@' | Group='%@'", s ?: @"*", a ?: @"*", g ?: @"default"]);
            NSString *statusStr = nil;
            if (ret == errSecSuccess) {
                id readVal = nil;
                if (result && *result) {
                    CFTypeRef resObj = *result;
                    if (CFGetTypeID(resObj) == CFDictionaryGetTypeID()) {
                        readVal = [(__bridge NSDictionary *)resObj objectForKey:(__bridge id)kSecValueData];
                    } else if (CFGetTypeID(resObj) == CFDataGetTypeID()) {
                        readVal = (__bridge NSData *)resObj;
                    }
                }
                if (readVal) {
                    statusStr = [NSString stringWithFormat:@"✅ TÌM THẤY | Value='%@'", format_sec_value_data(readVal)];
                } else {
                    statusStr = @"✅ TÌM THẤY DỮ LIỆU";
                }
            } else if (ret == errSecItemNotFound) {
                statusStr = @"⚪ errSecItemNotFound (Trống - Zalo sẽ tự sinh mới)";
            } else {
                statusStr = [NSString stringWithFormat:@"code=%d", (int)ret];
            }
            logAudit(@"KEYCHAIN-RESULT", [NSString stringWithFormat:@"   ↳ Kết quả đọc '%@'/'%@': %@", s ?: @"*", a ?: @"*", statusStr]);
        }
    }
    return ret;
}

static OSStatus (*orig_SecItemAdd)(CFDictionaryRef attributes, CFTypeRef *result);
static OSStatus my_SecItemAdd(CFDictionaryRef attributes, CFTypeRef *result) {
    OSStatus ret = orig_SecItemAdd ? orig_SecItemAdd(attributes, result) : SecItemAdd(attributes, result);
    if (is_tweak_active() && [ZTSettings sharedSettings].enableAuditLog && attributes) {
        NSDictionary *aDict = (__bridge NSDictionary *)attributes;
        NSString *s = aDict[(__bridge id)kSecAttrService];
        NSString *a = aDict[(__bridge id)kSecAttrAccount];
        NSString *g = aDict[(__bridge id)kSecAttrAccessGroup];
        id val = aDict[(__bridge id)kSecValueData];
        if (s || a) {
            NSString *statusStr = (ret == errSecSuccess) ? @"✅ THÀNH CÔNG" : [NSString stringWithFormat:@"code=%d", (int)ret];
            NSString *valStr = format_sec_value_data(val);
            logAudit(@"KEYCHAIN-ADD", [NSString stringWithFormat:@"💾 Zalo ghi mới Keychain: Service='%@' | Account='%@' | Group='%@' | Value='%@' -> %@", s ?: @"*", a ?: @"*", g ?: @"default", valStr, statusStr]);
        }
    }
    return ret;
}

static OSStatus (*orig_SecItemDelete)(CFDictionaryRef query);
static OSStatus my_SecItemDelete(CFDictionaryRef query) {
    OSStatus ret = orig_SecItemDelete ? orig_SecItemDelete(query) : SecItemDelete(query);
    if (is_tweak_active() && [ZTSettings sharedSettings].enableAuditLog && query) {
        NSDictionary *qDict = (__bridge NSDictionary *)query;
        NSString *s = qDict[(__bridge id)kSecAttrService];
        NSString *a = qDict[(__bridge id)kSecAttrAccount];
        if (s || a) {
            NSString *statusStr = (ret == errSecSuccess) ? @"✅ THÀNH CÔNG" : [NSString stringWithFormat:@"code=%d", (int)ret];
            logAudit(@"KEYCHAIN-DELETE", [NSString stringWithFormat:@"🗑️ Zalo xóa Keychain: Service='%@' | Account='%@' -> %@", s ?: @"*", a ?: @"*", statusStr]);
        }
    }
    return ret;
}

static OSStatus (*orig_SecItemUpdate)(CFDictionaryRef query, CFDictionaryRef attributesToUpdate);
static OSStatus my_SecItemUpdate(CFDictionaryRef query, CFDictionaryRef attributesToUpdate) {
    OSStatus ret = orig_SecItemUpdate ? orig_SecItemUpdate(query, attributesToUpdate) : SecItemUpdate(query, attributesToUpdate);
    if (is_tweak_active() && [ZTSettings sharedSettings].enableAuditLog && query) {
        NSDictionary *qDict = (__bridge NSDictionary *)query;
        NSString *s = qDict[(__bridge id)kSecAttrService];
        NSString *a = qDict[(__bridge id)kSecAttrAccount];
        id val = attributesToUpdate ? ((__bridge NSDictionary *)attributesToUpdate)[(__bridge id)kSecValueData] : nil;
        if (s || a) {
            NSString *statusStr = (ret == errSecSuccess) ? @"✅ THÀNH CÔNG" : [NSString stringWithFormat:@"code=%d", (int)ret];
            NSString *valStr = format_sec_value_data(val);
            logAudit(@"KEYCHAIN-UPDATE", [NSString stringWithFormat:@"📝 Zalo cập nhật Keychain: Service='%@' | Account='%@' | Value='%@' -> %@", s ?: @"*", a ?: @"*", valStr, statusStr]);
        }
    }
    return ret;
}

// ==========================================
// 4. TẦNG BẢO VỆ CHỐNG PHÁT HIỆN JAILBREAK TOÀN DIỆN & FAKE DUNG LƯỢNG Ổ CỨNG
// ==========================================

static BOOL is_jailbreak_path(const char *path) {
    if (!path) return NO;
    // Cho phép truy cập nội bộ tới file cấu hình của chính Tweak mà không bị chặn hay báo động giả
    if (strstr(path, "com.sonhu.zalotweak") != NULL ||
        strstr(path, "ZaloAudit.log") != NULL ||
        strstr(path, "ZaloTraffic.har") != NULL) {
        return NO;
    }
    static const char *jb_indicators[] = {
        "/Applications/Sileo.app",
        "/Applications/Zebra.app",
        "/Applications/Cydia.app",
        "/Applications/Filza.app",
        "/Applications/TrollStore.app",
        "/Applications/NewTerm.app",
        "/Applications/Santander.app",
        "/Applications/checkra1n.app",
        "/usr/sbin/sshd",
        "/usr/bin/ssh",
        "/bin/sh",
        "/bin/bash",
        "/etc/apt",
        "/private/var/lib/apt",
        "/private/var/stash",
        "/var/jb",
        "/var/bin",
        "/var/dropbear",
        "/var/checkra1n",
        "/var/lib/apt",
        "/var/lib/dpkg",
        "/var/log/dpkg",
        "/Library/MobileSubstrate",
        "/Library/PreferenceLoader",
        "/Library/PreferenceBundles",
        "/private/preboot",
        "MobileSubstrate.dylib",
        "cydia_substitute",
        "libsubstitute",
        "substitute",
        "ellekit",
        "libhooker",
        "test_jb",
        "jailbreak.txt",
        "TrollStore",
        "FridaGadget",
        "frida-server",
        "Choicy.dylib",
        "Shadow.dylib",
        "Zalotweak.dylib",
        NULL
    };
    for (int i = 0; jb_indicators[i] != NULL; i++) {
        if (strstr(path, jb_indicators[i]) != NULL) {
            return YES;
        }
    }
    return NO;
}

static int (*orig_access)(const char *path, int mode);
static int my_access(const char *path, int mode) {
    if (is_tweak_active() && path && is_jailbreak_path(path)) {
        void *c0 = __builtin_return_address(0);
        if (is_zalo_caller(c0)) {
            logAudit(@"JB-FILE-CHECK", [NSString stringWithFormat:@"Zalo gọi access('%s') -> [ĐÃ ẨN - TRẢ VỀ ENOENT]", path]);
        }
        errno = ENOENT;
        return -1;
    }
    return orig_access ? orig_access(path, mode) : access(path, mode);
}

static ssize_t (*orig_readlink)(const char *path, char *buf, size_t bufsiz);
static ssize_t my_readlink(const char *path, char *buf, size_t bufsiz) {
    if (is_tweak_active() && path && is_jailbreak_path(path)) {
        void *c0 = __builtin_return_address(0);
        if (is_zalo_caller(c0)) {
            logAudit(@"JB-FILE-CHECK", [NSString stringWithFormat:@"Zalo gọi readlink('%s') -> [ĐÃ ẨN - TRẢ VỀ ENOENT]", path]);
        }
        errno = ENOENT;
        return -1;
    }
    return orig_readlink ? orig_readlink(path, buf, bufsiz) : readlink(path, buf, bufsiz);
}

static ssize_t (*orig_readlinkat)(int fd, const char *path, char *buf, size_t bufsiz);
static ssize_t my_readlinkat(int fd, const char *path, char *buf, size_t bufsiz) {
    if (is_tweak_active() && path && is_jailbreak_path(path)) {
        void *c0 = __builtin_return_address(0);
        if (is_zalo_caller(c0)) {
            logAudit(@"JB-FILE-CHECK", [NSString stringWithFormat:@"Zalo gọi readlinkat('%s') -> [ĐÃ ẨN - TRẢ VỀ ENOENT]", path]);
        }
        errno = ENOENT;
        return -1;
    }
    return orig_readlinkat ? orig_readlinkat(fd, path, buf, bufsiz) : readlinkat(fd, path, buf, bufsiz);
}

static pid_t (*orig_fork)(void);
static pid_t my_fork(void) {
    void *c0 = __builtin_return_address(0);
    if (is_zalo_caller(c0)) {
        logAudit(@"RADAR-SECURITY", @"🛡️ Zalo gọi fork() -> [GIẢ LẬP LỖI SANDBOX ENOSYS (-1)]");
    }
    errno = ENOSYS;
    return -1;
}

static int (*orig_system)(const char *command);
static int my_system(const char *command) {
    if (is_tweak_active()) {
        void *c0 = __builtin_return_address(0);
        if (is_zalo_caller(c0)) {
            logAudit(@"RADAR-SECURITY", [NSString stringWithFormat:@"🛡️ Zalo gọi system('%s') -> [CHẶN THỰC THI SHELL SANDBOX]", command ? command : ""]);
            errno = EPERM;
            return -1;
        }
    }
    return orig_system ? orig_system(command) : -1;
}

static FILE *(*orig_popen)(const char *command, const char *type);
static FILE *my_popen(const char *command, const char *type) {
    if (is_tweak_active()) {
        void *c0 = __builtin_return_address(0);
        if (is_zalo_caller(c0)) {
            logAudit(@"RADAR-SECURITY", [NSString stringWithFormat:@"🛡️ Zalo gọi popen('%s') -> [CHẶN THỰC THI SHELL SANDBOX]", command ? command : ""]);
            errno = EPERM;
            return NULL;
        }
    }
    return orig_popen ? orig_popen(command, type) : NULL;
}

static char *(*orig_getenv)(const char *name);
static char *my_getenv(const char *name) {
    if (name && is_tweak_active()) {
        if (strcmp(name, "DYLD_INSERT_LIBRARIES") == 0 ||
            strcmp(name, "DYLD_LIBRARY_PATH") == 0 ||
            strcmp(name, "_MSSafeMode") == 0 ||
            strcmp(name, "SHELL") == 0) {
            void *c0 = __builtin_return_address(0);
            if (is_zalo_caller(c0)) {
                logAudit(@"RADAR-SECURITY", [NSString stringWithFormat:@"🛡️ Zalo truy vấn getenv('%s') -> [ẨN BIẾN MÔI TRƯỜNG JAILBREAK: TRẢ VỀ NULL]", name]);
                return NULL;
            }
        }
    }
    return orig_getenv ? orig_getenv(name) : getenv(name);
}

// Ẩn BSSID của trạm phát WiFi (tránh phát hiện chung router)
static CFDictionaryRef (*orig_CNCopyCurrentNetworkInfo)(CFStringRef interfaceName);
static CFDictionaryRef my_CNCopyCurrentNetworkInfo(CFStringRef interfaceName) {
    if (is_tweak_active()) {
        logAudit(@"WIFI-CHECK", @"Zalo cố đọc WiFi SSID/BSSID trạm phát -> [ĐÃ CHẶN ẨN HOÀN TOÀN]");
        return NULL;
    }
    return orig_CNCopyCurrentNetworkInfo ? orig_CNCopyCurrentNetworkInfo(interfaceName) : NULL;
}

// Lọc các giao diện mạng ảo (VPN, Tunnel, utun, ppp) để Zalo không quét được
static int (*orig_getifaddrs)(struct ifaddrs **ifap);
static int my_getifaddrs(struct ifaddrs **ifap) {
    int ret = orig_getifaddrs ? orig_getifaddrs(ifap) : getifaddrs(ifap);
    if (ret != 0 || !ifap || !*ifap || !is_tweak_active()) {
        return ret;
    }

    struct ifaddrs *prev = NULL;
    struct ifaddrs *curr = *ifap;
    BOOL modified = NO;
    while (curr) {
        BOOL is_vpn = NO;
        if (curr->ifa_name) {
            const char *n = curr->ifa_name;
            if (strncmp(n, "tun", 3) == 0 ||
                strncmp(n, "tap", 3) == 0 ||
                strncmp(n, "ppp", 3) == 0 ||
                strncmp(n, "ipsec", 5) == 0 ||
                strncmp(n, "utun", 4) == 0 ||
                strncmp(n, "pdp_ip9", 7) == 0) {
                is_vpn = YES;
            }
        }
        if (is_vpn) {
            modified = YES;
            if (prev) {
                // Node nằm sau: Unlink an toàn khỏi linked-list!
                // Con trỏ gốc *ifap không bị thay đổi nên freeifaddrs(*ifap) giải phóng nguyên vẹn khối malloc.
                prev->ifa_next = curr->ifa_next;
                curr = curr->ifa_next;
                continue;
            } else {
                // Trường hợp hy hữu nếu node đầu tiên là VPN: Đổi tên thành card Apple nội bộ awdl0
                curr->ifa_name = "awdl0";
                if (curr->ifa_flags) curr->ifa_flags &= ~(IFF_POINTOPOINT | IFF_LOOPBACK);
            }
        }
        prev = curr;
        curr = curr->ifa_next;
    }
    if (modified) {
        logAudit(@"VPN-CHECK", @"Quét danh sách getifaddrs -> [ĐÃ LỌC BỎ HOÀN TOÀN CARD MẠNG ẢO VPN/UTUN]");
    }
    return 0;
}

__attribute__((visibility("default"))) int zt_get_masked_ifaddrs(struct ifaddrs **ifap) {
    return my_getifaddrs(ifap);
}





// Giả lập dung lượng ổ cứng ở tầng POSIX C (statfs, fstatfs)
static int (*orig_statfs)(const char *path, struct statfs *buf);
static int my_statfs(const char *path, struct statfs *buf) {
    int ret = orig_statfs ? orig_statfs(path, buf) : statfs(path, buf);
    if (ret == 0 && is_tweak_active() && buf) {
        ZTSettings *settings = [ZTSettings sharedSettings];
        uint64_t bsize = buf->f_bsize ? (uint64_t)buf->f_bsize : 4096ULL;
        if (settings.diskTotalSize > 0) {
            buf->f_blocks = settings.diskTotalSize / bsize;
        }
        if (settings.diskFreeSize > 0) {
            buf->f_bavail = settings.diskFreeSize / bsize;
            buf->f_bfree = buf->f_bavail;
        }
    }
    return ret;
}

static int (*orig_fstatfs)(int fd, struct statfs *buf);
static int my_fstatfs(int fd, struct statfs *buf) {
    int ret = orig_fstatfs ? orig_fstatfs(fd, buf) : -1;
    if (ret == 0 && is_tweak_active() && buf) {
        ZTSettings *settings = [ZTSettings sharedSettings];
        uint64_t bsize = buf->f_bsize ? (uint64_t)buf->f_bsize : 4096ULL;
        if (settings.diskTotalSize > 0) {
            buf->f_blocks = settings.diskTotalSize / bsize;
        }
        if (settings.diskFreeSize > 0) {
            buf->f_bavail = settings.diskFreeSize / bsize;
            buf->f_bfree = buf->f_bavail;
        }
    }
    return ret;
}

static int (*orig_statvfs)(const char *path, struct statvfs *buf);
static int my_statvfs(const char *path, struct statvfs *buf) {
    int ret = orig_statvfs ? orig_statvfs(path, buf) : statvfs(path, buf);
    if (ret == 0 && is_tweak_active() && buf) {
        ZTSettings *settings = [ZTSettings sharedSettings];
        uint64_t bsize = buf->f_frsize ? (uint64_t)buf->f_frsize : (buf->f_bsize ? (uint64_t)buf->f_bsize : 4096ULL);
        if (settings.diskTotalSize > 0) {
            buf->f_blocks = (fsblkcnt_t)(settings.diskTotalSize / bsize);
        }
        if (settings.diskFreeSize > 0) {
            buf->f_bavail = (fsblkcnt_t)(settings.diskFreeSize / bsize);
            buf->f_bfree = buf->f_bavail;
        }
    }
    return ret;
}

static int (*orig_fstatvfs)(int fd, struct statvfs *buf);
static int my_fstatvfs(int fd, struct statvfs *buf) {
    int ret = orig_fstatvfs ? orig_fstatvfs(fd, buf) : fstatvfs(fd, buf);
    if (ret == 0 && is_tweak_active() && buf) {
        ZTSettings *settings = [ZTSettings sharedSettings];
        uint64_t bsize = buf->f_frsize ? (uint64_t)buf->f_frsize : (buf->f_bsize ? (uint64_t)buf->f_bsize : 4096ULL);
        if (settings.diskTotalSize > 0) {
            buf->f_blocks = (fsblkcnt_t)(settings.diskTotalSize / bsize);
        }
        if (settings.diskFreeSize > 0) {
            buf->f_bavail = (fsblkcnt_t)(settings.diskFreeSize / bsize);
            buf->f_bfree = buf->f_bavail;
        }
    }
    return ret;
}

static uint64_t get_real_available_disk_space(void) {
    struct statfs s;
    if (statfs([NSHomeDirectory() UTF8String], &s) == 0) {
        uint64_t bsize = s.f_bsize ? (uint64_t)s.f_bsize : 4096ULL;
        uint64_t freeBytes = (uint64_t)s.f_bavail * bsize;
        if (freeBytes > 0) return freeBytes;
    }
    NSDictionary *attrs = [[NSFileManager defaultManager] attributesOfFileSystemForPath:NSHomeDirectory() error:nil];
    NSNumber *freeSpace = attrs[NSFileSystemFreeSize];
    if (freeSpace && [freeSpace unsignedLongLongValue] > 0) {
        return [freeSpace unsignedLongLongValue];
    }
    return 18500000000ULL; // Fallback an toàn ~18.5 GB
}

// Hook CacheDeleteCopyAvailableSpaceForVolume: Trả về dung lượng bộ nhớ trống thực tế để chống báo lỗi 'Bộ nhớ đầy'
static CFNumberRef (*orig_CacheDeleteCopyAvailableSpaceForVolume)(CFStringRef volume);
static CFNumberRef my_CacheDeleteCopyAvailableSpaceForVolume(CFStringRef volume) {
    if (!is_tweak_active()) {
        return orig_CacheDeleteCopyAvailableSpaceForVolume ? orig_CacheDeleteCopyAvailableSpaceForVolume(volume) : NULL;
    }
    if (orig_CacheDeleteCopyAvailableSpaceForVolume) {
        CFNumberRef origNum = orig_CacheDeleteCopyAvailableSpaceForVolume(volume);
        if (origNum) {
            int64_t val = 0;
            if (CFNumberGetValue(origNum, kCFNumberSInt64Type, &val) && val > 100000000LL) {
                return origNum;
            }
            CFRelease(origNum);
        }
    }
    uint64_t avail = 0;
    ZTSettings *s = [ZTSettings sharedSettings];
    if (s.diskFreeSize > 0) {
        avail = s.diskFreeSize;
    } else {
        avail = get_real_available_disk_space();
    }
    if (s.enableAuditLog) {
        logAudit(@"DISK-CHECK", [NSString stringWithFormat:@"CacheDeleteCopyAvailableSpaceForVolume -> [TRẢ VỀ DUNG LƯỢNG TRỐNG KHẢ DỤNG %.2f GB]", (double)avail / (1024.0 * 1024.0 * 1024.0)]);
    }
    int64_t retVal = (int64_t)avail;
    return CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt64Type, &retVal);
}

// Hook _CFCopySystemVersionDictionary & _CFCopyServerVersionDictionary để đồng bộ OS Build Version cho Firebase / Crashlytics
static CFDictionaryRef (*orig_CFCopySystemVersionDictionary)(void) = NULL;
static CFDictionaryRef my_CFCopySystemVersionDictionary(void) {
    if (!is_tweak_active()) {
        return orig_CFCopySystemVersionDictionary ? orig_CFCopySystemVersionDictionary() : NULL;
    }
    CFDictionaryRef origDict = orig_CFCopySystemVersionDictionary ? orig_CFCopySystemVersionDictionary() : NULL;
    NSMutableDictionary *dict = origDict ? [(__bridge NSDictionary *)origDict mutableCopy] : [NSMutableDictionary dictionary];
    if (origDict) CFRelease(origDict);

    ZTSettings *s = [ZTSettings sharedSettings];
    if (s.systemVersion.length > 0) {
        dict[@"ProductVersion"] = s.systemVersion;
        dict[@"ProductUserVisibleVersion"] = s.systemVersion;
    }
    if (s.kernOsVersion.length > 0) {
        dict[@"ProductBuildVersion"] = s.kernOsVersion;
    }
    dict[@"ProductName"] = @"iPhone OS";
    return (__bridge_retained CFDictionaryRef)dict;
}

static CFDictionaryRef (*orig_CFCopyServerVersionDictionary)(void) = NULL;
static CFDictionaryRef my_CFCopyServerVersionDictionary(void) {
    if (!is_tweak_active()) {
        return orig_CFCopyServerVersionDictionary ? orig_CFCopyServerVersionDictionary() : NULL;
    }
    return my_CFCopySystemVersionDictionary();
}

// Hook POSIX stat, lstat, fstat & getattrlist để làm mới device_id và st_birthtimespec
static inline BOOL should_fake_stat_path(const char *path) {
    if (!path) return NO;
    if (strstr(path, "zaloaudit.log") || strstr(path, "zalotraffic.har") || strstr(path, "zalotweak") || strstr(path, ".jbroot") || strstr(path, "jbroot")) {
        return NO;
    }
    if (strstr(path, "/var") ||
        strstr(path, "/usr") ||
        strstr(path, "/cores") ||
        strstr(path, "/System") ||
        strstr(path, "/etc") ||
        strstr(path, "/dev") ||
        strstr(path, "Containers") ||
        strstr(path, "Documents") ||
        strstr(path, "Library") ||
        strstr(path, "Application") ||
        strstr(path, "mobile") ||
        strstr(path, "/private") ||
        strcmp(path, "/") == 0 ||
        strcmp(path, "/etc") == 0 ||
        strcmp(path, "/private") == 0 ||
        strcmp(path, "/private/var") == 0 ||
        strcmp(path, "/private/var/mobile") == 0 ||
        strcmp(path, ".") == 0 ||
        strcmp(path, "..") == 0) {
        return YES;
    }
    return NO;
}

static inline uint64_t get_effective_birth_for_path(const char *path, uint64_t base_birth) {
    if (!path || base_birth == 0) return base_birth;
    ZTSettings *s = [ZTSettings sharedSettings];

    // Căn chỉnh thời gian tăng dần tự nhiên theo đúng kiến trúc APFS SSV (Signed System Volume) của Apple:
    // 1. Phân vùng Hệ điều hành RootFS (/) được Apple đóng gói & ký số trước:
    //    Các thư mục /, /System, /System/Library, /usr, /cores, /bin, /sbin, /etc có cùng mốc build = base_birth.
    // 2. Phân vùng Dữ liệu Data Volume (/var) được format khi kích hoạt máy lần đầu:
    //    /var sinh sau RootFS từ vài chục giây đến vài phút (d_var): t1 > t2.
    // 3. Vì /usr và /cores cùng thuộc RootFS bất biến -> t2 == t3 tuyệt đối.
    // 4. /var/mobile sinh khi Setup Assistant tạo người dùng: d_mob > d_var.
    // 5. Thư mục Sandbox của App sinh khi cài đặt App: d_sbx (sau vài tuần/tháng).
    uint64_t d_var = (s.deltaVarSec > 0) ? (uint64_t)s.deltaVarSec : (60ULL + ((base_birth * 65537ULL) % 120ULL));
    uint64_t d_mob = (s.deltaMobileSec > d_var) ? (uint64_t)s.deltaMobileSec : (d_var + 25ULL + ((base_birth * 104729ULL) % 120ULL));
    uint64_t d_sbx = (s.deltaSandboxSec > d_mob) ? (uint64_t)s.deltaSandboxSec : (d_mob + 86400ULL * 7ULL + ((base_birth * 1299709ULL) % (86400ULL * 60ULL)));
    uint64_t d_lib = d_sbx + 2ULL + ((base_birth * 2246822519ULL) % 15ULL);

    // Bịt kín kẽ hở thời gian tương lai: Đảm bảo toàn bộ mốc thời gian thư mục luôn diễn ra TRƯỚC thời điểm hiện tại
    struct timeval curTv;
    gettimeofday(&curTv, NULL);
    uint64_t nowSec = (uint64_t)curTv.tv_sec;
    if (nowSec > base_birth + 600ULL) {
        uint64_t max_span = nowSec - base_birth - 300ULL;
        if (d_lib >= max_span) {
            uint64_t step = max_span / 6ULL;
            if (step >= 10ULL) {
                d_var = step;
                d_mob = step * 2ULL;
                d_sbx = step * 3ULL + (base_birth % step);
                d_lib = step * 4ULL + ((base_birth * 31ULL) % step);
            } else {
                d_sbx = (max_span > 60ULL) ? (max_span - 60ULL) : (max_span / 2ULL);
                d_lib = (max_span > 10ULL) ? (max_span - 10ULL) : max_span;
            }
        }
    }

    const char *p = path;
    if (strncmp(p, "/private/", 9) == 0) {
        p += 8; // Chuẩn hóa "/private/var/..." -> "/var/..."
    } else if (strcmp(p, "/private") == 0) {
        return base_birth;
    }

    // Tier 0: Phân vùng hệ thống RootFS read-only (Apple Signed System Volume)
    // Bao gồm "/", "/System/...", "/usr/...", "/cores", "/bin/...", "/sbin/...", "/etc/...", "/Library", "/Developer", "/dev"
    // BẮT BUỘC kiểm tra TRƯỚC Tier 4 để /System/Library không bao giờ bị rơi vào nhánh Sandbox App!
    // Trả về đúng base_birth: Đảm bảo Mốc 2 (/usr) == Mốc 3 (/cores) chuẩn xác 100% tài liệu Apple.
    if (strcmp(p, "/") == 0 ||
        strncmp(p, "/System", 7) == 0 ||
        strncmp(p, "/usr", 4) == 0 ||
        strncmp(p, "/cores", 6) == 0 ||
        strncmp(p, "/bin", 4) == 0 ||
        strncmp(p, "/sbin", 5) == 0 ||
        strncmp(p, "/etc", 4) == 0 ||
        strncmp(p, "/private/etc", 12) == 0 ||
        strncmp(p, "/dev", 4) == 0 ||
        strncmp(p, "/Library", 8) == 0 ||
        strncmp(p, "/Applications", 13) == 0 ||
        strncmp(p, "/Developer", 10) == 0) {
        return base_birth;
    }

    // Tier 4: Thư mục con cấu hình/cache trong Sandbox của App (Library, Caches, Preferences, tmp)
    if (strstr(p, "/Library") != NULL || strstr(p, "/Caches") != NULL || strstr(p, "/tmp") != NULL || strstr(p, "/Preferences") != NULL) {
        return base_birth + d_lib;
    }

    // Tier 3: Thư mục gốc Sandbox / Containers / Documents / Bundle Application
    if (strstr(p, "/Documents") != NULL || strstr(p, "/Containers/") != NULL || strstr(p, "/Application/") != NULL) {
        return base_birth + d_sbx;
    }

    // Tier 2b: Các thư mục con bên dưới /var/mobile/... (vd: /var/mobile/Media)
    if (strncmp(p, "/var/mobile/", 12) == 0 && p[12] != '\0') {
        uint64_t h = 0;
        for (const char *c = p + 12; *c; ++c) {
            if (*c != '/') h = h * 131ULL + (unsigned char)(*c);
        }
        return base_birth + d_mob + 12ULL + (h % 300ULL);
    }

    // Tier 2: /var/mobile
    if (strcmp(p, "/var/mobile") == 0 || strcmp(p, "/var/mobile/") == 0 || strstr(p, "mobile") != NULL) {
        return base_birth + d_mob;
    }

    // Tier 1b: Các thư mục con khác bên dưới /var/... (vd: /var/db, /var/root, /var/wireless, /var/msgs)
    if (strncmp(p, "/var/", 5) == 0 && p[5] != '\0') {
        uint64_t h = 0;
        for (const char *c = p + 5; *c; ++c) {
            if (*c != '/') h = h * 131ULL + (unsigned char)(*c);
        }
        return base_birth + d_var + 3ULL + (h % 20ULL);
    }

    // Tier 1: /var (Mốc 1 trong chuỗi device_id của Zalo: t1)
    // Data Volume được khởi tạo sau RootFS: t1 = base_birth + d_var > t2 (base_birth)
    if (strcmp(p, "/var") == 0 || strcmp(p, "/var/") == 0) {
        return base_birth + d_var;
    }

    return base_birth;
}

#define MAX_STAT_LOG_PATHS 64
static char s_stat_logged_paths[MAX_STAT_LOG_PATHS][256];
static int s_stat_logged_count = 0;
static pthread_mutex_t s_stat_log_lock = PTHREAD_MUTEX_INITIALIZER;

static void log_stat_path_once(const char *api, const char *path, uint64_t eff_birth, long nsec_b) {
    if (!path || !api || !path[0]) return;
    static __thread BOOL s_in_stat_log = NO;
    if (s_in_stat_log) return;
    if (strstr(path, "ZaloAudit.log") || strstr(path, "ZaloTraffic.har") || strstr(path, "zalotweak") || strstr(path, ".plist") || strstr(path, ".jbroot") || strstr(path, "jbroot")) {
        return;
    }
    ZTSettings *s = [ZTSettings sharedSettings];
    if (!s.enableAuditLog) return;

    s_in_stat_log = YES;
    char key[256];
    snprintf(key, sizeof(key), "%s:%s", api, path);
    BOOL shouldLog = NO;
    pthread_mutex_lock(&s_stat_log_lock);
    BOOL found = NO;
    for (int i = 0; i < s_stat_logged_count; i++) {
        if (strcmp(s_stat_logged_paths[i], key) == 0) {
            found = YES;
            break;
        }
    }
    if (!found && s_stat_logged_count < MAX_STAT_LOG_PATHS) {
        strncpy(s_stat_logged_paths[s_stat_logged_count], key, sizeof(s_stat_logged_paths[0]) - 1);
        s_stat_logged_paths[s_stat_logged_count][sizeof(s_stat_logged_paths[0]) - 1] = '\0';
        s_stat_logged_count++;
        shouldLog = YES;
    }
    pthread_mutex_unlock(&s_stat_log_lock);

    if (shouldLog) {
        uint64_t ms = eff_birth * 1000ULL + ((uint64_t)nsec_b / 1000000ULL);
        logAudit(@"STAT-PATH", [NSString stringWithFormat:@"[%s] path='%s' -> birth_ms=%llu (sec=%llu)", api, path, ms, eff_birth]);
    }
    s_in_stat_log = NO;
}

static inline void get_consistent_stat_times_for_path(const char *path, uint64_t fake_birth, time_t *out_mtime, time_t *out_ctime, long *out_nsec_b, long *out_nsec_m, long *out_nsec_c) {
    uint64_t phash = 5381ULL;
    // Đối với các đường dẫn thuộc phân vùng RootFS (/, /usr, /cores, /System...), tất cả thuộc cùng APFS SSV snapshot của Apple:
    // Giữ phash cố định để nsec_b bằng nhau 100%, bảo đảm t2 == t3 chuẩn xác đến từng mili-giây!
    BOOL is_rootfs = NO;
    if (path) {
        const char *p = path;
        if (strncmp(p, "/private/", 9) == 0) p += 8;
        if (strcmp(p, "/") == 0 || strncmp(p, "/usr", 4) == 0 || strncmp(p, "/cores", 6) == 0 ||
            strncmp(p, "/System", 7) == 0 || strncmp(p, "/bin", 4) == 0 || strncmp(p, "/sbin", 5) == 0 ||
            strncmp(p, "/etc", 4) == 0 || strncmp(p, "/dev", 4) == 0) {
            is_rootfs = YES;
        }
    }
    if (path && !is_rootfs) {
        for (const char *c = path; *c; ++c) {
            phash = ((phash << 5) + phash) + (unsigned char)(*c);
        }
    }
    uint64_t seed = fake_birth ^ phash;
    uint64_t delta_m = 180ULL + ((seed * 104729ULL) % 1800ULL) + (seed % 59ULL);
    uint64_t delta_c = delta_m + 30ULL + ((seed * 1299709ULL) % 600ULL) + ((seed / 13ULL) % 43ULL);

    uint64_t calc_mtime = fake_birth + delta_m;
    uint64_t calc_ctime = fake_birth + delta_c;

    // Bịt kín kẽ hở POSIX: Bảo đảm fake_birth <= mtime <= ctime < nowSec
    struct timeval curTv;
    gettimeofday(&curTv, NULL);
    uint64_t nowSec = (uint64_t)curTv.tv_sec;
    if (nowSec > fake_birth) {
        if (calc_ctime >= nowSec) {
            calc_ctime = nowSec - (5ULL + (seed % 10ULL));
            if (calc_mtime >= calc_ctime) {
                calc_mtime = (calc_ctime > fake_birth + 10ULL) ? (calc_ctime - (5ULL + ((seed / 7ULL) % 15ULL))) : fake_birth;
            }
        } else if (calc_mtime >= nowSec) {
            calc_mtime = nowSec - (15ULL + (seed % 15ULL));
        }
    }

    if (out_mtime) *out_mtime = (time_t)calc_mtime;
    if (out_ctime) *out_ctime = (time_t)calc_ctime;
    if (out_nsec_b) *out_nsec_b = (long)(((seed * 2654435761ULL) % 850ULL + 100ULL) * 1000000L);
    if (out_nsec_m) *out_nsec_m = (long)((((seed + delta_m) * 2654435761ULL) % 850ULL + 100ULL) * 1000000L);
    if (out_nsec_c) *out_nsec_c = (long)((((seed + delta_c) * 2654435761ULL) % 850ULL + 100ULL) * 1000000L);
}

// Wrapper tương thích ngược cho NSURL và NSFileManager
static inline void get_consistent_stat_times(uint64_t fake_birth, time_t *out_mtime, time_t *out_ctime, long *out_nsec_b, long *out_nsec_m, long *out_nsec_c) {
    get_consistent_stat_times_for_path(NULL, fake_birth, out_mtime, out_ctime, out_nsec_b, out_nsec_m, out_nsec_c);
}

static inline void fake_stat_timespec_for_path(const char *path, struct stat *buf, uint64_t btime) {
    if (!buf) return;
    ZTSettings *s = [ZTSettings sharedSettings];
    uint64_t base_birth = s.birthTimeSec > 0 ? s.birthTimeSec : (btime > 86400 ? (btime - (86400 * 15 + 3600 * 4 + 720)) : 1568160000ULL);
    time_t fake_birth = (time_t)get_effective_birth_for_path(path, base_birth);
    time_t fake_mtime = 0, fake_ctime = 0;
    long nsec_birth = 0, nsec_mtime = 0, nsec_ctime = 0;
    get_consistent_stat_times_for_path(path, (uint64_t)fake_birth, &fake_mtime, &fake_ctime, &nsec_birth, &nsec_mtime, &nsec_ctime);
    buf->st_birthtimespec.tv_sec = fake_birth;
    buf->st_birthtimespec.tv_nsec = nsec_birth;
    buf->st_mtimespec.tv_sec = fake_mtime;
    buf->st_mtimespec.tv_nsec = nsec_mtime;
    buf->st_ctimespec.tv_sec = fake_ctime;
    buf->st_ctimespec.tv_nsec = nsec_ctime;
    log_stat_path_once("stat/lstat/fstat", path, (uint64_t)fake_birth, nsec_birth);
}

static int (*orig_stat)(const char *path, struct stat *buf);
static int my_stat(const char *path, struct stat *buf) {
    static __thread BOOL s_in_stat = NO;
    if (s_in_stat) return orig_stat ? orig_stat(path, buf) : stat(path, buf);
    s_in_stat = YES;

    if (is_tweak_active() && path && is_jailbreak_path(path)) {
        void *c0 = __builtin_return_address(0);
        if (is_zalo_caller(c0)) {
            s_in_stat = NO;
            errno = ENOENT;
            return -1;
        }
    }

    int ret = orig_stat ? orig_stat(path, buf) : stat(path, buf);
    if (ret == 0 && is_tweak_active() && buf && path) {
        if (should_fake_stat_path(path)) {
            uint64_t btime = [ZTSettings sharedSettings].bootTimeSec;
            if (btime > 0 || [ZTSettings sharedSettings].birthTimeSec > 0) {
                fake_stat_timespec_for_path(path, buf, btime);
            }
        }
    }
    s_in_stat = NO;
    return ret;
}

static int (*orig_lstat)(const char *path, struct stat *buf);
static int my_lstat(const char *path, struct stat *buf) {
    static __thread BOOL s_in_lstat = NO;
    if (s_in_lstat) return orig_lstat ? orig_lstat(path, buf) : lstat(path, buf);
    s_in_lstat = YES;

    if (is_tweak_active() && path && is_jailbreak_path(path)) {
        void *c0 = __builtin_return_address(0);
        if (is_zalo_caller(c0)) {
            s_in_lstat = NO;
            errno = ENOENT;
            return -1;
        }
    }

    int ret = orig_lstat ? orig_lstat(path, buf) : lstat(path, buf);
    if (ret == 0 && is_tweak_active() && buf && path) {
        if (should_fake_stat_path(path)) {
            uint64_t btime = [ZTSettings sharedSettings].bootTimeSec;
            if (btime > 0 || [ZTSettings sharedSettings].birthTimeSec > 0) {
                fake_stat_timespec_for_path(path, buf, btime);
            }
        }
    }
    s_in_lstat = NO;
    return ret;
}

static int (*orig_fstat)(int fd, struct stat *buf);
static int my_fstat(int fd, struct stat *buf) {
    static __thread BOOL s_in_fstat = NO;
    if (s_in_fstat) return orig_fstat ? orig_fstat(fd, buf) : fstat(fd, buf);
    s_in_fstat = YES;

    int ret = orig_fstat ? orig_fstat(fd, buf) : fstat(fd, buf);
    if (ret == 0 && is_tweak_active() && buf) {
        char filePath[1024] = {0};
        BOOL shouldFake = NO;
        if (fcntl(fd, F_GETPATH, filePath) >= 0) {
            shouldFake = should_fake_stat_path(filePath);
        } else {
            shouldFake = S_ISDIR(buf->st_mode) || (buf->st_birthtimespec.tv_sec > 1400000000);
        }
        if (shouldFake) {
            uint64_t btime = [ZTSettings sharedSettings].bootTimeSec;
            if (btime > 0 || [ZTSettings sharedSettings].birthTimeSec > 0) {
                fake_stat_timespec_for_path(filePath[0] ? filePath : NULL, buf, btime);
            }
        }
    }
    s_in_fstat = NO;
    return ret;
}

static int (*orig_getattrlist)(const char *path, struct attrlist *attrList, void *attrBuf, size_t attrBufSize, unsigned int options);
static int my_getattrlist(const char *path, struct attrlist *attrList, void *attrBuf, size_t attrBufSize, unsigned int options) {
    if (is_tweak_active() && path && is_jailbreak_path(path)) {
        void *c0 = __builtin_return_address(0);
        if (is_zalo_caller(c0)) {
            logAudit(@"JB-FILE-CHECK", [NSString stringWithFormat:@"Zalo gọi getattrlist('%s') -> [ĐÃ ẨN - TRẢ VỀ ENOENT]", path]);
        }
        errno = ENOENT;
        return -1;
    }
    int ret = orig_getattrlist ? orig_getattrlist(path, attrList, attrBuf, attrBufSize, options) : getattrlist(path, attrList, attrBuf, attrBufSize, options);
    if (ret == 0 && is_tweak_active() && attrList && attrBuf && path) {
        if (should_fake_stat_path(path) && (attrList->commonattr & (ATTR_CMN_CRTIME | ATTR_CMN_MODTIME | ATTR_CMN_CHGTIME | ATTR_CMN_ACCTIME))) {
            ZTSettings *s = [ZTSettings sharedSettings];
            uint64_t baseBirth = s.birthTimeSec > 0 ? s.birthTimeSec : (s.bootTimeSec > 86400 ? (s.bootTimeSec - (86400 * 15 + 3600 * 4 + 720)) : 1568160000ULL);
            uint64_t effBirth = get_effective_birth_for_path(path, baseBirth);
            time_t fake_mtime = 0, fake_ctime = 0;
            long nsec_b = 0, nsec_m = 0, nsec_c = 0;
            get_consistent_stat_times_for_path(path, effBirth, &fake_mtime, &fake_ctime, &nsec_b, &nsec_m, &nsec_c);
            log_stat_path_once("getattrlist", path, effBirth, nsec_b);
            size_t words32 = attrBufSize / sizeof(uint32_t);
            uint32_t *ptr32 = (uint32_t *)attrBuf;
            int timeIdx = 0;
            for (size_t i = 0; i < words32; ++i) {
                if (ptr32[i] >= 1400000000U && ptr32[i] <= 2500000000U) {
                    if (timeIdx == 0) {
                        ptr32[i] = (uint32_t)effBirth;
                        if (sizeof(time_t) == 8 && i + 1 < words32 && ptr32[i + 1] == 0) {
                            i++;
                        }
                        if (i + 1 < words32 && ptr32[i + 1] < 1000000000U) {
                            ptr32[i + 1] = (uint32_t)nsec_b;
                        }
                    } else if (timeIdx == 1) {
                        ptr32[i] = (uint32_t)fake_mtime;
                        if (sizeof(time_t) == 8 && i + 1 < words32 && ptr32[i + 1] == 0) {
                            i++;
                        }
                        if (i + 1 < words32 && ptr32[i + 1] < 1000000000U) {
                            ptr32[i + 1] = (uint32_t)nsec_m;
                        }
                    } else {
                        ptr32[i] = (uint32_t)fake_ctime;
                        if (sizeof(time_t) == 8 && i + 1 < words32 && ptr32[i + 1] == 0) {
                            i++;
                        }
                        if (i + 1 < words32 && ptr32[i + 1] < 1000000000U) {
                            ptr32[i + 1] = (uint32_t)nsec_c;
                        }
                    }
                    timeIdx++;
                }
            }
        }
    }
    return ret;
}

// ==========================================
// HOOK DYLD & DLADDR: Ẩn hoàn toàn Zalotweak.dylib, Substrate, ElleKit, RootHide, Sileo, Zebra khỏi bộ quét của Zalo
// ==========================================
static BOOL is_sensitive_image_path_cstr(const char *name) {
    if (!name) return NO;
    return (strstr(name, "Zalotweak") != NULL ||
            strstr(name, "zalotweak") != NULL ||
            strstr(name, "Substrate") != NULL ||
            strstr(name, "substrate") != NULL ||
            strstr(name, "substitute") != NULL ||
            strstr(name, "ellekit") != NULL ||
            strstr(name, "ElleKit") != NULL ||
            strstr(name, "libinjector") != NULL ||
            strstr(name, "systemhook") != NULL ||
            strstr(name, "roothide") != NULL ||
            strstr(name, "RootHide") != NULL ||
            strstr(name, "jbroot") != NULL ||
            strstr(name, "/var/jb/") != NULL ||
            strstr(name, "/jb/") != NULL ||
            strstr(name, "TweakInject") != NULL ||
            strstr(name, "libhooker") != NULL ||
            strstr(name, "Choicy") != NULL ||
            strstr(name, "Shadow") != NULL ||
            strstr(name, "MobileSafety") != NULL ||
            strstr(name, "Frida") != NULL ||
            strstr(name, "frida") != NULL ||
            strstr(name, "cydia") != NULL ||
            strstr(name, "Cydia") != NULL ||
            strstr(name, "SSLKillSwitch") != NULL ||
            strstr(name, "sslkillswitch") != NULL ||
            strstr(name, "vnodebypass") != NULL ||
            strstr(name, "kernbypass") != NULL);
}

static const char *(*orig_dyld_get_image_name)(uint32_t image_index);
static const char *my_dyld_get_image_name(uint32_t image_index) {
    const char *name = orig_dyld_get_image_name ? orig_dyld_get_image_name(image_index) : _dyld_get_image_name(image_index);
    if (name && is_tweak_active() && is_sensitive_image_path_cstr(name)) {
        static const char *s_safe_fallback_images[] = {
            "/usr/lib/libobjc.A.dylib",
            "/usr/lib/system/libsystem_c.dylib",
            "/usr/lib/system/libsystem_kernel.dylib",
            "/usr/lib/system/libsystem_m.dylib",
            "/usr/lib/system/libdispatch.dylib"
        };
        return s_safe_fallback_images[image_index % 5];
    }
    return name;
}

static int my_dladdr(const void *addr, Dl_info *info) {
    int ret = raw_dladdr(addr, info);
    if (ret != 0 && info && is_tweak_active()) {
        BOOL sensitiveImg = (info->dli_fname && is_sensitive_image_path_cstr(info->dli_fname));
        BOOL sensitiveSym = (info->dli_sname && (strncmp(info->dli_sname, "ZT", 2) == 0 ||
                                                 strncmp(info->dli_sname, "my_", 3) == 0 ||
                                                 strncmp(info->dli_sname, "_logos_", 7) == 0));
        if (sensitiveImg || sensitiveSym) {
            info->dli_fname = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation";
            info->dli_sname = NULL;
            info->dli_saddr = NULL;
        }
    }
    return ret;
}

static const char *(*orig_class_getImageName)(Class cls) = NULL;
static const char *my_class_getImageName(Class cls) {
    const char *img = orig_class_getImageName ? orig_class_getImageName(cls) : class_getImageName(cls);
    if (img && is_tweak_active() && is_sensitive_image_path_cstr(img)) {
        return "/System/Library/Frameworks/UIKit.framework/UIKit";
    }
    return img;
}

static const char **(*orig_objc_copyImageNames)(unsigned int *outCount) = NULL;
static const char **my_objc_copyImageNames(unsigned int *outCount) {
    unsigned int realCount = 0;
    const char **list = orig_objc_copyImageNames ? orig_objc_copyImageNames(&realCount) : objc_copyImageNames(&realCount);
    if (!list || !is_tweak_active()) {
        if (outCount) *outCount = realCount;
        return list;
    }
    unsigned int writeIdx = 0;
    for (unsigned int i = 0; i < realCount; i++) {
        if (list[i] && is_sensitive_image_path_cstr(list[i])) {
            continue;
        }
        list[writeIdx++] = list[i];
    }
    list[writeIdx] = NULL;
    if (outCount) *outCount = writeIdx;
    return list;
}

static Class *(*orig_objc_copyClassList)(unsigned int *outCount) = NULL;
static Class *my_objc_copyClassList(unsigned int *outCount) {
    unsigned int realCount = 0;
    Class *list = orig_objc_copyClassList ? orig_objc_copyClassList(&realCount) : objc_copyClassList(&realCount);
    if (!list || !is_tweak_active()) {
        if (outCount) *outCount = realCount;
        return list;
    }
    unsigned int writeIdx = 0;
    for (unsigned int i = 0; i < realCount; i++) {
        Class cls = list[i];
        const char *img = orig_class_getImageName ? orig_class_getImageName(cls) : class_getImageName(cls);
        if (img && is_sensitive_image_path_cstr(img)) {
            continue;
        }
        list[writeIdx++] = cls;
    }
    list[writeIdx] = Nil;
    if (outCount) *outCount = writeIdx;
    return list;
}

// ==========================================
// HOOK POSIX open & openat: Chặn quét đường dẫn phát hiện Jailbreak
// ==========================================
static int (*orig_open)(const char *path, int oflag, ...);
static int my_open(const char *path, int oflag, ...) {
    mode_t mode = 0;
    if (oflag & O_CREAT) {
        va_list args;
        va_start(args, oflag);
        mode = (mode_t)va_arg(args, int);
        va_end(args);
    }

    if (is_tweak_active() && path && is_jailbreak_path(path)) {
        void *c0 = __builtin_return_address(0);
        if (is_zalo_caller(c0)) {
            errno = ENOENT;
            return -1;
        }
    }

    return orig_open ? orig_open(path, oflag, mode) : open(path, oflag, mode);
}

static int (*orig_openat)(int fd, const char *path, int oflag, ...);
static int my_openat(int fd, const char *path, int oflag, ...) {
    mode_t mode = 0;
    if (oflag & O_CREAT) {
        va_list args;
        va_start(args, oflag);
        mode = (mode_t)va_arg(args, int);
        va_end(args);
    }

    if (is_tweak_active() && path && is_jailbreak_path(path)) {
        void *c0 = __builtin_return_address(0);
        if (is_zalo_caller(c0)) {
            errno = ENOENT;
            return -1;
        }
    }

    return orig_openat ? orig_openat(fd, path, oflag, mode) : openat(fd, path, oflag, mode);
}

// ==========================================
// HOOK MOBILEGESTALT (MGCOPYANSWER) & HARDWARE RADAR
// ==========================================
static CFTypeRef (*orig_MGCopyAnswer)(CFStringRef property) = NULL;
static CFTypeRef my_MGCopyAnswer(CFStringRef property) {
    static __thread BOOL s_in_mg = NO;
    if (s_in_mg || !property || CFGetTypeID(property) != CFStringGetTypeID() || !is_tweak_active()) {
        return orig_MGCopyAnswer ? orig_MGCopyAnswer(property) : NULL;
    }
    s_in_mg = YES;

    NSString *prop = (__bridge NSString *)property;
    ZTSettings *settings = [ZTSettings sharedSettings];

    if ([prop isEqualToString:@"SerialNumber"]) {
        s_in_mg = NO;
        // App Store apps không có quyền đọc SerialNumber qua MGCopyAnswer -> Trả NULL chuẩn Apple Sandbox
        return orig_MGCopyAnswer ? orig_MGCopyAnswer(property) : NULL;
    }
    if ([prop isEqualToString:@"UniqueDeviceID"]) {
        NSString *udid = [[settings.spoofedIDFV stringByReplacingOccurrencesOfString:@"-" withString:@""] lowercaseString];
        s_in_mg = NO;
        return (__bridge_retained CFTypeRef)[udid copy];
    }
    if ([prop isEqualToString:@"WifiAddress"]) {
        s_in_mg = NO;
        // Chuẩn iOS 7+: Third-party apps luôn nhận 02:00:00:00:00:00
        return (__bridge_retained CFTypeRef)[@"02:00:00:00:00:00" copy];
    }
    if ([prop isEqualToString:@"BluetoothAddress"]) {
        s_in_mg = NO;
        return NULL;
    }
    if ([prop isEqualToString:@"UserAssignedDeviceName"]) {
        s_in_mg = NO;
        NSString *sysVer = settings.systemVersion;
        if (sysVer.length > 0 && [[sysVer componentsSeparatedByString:@"."].firstObject integerValue] >= 16) {
            return (__bridge_retained CFTypeRef)[@"iPhone" copy];
        }
        return settings.deviceName ? (__bridge_retained CFTypeRef)[settings.deviceName copy] : (orig_MGCopyAnswer ? orig_MGCopyAnswer(property) : NULL);
    }
    if ([prop isEqualToString:@"ProductType"]) {
        s_in_mg = NO;
        return settings.deviceMachine ? (__bridge_retained CFTypeRef)[settings.deviceMachine copy] : (orig_MGCopyAnswer ? orig_MGCopyAnswer(property) : NULL);
    }
    if ([prop isEqualToString:@"ProductVersion"]) {
        s_in_mg = NO;
        return settings.systemVersion ? (__bridge_retained CFTypeRef)[settings.systemVersion copy] : (orig_MGCopyAnswer ? orig_MGCopyAnswer(property) : NULL);
    }
    if ([prop isEqualToString:@"BuildVersion"]) {
        s_in_mg = NO;
        return settings.kernOsVersion ? (__bridge_retained CFTypeRef)[settings.kernOsVersion copy] : (orig_MGCopyAnswer ? orig_MGCopyAnswer(property) : NULL);
    }
    if ([prop isEqualToString:@"HWModelStr"] || [prop isEqualToString:@"HardwarePlatform"]) {
        s_in_mg = NO;
        return settings.deviceModel ? (__bridge_retained CFTypeRef)[settings.deviceModel copy] : (orig_MGCopyAnswer ? orig_MGCopyAnswer(property) : NULL);
    }
    if ([prop isEqualToString:@"TotalDiskCapacity"] || [prop isEqualToString:@"TotalDataCapacity"] || [prop isEqualToString:@"TotalDataAvailable"] || [prop isEqualToString:@"DiskUsage"]) {
        s_in_mg = NO;
        if (settings.enableAuditLog) {
            logAudit(@"RADAR-MG", [NSString stringWithFormat:@"MobileGestalt MGCopyAnswer(%@) -> [CHUẨN SANDBOX APPLE: TRẢ VỀ NULL/0]", prop]);
        }
        return NULL;
    }

    s_in_mg = NO;
    return orig_MGCopyAnswer ? orig_MGCopyAnswer(property) : NULL;
}

static inline BOOL is_sideload_provision_path(NSString *path) {
    if (!path) return NO;
    NSString *lower = [path lowercaseString];
    return [lower containsString:@"embedded.mobileprovision"] ||
           [lower containsString:@"embedded.provisionprofile"];
}

%hook NSFileManager

- (BOOL)fileExistsAtPath:(NSString *)path {
    if (path) {
        if (is_sideload_provision_path(path)) {
            logAudit(@"SIDELOAD-CHECK", [NSString stringWithFormat:@"Zalo quét chứng chỉ '%@' -> [ĐÃ ẨN - TRẢ VỀ NO]", path]);
            return NO;
        }
        if (is_tweak_active() && is_jailbreak_path([path UTF8String])) {
            logAudit(@"JB-FILE-CHECK", [NSString stringWithFormat:@"Zalo quét file Jailbreak '%@' -> [ĐÃ ẨN - TRẢ VỀ NO]", path]);
            return NO;
        }
    }
    return %orig;
}

- (BOOL)fileExistsAtPath:(NSString *)path isDirectory:(BOOL *)isDirectory {
    if (path) {
        if (is_sideload_provision_path(path)) {
            if (isDirectory) *isDirectory = NO;
            logAudit(@"SIDELOAD-CHECK", [NSString stringWithFormat:@"Zalo quét chứng chỉ '%@' -> [ĐÃ ẨN - TRẢ VỀ NO]", path]);
            return NO;
        }
        if (is_tweak_active() && is_jailbreak_path([path UTF8String])) {
            if (isDirectory) *isDirectory = NO;
            logAudit(@"JB-FILE-CHECK", [NSString stringWithFormat:@"Zalo quét file Jailbreak '%@' -> [ĐÃ ẨN - TRẢ VỀ NO]", path]);
            return NO;
        }
    }
    return %orig;
}

- (NSDictionary<NSFileAttributeKey, id> *)attributesOfFileSystemForPath:(NSString *)path error:(NSError **)error {
    NSDictionary *attrs = %orig;
    if (!is_tweak_active()) {
        return attrs;
    }
    ZTSettings *settings = [ZTSettings sharedSettings];
    if (settings.diskTotalSize == 0 && settings.diskFreeSize == 0) {
        return attrs;
    }
    NSMutableDictionary *fakeAttrs = attrs ? [attrs mutableCopy] : [NSMutableDictionary dictionary];
    if (settings.diskTotalSize > 0) {
        fakeAttrs[NSFileSystemSize] = @(settings.diskTotalSize);
    }
    if (settings.diskFreeSize > 0) {
        fakeAttrs[NSFileSystemFreeSize] = @(settings.diskFreeSize);
    }
    return fakeAttrs;
}

- (NSDictionary<NSFileAttributeKey, id> *)attributesOfItemAtPath:(NSString *)path error:(NSError **)error {
    if (is_tweak_active() && path && is_jailbreak_path([path UTF8String])) {
        void *c0 = __builtin_return_address(0);
        if (is_zalo_caller(c0)) {
            logAudit(@"JB-FILE-CHECK", [NSString stringWithFormat:@"Zalo gọi attributesOfItemAtPath:'%@' -> [ĐÃ ẨN - TRẢ VỀ NIL]", path]);
        }
        if (error) *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileReadNoSuchFileError userInfo:nil];
        return nil;
    }
    NSDictionary *attrs = %orig;
    if (is_tweak_active() && attrs && path) {
        NSString *lower = [path lowercaseString];
        if ([lower containsString:@"zalotweak"] ||
            [lower containsString:@".adbk"] ||
            [lower containsString:@"appsmanager"] ||
            [lower containsString:@"zaloaudit.log"] ||
            [lower containsString:@"zalotraffic.har"]) {
            return attrs;
        }
        if ([lower containsString:@"container"] ||
            [lower containsString:@"document"] ||
            [lower containsString:@"library"] ||
            [lower containsString:@"mobile"] ||
            [lower containsString:@"var"] ||
            [lower containsString:@"application"] ||
            [lower isEqualToString:@"/"] ||
            [lower isEqualToString:@"/private"]) {
            ZTSettings *s = [ZTSettings sharedSettings];
            uint64_t btime = s.bootTimeSec;
            if (btime > 0 || s.birthTimeSec > 0) {
                uint64_t base_birth = s.birthTimeSec > 0 ? s.birthTimeSec : (btime > 86400 ? (btime - (86400 * 15 + 3600 * 4 + 720)) : 1568160000ULL);
                uint64_t fake_birth = get_effective_birth_for_path([path UTF8String], base_birth);
                time_t fake_mtime = 0, fake_ctime = 0;
                long nsec_b = 0, nsec_m = 0, nsec_c = 0;
                get_consistent_stat_times_for_path([path UTF8String], fake_birth, &fake_mtime, &fake_ctime, &nsec_b, &nsec_m, &nsec_c);
                log_stat_path_once("NSFileManager", [path UTF8String], fake_birth, nsec_b);
                NSDate *fakeDate = [NSDate dateWithTimeIntervalSince1970:((NSTimeInterval)fake_birth + (NSTimeInterval)nsec_b / 1000000000.0)];
                NSDate *fakeModDate = [NSDate dateWithTimeIntervalSince1970:((NSTimeInterval)fake_mtime + (NSTimeInterval)nsec_m / 1000000000.0)];
                NSMutableDictionary *m = [attrs mutableCopy];
                m[NSFileCreationDate] = fakeDate;
                m[NSFileModificationDate] = fakeModDate;
                return m;
            }
        }
    }
    return attrs;
}

// Chặn không cho quét danh sách các container ứng dụng khác và lọc sạch app Jailbreak trong /Applications
- (NSArray<NSString *> *)contentsOfDirectoryAtPath:(NSString *)path error:(NSError **)error {
    if (path) {
        NSString *lower = [path lowercaseString];
        if ([lower isEqualToString:@"/applications"] || [lower isEqualToString:@"/applications/"]) {
            NSArray<NSString *> *items = %orig;
            if (items && items.count > 0) {
                NSMutableArray<NSString *> *filtered = [NSMutableArray arrayWithCapacity:items.count];
                for (NSString *item in items) {
                    NSString *itemLower = [item lowercaseString];
                    if ([itemLower containsString:@"sileo"] ||
                        [itemLower containsString:@"cydia"] ||
                        [itemLower containsString:@"zebra"] ||
                        [itemLower containsString:@"filza"] ||
                        [itemLower containsString:@"substitute"] ||
                        [itemLower containsString:@"ellekit"] ||
                        [itemLower containsString:@"trollstore"] ||
                        [itemLower containsString:@"newterm"] ||
                        [itemLower containsString:@"santander"] ||
                        [itemLower containsString:@"checkra1n"] ||
                        [itemLower containsString:@"dropbear"] ||
                        [itemLower containsString:@"roothide"] ||
                        [itemLower containsString:@"dopamine"] ||
                        [itemLower containsString:@"palera1n"]) {
                        continue;
                    }
                    [filtered addObject:item];
                }
                return filtered;
            }
        }
        if ([lower containsString:@"/containers/data/application"] && ![lower containsString:[NSHomeDirectory() lowercaseString]]) {
            logAudit(@"SCAN-CONTAINER", [NSString stringWithFormat:@"Zalo quét thư mục container '%@' -> [ĐÃ CHẶN - TRẢ VỀ RỖNG]", path]);
            return @[];
        }
        if ([lower containsString:@"/containers/shared/appgroup"]) {
            logAudit(@"SCAN-GROUP", [NSString stringWithFormat:@"Zalo quét danh mục App Group '%@' -> [ĐÃ CHẶN - TRẢ VỀ RỖNG]", path]);
            return @[];
        }
    }
    return %orig;
}

- (NSArray<NSURL *> *)contentsOfDirectoryAtURL:(NSURL *)url includingPropertiesForKeys:(NSArray<NSURLResourceKey> *)keys options:(NSDirectoryEnumerationOptions)mask error:(NSError **)error {
    if (url && [url isFileURL]) {
        NSString *path = [url path];
        NSString *lower = [path lowercaseString];
        if ([lower isEqualToString:@"/applications"] || [lower isEqualToString:@"/applications/"]) {
            NSArray<NSURL *> *items = %orig;
            if (items && items.count > 0) {
                NSMutableArray<NSURL *> *filtered = [NSMutableArray arrayWithCapacity:items.count];
                for (NSURL *u in items) {
                    NSString *uLower = [[u lastPathComponent] lowercaseString];
                    if ([uLower containsString:@"sileo"] ||
                        [uLower containsString:@"cydia"] ||
                        [uLower containsString:@"zebra"] ||
                        [uLower containsString:@"filza"] ||
                        [uLower containsString:@"substitute"] ||
                        [uLower containsString:@"ellekit"] ||
                        [uLower containsString:@"trollstore"] ||
                        [uLower containsString:@"newterm"] ||
                        [uLower containsString:@"santander"] ||
                        [uLower containsString:@"checkra1n"] ||
                        [uLower containsString:@"dropbear"] ||
                        [uLower containsString:@"roothide"] ||
                        [uLower containsString:@"dopamine"] ||
                        [uLower containsString:@"palera1n"]) {
                        continue;
                    }
                    [filtered addObject:u];
                }
                return filtered;
            }
        }
    }
    return %orig;
}

%end

// ==========================================
// HOOK NSURL: Trả về ngày tạo file đồng bộ chính xác tới nano-giây với stat/getattrlist
// ==========================================
%hook NSURL

- (BOOL)getResourceValue:(id *)value forKey:(NSURLResourceKey)key error:(NSError **)error {
    BOOL ret = %orig;
    if (is_tweak_active() && value && key) {
        ZTSettings *s = [ZTSettings sharedSettings];
        if ([key isEqualToString:NSURLVolumeTotalCapacityKey] && s.diskTotalSize > 0) {
            *value = @(s.diskTotalSize);
            return YES;
        }
        if ([key isEqualToString:NSURLVolumeAvailableCapacityKey] && s.diskFreeSize > 0) {
            *value = @(s.diskFreeSize);
            return YES;
        }
        if ([key isEqualToString:NSURLVolumeAvailableCapacityForImportantUsageKey] && s.diskFreeSize > 0) {
            uint64_t purgeable = 1450000000ULL + ((s.diskFreeSize * 104729ULL) % 1500000000ULL);
            *value = @(s.diskFreeSize + purgeable);
            return YES;
        }
        if ([key isEqualToString:NSURLVolumeAvailableCapacityForOpportunisticUsageKey] && s.diskFreeSize > 0) {
            uint64_t reserve = 450000000ULL + ((s.diskFreeSize * 2654435761ULL) % 450000000ULL);
            uint64_t oppFree = (s.diskFreeSize > reserve) ? (s.diskFreeSize - reserve) : s.diskFreeSize;
            *value = @(oppFree);
            return YES;
        }
        if ([key isEqualToString:NSURLCreationDateKey] || [key isEqualToString:NSURLContentModificationDateKey] || [key isEqualToString:NSURLAttributeModificationDateKey]) {
            uint64_t btime = s.bootTimeSec;
            if (btime > 0 || s.birthTimeSec > 0) {
                uint64_t base_birth = s.birthTimeSec > 0 ? s.birthTimeSec : (btime > 86400 ? (btime - (86400 * 15 + 3600 * 4 + 720)) : 1568160000ULL);
                NSString *urlPath = [self isFileURL] ? [self path] : nil;
                uint64_t fake_birth = get_effective_birth_for_path(urlPath ? [urlPath UTF8String] : NULL, base_birth);
                time_t fake_mtime = 0, fake_ctime = 0;
                long nsec_b = 0, nsec_m = 0, nsec_c = 0;
                get_consistent_stat_times_for_path(urlPath ? [urlPath UTF8String] : NULL, fake_birth, &fake_mtime, &fake_ctime, &nsec_b, &nsec_m, &nsec_c);
                if ([key isEqualToString:NSURLCreationDateKey]) {
                    if (urlPath) log_stat_path_once("NSURL.getResourceValue", [urlPath UTF8String], fake_birth, nsec_b);
                    *value = [NSDate dateWithTimeIntervalSince1970:((NSTimeInterval)fake_birth + (NSTimeInterval)nsec_b / 1000000000.0)];
                } else if ([key isEqualToString:NSURLContentModificationDateKey]) {
                    *value = [NSDate dateWithTimeIntervalSince1970:((NSTimeInterval)fake_mtime + (NSTimeInterval)nsec_m / 1000000000.0)];
                } else {
                    *value = [NSDate dateWithTimeIntervalSince1970:((NSTimeInterval)fake_ctime + (NSTimeInterval)nsec_c / 1000000000.0)];
                }
                return YES;
            }
        }
    }
    return ret;
}

- (NSDictionary<NSURLResourceKey, id> *)resourceValuesForKeys:(NSArray<NSURLResourceKey> *)keys error:(NSError **)error {
    NSDictionary<NSURLResourceKey, id> *values = %orig;
    if (is_tweak_active() && keys) {
        ZTSettings *s = [ZTSettings sharedSettings];
        NSMutableDictionary *m = values ? [values mutableCopy] : [NSMutableDictionary dictionary];
        BOOL changed = NO;
        if ([keys containsObject:NSURLVolumeTotalCapacityKey] && s.diskTotalSize > 0) {
            m[NSURLVolumeTotalCapacityKey] = @(s.diskTotalSize);
            changed = YES;
        }
        if ([keys containsObject:NSURLVolumeAvailableCapacityKey] && s.diskFreeSize > 0) {
            m[NSURLVolumeAvailableCapacityKey] = @(s.diskFreeSize);
            changed = YES;
        }
        if ([keys containsObject:NSURLVolumeAvailableCapacityForImportantUsageKey] && s.diskFreeSize > 0) {
            uint64_t purgeable = 1450000000ULL + ((s.diskFreeSize * 104729ULL) % 1500000000ULL);
            m[NSURLVolumeAvailableCapacityForImportantUsageKey] = @(s.diskFreeSize + purgeable);
            changed = YES;
        }
        if ([keys containsObject:NSURLVolumeAvailableCapacityForOpportunisticUsageKey] && s.diskFreeSize > 0) {
            uint64_t reserve = 450000000ULL + ((s.diskFreeSize * 2654435761ULL) % 450000000ULL);
            uint64_t oppFree = (s.diskFreeSize > reserve) ? (s.diskFreeSize - reserve) : s.diskFreeSize;
            m[NSURLVolumeAvailableCapacityForOpportunisticUsageKey] = @(oppFree);
            changed = YES;
        }
        uint64_t btime = s.bootTimeSec;
        if (btime > 0 || s.birthTimeSec > 0) {
            uint64_t base_birth = s.birthTimeSec > 0 ? s.birthTimeSec : (btime > 86400 ? (btime - (86400 * 15 + 3600 * 4 + 720)) : 1568160000ULL);
            NSString *urlPath = [self isFileURL] ? [self path] : nil;
            uint64_t fake_birth = get_effective_birth_for_path(urlPath ? [urlPath UTF8String] : NULL, base_birth);
            time_t fake_mtime = 0, fake_ctime = 0;
            long nsec_b = 0, nsec_m = 0, nsec_c = 0;
            get_consistent_stat_times_for_path(urlPath ? [urlPath UTF8String] : NULL, fake_birth, &fake_mtime, &fake_ctime, &nsec_b, &nsec_m, &nsec_c);
            if ([keys containsObject:NSURLCreationDateKey]) {
                if (urlPath) log_stat_path_once("NSURL.resourceValues", [urlPath UTF8String], fake_birth, nsec_b);
                m[NSURLCreationDateKey] = [NSDate dateWithTimeIntervalSince1970:((NSTimeInterval)fake_birth + (NSTimeInterval)nsec_b / 1000000000.0)];
                changed = YES;
            }
            if ([keys containsObject:NSURLContentModificationDateKey]) {
                m[NSURLContentModificationDateKey] = [NSDate dateWithTimeIntervalSince1970:((NSTimeInterval)fake_mtime + (NSTimeInterval)nsec_m / 1000000000.0)];
                changed = YES;
            }
            if ([keys containsObject:NSURLAttributeModificationDateKey]) {
                m[NSURLAttributeModificationDateKey] = [NSDate dateWithTimeIntervalSince1970:((NSTimeInterval)fake_ctime + (NSTimeInterval)nsec_c / 1000000000.0)];
                changed = YES;
            }
        }
        if (changed) return m;
    }
    return values;
}

- (BOOL)checkResourceIsReachableAndReturnError:(NSError **)error {
    if (is_tweak_active() && [self isFileURL]) {
        NSString *p = [self path];
        if (p && is_jailbreak_path([p UTF8String])) {
            void *c0 = __builtin_return_address(0);
            if (is_zalo_caller(c0)) {
                if (error) {
                    *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileReadNoSuchFileError userInfo:@{NSFilePathErrorKey: p}];
                }
                return NO;
            }
        }
    }
    return %orig;
}

%end

@interface NSObject (ZTPKPushRegistrySupport)
- (void)pushRegistry:(id)registry didUpdatePushCredentials:(id)credentials forType:(NSString *)type;
- (NSData *)token;
@end

static NSData *get_or_create_spoofed_voip_token_data(void) {
    ZTSettings *st = [ZTSettings sharedSettings];
    if (st.spoofedVoIPToken.length != 64) {
        unsigned char voipBytes[32];
        arc4random_buf(voipBytes, sizeof(voipBytes));
        NSMutableString *vHex = [NSMutableString stringWithCapacity:64];
        for (int i = 0; i < 32; i++) {
            [vHex appendFormat:@"%02x", voipBytes[i]];
        }
        st.spoofedVoIPToken = [vHex copy];
        st.currentVoIPToken = st.spoofedVoIPToken;
        [st saveSettings];
        logAudit(@"PUSH-TOKEN", [NSString stringWithFormat:@"🎲 [SYSTEM AUTO-GEN] Tự sinh Token VoIP 32-byte độc nhất tầng hệ thống: %@", st.spoofedVoIPToken]);
    }

    static NSData *s_cachedVoIPData = nil;
    static NSString *s_lastVoIPTokenHex = nil;
    if (s_cachedVoIPData && s_lastVoIPTokenHex && [s_lastVoIPTokenHex isEqualToString:st.spoofedVoIPToken]) {
        return s_cachedVoIPData;
    }

    NSMutableData *data = [NSMutableData dataWithCapacity:32];
    const char *chars = [st.spoofedVoIPToken UTF8String];
    char byteChars[3] = {'\0', '\0', '\0'};
    for (int i = 0; i < 64; i += 2) {
        byteChars[0] = chars[i];
        byteChars[1] = chars[i + 1];
        unsigned char byte = (unsigned char)strtol(byteChars, NULL, 16);
        [data appendBytes:&byte length:1];
    }
    s_cachedVoIPData = [data copy];
    s_lastVoIPTokenHex = [st.spoofedVoIPToken copy];
    return s_cachedVoIPData;
}

%hook PKPushCredentials

- (NSData *)token {
    if (is_tweak_active()) {
        ZTSettings *st = [ZTSettings sharedSettings];
        if (st.spoofVoIPPushToken) {
            return get_or_create_spoofed_voip_token_data();
        }
    }
    return %orig;
}

%end

%hook PKPushRegistry

- (NSData *)pushTokenForType:(id)type {
    if (is_tweak_active()) {
        ZTSettings *st = [ZTSettings sharedSettings];
        if (st.spoofVoIPPushToken) {
            NSString *tStr = [type description];
            if ([tStr isEqualToString:@"PKPushTypeVoIP"] || [tStr containsString:@"VoIP"]) {
                return get_or_create_spoofed_voip_token_data();
            }
        }
    }
    return %orig(type);
}

- (void)setDelegate:(id)delegate {
    if (delegate && is_tweak_active()) {
        static NSMutableSet *s_swappedPKDelClasses = nil;
        static dispatch_once_t s_pkOnceToken;
        dispatch_once(&s_pkOnceToken, ^{
            s_swappedPKDelClasses = [NSMutableSet new];
        });
        Class delClass = [delegate class];
        if (delClass && ![s_swappedPKDelClasses containsObject:delClass]) {
            [s_swappedPKDelClasses addObject:delClass];
            SEL credSel = @selector(pushRegistry:didUpdatePushCredentials:forType:);
            Method credMethod = class_getInstanceMethod(delClass, credSel);
            if (credMethod) {
                typedef void (*OrigCredIMP)(id, SEL, id, id, NSString *);
                OrigCredIMP origImp = (OrigCredIMP)method_getImplementation(credMethod);
                IMP customCredImp = imp_implementationWithBlock(^(id self_del, id registry, id creds, NSString *type) {
                    if (creds && [creds respondsToSelector:@selector(token)]) {
                        BOOL isVoIP = YES;
                        if (type && [type isKindOfClass:[NSString class]]) {
                            isVoIP = [type isEqualToString:@"PKPushTypeVoIP"] || [type.lowercaseString containsString:@"voip"];
                        }
                        if (!isVoIP) {
                            logAudit(@"PUSH-TOKEN", [NSString stringWithFormat:@"ℹ️ [PUSHKIT PHỤ] Bỏ qua credentials không phải VoIP (type=%@)", type]);
                        } else {
                            ZTSettings *st = [ZTSettings sharedSettings];
                            if (st.spoofVoIPPushToken) {
                                get_or_create_spoofed_voip_token_data();
                                st.currentVoIPToken = st.spoofedVoIPToken;
                                [st saveSettings];
                                logAudit(@"PUSH-TOKEN", [NSString stringWithFormat:@"📞 [PUSHKIT CREDENTIALS] Đã cấp Token VoIP giả lập độc nhất từ PushKit (Type=%@): %@", type ?: @"VoIP", st.spoofedVoIPToken]);
                            } else {
                                NSData *tokData = [creds respondsToSelector:@selector(token)] ? [creds token] : nil;
                                if (tokData && tokData.length > 0) {
                                    const unsigned char *b = (const unsigned char *)[tokData bytes];
                                    NSUInteger len = [tokData length];
                                    NSMutableString *hex = [NSMutableString stringWithCapacity:(len * 2)];
                                    for (NSUInteger i = 0; i < len; i++) {
                                        [hex appendFormat:@"%02x", b[i]];
                                    }
                                    st.currentVoIPToken = hex;
                                    [st saveSettings];
                                    logAudit(@"PUSH-TOKEN", [NSString stringWithFormat:@"📞 [PUSHKIT CREDENTIALS] Đã bắt Token VoIP gốc từ PushKit (Type=%@): %@", type ?: @"VoIP", hex]);
                                }
                            }
                        }
                    }
                    if (origImp) {
                        origImp(self_del, credSel, registry, creds, type);
                    }
                });
                method_setImplementation(credMethod, customCredImp);
            }
        }
    }
    %orig;
}

%end

%hook UIApplication

- (void)registerForRemoteNotifications {
    if (is_tweak_active()) {
        logAudit(@"APNS-REGISTER", @"📡 [APNS-REGISTER] Zalo đã gọi [[UIApplication sharedApplication] registerForRemoteNotifications] đến Apple Push Gateway (apsd)");
    }
    %orig;
}

- (void)setDelegate:(id<UIApplicationDelegate>)delegate {
    if (delegate && is_tweak_active()) {
        static Class s_swappedDelClass = nil;
        Class delClass = [delegate class];
        if (delClass && delClass != s_swappedDelClass) {
            s_swappedDelClass = delClass;
            SEL regSel = @selector(application:didRegisterForRemoteNotificationsWithDeviceToken:);
            Method regMethod = class_getInstanceMethod(delClass, regSel);

            void (^tokenProcessorBlock)(id, UIApplication *, NSData *) = ^(id self_del, UIApplication *app, NSData *realToken) {
                if (realToken && [realToken length] > 0) {
                    const unsigned char *tokenBytes = (const unsigned char *)[realToken bytes];
                    NSUInteger tokenLen = [realToken length];
                    NSMutableString *tokenHex = [NSMutableString stringWithCapacity:(tokenLen * 2)];
                    for (NSUInteger i = 0; i < tokenLen; i++) {
                        [tokenHex appendFormat:@"%02x", tokenBytes[i]];
                    }

                    ZTSettings *s = [ZTSettings sharedSettings];
                    NSString *lastWiped = s.lastWipedAPNsToken;
                    if (!lastWiped || lastWiped.length == 0) {
                        NSDictionary *dict = [NSDictionary dictionaryWithContentsOfFile:getConfigPath()];
                        if (!dict) dict = [NSDictionary dictionaryWithContentsOfFile:GLOBAL_PREFS_PATH];
                        lastWiped = dict[@"lastWipedAPNsToken"];
                    }
                    NSString *statusStr = @"INITIAL_CAPTURED";

                    if (lastWiped && lastWiped.length > 0) {
                        if ([tokenHex isEqualToString:lastWiped]) {
                            statusStr = @"DUPLICATE";
                            logAudit(@"APNS-STATUS", [NSString stringWithFormat:@"🔴 [CẢNH BÁO TRÙNG] Token APNs nhận từ Apple TRÙNG 100%% với Token trước Wipe: %@ -> TUYỆT ĐỐI CHƯA ĐĂNG KÝ ACC MỚI! Vui lòng bật/tắt Airplane Mode 10s hoặc Wipe lại!", tokenHex]);
                            
                            // SAFETY INTERLOCK: Hiển thị cảnh báo trực tiếp trên màn hình Zalo
                            dispatch_async(dispatch_get_main_queue(), ^{
                                UIWindow *keyWin = nil;
                                for (UIWindow *w in [UIApplication sharedApplication].windows) {
                                    if (w.isKeyWindow || w.rootViewController) { keyWin = w; break; }
                                }
                                UIViewController *topVC = keyWin.rootViewController;
                                while (topVC.presentedViewController) {
                                    topVC = topVC.presentedViewController;
                                }
                                if (topVC) {
                                    UIAlertController *dupAlert = [UIAlertController alertControllerWithTitle:@"⚠️ CẢNH BÁO NGUY HIỂM"
                                                                                                      message:@"Token APNs từ Apple bị TRÙNG 100% với tài khoản trước vừa Wipe!

"
                                                                                                              @"• Nguyên nhân: Apple Gateway chưa kịp cấp Token mới.
"
                                                                                                              @"• Hậu quả: Nếu đăng ký bây giờ, Zalo sẽ khóa tài khoản ngay lập tức!

"
                                                                                                              @"👉 HÃY BẬT CHẾ ĐỘ MÁY BAY 10 GIÂY rồi tắt lại, hoặc Wipe lại từ Floating Menu."
                                                                                               preferredStyle:UIAlertControllerStyleAlert];
                                    [dupAlert addAction:[UIAlertAction actionWithTitle:@"Đã hiểu (Chờ đổi Token)" style:UIAlertActionStyleDestructive handler:nil]];
                                    [topVC presentViewController:dupAlert animated:YES completion:nil];
                                }
                            });
                        } else {
                            statusStr = @"ROTATED_NEW";
                            logAudit(@"APNS-STATUS", [NSString stringWithFormat:@"🟢 [THÀNH CÔNG] Token APNs ĐÃ ĐỔI MỚI HOÀN TOÀN!
- Token Mới: %@
- Token Cũ trước Wipe: %@
-> AN TOÀN TUYỆT ĐỐI ĐỂ ĐĂNG KÝ ACC MỚI!", tokenHex, lastWiped]);
                        }
                    } else {
                        logAudit(@"APNS-STATUS", [NSString stringWithFormat:@"ℹ️ [ĐÃ BẮT TOKEN ĐẦU TIÊN] Token APNs hiện tại của máy: %@ (Đã lưu làm mốc. Hãy vào Settings bấm Wipe để bắt đầu chu trình đổi token).", tokenHex]);
                    }

                    s.currentAPNsToken = tokenHex;
                    s.lastKnownAPNsToken = tokenHex;
                    s.apnsRotatedStatus = statusStr;
                    [s saveSettings];
                    chmod([GLOBAL_PREFS_PATH UTF8String], 0666);
                    CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(), CFSTR("com.sonhu.zalotweak/settingschanged"), NULL, NULL, YES);
                }
            };

            if (regMethod) {
                typedef void (*OrigDidRegIMP)(id, SEL, UIApplication *, NSData *);
                OrigDidRegIMP origImp = (OrigDidRegIMP)method_getImplementation(regMethod);
                IMP customRegImp = imp_implementationWithBlock(^(id self_del, UIApplication *app, NSData *realToken) {
                    tokenProcessorBlock(self_del, app, realToken);
                    if (origImp) {
                        origImp(self_del, regSel, app, realToken);
                    }
                });
                method_setImplementation(regMethod, customRegImp);
            } else {
                IMP customRegImp = imp_implementationWithBlock(^(id self_del, UIApplication *app, NSData *realToken) {
                    tokenProcessorBlock(self_del, app, realToken);
                });
                class_addMethod(delClass, regSel, customRegImp, "v@:@@");
            }

            // Tự động kết nối Apple Push Gateway để nhận APNs Token mới tinh sau khi Wipe
            static dispatch_once_t s_autoApnsOnce;
            dispatch_once(&s_autoApnsOnce, ^{
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                    if (is_tweak_active()) {
                        logAudit(@"APNS-REGISTER", @"🚀 [AUTO-APNS] Tự động kích hoạt registerForRemoteNotifications kết nối Apple Push Gateway...");
                        [[UIApplication sharedApplication] registerForRemoteNotifications];
                    }
                });
            });

            SEL bgSel = @selector(applicationDidEnterBackground:);
            Method bgMethod = class_getInstanceMethod(delClass, bgSel);
            if (bgMethod) {
                typedef void (*OrigBgIMP)(id, SEL, UIApplication *);
                OrigBgIMP origBg = (OrigBgIMP)method_getImplementation(bgMethod);
                IMP customBg = imp_implementationWithBlock(^(id self_del, UIApplication *app) {
                    logAudit(@"APP-LIFECYCLE", @"⏸️ [BACKGROUND] Zalo chuyển vào chạy ngầm (DidEnterBackground) -> Đang gia hạn Task & xả buffer log...");
                    renew_background_task_assertion();
                    flush_audit_and_har_queues_sync();
                    if (origBg) origBg(self_del, bgSel, app);
                });
                method_setImplementation(bgMethod, customBg);
            }

            SEL termSel = @selector(applicationWillTerminate:);
            Method termMethod = class_getInstanceMethod(delClass, termSel);
            if (termMethod) {
                typedef void (*OrigTermIMP)(id, SEL, UIApplication *);
                OrigTermIMP origTerm = (OrigTermIMP)method_getImplementation(termMethod);
                IMP customTerm = imp_implementationWithBlock(^(id self_del, UIApplication *app) {
                    handle_app_termination_event("applicationWillTerminate");
                    if (origTerm) origTerm(self_del, termSel, app);
                });
                method_setImplementation(termMethod, customTerm);
            }
        }
    }
    %orig;
}

- (void)_handleApplicationSuspend:(id)arg1 eventType:(int)arg2 {
    logAudit(@"APP-LIFECYCLE", @"⏸️ [SUSPEND] Zalo nhận sự kiện tạm dừng hệ thống -> Đã xả buffer log an toàn ✅");
    flush_audit_and_har_queues_sync();
    %orig;
}

- (BOOL)canOpenURL:(NSURL *)url {
    if (url) {
        NSString *scheme = [[url scheme] lowercaseString];
        // Chỉ chặn duy nhất phát hiện Jailbreak package managers & file explorers qua schemes
        if ([scheme isEqualToString:@"cydia"] ||
            [scheme isEqualToString:@"sileo"] ||
            [scheme isEqualToString:@"zbra"] ||
            [scheme isEqualToString:@"filza"] ||
            [scheme isEqualToString:@"santander"] ||
            [scheme isEqualToString:@"apt"] ||
            [scheme isEqualToString:@"trollstore"] ||
            [scheme isEqualToString:@"newterm"] ||
            [scheme isEqualToString:@"dropbear"] ||
            [scheme isEqualToString:@"ssh"] ||
            [scheme isEqualToString:@"undecimus"]) {
            logAudit(@"SCHEME-CHECK", [NSString stringWithFormat:@"canOpenURL('%@') -> [ĐÃ CHẶN JAILBREAK - TRẢ VỀ NO]", [url absoluteString]]);
            return NO;
        }
        // Cho phép quét thực tế app trên màn hình (YouTube, Facebook, Momo, Vietcombank, ZaloPay...)
        // Để Zalo gửi danh sách apps thực tế tự nhiên lên máy chủ, không bị rỗng apps: []
        BOOL res = %orig(url);
        void *c0 = __builtin_return_address(0);
        if (is_zalo_caller(c0)) {
            logAudit(@"SCHEME-CHECK", [NSString stringWithFormat:@"canOpenURL('%@') -> %@", [url absoluteString], (res ? @"YES ✅ (Có cài đặt)" : @"NO ❌ (Chưa cài đặt hoặc bị Apple LS chặn)")]);
        }
        return res;
    }
    return %orig;
}

%end

%hook UNNotificationServiceExtension

- (void)didReceiveNotificationRequest:(UNNotificationRequest *)request withContentHandler:(void (^)(UNNotificationContent *contentToDeliver))contentHandler {
    if (request && request.content) {
        NSDictionary *userInfo = request.content.userInfo;
        NSString *title = request.content.title ?: @"";
        NSString *body = request.content.body ?: @"";
        NSString *jsonStr = @"";
        if (userInfo) {
            @try {
                NSData *jd = [NSJSONSerialization dataWithJSONObject:userInfo options:0 error:nil];
                if (jd) jsonStr = [[NSString alloc] initWithData:jd encoding:NSUTF8StringEncoding];
            } @catch (NSException *e) {}
        }
        logAudit(@"PUSH-EXTENSION", [NSString stringWithFormat:@"📬 [PUSH-ON-TERMINATED] Nhận Push Notification khi app đóng: Title='%@' Body='%@' Payload=%@", title, body, jsonStr]);
        flush_audit_and_har_queues_sync();
    }
    %orig;
}

%end

%hook UIPasteboard

+ (UIPasteboard *)pasteboardWithName:(UIPasteboardName)pasteboardName create:(BOOL)create {
    if (pasteboardName) {
        NSString *lower = [pasteboardName lowercaseString];
        if ([lower containsString:@"zalo"] || [lower containsString:@"zingalo"] || [lower containsString:@"vng"]) {
            logAudit(@"PASTEBOARD", [NSString stringWithFormat:@"Zalo truy vấn pasteboard '%@' -> [ĐÃ CÁCH LY CHẶN ĐỌC]", pasteboardName]);
            return nil;
        }
    }
    return %orig;
}

%end

// ==========================================
// 8. TẦNG MẠNG: HAR NETWORK INSPECTOR TOÀN DIỆN (REQUEST & RESPONSE CHUẨN HAR 1.2)
// ==========================================

static NSString *getHarPath(void) {
    NSString *home = NSHomeDirectory();
    if (home) {
        return [home stringByAppendingPathComponent:@"Documents/ZaloTraffic.har"];
    }
    return @"/var/mobile/Library/Preferences/ZaloTraffic.har";
}

static void append_to_har_file(NSDictionary *entryDict) {
    if (!harQueue) {
        harQueue = dispatch_queue_create("com.sonhu.zalotweak.harQueue", DISPATCH_QUEUE_SERIAL);
    }

    dispatch_async(harQueue, ^{
        NSString *harPath = getHarPath();
        NSMutableDictionary *harRoot = nil;
        if ([[NSFileManager defaultManager] fileExistsAtPath:harPath]) {
            NSData *existingData = [NSData dataWithContentsOfFile:harPath];
            if (existingData) {
                harRoot = [NSJSONSerialization JSONObjectWithData:existingData options:NSJSONReadingMutableContainers error:nil];
            }
        }

        if (!harRoot || ![harRoot isKindOfClass:[NSMutableDictionary class]] || !harRoot[@"log"]) {
            harRoot = [NSMutableDictionary dictionary];
            NSMutableDictionary *logDict = [NSMutableDictionary dictionary];
            logDict[@"version"] = @"1.2";
            logDict[@"creator"] = @{
                @"name": @"ZaloTweak HAR Inspector",
                @"version": @"1.0"
            };
            logDict[@"entries"] = [NSMutableArray array];
            harRoot[@"log"] = logDict;
        }

        NSMutableArray *entries = harRoot[@"log"][@"entries"];
        if (entries) {
            [entries addObject:entryDict];
            // Giới hạn 500 request gần nhất
            if (entries.count > 500) {
                [entries removeObjectsInRange:NSMakeRange(0, entries.count - 500)];
            }
        }

        NSData *jsonData = [NSJSONSerialization dataWithJSONObject:harRoot options:NSJSONWritingPrettyPrinted error:nil];
        if (jsonData) {
            [jsonData writeToFile:harPath atomically:YES];
            chmod([harPath UTF8String], 0666);
            if (![harPath isEqualToString:@"/var/mobile/Documents/ZaloTraffic.har"]) {
                @try {
                    [jsonData writeToFile:@"/var/mobile/Documents/ZaloTraffic.har" atomically:YES];
                    chmod("/var/mobile/Documents/ZaloTraffic.har", 0666);
                } @catch (NSException *e) {}
            }
        }
    });
}

static NSInteger s_runtime_last_centralized_status = 0;
static NSString *s_runtime_last_centralized_did = nil;
static NSInteger s_runtime_qos_error_count = 0;

__attribute__((visibility("default"))) NSInteger zt_get_last_centralized_status(void) {
    return s_runtime_last_centralized_status;
}

__attribute__((visibility("default"))) NSString *zt_get_last_centralized_did(void) {
    if (s_runtime_last_centralized_did && s_runtime_last_centralized_did.length > 0) {
        return s_runtime_last_centralized_did;
    }
    return [ZTSettings sharedSettings].centralizedDid;
}

__attribute__((visibility("default"))) NSInteger zt_get_qos_error_count(void) {
    return s_runtime_qos_error_count;
}

__attribute__((visibility("default"))) void zt_reset_runtime_counters(void) {
    s_runtime_last_centralized_status = 0;
    s_runtime_last_centralized_did = nil;
    s_runtime_qos_error_count = 0;
}

__attribute__((visibility("default"))) void zt_log_audit(NSString *category, NSString *detail) {
    logAudit(category, detail);
}

static __attribute__((unused)) void record_har_traffic(NSURLRequest *request, NSData *reqBody, NSURLResponse *response, NSData *respData, NSError *error, NSDate *startDate, NSDate *finishDate) {
    if (!request || !request.URL) return;
    if ([request valueForHTTPHeaderField:@"X-ZT-Diagnostic"]) return;

    NSURL *url = request.URL;
    NSString *urlStr = url.absoluteString ?: @"";

    NSInteger statusCode = 0;
    if ([response isKindOfClass:[NSHTTPURLResponse class]]) {
        statusCode = ((NSHTTPURLResponse *)response).statusCode;
    } else if (error) {
        statusCode = error.code;
    }

    if ([urlStr containsString:@"centralized.zaloapp.com"]) {
        s_runtime_last_centralized_status = statusCode;
        if (respData && respData.length > 0) {
            @try {
                id jObj = [NSJSONSerialization JSONObjectWithData:respData options:0 error:nil];
                if ([jObj isKindOfClass:[NSDictionary class]]) {
                    id dataObj = jObj[@"data"];
                    if ([dataObj isKindOfClass:[NSDictionary class]]) {
                        NSString *did = dataObj[@"deviceId"] ?: (dataObj[@"dId"] ?: dataObj[@"did"]);
                        if (did && did.length > 0) {
                            s_runtime_last_centralized_did = [did copy];
                            if (![[ZTSettings sharedSettings].centralizedDid isEqualToString:did]) {
                                [ZTSettings sharedSettings].centralizedDid = [did copy];
                                [[ZTSettings sharedSettings] saveSettings];
                            }
                        }
                    }
                }
            } @catch (NSException *e) {}
        }
    }
    if ([urlStr containsString:@"qos-talk.123c.vn"]) {
        s_runtime_qos_error_count++;
    }

    if (![ZTSettings sharedSettings].enableAuditLog) return;
    NSString *method = request.HTTPMethod ?: @"GET";

    NSTimeInterval duration = finishDate ? [finishDate timeIntervalSinceDate:startDate] : 0;
    uint64_t durationMs = (uint64_t)(duration * 1000.0);

    NSHTTPURLResponse *httpResp = [response isKindOfClass:[NSHTTPURLResponse class]] ? (NSHTTPURLResponse *)response : nil;
    statusCode = httpResp ? httpResp.statusCode : (error ? error.code : 0);
    NSString *statusText = httpResp ? [NSHTTPURLResponse localizedStringForStatusCode:statusCode] : (error ? [error localizedDescription] : @"Pending/Unknown");

    // Diễn giải mục đích nghiệp vụ của request Zalo
    NSString *purpose = @"";
    if ([urlStr containsString:@"centralized.zaloapp.com/sdk/mobile/ios"]) {
        purpose = @"📲 [Zalo SDK: Khởi tạo phiên SDK & gửi cấu hình màn hình/thiết bị]";
    } else if ([urlStr containsString:@"centralized.zaloapp.com/id/mobile/ios"]) {
        purpose = @"🆔 [Zalo Định Danh: Gửi IDFA, IDFV, Hardware Model lên hệ thống Device Fingerprint]";
    } else if ([urlStr containsString:@"centralized.zaloapp.com/apps/mobile/ios"]) {
        purpose = @"🔍 [Zalo Version Check: Kiểm tra phiên bản ứng dụng]";
    } else if ([urlStr containsString:@"register.zaloapp.com/api/v1/register/consents"]) {
        purpose = @"📜 [Zalo Đăng Ký: Tải chính sách & điều khoản đồng ý người dùng]";
    } else if ([urlStr containsString:@"register.zaloapp.com/api/v1/login/phone/verify"]) {
        purpose = @"🔑 [Zalo Xác Thực: Gửi số điện thoại yêu cầu mã OTP đăng nhập/đăng ký]";
    } else if ([urlStr containsString:@"register.zaloapp.com/api/v1/register/accounts"]) {
        purpose = @"👤 [Zalo Đăng Ký: Gửi thông tin hoàn tất tạo tài khoản mới]";
    } else if ([urlStr containsString:@"register.zaloapp.com/api/v1/login/otp/verify"]) {
        purpose = @"🔢 [Zalo OTP: Xác thực mã OTP người dùng nhập]";
    } else if ([urlStr containsString:@"register.zaloapp.com/api/v2/login/otp"]) {
        purpose = @"📩 [Zalo OTP: Yêu cầu máy chủ gửi mã OTP về máy]";
    } else if ([urlStr containsString:@"register.zaloapp.com/api/v1/register/verify/name"]) {
        purpose = @"🏷️ [Zalo Đăng Ký: Xác thực tên hiển thị tài khoản]";
    } else if ([urlStr containsString:@"register.zaloapp.com/api/v1/register/verify/dob"]) {
        purpose = @"🎂 [Zalo Đăng Ký: Xác thực ngày sinh & giới tính]";
    } else if ([urlStr containsString:@"register.zaloapp.com/api/v1/settings/common"]) {
        purpose = @"⚙️ [Zalo Cấu Hình: Tải tham số hệ thống & máy chủ]";
    } else if ([urlStr containsString:@"register.zaloapp.com/api/register/getSupportCountry"]) {
        purpose = @"🌍 [Zalo Quốc Gia: Tải danh sách mã quốc gia hỗ trợ đăng ký]";
    } else if ([urlStr containsString:@"register.zaloapp.com/api/helper/getDefaultCountry"]) {
        purpose = @"📍 [Zalo Vị Trí: Lấy quốc gia mặc định của thiết bị]";
    } else if ([urlStr containsString:@"firebase-settings.crashlytics.com"]) {
        purpose = @"🛡️ [Crashlytics: Kiểm tra cấu hình Crashlytics Firebase]";
    } else if ([urlStr containsString:@"firebaselogging-pa.googleapis.com"]) {
        purpose = @"📊 [Firebase Analytics: Gửi log phân tích người dùng]";
    } else if ([urlStr containsString:@"app-analytics-services.com"]) {
        purpose = @"📈 [Analytics: Gửi dữ liệu thống kê ứng dụng]";
    }

    // 1. Format Human-Readable Text Log (In ra Console & ZaloAudit.log)
    NSMutableString *logText = [NSMutableString string];
    [logText appendString:@"\n================================================================================"];
    [logText appendFormat:@"\n🌐 [HAR] %@ %@", method, urlStr];
    if (purpose.length > 0) {
        [logText appendFormat:@"\n👉 Hành động: %@", purpose];
    }
    [logText appendFormat:@"\n⏱ Thời gian: %llums | Status: %ld %@", durationMs, (long)statusCode, statusText];
    if (error) {
        [logText appendFormat:@"\n⚠️ Chi tiết lỗi mạng: Domain=%@ | Code=%ld (%@)", error.domain, (long)error.code, [error localizedDescription]];
        if (error.userInfo && error.userInfo.count > 0) {
            [logText appendFormat:@"\n   • UserInfo: %@", error.userInfo];
        }
    }
    
    // Request Headers
    [logText appendString:@"\n--------------------------------- REQUEST HEADERS ------------------------------"];
    NSDictionary *reqHeaders = request.allHTTPHeaderFields;
    if (reqHeaders.count > 0) {
        for (NSString *hKey in reqHeaders) {
            [logText appendFormat:@"\n   • %@: %@", hKey, reqHeaders[hKey]];
        }
    } else {
        [logText appendString:@"\n   (Không có headers)"];
    }

    // Request Body
    [logText appendString:@"\n--------------------------------- REQUEST BODY ---------------------------------"];
    NSString *reqBodyStr = nil;
    if (reqBody && reqBody.length > 0) {
        reqBodyStr = [[NSString alloc] initWithData:reqBody encoding:NSUTF8StringEncoding];
        if (reqBodyStr) {
            [logText appendFormat:@"\n%@", reqBodyStr];
            if ([reqBodyStr containsString:@"%"]) {
                NSString *decoded = [reqBodyStr stringByRemovingPercentEncoding];
                if (decoded && ![decoded isEqualToString:reqBodyStr]) {
                    [logText appendFormat:@"\n   [ĐÃ GIẢI MÃ NỘI DUNG URL-ENCODED]:\n%@", decoded];
                }
            }
        } else {
            [logText appendFormat:@"\n(Dữ liệu nhị phân %lu bytes)", (unsigned long)reqBody.length];
        }
    } else {
        [logText appendString:@"\n(Không có body)"];
    }

    // Response Headers
    [logText appendString:@"\n--------------------------------- RESPONSE HEADERS -----------------------------"];
    NSDictionary *respHeaders = httpResp.allHeaderFields;
    if (respHeaders.count > 0) {
        for (NSString *hKey in respHeaders) {
            [logText appendFormat:@"\n   • %@: %@", hKey, respHeaders[hKey]];
        }
    } else {
        [logText appendString:@"\n   (Không có headers)"];
    }

    // Response Body
    [logText appendString:@"\n--------------------------------- RESPONSE BODY --------------------------------"];
    NSString *respBodyStr = nil;
    if (respData && respData.length > 0) {
        respBodyStr = [[NSString alloc] initWithData:respData encoding:NSUTF8StringEncoding];
        if (respBodyStr) {
            [logText appendFormat:@"\n%@", respBodyStr];
            if ([respBodyStr containsString:@"error"]) {
                NSData *jd = [respBodyStr dataUsingEncoding:NSUTF8StringEncoding];
                if (jd) {
                    id jObj = [NSJSONSerialization JSONObjectWithData:jd options:0 error:nil];
                    if ([jObj isKindOfClass:[NSDictionary class]]) {
                        NSInteger errCode = [jObj[@"error"] integerValue];
                        NSString *errMsg = jObj[@"errorMsg"] ?: @"";
                        if (errCode != 0) {
                            [logText appendFormat:@"\n🚨 [MÁY CHỦ BÁO LỖI NGHIỆP VỤ] ErrorCode: %ld | Thông báo: \"%@\"", (long)errCode, errMsg];
                        }
                    }
                }
            }
        } else {
            [logText appendFormat:@"\n(Dữ liệu nhị phân %lu bytes)", (unsigned long)respData.length];
        }
    } else {
        [logText appendString:@"\n(Không có body phản hồi)"];
    }
    [logText appendString:@"\n================================================================================"];

    logAudit(@"HAR-INSPECTOR", logText);

    // 2. Tạo đối tượng HAR Entry chuẩn JSON 1.2
    NSISO8601DateFormatter *isoDF = [[NSISO8601DateFormatter alloc] init];
    NSString *startedISO = [isoDF stringFromDate:startDate];

    NSMutableArray *reqHeadersArray = [NSMutableArray array];
    for (NSString *k in reqHeaders) {
        [reqHeadersArray addObject:@{@"name": k, @"value": [NSString stringWithFormat:@"%@", reqHeaders[k]]}];
    }

    NSMutableDictionary *postDataDict = nil;
    if (reqBodyStr) {
        postDataDict = [NSMutableDictionary dictionary];
        postDataDict[@"mimeType"] = reqHeaders[@"Content-Type"] ?: @"application/octet-stream";
        postDataDict[@"text"] = reqBodyStr;
    }

    NSMutableArray *respHeadersArray = [NSMutableArray array];
    for (NSString *k in respHeaders) {
        [respHeadersArray addObject:@{@"name": k, @"value": [NSString stringWithFormat:@"%@", respHeaders[k]]}];
    }

    NSMutableDictionary *contentDict = [NSMutableDictionary dictionary];
    contentDict[@"size"] = @(respData ? respData.length : 0);
    contentDict[@"mimeType"] = respHeaders[@"Content-Type"] ?: @"application/octet-stream";
    if (respBodyStr) {
        contentDict[@"text"] = respBodyStr;
    }

    NSDictionary *harEntry = @{
        @"startedDateTime": startedISO ?: @"",
        @"time": @(durationMs),
        @"request": @{
            @"method": method,
            @"url": urlStr,
            @"httpVersion": @"HTTP/1.1",
            @"cookies": @[],
            @"headers": reqHeadersArray,
            @"queryString": @[],
            @"postData": postDataDict ?: [NSNull null],
            @"headersSize": @(-1),
            @"bodySize": @(reqBody ? reqBody.length : 0)
        },
        @"response": @{
            @"status": @(statusCode),
            @"statusText": statusText ?: @"",
            @"httpVersion": @"HTTP/1.1",
            @"cookies": @[],
            @"headers": respHeadersArray,
            @"content": contentDict,
            @"redirectURL": respHeaders[@"Location"] ?: @"",
            @"headersSize": @(-1),
            @"bodySize": @(respData ? respData.length : 0)
        },
        @"cache": @{},
        @"timings": @{
            @"send": @(0),
            @"wait": @(durationMs),
            @"receive": @(0)
        }
    };

    append_to_har_file(harEntry);
}

// ==========================================
// BỘ QUAN SÁT MẠNG CHỈ ĐỌC (100% READ-ONLY AUDIT OBSERVER)
// Tuyệt đối KHÔNG sửa đổi NSURLRequest, Header, Body hay dữ liệu trả về của Zalo.
// Chỉ ghi log khi người dùng bật enableAuditLog để kiểm tra gói tin.
// ==========================================

typedef void (*zt_didReceiveData_imp)(id, SEL, NSURLSession *, NSURLSessionDataTask *, NSData *);
typedef void (*zt_didCompleteWithError_imp)(id, SEL, NSURLSession *, NSURLSessionTask *, NSError *);

static NSMutableDictionary<NSString *, NSValue *> *s_orig_didReceiveData_map = nil;
static NSMutableDictionary<NSString *, NSValue *> *s_orig_didCompleteWithError_map = nil;
static __thread BOOL s_in_did_receive_data = NO;
static __thread BOOL s_in_did_complete = NO;

static void zt_didReceiveData_handler(id self, SEL _cmd, NSURLSession *session, NSURLSessionDataTask *dataTask, NSData *data) {
    if (s_in_did_receive_data) return;
    s_in_did_receive_data = YES;

    if (dataTask && data && [ZTSettings sharedSettings].enableAuditLog) {
        NSMutableData *accum = objc_getAssociatedObject(dataTask, "zt_resp_data");
        if (accum) {
            @synchronized(accum) {
                [accum appendData:data];
            }
        }
    }
    Class cur = [self class];
    NSValue *val = nil;
    while (cur && !val) {
        val = s_orig_didReceiveData_map[NSStringFromClass(cur)];
        if (!val) cur = class_getSuperclass(cur);
    }
    if (val) {
        zt_didReceiveData_imp origFunc = (zt_didReceiveData_imp)[val pointerValue];
        if (origFunc && (IMP)origFunc != (IMP)zt_didReceiveData_handler) {
            origFunc(self, _cmd, session, dataTask, data);
        }
    }
    s_in_did_receive_data = NO;
}

static void zt_didCompleteWithError_handler(id self, SEL _cmd, NSURLSession *session, NSURLSessionTask *task, NSError *error) {
    if (s_in_did_complete) return;
    s_in_did_complete = YES;

    if (task && [ZTSettings sharedSettings].enableAuditLog) {
        NSNumber *alreadyRecorded = objc_getAssociatedObject(task, "zt_har_recorded");
        if (![alreadyRecorded boolValue]) {
            objc_setAssociatedObject(task, "zt_har_recorded", @(YES), OBJC_ASSOCIATION_RETAIN_NONATOMIC);
            NSURLRequest *origReq = objc_getAssociatedObject(task, "zt_orig_req") ?: (task.currentRequest ?: task.originalRequest);
            NSDate *startDate = objc_getAssociatedObject(task, "zt_start_date") ?: [NSDate date];
            NSData *respData = objc_getAssociatedObject(task, "zt_resp_data");
            NSURLResponse *response = task.response;
            NSData *reqBody = origReq.HTTPBody ?: objc_getAssociatedObject(task, "zt_body_data");

            if (origReq) {
                record_har_traffic(origReq, reqBody, response, respData, error, startDate, [NSDate date]);
            }
        }
    }
    Class cur = [self class];
    NSValue *val = nil;
    while (cur && !val) {
        val = s_orig_didCompleteWithError_map[NSStringFromClass(cur)];
        if (!val) cur = class_getSuperclass(cur);
    }
    if (val) {
        zt_didCompleteWithError_imp origFunc = (zt_didCompleteWithError_imp)[val pointerValue];
        if (origFunc && (IMP)origFunc != (IMP)zt_didCompleteWithError_handler) {
            origFunc(self, _cmd, session, task, error);
        }
    }
    s_in_did_complete = NO;
}

static void swizzle_session_delegate_class(Class cls) {
    if (!cls) return;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        s_orig_didReceiveData_map = [[NSMutableDictionary alloc] init];
        s_orig_didCompleteWithError_map = [[NSMutableDictionary alloc] init];
    });

    NSString *clsName = NSStringFromClass(cls);
    @synchronized(s_orig_didReceiveData_map) {
        if (s_orig_didReceiveData_map[clsName] || s_orig_didCompleteWithError_map[clsName]) return;
    }

    SEL selData = @selector(URLSession:dataTask:didReceiveData:);
    Method mData = class_getInstanceMethod(cls, selData);
    if (mData) {
        IMP currentImp = method_getImplementation(mData);
        if (currentImp != (IMP)zt_didReceiveData_handler) {
            const char *types = method_getTypeEncoding(mData);
            if (class_addMethod(cls, selData, (IMP)zt_didReceiveData_handler, types)) {
                @synchronized(s_orig_didReceiveData_map) {
                    s_orig_didReceiveData_map[clsName] = [NSValue valueWithPointer:(void *)currentImp];
                }
            } else {
                IMP origImp = method_setImplementation(mData, (IMP)zt_didReceiveData_handler);
                if (origImp && origImp != (IMP)zt_didReceiveData_handler) {
                    @synchronized(s_orig_didReceiveData_map) {
                        s_orig_didReceiveData_map[clsName] = [NSValue valueWithPointer:(void *)origImp];
                    }
                }
            }
        }
    }

    SEL selComplete = @selector(URLSession:task:didCompleteWithError:);
    Method mComplete = class_getInstanceMethod(cls, selComplete);
    if (mComplete) {
        IMP currentImp = method_getImplementation(mComplete);
        if (currentImp != (IMP)zt_didCompleteWithError_handler) {
            const char *types = method_getTypeEncoding(mComplete);
            if (class_addMethod(cls, selComplete, (IMP)zt_didCompleteWithError_handler, types)) {
                @synchronized(s_orig_didCompleteWithError_map) {
                    s_orig_didCompleteWithError_map[clsName] = [NSValue valueWithPointer:(void *)currentImp];
                }
            } else {
                IMP origImp = method_setImplementation(mComplete, (IMP)zt_didCompleteWithError_handler);
                if (origImp && origImp != (IMP)zt_didCompleteWithError_handler) {
                    @synchronized(s_orig_didCompleteWithError_map) {
                        s_orig_didCompleteWithError_map[clsName] = [NSValue valueWithPointer:(void *)origImp];
                    }
                }
            }
        }
    }
}

%hook NSURLSession

+ (NSURLSession *)sessionWithConfiguration:(NSURLSessionConfiguration *)configuration delegate:(id<NSURLSessionDelegate>)delegate delegateQueue:(NSOperationQueue *)queue {
    if (delegate && [ZTSettings sharedSettings].enableAuditLog) {
        swizzle_session_delegate_class([delegate class]);
    }
    return %orig;
}

- (NSURLSessionDataTask *)dataTaskWithRequest:(NSURLRequest *)request {
    NSURLSessionDataTask *task = %orig(request);
    if ([ZTSettings sharedSettings].enableAuditLog && task && request) {
        objc_setAssociatedObject(task, "zt_orig_req", request, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        objc_setAssociatedObject(task, "zt_start_date", [NSDate date], OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        objc_setAssociatedObject(task, "zt_resp_data", [NSMutableData data], OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        if (request.URL) {
            NSString *urlStr = request.URL.absoluteString ?: @"";
            NSString *method = request.HTTPMethod ?: @"GET";
            logAudit(@"ZALO-HTTP-TASK", [NSString stringWithFormat:@"🚀 [ASYNC DELEGATE] %@ %@", method, urlStr]);
        }
    }
    return task;
}

- (NSURLSessionDataTask *)dataTaskWithRequest:(NSURLRequest *)request completionHandler:(void (^)(NSData *data, NSURLResponse *response, NSError *error))completionHandler {
    if (![ZTSettings sharedSettings].enableAuditLog) {
        return %orig;
    }
    NSDate *startDate = [NSDate date];
    NSData *reqBody = request.HTTPBody;

    if (!completionHandler) {
        if (request && request.URL) {
            logAudit(@"ZALO-HTTP-TASK", [NSString stringWithFormat:@"🚀 [TASK-NO-HANDLER] %@ %@", request.HTTPMethod ?: @"GET", request.URL.absoluteString ?: @""]);
        }
        return %orig(request, nil);
    }

    void (^wrappedHandler)(NSData *data, NSURLResponse *response, NSError *error) = ^(NSData *data, NSURLResponse *response, NSError *error) {
        record_har_traffic(request, reqBody, response, data, error, startDate, [NSDate date]);
        completionHandler(data, response, error);
    };

    return %orig(request, wrappedHandler);
}

- (NSURLSessionUploadTask *)uploadTaskWithRequest:(NSURLRequest *)request fromData:(NSData *)bodyData {
    NSURLSessionUploadTask *task = %orig(request, bodyData);
    if ([ZTSettings sharedSettings].enableAuditLog && task && request) {
        objc_setAssociatedObject(task, "zt_orig_req", request, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        objc_setAssociatedObject(task, "zt_start_date", [NSDate date], OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        objc_setAssociatedObject(task, "zt_resp_data", [NSMutableData data], OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        if (bodyData) {
            objc_setAssociatedObject(task, "zt_body_data", bodyData, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        }
        if (request.URL) {
            logAudit(@"ZALO-HTTP-TASK", [NSString stringWithFormat:@"🚀 [UPLOAD-DELEGATE] %@ %@", request.HTTPMethod ?: @"POST", request.URL.absoluteString ?: @""]);
        }
    }
    return task;
}

- (NSURLSessionUploadTask *)uploadTaskWithRequest:(NSURLRequest *)request fromData:(NSData *)bodyData completionHandler:(void (^)(NSData *data, NSURLResponse *response, NSError *error))completionHandler {
    if (![ZTSettings sharedSettings].enableAuditLog) {
        return %orig;
    }
    NSDate *startDate = [NSDate date];

    if (!completionHandler) {
        if (request && request.URL) {
            logAudit(@"ZALO-HTTP-TASK", [NSString stringWithFormat:@"🚀 [UPLOAD-NO-HANDLER] %@ %@", request.HTTPMethod ?: @"POST", request.URL.absoluteString ?: @""]);
        }
        return %orig(request, bodyData, nil);
    }

    void (^wrappedHandler)(NSData *data, NSURLResponse *response, NSError *error) = ^(NSData *data, NSURLResponse *response, NSError *error) {
        record_har_traffic(request, bodyData, response, data, error, startDate, [NSDate date]);
        completionHandler(data, response, error);
    };

    return %orig(request, bodyData, wrappedHandler);
}

%end

%hook UIAlertController

+ (instancetype)alertControllerWithTitle:(NSString *)title message:(NSString *)message preferredStyle:(UIAlertControllerStyle)preferredStyle {
    UIAlertController *alert = %orig;
    if ([ZTSettings sharedSettings].enableAuditLog) {
        NSString *t = title ?: @"(Không có tiêu đề)";
        NSString *m = message ?: @"(Không có nội dung)";
        
        logAudit(@"UI-ALERT", [NSString stringWithFormat:@"🚨 [POPUP ALERT] Tiêu đề: '%@' | Nội dung: '%@' | Style: %ld", t, m, (long)preferredStyle]);
        
        NSString *combined = [NSString stringWithFormat:@"%@ %@", t, m];
        if ([combined rangeOfString:@"vô hiệu" options:NSCaseInsensitiveSearch].location != NSNotFound ||
            [combined rangeOfString:@"khóa" options:NSCaseInsensitiveSearch].location != NSNotFound ||
            [combined rangeOfString:@"tạm thời" options:NSCaseInsensitiveSearch].location != NSNotFound ||
            [combined rangeOfString:@"vi phạm" options:NSCaseInsensitiveSearch].location != NSNotFound ||
            [combined rangeOfString:@"bảo mật" options:NSCaseInsensitiveSearch].location != NSNotFound ||
            [combined rangeOfString:@"2020" options:NSCaseInsensitiveSearch].location != NSNotFound ||
            [combined rangeOfString:@"2028" options:NSCaseInsensitiveSearch].location != NSNotFound ||
            [combined rangeOfString:@"quy định" options:NSCaseInsensitiveSearch].location != NSNotFound ||
            [combined rangeOfString:@"bị đình chỉ" options:NSCaseInsensitiveSearch].location != NSNotFound ||
            [combined rangeOfString:@"chặn" options:NSCaseInsensitiveSearch].location != NSNotFound) {
            
            NSArray *syms = [NSThread callStackSymbols];
            NSString *stackTrace = [syms componentsJoinedByString:@"\n   ↳ "];
            logAudit(@"ACCOUNT-LOCK-ALERT", [NSString stringWithFormat:@"🛑 [PHÁT HIỆN THÔNG BÁO KHÓA TÀI KHOẢN / BẢO MẬT]\n   Tiêu đề: %@\n   Nội dung: %@\n   TRUY VẾT NGUỒN PHÁT LỆNH (CALL STACK):\n   ↳ %@", t, m, stackTrace]);
        }
    }
    return alert;
}

- (void)addAction:(UIAlertAction *)action {
    %orig;
    if ([ZTSettings sharedSettings].enableAuditLog && action.title.length > 0) {
        logAudit(@"UI-ALERT-ACTION", [NSString stringWithFormat:@"👉 [ALERT ACTION] Nút: '%@' (Style: %ld)", action.title, (long)action.style]);
    }
}

%end

static void recursively_collect_dialog_texts(UIView *view, NSMutableArray<NSString *> *texts) {
    if (!view) return;
    if ([view isKindOfClass:[UILabel class]]) {
        NSString *txt = ((UILabel *)view).text;
        if (txt && [txt stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]].length > 0) {
            [texts addObject:[txt stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]]];
        }
    } else if ([view isKindOfClass:[UIButton class]]) {
        NSString *bt = [((UIButton *)view) titleForState:UIControlStateNormal];
        if (bt && [bt stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]].length > 0) {
            [texts addObject:[NSString stringWithFormat:@"[Nút: %@]", [bt stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]]]];
        }
    } else if ([view isKindOfClass:[UITextView class]]) {
        NSString *txt = ((UITextView *)view).text;
        if (txt && [txt stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]].length > 0) {
            [texts addObject:[txt stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]]];
        }
    }
    for (UIView *sub in view.subviews) {
        recursively_collect_dialog_texts(sub, texts);
    }
}

static void log_controller_ivars_if_relevant(UIViewController *vc, NSString *label) {
    if (!vc) return;
    NSString *clsName = NSStringFromClass([vc class]);
    if ([clsName containsString:@"ZT"] || [clsName containsString:@"UIEditingOverlay"]) return;
    
    unsigned int count = 0;
    Ivar *ivars = class_copyIvarList([vc class], &count);
    if (!ivars) return;
    NSMutableArray *ivarDetails = [NSMutableArray array];
    for (unsigned int i = 0; i < count; i++) {
        const char *name = ivar_getName(ivars[i]);
        const char *encoding = ivar_getTypeEncoding(ivars[i]);
        if (!name || !encoding || encoding[0] != '@') continue;
        
        ptrdiff_t offset = ivar_getOffset(ivars[i]);
        void *rawPtr = *(void **)((char *)(__bridge void *)vc + offset);
        if (!rawPtr) continue;
        
        uintptr_t uPtr = (uintptr_t)rawPtr;
        BOOL isTagged = (uPtr & (1ULL << 63)) != 0;
        if (!isTagged && uPtr < 0x100000000ULL) continue;
        
        NSString *nameStr = [NSString stringWithUTF8String:name];
        @try {
            id val = (__bridge id)rawPtr;
            if (val && ![val isKindOfClass:[UIView class]] && ![val isKindOfClass:[UIViewController class]]) {
                NSString *valDesc = [val description];
                if (valDesc.length > 500) valDesc = [valDesc substringToIndex:500];
                [ivarDetails addObject:[NSString stringWithFormat:@"%@ = %@", nameStr, valDesc]];
            }
        } @catch (NSException *e) {}
    }
    free(ivars);
    if (ivarDetails.count > 0) {
        logAudit(@"VC-DATA-IVARS", [NSString stringWithFormat:@"🔍 [%@ IVARS CỦA %@]:\n   • %@", label ?: @"THÔNG SỐ", clsName, [ivarDetails componentsJoinedByString:@"\n   • "]]);
    }
}

%hook UIViewController

- (void)viewDidLoad {
    %orig;
    if ([ZTSettings sharedSettings].enableAuditLog) {
        NSString *clsName = NSStringFromClass([self class]);
        if ([clsName rangeOfString:@"Deactivat" options:NSCaseInsensitiveSearch].location != NSNotFound ||
            [clsName rangeOfString:@"AccountLock" options:NSCaseInsensitiveSearch].location != NSNotFound ||
            [clsName rangeOfString:@"SecurityCheck" options:NSCaseInsensitiveSearch].location != NSNotFound ||
            [clsName rangeOfString:@"ZInstantActionList" options:NSCaseInsensitiveSearch].location != NSNotFound) {
            
            logAudit(@"DEACT-CONTROLLER", [NSString stringWithFormat:@"🛑 [CONTROLLER LOADED]: %@", clsName]);
            log_controller_ivars_if_relevant(self, @"CONTROLLER-LOAD");
            NSArray *syms = [NSThread callStackSymbols];
            logAudit(@"DEACT-CALLSTACK", [NSString stringWithFormat:@"↳ CALL STACK KÍCH HOẠT %@:\n   ↳ %@", clsName, [syms componentsJoinedByString:@"\n   ↳ "]]);
        }
    }
}

- (void)presentViewController:(UIViewController *)viewControllerToPresent animated:(BOOL)flag completion:(void (^)(void))completion {
    if ([ZTSettings sharedSettings].enableAuditLog && viewControllerToPresent) {
        NSString *vcClass = NSStringFromClass([viewControllerToPresent class]);
        // Bỏ qua các controller nội bộ của Zalotweak để tránh spam log
        if (![vcClass containsString:@"ZT"] && ![vcClass containsString:@"UIEditingOverlay"]) {
            UIViewController *targetVC = viewControllerToPresent;
            NSString *extraInfo = @"";
            
            if ([viewControllerToPresent isKindOfClass:[UINavigationController class]]) {
                UINavigationController *nav = (UINavigationController *)viewControllerToPresent;
                if (nav.topViewController) {
                    targetVC = nav.topViewController;
                    extraInfo = [NSString stringWithFormat:@" [TopVC: %@]", NSStringFromClass([targetVC class])];
                }
            } else if ([viewControllerToPresent isKindOfClass:[UIAlertController class]]) {
                UIAlertController *ac = (UIAlertController *)viewControllerToPresent;
                extraInfo = [NSString stringWithFormat:@" | Alert Title: '%@' | Message: '%@'", ac.title ?: @"", ac.message ?: @""];
            }
            
            __weak UIViewController *weakTarget = targetVC;
            __weak UIViewController *weakPresented = viewControllerToPresent;
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.2 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                if (weakTarget && weakTarget.isViewLoaded) {
                    NSMutableArray<NSString *> *texts = [NSMutableArray array];
                    recursively_collect_dialog_texts(weakTarget.view, texts);
                    if (weakPresented && weakPresented != weakTarget && weakPresented.isViewLoaded) {
                        recursively_collect_dialog_texts(weakPresented.view, texts);
                    }
                    if (texts.count > 0) {
                        NSString *content = [texts componentsJoinedByString:@" | "];
                        logAudit(@"UI-SCREEN-CONTENT", [NSString stringWithFormat:@"📜 [NỘI DUNG MÀN HÌNH %@]: %@", NSStringFromClass([weakTarget class]), content]);
                        
                        if ([content rangeOfString:@"vô hiệu" options:NSCaseInsensitiveSearch].location != NSNotFound ||
                            [content rangeOfString:@"khóa" options:NSCaseInsensitiveSearch].location != NSNotFound ||
                            [content rangeOfString:@"tạm thời" options:NSCaseInsensitiveSearch].location != NSNotFound ||
                            [content rangeOfString:@"vi phạm" options:NSCaseInsensitiveSearch].location != NSNotFound ||
                            [content rangeOfString:@"bảo mật" options:NSCaseInsensitiveSearch].location != NSNotFound ||
                            [content rangeOfString:@"2020" options:NSCaseInsensitiveSearch].location != NSNotFound ||
                            [content rangeOfString:@"2028" options:NSCaseInsensitiveSearch].location != NSNotFound) {
                            NSArray *syms = [NSThread callStackSymbols];
                            NSString *stackTrace = [syms componentsJoinedByString:@"\n   ↳ "];
                            logAudit(@"ACCOUNT-LOCK-UI", [NSString stringWithFormat:@"🛑 [PHÁT HIỆN MÀN HÌNH KHÓA ACC] %@ | Nội dung: %@\n   CALL STACK LẦN VỀ HÀM PHÁT LỆNH:\n   ↳ %@", NSStringFromClass([weakTarget class]), content, stackTrace]);
                        }
                    }
                }
            });
            
            logAudit(@"UI-PRESENT", [NSString stringWithFormat:@"📺 [HIỂN THỊ MÀN HÌNH / DIALOG] Controller: %@%@", vcClass, extraInfo]);
            
            NSString *checkStr = [NSString stringWithFormat:@"%@ %@", vcClass, extraInfo];
            if ([checkStr rangeOfString:@"vô hiệu" options:NSCaseInsensitiveSearch].location != NSNotFound ||
                [checkStr rangeOfString:@"khóa" options:NSCaseInsensitiveSearch].location != NSNotFound ||
                [checkStr rangeOfString:@"deact" options:NSCaseInsensitiveSearch].location != NSNotFound ||
                [checkStr rangeOfString:@"ban" options:NSCaseInsensitiveSearch].location != NSNotFound ||
                [checkStr rangeOfString:@"kick" options:NSCaseInsensitiveSearch].location != NSNotFound ||
                [checkStr rangeOfString:@"security" options:NSCaseInsensitiveSearch].location != NSNotFound ||
                [checkStr rangeOfString:@"ZInstant" options:NSCaseInsensitiveSearch].location != NSNotFound ||
                [checkStr rangeOfString:@"ActionList" options:NSCaseInsensitiveSearch].location != NSNotFound) {
                
                log_controller_ivars_if_relevant(targetVC, @"PRESENT-TARGET");
                if (viewControllerToPresent != targetVC) {
                    log_controller_ivars_if_relevant(viewControllerToPresent, @"PRESENT-CONTAINER");
                }
                
                NSArray *syms = [NSThread callStackSymbols];
                NSString *stackTrace = [syms componentsJoinedByString:@"\n   ↳ "];
                logAudit(@"ACCOUNT-LOCK-UI", [NSString stringWithFormat:@"🛑 [PRESENT MÀN HÌNH BẢO MẬT/ZINSTANT] Controller: %@%@\n   CALL STACK LẦN VỀ HÀM PHÁT LỆNH:\n   ↳ %@", vcClass, extraInfo, stackTrace]);
            }
        }
    }
    %orig;
}

- (void)viewDidAppear:(BOOL)animated {
    %orig;
    if (![[NSBundle mainBundle].bundlePath containsString:@".appex"]) {
        if ([ZTSettings sharedSettings].showFloatingMenu) {
            dispatch_async(dispatch_get_main_queue(), ^{
                [[ZTMenuManager sharedManager] tryAttachFloatingButton];
            });
        }
        if ([ZTSettings sharedSettings].justGeneratedColdBoot) {
            [ZTSettings sharedSettings].justGeneratedColdBoot = NO;
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                [[ZTMenuManager sharedManager] showColdBootBanner];
            });
        }
    }
}

%end

%hook UIWindow

- (void)makeKeyAndVisible {
    %orig;
    if (![[NSBundle mainBundle].bundlePath containsString:@".appex"]) {
        if ([ZTSettings sharedSettings].showFloatingMenu) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.2 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                [[ZTMenuManager sharedManager] tryAttachFloatingButton];
            });
        }
    }
}

%end

%hook UIResponder

- (void)motionEnded:(UIEventSubtype)motion withEvent:(UIEvent *)event {
    if (motion == UIEventSubtypeMotionShake) {
        if (![[NSBundle mainBundle].bundlePath containsString:@".appex"]) {
            dispatch_async(dispatch_get_main_queue(), ^{
                [[ZTMenuManager sharedManager] presentMainMenuFrom:nil];
            });
        }
    }
    %orig;
}

%end

%hook NSNotificationCenter

- (void)postNotificationName:(NSNotificationName)aName object:(id)anObject userInfo:(NSDictionary *)aUserInfo {
    if ([ZTSettings sharedSettings].enableAuditLog && aName) {
        if (![aName hasPrefix:@"_UI"] && ![aName hasPrefix:@"UI"] && ![aName hasPrefix:@"NS"]) {
            if ([aName rangeOfString:@"deact" options:NSCaseInsensitiveSearch].location != NSNotFound ||
                [aName rangeOfString:@"kick" options:NSCaseInsensitiveSearch].location != NSNotFound ||
                [aName rangeOfString:@"ban" options:NSCaseInsensitiveSearch].location != NSNotFound ||
                [aName rangeOfString:@"lock" options:NSCaseInsensitiveSearch].location != NSNotFound ||
                [aName rangeOfString:@"vô hiệu" options:NSCaseInsensitiveSearch].location != NSNotFound ||
                [aName rangeOfString:@"accountstate" options:NSCaseInsensitiveSearch].location != NSNotFound ||
                [aName rangeOfString:@"authfailure" options:NSCaseInsensitiveSearch].location != NSNotFound ||
                [aName rangeOfString:@"sessiontermi" options:NSCaseInsensitiveSearch].location != NSNotFound) {
                
                NSArray *syms = [NSThread callStackSymbols];
                NSString *stackTrace = [syms componentsJoinedByString:@"\n   ↳ "];
                logAudit(@"EVENT-DISPATCH", [NSString stringWithFormat:@"⚡ [EVENT TÀI KHOẢN/SECURITY]: '%@' | Object: %@ | UserInfo: %@\n   CALL STACK:\n   ↳ %@", aName, anObject, aUserInfo, stackTrace]);
            }
        }
    }
    %orig;
}

%end

static NSString *get_runtime_environment_desc(void) {
    Dl_info info;
    NSString *dpath = nil;
    NSString *dname = @"Zalotweak.dylib";
    if (dladdr((const void *)get_runtime_environment_desc, &info) && info.dli_fname) {
        dpath = [NSString stringWithUTF8String:info.dli_fname];
        dname = [dpath lastPathComponent] ?: @"Zalotweak.dylib";
    }

#if defined(THEOS_PACKAGE_SCHEME_ROOTHIDE)
    return [NSString stringWithFormat:@"🛡️ Roothide (DEB) [%@]", dname];
#elif defined(THEOS_PACKAGE_SCHEME_ROOTLESS)
    return [NSString stringWithFormat:@"⚡ Rootless (DEB) [%@]", dname];
#endif

    if (dlsym(RTLD_DEFAULT, "jbrand") != NULL ||
        dlsym(RTLD_DEFAULT, "jbroot") != NULL ||
        dlsym(RTLD_DEFAULT, "roothide_check_path") != NULL ||
        (dpath && ([dpath containsString:@"/jb-"] || [dpath containsString:@"roothide"]))) {
        return [NSString stringWithFormat:@"🛡️ Roothide (DEB) [%@]", dname];
    }

    if (dpath && [dpath containsString:@".app/"]) {
        return [NSString stringWithFormat:@"📱 Sideload / Clone [%@]", dname];
    }

    if (dlsym(RTLD_DEFAULT, "ellekit_hook_c_function") != NULL ||
        (dpath && ([dpath containsString:@"/var/jb/"] || [dpath containsString:@"/var/jb"]))) {
        return [NSString stringWithFormat:@"⚡ Rootless (DEB) [%@]", dname];
    }

    if (dpath && ([dpath containsString:@"/Library/MobileSubstrate/"] || [dpath containsString:@"/usr/lib/TweakInject/"])) {
        return [NSString stringWithFormat:@"👑 Rootful (DEB) [%@]", dname];
    }

    if (is_device_jailbroken()) {
        return [NSString stringWithFormat:@"🛡️ Roothide (DEB) [%@]", dname];
    }

    return [NSString stringWithFormat:@"🔌 Custom Dylib [%@]", dname];
}

static void pushUnregisterCallback(CFNotificationCenterRef center, void *observer, CFStringRef name, const void *object, CFDictionaryRef userInfo) {
    dispatch_async(dispatch_get_main_queue(), ^{
        if ([[UIApplication sharedApplication] respondsToSelector:@selector(unregisterForRemoteNotifications)]) {
            logAudit(@"APNS-ROTATE", @"📡 [SETTINGS-WIPE] Nhận tín hiệu từ Cài đặt -> Hủy đăng ký push APNs & VoIP với Apple và xả RunLoop Mach IPC...");
            [[UIApplication sharedApplication] unregisterForRemoteNotifications];
        }
        Class pkClass = NSClassFromString(@"PKPushRegistry");
        if (pkClass) {
            @try {
                SEL initSel = sel_registerName("initWithQueue:");
                SEL setTypesSel = sel_registerName("setDesiredPushTypes:");
                Method initM = class_getInstanceMethod(pkClass, initSel);
                Method setTypesM = class_getInstanceMethod(pkClass, setTypesSel);
                if (initM && setTypesM) {
                    id (*initFn)(id, SEL, dispatch_queue_t) = (id (*)(id, SEL, dispatch_queue_t))method_getImplementation(initM);
                    void (*setTypesFn)(id, SEL, id) = (void (*)(id, SEL, id))method_getImplementation(setTypesM);
                    id allocObj = [pkClass alloc];
                    if (allocObj && initFn) {
                        id registry = initFn(allocObj, initSel, dispatch_get_main_queue());
                        if (registry && setTypesFn) {
                            setTypesFn(registry, setTypesSel, [NSSet set]);
                        }
                    }
                }
            } @catch (NSException *ex) {}
        }
        [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.5]];
        exit(0);
    });
}

static void settingsChangedCallback(CFNotificationCenterRef center, void *observer, CFStringRef name, const void *object, CFDictionaryRef userInfo) {
    if ([ZTSettings sharedSettings].isShuttingDownForDeepWipe) {
        return;
    }
    [[ZTSettings sharedSettings] loadSettings];
    update_cached_locale_and_tz();
    dispatch_async(dispatch_get_main_queue(), ^{
        if ([ZTSettings sharedSettings].showFloatingMenu) {
            [[ZTMenuManager sharedManager] setupInAppMenu];
            [[ZTFloatingButton sharedButton] show];
        } else {
            [[ZTFloatingButton sharedButton] hide];
        }
    });
}

static NSArray<NSString *> *s_discovered_security_modules = nil;

static NSArray<NSString *> *perform_zalo_security_modules_scan_now(void) {
    if (!ZTSecurityCheckLicenseFast()) {
        return @[@"🔒 Yêu cầu kích hoạt bản quyền để sử dụng tính năng Quét Module Bảo Mật!"];
    }
    int numClasses = objc_getClassList(NULL, 0);
    if (numClasses <= 0) return @[];
    Class *classes = (Class *)malloc(sizeof(Class) * numClasses);
    if (!classes) return @[];
    numClasses = objc_getClassList(classes, numClasses);

    NSMutableArray *foundModules = [NSMutableArray array];

    for (int i = 0; i < numClasses; i++) {
        Class cls = classes[i];
        const char *clsName = class_getName(cls);
        if (!clsName) continue;

        const char *imgName = orig_class_getImageName ? orig_class_getImageName(cls) : class_getImageName(cls);
        if (!imgName || is_sensitive_image_path_cstr(imgName)) continue;
        // Chỉ quét các class thuộc Zalo hoặc Frameworks nhúng của Zalo
        if (!strcasestr(imgName, "Zalo") && !strcasestr(imgName, "ZDK") && !strcasestr(imgName, "zingalo")) {
            continue;
        }

        if (strcasestr(clsName, "Security") ||
            strcasestr(clsName, "Fingerprint") ||
            strcasestr(clsName, "Integrity") ||
            strcasestr(clsName, "Jailbreak") ||
            strcasestr(clsName, "Detector") ||
            strcasestr(clsName, "Anti") ||
            strcasestr(clsName, "Risk") ||
            strcasestr(clsName, "ZShield") ||
            strcasestr(clsName, "DeviceID") ||
            strcasestr(clsName, "DeviceInfo") ||
            strcasestr(clsName, "Hardware") ||
            strcasestr(clsName, "Biometric") ||
            strcasestr(clsName, "Telemetry") ||
            strcasestr(clsName, "Fraud") ||
            strcasestr(clsName, "Tamper") ||
            strcasestr(clsName, "Hook") ||
            strcasestr(clsName, "Socket") ||
            strcasestr(clsName, "Packet") ||
            strcasestr(clsName, "Transport") ||
            strcasestr(clsName, "Kick") ||
            strcasestr(clsName, "Deact") ||
            strcasestr(clsName, "Ban")) {
            [foundModules addObject:[NSString stringWithUTF8String:clsName]];
        }
    }
    free(classes);

    [foundModules sortUsingSelector:@selector(compare:)];
    return [foundModules copy];
}

static void scan_zalo_security_modules_async(void) {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_LOW, 0), ^{
        @autoreleasepool {
            // Đợi 2 giây để Zalo hoàn tất nạp các dynamic frameworks vào bộ nhớ
            [NSThread sleepForTimeInterval:2.0];

            NSArray<NSString *> *modules = perform_zalo_security_modules_scan_now();
            s_discovered_security_modules = modules;

            if (modules.count > 0) {
                logAudit(@"ZALO-SECURITY-RADAR", [NSString stringWithFormat:@"🛡️ [RADAR TOÀN DIỆN] Phát hiện %lu module bảo mật/định danh của Zalo:\n   • %@", (unsigned long)modules.count, [modules componentsJoinedByString:@"\n   • "]]);
            } else {
                logAudit(@"ZALO-SECURITY-RADAR", @"🛡️ [RADAR TOÀN DIỆN] Đã quét toàn bộ binary Zalo nhưng không phát hiện module bảo mật riêng biệt.");
            }
        }
    });
}

__attribute__((visibility("default"))) NSArray<NSString *> *zt_get_discovered_security_modules(void) {
    if (s_discovered_security_modules && s_discovered_security_modules.count > 0) {
        return s_discovered_security_modules;
    }
    s_discovered_security_modules = perform_zalo_security_modules_scan_now();
    return s_discovered_security_modules;
}

// ==========================================
// DỌN KEYCHAIN SỚM TẠI %ctor (TRƯỚC main(), TRƯỚC KHI ZALO ĐỌC/GHI BẤT KỲ ĐỊNH DANH NÀO)
// Chỉ chạy 1 lần cho mỗi lần Wipe (cờ needsKeychainPurge do Settings đặt), sau đó tắt cờ ngay
// để các lần mở sau Zalo đọc lại đúng định danh đã sinh.
// ==========================================
static NSUInteger zt_count_remaining_keychain_items(void) {
    NSUInteger total = 0;
    NSArray *classes = @[(__bridge id)kSecClassGenericPassword, (__bridge id)kSecClassInternetPassword, (__bridge id)kSecClassKey];
    for (id cls in classes) {
        NSDictionary *q = @{
            (__bridge id)kSecClass: cls,
            (__bridge id)kSecAttrSynchronizable: (__bridge id)kSecAttrSynchronizableAny,
            (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitAll,
            (__bridge id)kSecReturnAttributes: @YES
        };
        CFTypeRef res = NULL;
        if (SecItemCopyMatching((__bridge CFDictionaryRef)q, &res) == errSecSuccess && res) {
            if (CFGetTypeID(res) == CFArrayGetTypeID()) total += (NSUInteger)CFArrayGetCount((CFArrayRef)res);
            else total += 1;
        }
        if (res) CFRelease(res);
    }
    return total;
}

static void zt_early_keychain_purge_if_needed(void) {
    if (!is_original_zalo_app()) return;
    NSString *prefPath = getConfigPath();
    NSDictionary *dict = [NSDictionary dictionaryWithContentsOfFile:prefPath];
    if (!dict) dict = [NSDictionary dictionaryWithContentsOfFile:GLOBAL_PREFS_PATH];
    if (![dict[@"needsKeychainPurge"] boolValue]) return;

    NSUInteger before = zt_count_remaining_keychain_items();
    purge_all_zalo_keychain_safely();
    NSUInteger after = zt_count_remaining_keychain_items();

    // Tắt cờ NGAY để không bao giờ xóa lần 2 sau khi Zalo đã sinh định danh
    NSMutableDictionary *m = [dict mutableCopy];
    m[@"needsKeychainPurge"] = @(NO);
    [m writeToFile:prefPath atomically:YES];
    [m writeToFile:GLOBAL_PREFS_PATH atomically:YES];

    logAudit(@"KEYCHAIN-PURGE", [NSString stringWithFormat:@"🧹 [CTOR] Dọn Keychain trước main() | Trước: %lu mục | Còn lại: %lu mục%@",
        (unsigned long)before, (unsigned long)after, after == 0 ? @" ✅ SẠCH" : @" ⚠️ CÒN SÓT"]);
}

%ctor {
    @autoreleasepool {
        s_is_cold_boot_phase = YES;
        // 1. Khởi tạo toàn bộ dữ liệu cấu hình, bộ nhớ hàng đợi và xác thực bản quyền TRƯỚC KHI BẬT HOOK
        // Đảm bảo không bị deadlock re-entrant
        loggedAuditKeys = [[NSMutableSet alloc] init];
        auditQueue = dispatch_queue_create("com.sonhu.zalotweak.auditQueue", DISPATCH_QUEUE_SERIAL);
        harQueue = dispatch_queue_create("com.sonhu.zalotweak.harQueue", DISPATCH_QUEUE_SERIAL);

        [ZTSettings sharedSettings];
        update_cached_locale_and_tz();
        [[ZTSecurityManager sharedManager] isLicenseValid];
        zt_early_keychain_purge_if_needed();
        s_is_cold_boot_phase = NO;

        // 2. Kích hoạt toàn bộ hook Objective-C của Logos sau khi cấu hình đã sẵn sàng
        %init;

        CFNotificationCenterAddObserver(
            CFNotificationCenterGetDarwinNotifyCenter(),
            NULL,
            settingsChangedCallback,
            CFSTR("com.sonhu.zalotweak/settingschanged"),
            NULL,
            CFNotificationSuspensionBehaviorCoalesce
        );

        CFNotificationCenterAddObserver(
            CFNotificationCenterGetDarwinNotifyCenter(),
            NULL,
            pushUnregisterCallback,
            CFSTR("com.sonhu.zalotweak/perform_push_unregister"),
            NULL,
            CFNotificationSuspensionBehaviorDeliverImmediately
        );

        // 3. Cài đặt các hook C an toàn (tương thích 100% cả Jailbreak lẫn Sideload/LARA qua Fishhook)
        dynamic_MSHookFunction = (void (*)(void *, void *, void **))dlsym(RTLD_DEFAULT, "MSHookFunction");

        universal_hook_c_function("sysctl", (void *)sysctl, (void *)my_sysctl, (void **)&orig_sysctl);
        universal_hook_c_function("sysctlbyname", (void *)sysctlbyname, (void *)my_sysctlbyname, (void **)&orig_sysctlbyname);
        universal_hook_c_function("uname", (void *)uname, (void *)my_uname, (void **)&orig_uname);
        universal_hook_c_function("statfs", (void *)statfs, (void *)my_statfs, (void **)&orig_statfs);
        void *fstatfs_ptr = (void *)fstatfs;
        if (fstatfs_ptr) {
            universal_hook_c_function("fstatfs", fstatfs_ptr, (void *)my_fstatfs, (void **)&orig_fstatfs);
        }
        universal_hook_c_function("statvfs", (void *)statvfs, (void *)my_statvfs, (void **)&orig_statvfs);
        universal_hook_c_function("fstatvfs", (void *)fstatvfs, (void *)my_fstatvfs, (void **)&orig_fstatvfs);
        universal_hook_c_function("access", (void *)access, (void *)my_access, (void **)&orig_access);
        universal_hook_c_function("readlink", (void *)readlink, (void *)my_readlink, (void **)&orig_readlink);
        universal_hook_c_function("readlinkat", (void *)readlinkat, (void *)my_readlinkat, (void **)&orig_readlinkat);
        universal_hook_c_function("fork", (void *)fork, (void *)my_fork, (void **)&orig_fork);
        void *sys_ptr = dlsym(RTLD_DEFAULT, "system");
        if (sys_ptr) {
            universal_hook_c_function("system", sys_ptr, (void *)my_system, (void **)&orig_system);
        }
        void *popen_ptr = dlsym(RTLD_DEFAULT, "popen");
        if (popen_ptr) {
            universal_hook_c_function("popen", popen_ptr, (void *)my_popen, (void **)&orig_popen);
        }
        universal_hook_c_function("getenv", (void *)getenv, (void *)my_getenv, (void **)&orig_getenv);
        universal_hook_c_function("stat", (void *)stat, (void *)my_stat, (void **)&orig_stat);
        universal_hook_c_function("lstat", (void *)lstat, (void *)my_lstat, (void **)&orig_lstat);
        universal_hook_c_function("fstat", (void *)fstat, (void *)my_fstat, (void **)&orig_fstat);
        universal_hook_c_function("getattrlist", (void *)getattrlist, (void *)my_getattrlist, (void **)&orig_getattrlist);
        {
            struct rebinding inode64_rebs[] = {
                { "stat$INODE64", (void *)my_stat, NULL },
                { "lstat$INODE64", (void *)my_lstat, NULL },
                { "fstat$INODE64", (void *)my_fstat, NULL },
                { "statfs$INODE64", (void *)my_statfs, (void **)&orig_statfs },
                { "fstatfs$INODE64", (void *)my_fstatfs, (void **)&orig_fstatfs },
                { "statvfs", (void *)my_statvfs, (void **)&orig_statvfs },
                { "fstatvfs", (void *)my_fstatvfs, (void **)&orig_fstatvfs },
                { "readlink", (void *)my_readlink, (void **)&orig_readlink },
                { "readlinkat", (void *)my_readlinkat, (void **)&orig_readlinkat },
                { "fork", (void *)my_fork, (void **)&orig_fork },
                { "system", (void *)my_system, (void **)&orig_system },
                { "popen", (void *)my_popen, (void **)&orig_popen },
                { "getenv", (void *)my_getenv, (void **)&orig_getenv },
                { "uname", (void *)my_uname, (void **)&orig_uname },
                { "sysctl", (void *)my_sysctl, (void **)&orig_sysctl },
                { "sysctlbyname", (void *)my_sysctlbyname, (void **)&orig_sysctlbyname }
            };
            rebind_symbols(inode64_rebs, sizeof(inode64_rebs) / sizeof(struct rebinding));
        }
        void *cdFunc = dlsym(RTLD_DEFAULT, "CacheDeleteCopyAvailableSpaceForVolume");
        if (cdFunc) {
            universal_hook_c_function("CacheDeleteCopyAvailableSpaceForVolume", cdFunc, (void *)my_CacheDeleteCopyAvailableSpaceForVolume, (void **)&orig_CacheDeleteCopyAvailableSpaceForVolume);
        }

        // Hook POSIX open & openat (Chặn quét đường dẫn phát hiện Jailbreak)
        universal_hook_c_function("open", (void *)open, (void *)my_open, (void **)&orig_open);
        universal_hook_c_function("openat", (void *)openat, (void *)my_openat, (void **)&orig_openat);

        // Hook Security Framework (Pass-through 100%, chỉ ghi log khi bật Audit Log)
        universal_hook_c_function("SecItemCopyMatching", (void *)SecItemCopyMatching, (void *)my_SecItemCopyMatching, (void **)&orig_SecItemCopyMatching);
        universal_hook_c_function("SecItemAdd", (void *)SecItemAdd, (void *)my_SecItemAdd, (void **)&orig_SecItemAdd);
        universal_hook_c_function("SecItemDelete", (void *)SecItemDelete, (void *)my_SecItemDelete, (void **)&orig_SecItemDelete);
        universal_hook_c_function("SecItemUpdate", (void *)SecItemUpdate, (void *)my_SecItemUpdate, (void **)&orig_SecItemUpdate);

        // Hook WiFi BSSID Anonymization
        void *cnFunc = (void *)CNCopyCurrentNetworkInfo;
        if (cnFunc) {
            universal_hook_c_function("CNCopyCurrentNetworkInfo", cnFunc, (void *)my_CNCopyCurrentNetworkInfo, (void **)&orig_CNCopyCurrentNetworkInfo);
        }



        // Hook getifaddrs (Lọc bỏ interface VPN, tap, tun, utun)
        universal_hook_c_function("getifaddrs", (void *)getifaddrs, (void *)my_getifaddrs, (void **)&orig_getifaddrs);

        // Hook MobileGestalt MGCopyAnswer (Radar bắt toàn bộ điểm check phần cứng của Zalo)
        void *mgFunc = dlsym(RTLD_DEFAULT, "MGCopyAnswer");
        if (mgFunc) {
            universal_hook_c_function("MGCopyAnswer", mgFunc, (void *)my_MGCopyAnswer, (void **)&orig_MGCopyAnswer);
        }

        // Hook CoreFoundation SystemVersion Dictionary (Khử rò rỉ OS Build Version lên Crashlytics/GoogleUtilities)
        void *cfSysVer = dlsym(RTLD_DEFAULT, "_CFCopySystemVersionDictionary");
        if (cfSysVer) {
            universal_hook_c_function("_CFCopySystemVersionDictionary", cfSysVer, (void *)my_CFCopySystemVersionDictionary, (void **)&orig_CFCopySystemVersionDictionary);
        }
        void *cfSrvVer = dlsym(RTLD_DEFAULT, "_CFCopyServerVersionDictionary");
        if (cfSrvVer) {
            universal_hook_c_function("_CFCopyServerVersionDictionary", cfSrvVer, (void *)my_CFCopyServerVersionDictionary, (void **)&orig_CFCopyServerVersionDictionary);
        }

        // Hook Hardware Uptime Clocks Radar (Chế độ Radar Giám Sát, bảo vệ 100% socket mạng khỏi lỗi EINVAL 22)
        universal_hook_c_function("clock_gettime", (void *)clock_gettime, (void *)my_clock_gettime, (void **)&orig_clock_gettime);
        universal_hook_c_function("mach_continuous_time", (void *)mach_continuous_time, (void *)my_mach_continuous_time, (void **)&orig_mach_continuous_time);
        universal_hook_c_function("mach_absolute_time", (void *)mach_absolute_time, (void *)my_mach_absolute_time, (void **)&orig_mach_absolute_time);

        // Hook TCC AddressBook Authorization Status
        void *abStatus = dlsym(RTLD_DEFAULT, "ABAddressBookGetAuthorizationStatus");
        if (abStatus) {
            universal_hook_c_function("ABAddressBookGetAuthorizationStatus", abStatus, (void *)my_ABAddressBookGetAuthorizationStatus, (void **)&orig_ABAddressBookGetAuthorizationStatus);
        }

        // Hook Anti-Debug & Process Security Radar
        void *ptrace_ptr = dlsym(RTLD_DEFAULT, "ptrace");
        if (ptrace_ptr) {
            universal_hook_c_function("ptrace", ptrace_ptr, (void *)my_ptrace, (void **)&orig_ptrace);
        }
        universal_hook_c_function("getppid", (void *)getppid, (void *)my_getppid, (void **)&orig_getppid);
        universal_hook_c_function("gethostname", (void *)gethostname, (void *)my_gethostname, (void **)&orig_gethostname);

        // Hook Dyld, dladdr & Objective-C Runtime (Ẩn tuyệt đối Zalotweak.dylib, Substrate, ElleKit, RootHide, systemhook và các class nội bộ khỏi bộ quét của Zalo)
        universal_hook_c_function("_dyld_get_image_name", (void *)_dyld_get_image_name, (void *)my_dyld_get_image_name, (void **)&orig_dyld_get_image_name);
        universal_hook_c_function("dladdr", (void *)dladdr, (void *)my_dladdr, (void **)&orig_dladdr);
        universal_hook_c_function("class_getImageName", (void *)class_getImageName, (void *)my_class_getImageName, (void **)&orig_class_getImageName);
        universal_hook_c_function("objc_copyImageNames", (void *)objc_copyImageNames, (void *)my_objc_copyImageNames, (void **)&orig_objc_copyImageNames);
        universal_hook_c_function("objc_copyClassList", (void *)objc_copyClassList, (void *)my_objc_copyClassList, (void **)&orig_objc_copyClassList);

        {
            struct rebinding dyld_rebs[] = {
                { "_dyld_get_image_name", (void *)my_dyld_get_image_name, (void **)&orig_dyld_get_image_name },
                { "dladdr", (void *)my_dladdr, (void **)&orig_dladdr },
                { "class_getImageName", (void *)my_class_getImageName, (void **)&orig_class_getImageName },
                { "objc_copyImageNames", (void *)my_objc_copyImageNames, (void **)&orig_objc_copyImageNames },
                { "objc_copyClassList", (void *)my_objc_copyClassList, (void **)&orig_objc_copyClassList }
            };
            rebind_symbols(dyld_rebs, 5);
        }

        if (![[ZTSecurityManager sharedManager] isLicenseValid]) {
            NSLog(@"[ZaloTweak] ❌ BẢN QUYỀN CHƯA KÍCH HOẠT HOẶC ĐÃ HẾT HẠN! Vui lòng vào Cài đặt để kích hoạt.");
        } else {
            NSLog(@"[ZaloTweak] 🟢 Bản quyền hợp lệ: %@", [[ZTSecurityManager sharedManager] getLicenseStatusText]);
        }

        NSLog(@"[ZaloTweak] Đã khởi tạo hoàn chỉnh - Model: %@ | Res: %.0fx%.0f@%.0fx | IDFV: %@ | Disk: %@",
              [ZTSettings sharedSettings].deviceMachine,
              [ZTSettings sharedSettings].screenWidth,
              [ZTSettings sharedSettings].screenHeight,
              [ZTSettings sharedSettings].screenScale,
              [ZTSettings sharedSettings].spoofedIDFV,
              [ZTSettings sharedSettings].diskTotalSize > 0 ? [NSString stringWithFormat:@"%llu GB", [ZTSettings sharedSettings].diskTotalSize / (1000000000ULL)] : @"APFS Thật (Passthrough)");

        NSString *envDesc = get_runtime_environment_desc();
        NSLog(@"[ZaloTweak] 🚀 Môi trường: %@", envDesc);

        // Lưu thông tin môi trường vào cấu hình để mục Cài đặt Settings hiển thị
        NSString *cfgPath = getConfigPath();
        NSMutableDictionary *cfgDict = [NSMutableDictionary dictionaryWithContentsOfFile:cfgPath] ?: [NSMutableDictionary dictionary];
        cfgDict[@"runtimeEnvironment"] = envDesc;
        [cfgDict writeToFile:cfgPath atomically:YES];
        chmod([cfgPath UTF8String], 0666);
        if (is_device_jailbroken()) {
            NSString *rhPath = get_roothide_prefs_path();
            if (rhPath) {
                [cfgDict writeToFile:rhPath atomically:YES];
                chmod([rhPath UTF8String], 0666);
            }
            [cfgDict writeToFile:GLOBAL_PREFS_PATH atomically:YES];
            chmod([GLOBAL_PREFS_PATH UTF8String], 0666);
        }

        // Khởi tạo In-App Floating Menu (Chỉ nạp khi app đã nạp xong UIKit và nhận thông báo DidFinishLaunching)
        if (![[NSBundle mainBundle].bundlePath containsString:@".appex"]) {
            [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidFinishLaunchingNotification
                                                              object:nil
                                                               queue:[NSOperationQueue mainQueue]
                                                          usingBlock:^(NSNotification * _Nonnull note) {
                if ([ZTSettings sharedSettings].showFloatingMenu) {
                    [[ZTMenuManager sharedManager] setupInAppMenu];
                }
                start_battery_drain_timer_if_needed();
            }];
        }

        // Ghi nhận dòng kiểm toán khởi động ban đầu
        if ([ZTSettings sharedSettings].enableAuditLog) {
            ZTSettings *s = [ZTSettings sharedSettings];
            logAudit(@"SYSTEM-INIT", [NSString stringWithFormat:@"Khởi động ZaloTweak v1.0 | Môi trường: %@ | App: %@ | Model: %@ | Res: %.0fx%.0f@%.0fx | IDFV: %@ | Bản quyền: %@",
                      envDesc,
                      [[NSBundle mainBundle] bundleIdentifier],
                      s.deviceMachine,
                      s.screenWidth,
                      s.screenHeight,
                      s.screenScale,
                      s.spoofedIDFV,
                      [[ZTSecurityManager sharedManager] getLicenseStatusText]]);

            if (!is_original_zalo_app()) {
                logAudit(@"CLONE-SYNC", @"[ZALO CLONE] Kích hoạt cơ chế chuẩn App Store: 1) Bẻ hướng C-layer CFBundleGetIdentifier & InfoDictionary -> vn.com.vng.zingalo | 2) Bẻ hướng NSBundle mainBundle -> vn.com.vng.zingalo | 3) Nạp APNs Device Token 32-byte SHA-256 | 4) Bỏ qua lỗi APNs iOS");
            }

            // 1. Đồng bộ Vùng, Ngôn ngữ & Múi giờ máy thật
            NSString *langStr = [s.preferredLanguages componentsJoinedByString:@", "] ?: @"vi-VN, en-VN";
            NSTimeZone *sysTz = [NSTimeZone systemTimeZone];
            NSInteger gmtSec = sysTz ? [sysTz secondsFromGMT] : 25200;
            int gmtH = (int)(gmtSec / 3600);
            int gmtM = abs((int)((gmtSec % 3600) / 60));
            NSString *gmtStr = gmtM > 0 ? [NSString stringWithFormat:@"GMT%+d:%02d", gmtH, gmtM] : [NSString stringWithFormat:@"GMT%+d", gmtH];
            logAudit(@"PROFILE-SYNC", [NSString stringWithFormat:@"🌍 [VÙNG / MÚI GIỜ] Region: %@ | Locale: %@ | TimeZone: %@ (%@) [Thu thập thật từ máy] | Ngôn ngữ: [%@]",
                      s.regionMode ?: @"VN",
                      s.localeIdentifier ?: @"vi_VN",
                      sysTz.name ?: @"Asia/Ho_Chi_Minh",
                      gmtStr,
                      langStr]);

            // 2. Nhà mạng di động & Cellular
            logAudit(@"PROFILE-SYNC", [NSString stringWithFormat:@"📶 [NHÀ MẠNG SIM] Mạng: %@ | MCC: %@ | MNC: %@ | ISO: %@ | Radio: LTE",
                      s.carrierName ?: @"Viettel",
                      s.carrierMCC ?: @"452",
                      s.carrierMNC ?: @"04",
                      s.carrierCountryCode ?: @"vn"]);

            // 3. Phần cứng & Radar tập lệnh / Cache
            logAudit(@"PROFILE-SYNC", [NSString stringWithFormat:@"⚙️ [RADAR PHẦN CỨNG] hw.product: %@ | L2Cache: %u MB | PageSize: 16KB | ProcTranslated: 0",
                      s.deviceMachine ?: @"iPhone9,1",
                      (unsigned int)(s.l2cacheSize / (1024 * 1024))]);

            // 4. Thời gian khởi tạo hệ thống file & Boot Time
            time_t fake_ctime = (time_t)(s.birthTimeSec > 0 ? s.birthTimeSec : (s.bootTimeSec > 86400 ? (s.bootTimeSec - (86400 * 15 + 3600 * 4 + 720)) : 1568160000ULL));
            struct tm b_tm, boot_tm;
            gmtime_r(&fake_ctime, &b_tm);
            time_t btime_sec = (time_t)s.bootTimeSec;
            gmtime_r(&btime_sec, &boot_tm);
            char bTimeBuf[32] = {0};
            char bootBuf[32] = {0};
            snprintf(bTimeBuf, sizeof(bTimeBuf), "%04d-%02d-%02d %02d:%02d:%02d UTC",
                     b_tm.tm_year + 1900, b_tm.tm_mon + 1, b_tm.tm_mday,
                     b_tm.tm_hour, b_tm.tm_min, b_tm.tm_sec);
            snprintf(bootBuf, sizeof(bootBuf), "%04d-%02d-%02d %02d:%02d:%02d UTC",
                     boot_tm.tm_year + 1900, boot_tm.tm_mon + 1, boot_tm.tm_mday,
                     boot_tm.tm_hour, boot_tm.tm_min, boot_tm.tm_sec);

            double contUp = 0, awakeUp = 0;
            get_consistent_uptimes(&contUp, &awakeUp);
            logAudit(@"PROFILE-SYNC", [NSString stringWithFormat:@"🕒 [THỜI GIAN/Ổ ĐĨA] st_birthtime: %s (%llu) | BootTime: %s | ContCPU: %.0fs (%.1fh) | AwakeCPU: %.0fs (%.1fh) | Disk: %@",
                      bTimeBuf,
                      (unsigned long long)fake_ctime,
                      bootBuf,
                      contUp, contUp / 3600.0,
                      awakeUp, awakeUp / 3600.0,
                      s.diskTotalSize > 0 ? [NSString stringWithFormat:@"%llu GB", s.diskTotalSize / (1000000000ULL)] : @"APFS Thật (Passthrough)"]);

            if (!is_original_zalo_app()) {
                logAudit(@"PROFILE-SYNC", @"🛡️ [CHỐNG LIÊN KẾT NÂNG CAO] Zalo Clone: Đã chặn Token APNs Fake & Triệt tiêu submitToken (Chống Apple BadDeviceToken ban 3h) | Anti-Dyld/dladdr: Đã ẩn Zalotweak.dylib | SIM Slot: 0000000100000001");
            } else {
                NSString *voipMode = s.spoofVoIPPushToken ? @"Tự sinh Token PushKit VoIP 32-byte theo Profile" : @"Bảo toàn Token Apple Gateway gốc (Passthrough)";
                NSString *cpuMode = s.spoofContinuousCPUClock ? @"Đồng bộ mach_time" : @"Passthrough CPU thật";
                logAudit(@"PROFILE-SYNC", [NSString stringWithFormat:@"🛡️ [CHỐNG LIÊN KẾT NÂNG CAO] Zalo Gốc: %@ | CPU: %@ | Anti-Dyld/dladdr: Đã ẩn Zalotweak.dylib | SIM Slot: 0000000100000001", voipMode, cpuMode]);
            }
        }

        // Tự động quét và lập danh mục các module bảo mật nội bộ của Zalo
        scan_zalo_security_modules_async();

        s_bg_task_id = UIBackgroundTaskInvalid;

        // Đăng ký bộ bảo vệ dữ liệu khi tiến trình bị tắt / kết thúc đột ngột
        atexit(zt_atexit_handler);
        signal(SIGTERM, zt_sig_handler);
        signal(SIGINT, zt_sig_handler);
        signal(SIGABRT, zt_sig_handler);
    }
}
