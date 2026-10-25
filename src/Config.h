#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>

@interface ZTSettings : NSObject

@property (nonatomic, assign) BOOL enabled;
@property (nonatomic, strong) NSString *deviceMachine;     // hw.machine: vd "iPhone14,2"
@property (nonatomic, strong) NSString *deviceModel;       // hw.model: vd "D63AP"
@property (nonatomic, strong) NSString *deviceName;        // UIDevice.name: vd "iPhone"
@property (nonatomic, strong) NSString *systemVersion;     // UIDevice.systemVersion: vd "16.5"
@property (nonatomic, strong) NSString *kernOsVersion;     // kern.osversion: vd "20F66"
@property (nonatomic, strong) NSString *darwinKernelRelease; // kern.osrelease: vd "22.5.0", "24.2.0"
@property (nonatomic, assign) uint32_t ncpu;               // hw.ncpu: 6
@property (nonatomic, assign) uint64_t memsize;            // hw.memsize: 6GB RAM
@property (nonatomic, assign) uint64_t l2cacheSize;         // hw.l2cachesize: 3MB, 8MB, 12MB, 16MB
@property (nonatomic, strong) NSString *localeIdentifier;  // NSLocale: "vi_VN", "en_US"
@property (nonatomic, strong) NSString *timeZoneName;      // NSTimeZone: "Asia/Ho_Chi_Minh", "America/New_York"
@property (nonatomic, strong) NSArray<NSString *> *preferredLanguages; // NSLocale preferredLanguages
@property (nonatomic, assign) CGFloat screenWidth;         // pt width (vd: 390.0)
@property (nonatomic, assign) CGFloat screenHeight;        // pt height (vd: 844.0)
@property (nonatomic, assign) CGFloat screenScale;         // scale (vd: 3.0)
@property (nonatomic, assign) uint64_t bootTimeSec;        // kern.boottime sec
@property (nonatomic, assign) uint64_t birthTimeSec;       // st_birthtime sec (theo vòng đời Apple)
@property (nonatomic, assign) uint32_t deltaVarSec;        // Độ lệch ngẫu nhiên của /var so với birthTime (s)
@property (nonatomic, assign) uint32_t deltaMobileSec;     // Độ lệch ngẫu nhiên của /var/mobile so với birthTime (s)
@property (nonatomic, assign) uint32_t deltaSandboxSec;    // Độ lệch ngẫu nhiên của Sandbox Zalo so với birthTime (s)
@property (nonatomic, assign) BOOL autoSyncTimezoneWithIP; // Vô hiệu hóa (Mặc định NO, không tự đổi múi giờ Profile theo IP)
@property (nonatomic, assign) BOOL enableFakeTimeZone;     // Bật/Tắt ép múi giờ giả (Mặc định NO, để Zalo đọc múi giờ thật của iOS)
@property (nonatomic, strong) NSString *bootSessionUUID;   // kern.bootsessionuuid
@property (nonatomic, strong) NSString *spoofedIDFV;       // identifierForVendor UUID
@property (nonatomic, strong) NSString *spoofedIDFA;       // advertisingIdentifier IDFA
@property (nonatomic, strong) NSString *profileId;         // Dùng để cách ly Keychain theo profile
@property (nonatomic, assign) uint64_t diskTotalSize;      // Dung lượng tổng ổ cứng (bytes)
@property (nonatomic, assign) uint64_t diskFreeSize;       // Dung lượng trống ổ cứng (bytes)
@property (nonatomic, assign) BOOL enableAuditLog;         // Bật ghi nhật ký kiểm toán Zalo (Audit Mode)
@property (nonatomic, strong) NSString *lastWipedIDFV;     // IDFV lần wipe trước
@property (nonatomic, strong) NSString *lastWipedIP;       // IP mạng lần wipe trước
@property (nonatomic, assign) uint64_t lastWipedTimestamp; // Thời điểm wipe lần trước
@property (nonatomic, strong) NSString *carrierName;        // Tên nhà mạng (vd: "Viettel", "VN MOBIFONE", "VINAPHONE")
@property (nonatomic, strong) NSString *carrierMCC;         // Mobile Country Code (vd: "452")
@property (nonatomic, strong) NSString *carrierMNC;         // Mobile Network Code (vd: "04", "01", "02")
@property (nonatomic, strong) NSString *carrierCountryCode; // Country Code ISO (vd: "vn")
@property (nonatomic, assign) float batteryLevel;           // Mức pin (vd: 0.82)
@property (nonatomic, assign) NSInteger batteryState;       // Trạng thái pin (UIDeviceBatteryStateUnplugged = 1)
@property (nonatomic, strong) NSString *regionMode;        // Khu vực: @"VN", @"US_STUDENT", @"US", @"PL"
@property (nonatomic, strong) NSString *preferredCarrier;  // Nhà mạng chỉ định khi Wipe / Cold-Boot ("Viettel", "VINAPHONE", "VN MOBIFONE", "Vietnamobile" hoặc rỗng)
@property (nonatomic, strong) NSString *spoofedSerial;      // Serial Number (vd: "F17X892JK9L")
@property (nonatomic, strong) NSString *spoofedWifiMAC;     // Wi-Fi MAC Address
@property (nonatomic, strong) NSString *spoofedBluetoothMAC;// Bluetooth MAC Address
@property (nonatomic, assign) BOOL showFloatingMenu;        // Hiện nút nổi trong app (Mặc định NO cho Zalo gốc, YES cho Clone)
@property (nonatomic, assign) BOOL needsNewProfile;         // Đánh dấu yêu cầu sinh profile mới khi Cold-Boot
@property (nonatomic, assign) BOOL needsSandboxPurge;       // Đánh dấu yêu cầu quét sạch hoàn toàn sandbox khi Cold-Boot
@property (nonatomic, assign) BOOL isShuttingDownForDeepWipe;// Cờ đang đóng app sau Deep Wipe (chống nuốt cờ sớm)
@property (nonatomic, assign) BOOL justGeneratedColdBoot;   // Cờ tạm thời: vừa sinh máy mới từ Cold-Boot
@property (nonatomic, assign) BOOL hasConfiguredProfile;   // Đã từng cấu hình profile hay chưa (Mặc định NO khi mới cài đặt)
@property (nonatomic, assign) BOOL proxyEnabled;           // Bật/tắt Proxy riêng cho Zalo (Yêu cầu có Key)
@property (nonatomic, strong) NSString *proxyType;         // @"HTTP" hoặc @"SOCKS5"
@property (nonatomic, strong) NSString *proxyHost;         // Host / IP của Proxy
@property (nonatomic, assign) uint16_t proxyPort;          // Cổng Port của Proxy
@property (nonatomic, strong) NSString *proxyUser;         // Tài khoản Proxy (tuỳ chọn)
@property (nonatomic, strong) NSString *proxyPass;         // Mật khẩu Proxy (tuỳ chọn)
@property (nonatomic, assign) BOOL spoofContinuousCPUClock; // Đồng bộ bộ đếm thạch anh CPU mach_time theo Profile (Mặc định YES)
@property (nonatomic, assign) BOOL spoofVoIPPushToken;      // Tự sinh mã VoIP token 32-byte (Mặc định NO để dùng Token gốc Apple)
@property (nonatomic, assign) BOOL resetTCCPromptOnWipe;     // Reset quyền Danh bạ để Zalo hỏi lại như máy mới (Mặc định YES)
@property (nonatomic, assign) BOOL contactsPermissionDetermined; // Đã từng hỏi quyền danh bạ trong profile này chưa
@property (nonatomic, assign) BOOL notificationPermissionDetermined; // Đã từng hỏi quyền thông báo trong profile này chưa
@property (nonatomic, strong) NSString *centralizedDid;       // Central Device ID từ centralized.zaloapp.com
@property (nonatomic, strong) NSString *currentAPNsToken;      // Token APNs hiện tại của Zalo
@property (nonatomic, strong) NSString *lastWipedAPNsToken;    // Token APNs trước lần Wipe gần nhất
@property (nonatomic, strong) NSString *lastKnownAPNsToken;    // Token APNs đã biết gần nhất
@property (nonatomic, strong) NSString *apnsRotatedStatus;     // Trạng thái xoay vòng APNs (@"WAITING", @"ROTATED_NEW", @"DUPLICATE", @"INITIAL_CAPTURED")
@property (nonatomic, strong) NSString *spoofedScreenSize;    // Độ phân giải màn hình dạng "750x1334", "828x1792"
@property (nonatomic, strong) NSString *currentZCID;          // zcid hiện tại do Zalo tự sinh
@property (nonatomic, strong) NSString *lastWipedZCID;        // zcid trước lần Wipe gần nhất
@property (nonatomic, strong) NSString *currentVoIPToken;     // VoIP token hiện tại
@property (nonatomic, strong) NSString *lastWipedVoIPToken;   // VoIP token trước lần Wipe gần nhất
@property (nonatomic, strong) NSString *spoofedVoIPToken;     // VoIP token sinh riêng cho profile mới

+ (instancetype)sharedSettings;
- (void)loadSettings;
- (void)saveSettings;
- (void)generateNewProfile;

@end
