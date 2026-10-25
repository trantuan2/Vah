#import "DeviceProfilePool.h"
#import <UIKit/UIKit.h>
#import <sys/sysctl.h>
#import <sys/utsname.h>

typedef struct {
    const char *machine;        // hw.machine, vd: "iPhone14,5"
    const char *model;          // hw.model, vd: "D17AP"
    uint32_t ncpu;              // 2, 6
    uint64_t ramBytes;          // 2GB, 3GB, 4GB, 6GB, 8GB
    uint64_t l2cacheBytes;      // hw.l2cachesize: 3MB, 8MB, 12MB, 16MB
    CGFloat width;              // pt width
    CGFloat height;             // pt height
    CGFloat scale;              // 2.0 hoặc 3.0
    uint64_t supportedDisks[5]; // Danh sách bộ nhớ hợp lệ (bytes), kết thúc bằng 0
    int minIOS;                 // Phiên bản iOS tối thiểu (Tối thiểu 15 để tương thích Zalo 26+)
    int maxIOS;                 // Phiên bản iOS tối đa (iPhone 7 = 15, iPhone 8/X = 16, iPhone 11+ = 18)
    const char *family;         // Nhóm nhận diện: "iPhone 7", "iPhone 7 Plus", "iPhone 8", ...
    uint64_t launchTimestamp;   // Thời điểm phát hành của dòng máy (Unix epoch sec)
    uint64_t eolTimestamp;      // Thời điểm ngừng sản xuất/khai tử (Unix epoch sec)
} AppleDeviceSpec;

// Ngân hàng thiết bị iPhone chuẩn xác 100% phần cứng của Apple kèm vòng đời sản xuất
static const AppleDeviceSpec kAppleDeviceSpecs[] = {
    // iPhone 6 Series (A8, 2 Cores, 1GB RAM) [09/2014 - 09/2016]
    {"iPhone7,2",  "N61AP",   2, 1073741824ULL, 2097152ULL,  375.0, 667.0, 2.0, {16000000000ULL, 64000000000ULL, 128000000000ULL, 0}, 15, 15, "iPhone 6", 1410998400ULL, 1473984000ULL},
    {"iPhone7,1",  "N56AP",   2, 1073741824ULL, 2097152ULL,  414.0, 736.0, 3.0, {16000000000ULL, 64000000000ULL, 128000000000ULL, 0}, 15, 15, "iPhone 6 Plus", 1410998400ULL, 1473984000ULL},

    // iPhone 6s Series & SE 1 (A9, 2 Cores, 2GB RAM, L2: 3MB) [09/2015 - 09/2018]
    {"iPhone8,1",  "N71AP",   2, 2147483648ULL, 3145728ULL,  375.0, 667.0, 2.0, {16000000000ULL, 32000000000ULL, 64000000000ULL, 128000000000ULL, 0}, 15, 15, "iPhone 6s", 1442361600ULL, 1536710400ULL},
    {"iPhone8,2",  "N66AP",   2, 2147483648ULL, 3145728ULL,  414.0, 736.0, 3.0, {16000000000ULL, 32000000000ULL, 64000000000ULL, 128000000000ULL, 0}, 15, 15, "iPhone 6s Plus", 1442361600ULL, 1536710400ULL},
    {"iPhone8,4",  "N69AP",   2, 2147483648ULL, 3145728ULL,  320.0, 568.0, 2.0, {16000000000ULL, 32000000000ULL, 64000000000ULL, 128000000000ULL, 0}, 15, 15, "iPhone SE (1st gen)", 1458518400ULL, 1536710400ULL},

    // iPhone 7 Series (A10 Fusion, 2 Cores, L2: 3MB, 375x667 @2x) [09/2016 - 09/2019]
    {"iPhone9,1",  "D10AP",   2, 2147483648ULL, 3145728ULL,  375.0, 667.0, 2.0, {32000000000ULL, 128000000000ULL, 256000000000ULL, 0}, 15, 15, "iPhone 7", 1473984000ULL, 1568160000ULL},
    {"iPhone9,3",  "D101AP",  2, 2147483648ULL, 3145728ULL,  375.0, 667.0, 2.0, {32000000000ULL, 128000000000ULL, 256000000000ULL, 0}, 15, 15, "iPhone 7", 1473984000ULL, 1568160000ULL},

    // iPhone 7 Plus Series (A10 Fusion, 2 Cores, 3GB RAM, L2: 3MB, 414x736 @3x) [09/2016 - 09/2019]
    {"iPhone9,2",  "D11AP",   2, 3221225472ULL, 3145728ULL,  414.0, 736.0, 3.0, {32000000000ULL, 128000000000ULL, 256000000000ULL, 0}, 15, 15, "iPhone 7 Plus", 1473984000ULL, 1568160000ULL},
    {"iPhone9,4",  "D111AP",  2, 3221225472ULL, 3145728ULL,  414.0, 736.0, 3.0, {32000000000ULL, 128000000000ULL, 256000000000ULL, 0}, 15, 15, "iPhone 7 Plus", 1473984000ULL, 1568160000ULL},

    // iPhone 8 Series (A11 Bionic, 6 Cores, 2GB RAM, L2: 8MB, 375x667 @2x) [09/2017 - 04/2020]
    {"iPhone10,1", "D20AP",   6, 2147483648ULL, 8388608ULL,  375.0, 667.0, 2.0, {64000000000ULL, 128000000000ULL, 256000000000ULL, 0}, 15, 16, "iPhone 8", 1505952000ULL, 1586908800ULL},
    {"iPhone10,4", "D201AP",  6, 2147483648ULL, 8388608ULL,  375.0, 667.0, 2.0, {64000000000ULL, 128000000000ULL, 256000000000ULL, 0}, 15, 16, "iPhone 8", 1505952000ULL, 1586908800ULL},

    // iPhone 8 Plus Series (A11 Bionic, 6 Cores, 3GB RAM, L2: 8MB, 414x736 @3x) [09/2017 - 04/2020]
    {"iPhone10,2", "D21AP",   6, 3221225472ULL, 8388608ULL,  414.0, 736.0, 3.0, {64000000000ULL, 128000000000ULL, 256000000000ULL, 0}, 15, 16, "iPhone 8 Plus", 1505952000ULL, 1586908800ULL},
    {"iPhone10,5", "D211AP",  6, 3221225472ULL, 8388608ULL,  414.0, 736.0, 3.0, {64000000000ULL, 128000000000ULL, 256000000000ULL, 0}, 15, 16, "iPhone 8 Plus", 1505952000ULL, 1586908800ULL},

    // iPhone X (A11 Bionic, 6 Cores, 3GB RAM, L2: 8MB, 375x812 @3x) [09/2017 - 09/2018]
    {"iPhone10,3", "D22AP",   6, 3221225472ULL, 8388608ULL,  375.0, 812.0, 3.0, {64000000000ULL, 256000000000ULL, 0, 0},              15, 16, "iPhone X", 1505952000ULL, 1536710400ULL},
    {"iPhone10,6", "D221AP",  6, 3221225472ULL, 8388608ULL,  375.0, 812.0, 3.0, {64000000000ULL, 256000000000ULL, 0, 0},              15, 16, "iPhone X", 1505952000ULL, 1536710400ULL},

    // iPhone XR / XS / XS Max Series (A12 Bionic, L2: 8MB) [09/2018 - 09/2021]
    {"iPhone11,8", "N841AP",  6, 3221225472ULL, 8388608ULL,  414.0, 896.0, 2.0, {64000000000ULL, 128000000000ULL, 256000000000ULL, 0}, 15, 18, "iPhone XR", 1536710400ULL, 1631577600ULL},
    {"iPhone11,2", "D321AP",  6, 4294967296ULL, 8388608ULL,  375.0, 812.0, 3.0, {64000000000ULL, 256000000000ULL, 512000000000ULL, 0}, 15, 18, "iPhone XS", 1536710400ULL, 1568160000ULL},
    {"iPhone11,6", "D331pAP", 6, 4294967296ULL, 8388608ULL,  414.0, 896.0, 3.0, {64000000000ULL, 256000000000ULL, 512000000000ULL, 0}, 15, 18, "iPhone XS Max", 1536710400ULL, 1568160000ULL},

    // iPhone 11 Series (A13 Bionic, 4GB RAM, L2: 8MB) [09/2019 - 09/2022]
    {"iPhone12,1", "N104AP",  6, 4294967296ULL, 8388608ULL,  414.0, 896.0, 2.0, {64000000000ULL, 128000000000ULL, 256000000000ULL, 0}, 15, 18, "iPhone 11", 1568160000ULL, 1662508800ULL},
    {"iPhone12,3", "D421AP",  6, 4294967296ULL, 8388608ULL,  375.0, 812.0, 3.0, {64000000000ULL, 256000000000ULL, 512000000000ULL, 0}, 15, 18, "iPhone 11 Pro", 1568160000ULL, 1602547200ULL},
    {"iPhone12,5", "D431AP",  6, 4294967296ULL, 8388608ULL,  414.0, 896.0, 3.0, {64000000000ULL, 256000000000ULL, 512000000000ULL, 0}, 15, 18, "iPhone 11 Pro Max", 1568160000ULL, 1602547200ULL},
    {"iPhone12,8", "D79AP",   6, 3221225472ULL, 8388608ULL,  375.0, 667.0, 2.0, {64000000000ULL, 128000000000ULL, 256000000000ULL, 0}, 15, 18, "iPhone SE 2", 1587686400ULL, 1646784000ULL},

    // iPhone 12 Series (A14 Bionic, L2: 8MB) [10/2020 - 09/2023]
    {"iPhone13,1", "D52gAP",  6, 4294967296ULL, 8388608ULL,  360.0, 780.0, 3.0, {64000000000ULL, 128000000000ULL, 256000000000ULL, 0}, 15, 18, "iPhone 12 mini", 1603411200ULL, 1662508800ULL},
    {"iPhone13,2", "D53gAP",  6, 4294967296ULL, 8388608ULL,  390.0, 844.0, 3.0, {64000000000ULL, 128000000000ULL, 256000000000ULL, 0}, 15, 18, "iPhone 12", 1603411200ULL, 1694563200ULL},
    {"iPhone13,3", "D53pAP",  6, 6442450944ULL, 8388608ULL,  390.0, 844.0, 3.0, {128000000000ULL, 256000000000ULL, 512000000000ULL, 0}, 15, 18, "iPhone 12 Pro", 1603411200ULL, 1631577600ULL},
    {"iPhone13,4", "D54pAP",  6, 6442450944ULL, 8388608ULL,  428.0, 926.0, 3.0, {128000000000ULL, 256000000000ULL, 512000000000ULL, 0}, 15, 18, "iPhone 12 Pro Max", 1603411200ULL, 1631577600ULL},

    // iPhone 13 Series (A15 Bionic, L2: 12MB) [09/2021 - 09/2024]
    {"iPhone14,4", "D16AP",   6, 4294967296ULL, 12582912ULL, 360.0, 780.0, 3.0, {128000000000ULL, 256000000000ULL, 512000000000ULL, 0}, 17, 18, "iPhone 13 mini", 1632441600ULL, 1694563200ULL},
    {"iPhone14,5", "D17AP",   6, 4294967296ULL, 12582912ULL, 390.0, 844.0, 3.0, {128000000000ULL, 256000000000ULL, 512000000000ULL, 0}, 17, 18, "iPhone 13", 1632441600ULL, 1725840000ULL},
    {"iPhone14,2", "D63AP",   6, 6442450944ULL, 12582912ULL, 390.0, 844.0, 3.0, {128000000000ULL, 256000000000ULL, 512000000000ULL, 1000000000000ULL, 0}, 17, 18, "iPhone 13 Pro", 1632441600ULL, 1662508800ULL},
    {"iPhone14,3", "D64AP",   6, 6442450944ULL, 12582912ULL, 428.0, 926.0, 3.0, {128000000000ULL, 256000000000ULL, 512000000000ULL, 1000000000000ULL, 0}, 17, 18, "iPhone 13 Pro Max", 1632441600ULL, 1662508800ULL},
    {"iPhone14,6", "D49AP",   6, 4294967296ULL, 12582912ULL, 375.0, 667.0, 2.0, {64000000000ULL, 128000000000ULL, 256000000000ULL, 0}, 17, 18, "iPhone SE 3", 1646784000ULL, 1725840000ULL},

    // iPhone 14 Series (A15 / A16 Bionic, L2: 16MB) [09/2022 - 09/2025]
    {"iPhone14,7", "D27AP",   6, 6442450944ULL, 16777216ULL, 390.0, 844.0, 3.0, {128000000000ULL, 256000000000ULL, 512000000000ULL, 0}, 17, 18, "iPhone 14", 1663286400ULL, 1757376000ULL},
    {"iPhone14,8", "D28AP",   6, 6442450944ULL, 16777216ULL, 428.0, 926.0, 3.0, {128000000000ULL, 256000000000ULL, 512000000000ULL, 0}, 17, 18, "iPhone 14 Plus", 1663286400ULL, 1725840000ULL},
    {"iPhone15,2", "D73AP",   6, 6442450944ULL, 16777216ULL, 393.0, 852.0, 3.0, {128000000000ULL, 256000000000ULL, 512000000000ULL, 1000000000000ULL, 0}, 17, 18, "iPhone 14 Pro", 1663286400ULL, 1694563200ULL},
    {"iPhone15,3", "D74AP",   6, 6442450944ULL, 16777216ULL, 430.0, 932.0, 3.0, {128000000000ULL, 256000000000ULL, 512000000000ULL, 1000000000000ULL, 0}, 17, 18, "iPhone 14 Pro Max", 1663286400ULL, 1694563200ULL},

    // iPhone 15 Series (A16 / A17 Pro, L2: 16MB) [09/2023 - 09/2026]
    {"iPhone15,4", "D37AP",   6, 6442450944ULL, 16777216ULL, 393.0, 852.0, 3.0, {128000000000ULL, 256000000000ULL, 512000000000ULL, 0}, 17, 18, "iPhone 15", 1694736000ULL, 1788739200ULL},
    {"iPhone15,5", "D38AP",   6, 6442450944ULL, 16777216ULL, 430.0, 932.0, 3.0, {128000000000ULL, 256000000000ULL, 512000000000ULL, 0}, 17, 18, "iPhone 15 Plus", 1694736000ULL, 1757376000ULL},
    {"iPhone16,1", "D83AP",   6, 8589934592ULL, 16777216ULL, 393.0, 852.0, 3.0, {128000000000ULL, 256000000000ULL, 512000000000ULL, 1000000000000ULL, 0}, 17, 18, "iPhone 15 Pro", 1694736000ULL, 1725840000ULL},
    {"iPhone16,2", "D84AP",   6, 8589934592ULL, 16777216ULL, 430.0, 932.0, 3.0, {256000000000ULL, 512000000000ULL, 1000000000000ULL, 0}, 17, 18, "iPhone 15 Pro Max", 1694736000ULL, 1725840000ULL},

    // iPhone 16 Series (A18 / A18 Pro, 8GB RAM, L2: 16MB, chỉ chạy iOS 18+) [09/2024 - 10/2026]
    {"iPhone17,3", "D47AP",   6, 8589934592ULL, 16777216ULL, 393.0, 852.0, 3.0, {128000000000ULL, 256000000000ULL, 512000000000ULL, 0}, 18, 18, "iPhone 16", 1726790400ULL, 1792000000ULL},
    {"iPhone17,4", "D48AP",   6, 8589934592ULL, 16777216ULL, 430.0, 932.0, 3.0, {128000000000ULL, 256000000000ULL, 512000000000ULL, 0}, 18, 18, "iPhone 16 Plus", 1726790400ULL, 1792000000ULL},
    {"iPhone17,1", "D93AP",   6, 8589934592ULL, 16777216ULL, 402.0, 874.0, 3.0, {128000000000ULL, 256000000000ULL, 512000000000ULL, 1000000000000ULL, 0}, 18, 18, "iPhone 16 Pro", 1726790400ULL, 1792000000ULL},
    {"iPhone17,2", "D94AP",   6, 8589934592ULL, 16777216ULL, 440.0, 956.0, 3.0, {256000000000ULL, 512000000000ULL, 1000000000000ULL, 0}, 18, 18, "iPhone 16 Pro Max", 1726790400ULL, 1792000000ULL}
};

typedef struct {
    const char *version; // "15.8.3", "17.6.1"
    const char *build;   // "19H386", "21G93"
    int major;           // 15, 16, 17, 18
    BOOL legacyOnly;     // Chỉ dành cho thiết bị ngừng hỗ trợ (iPhone 6s/7 cho 15.8.x, iPhone 8/X cho 16.7.x)
    uint64_t releaseTimestamp; // Thời điểm Apple chính thức phát hành bản dựng IPSW này (chuẩn giờ Cupertino 17:00 / 18:00 UTC)
    const char *darwinRelease; // Bản phát hành Darwin Kernel chính xác: vd "21.6.0", "22.6.0", "24.2.0"
} AppleOSRelease;

// Bảng phiên bản iOS thực tế & Build ID chính xác của Apple (Tối thiểu 15.1+ để tương thích hệ thống)
static const AppleOSRelease kAppleOSReleases[] = {
    // iOS 15 Releases (iPhone 6s / 6s Plus / SE 1 / iPhone 7 / 7 Plus)
    {"15.4.1", "19E258",  15, NO,  1648746000ULL, "21.4.0"}, // 31/03/2022 17:00 UTC
    {"15.5",   "19F77",   15, NO,  1652720400ULL, "21.5.0"}, // 16/05/2022 17:00 UTC
    {"15.6",   "19G69",   15, NO,  1658336400ULL, "21.6.0"}, // 20/07/2022 17:00 UTC
    {"15.6.1", "19G82",   15, NO,  1660755600ULL, "21.6.0"}, // 17/08/2022 17:00 UTC
    {"15.7",   "19H12",   15, NO,  1663002000ULL, "21.6.0"}, // 12/09/2022 17:00 UTC
    {"15.7.1", "19H117",  15, NO,  1666890000ULL, "21.6.0"}, // 27/10/2022 17:00 UTC
    {"15.7.2", "19H218",  15, NO,  1670950800ULL, "21.6.0"}, // 13/12/2022 17:00 UTC
    {"15.7.5", "19H332",  15, NO,  1681146000ULL, "21.6.0"}, // 10/04/2023 17:00 UTC
    {"15.8",   "19H370",  15, YES, 1698253200ULL, "21.6.0"}, // 25/10/2023 17:00 UTC
    {"15.8.1", "19H380",  15, YES, 1705946400ULL, "21.6.0"}, // 22/01/2024 18:00 UTC
    {"15.8.2", "19H384",  15, YES, 1709661600ULL, "21.6.0"}, // 05/03/2024 18:00 UTC
    {"15.8.3", "19H386",  15, YES, 1722272400ULL, "21.6.0"}, // 29/07/2024 17:00 UTC
    {"15.8.4", "19H390",  15, YES, 1743440400ULL, "21.6.0"}, // 31/03/2025 17:00 UTC
    {"15.8.5", "19H394",  15, YES, 1757955600ULL, "21.6.0"}, // 15/09/2025 17:00 UTC
    {"15.8.6", "19H402",  15, YES, 1769450400ULL, "21.6.0"}, // 26/01/2026 18:00 UTC
    {"15.8.7", "19H411",  15, YES, 1773248400ULL, "21.6.0"}, // 11/03/2026 17:00 UTC

    // iOS 16 Releases (iPhone 8 / 8 Plus / X)
    {"16.5",    "20F66",  16, NO,  1684429200ULL, "22.5.0"}, // 18/05/2023 17:00 UTC
    {"16.6",    "20G75",  16, NO,  1690218000ULL, "22.6.0"}, // 24/07/2023 17:00 UTC
    {"16.6.1",  "20G81",  16, NO,  1694106000ULL, "22.6.0"}, // 07/09/2023 17:00 UTC
    {"16.7.2",  "20H115", 16, YES, 1698253200ULL, "22.6.0"}, // 25/10/2023 17:00 UTC
    {"16.7.5",  "20H307", 16, YES, 1705946400ULL, "22.6.0"}, // 22/01/2024 18:00 UTC
    {"16.7.10", "20H350", 16, YES, 1723050000ULL, "22.6.0"}, // 07/08/2024 17:00 UTC
    {"16.7.11", "20H360", 16, YES, 1743440400ULL, "22.6.0"}, // 31/03/2025 17:00 UTC
    {"16.7.12", "20H364", 16, YES, 1757955600ULL, "22.6.0"}, // 15/09/2025 17:00 UTC
    {"16.7.13", "20H365", 16, YES, 1769450400ULL, "22.6.0"}, // 26/01/2026 18:00 UTC
    {"16.7.14", "20H370", 16, YES, 1770055200ULL, "22.6.0"}, // 02/02/2026 18:00 UTC

    // iOS 17 Releases
    {"17.4",   "21E219",  17, NO,  1709661600ULL, "23.4.0"}, // 05/03/2024 18:00 UTC
    {"17.4.1", "21E236",  17, NO,  1711040400ULL, "23.4.0"}, // 21/03/2024 17:00 UTC
    {"17.5",   "21F79",   17, NO,  1715619600ULL, "23.5.0"}, // 13/05/2024 17:00 UTC
    {"17.5.1", "21F90",   17, NO,  1716224400ULL, "23.5.0"}, // 20/05/2024 17:00 UTC
    {"17.6",   "21G80",   17, NO,  1722272400ULL, "23.6.0"}, // 29/07/2024 17:00 UTC
    {"17.6.1", "21G93",   17, NO,  1723050000ULL, "23.6.0"}, // 07/08/2024 17:00 UTC
    {"17.7",   "21H16",   17, NO,  1726506000ULL, "23.6.0"}, // 16/09/2024 17:00 UTC
    {"17.7.1", "21H216",  17, NO,  1730134800ULL, "23.6.0"}, // 28/10/2024 17:00 UTC
    {"17.7.2", "21H221",  17, NO,  1732039200ULL, "23.6.0"}, // 19/11/2024 18:00 UTC

    // iOS 18 Releases (Bản phát hành chính thức Apple IPSW)
    {"18.0",   "22A3354", 18, NO,  1726506000ULL, "24.0.0"}, // 16/09/2024 17:00 UTC
    {"18.0.1", "22A3370", 18, NO,  1727974800ULL, "24.0.0"}, // 03/10/2024 17:00 UTC
    {"18.1",   "22B83",   18, NO,  1730134800ULL, "24.1.0"}, // 28/10/2024 17:00 UTC
    {"18.1.1", "22B91",   18, NO,  1732039200ULL, "24.1.0"}, // 19/11/2024 18:00 UTC
    {"18.2",   "22C152",  18, NO,  1733936400ULL, "24.2.0"}, // 11/12/2024 18:00 UTC
    {"18.2.1", "22C161",  18, NO,  1736186400ULL, "24.2.0"}, // 06/01/2025 18:00 UTC
    {"18.3",   "22D63",   18, NO,  1737997200ULL, "24.3.0"}, // 27/01/2025 18:00 UTC
    {"18.3.1", "22D72",   18, NO,  1739210400ULL, "24.3.0"}, // 10/02/2025 18:00 UTC
    {"18.3.2", "22D82",   18, NO,  1741802400ULL, "24.3.0"}, // 12/03/2025 18:00 UTC
    {"18.4",   "22E210",  18, NO,  1743440400ULL, "24.4.0"}  // 31/03/2025 17:00 UTC
};

NSString *generate_apple_serial(void) {
    const char chars[] = "0123456789ABCDEFGHJKLMNPQRSTUVWXYZ";
    char serial[13] = {0};
    // Tiền tố xuất xưởng Apple phổ biến (F17, F2L, DX3, G6T, H0V, C39, G0N...)
    const char *prefixes[] = {"F17", "F2L", "DX3", "G6T", "H0V", "C39", "G0N", "FK1", "DN6", "DLX"};
    const char *p = prefixes[arc4random_uniform(10)];
    serial[0] = p[0];
    serial[1] = p[1];
    serial[2] = p[2];
    for (int i = 3; i < 12; i++) {
        serial[i] = chars[arc4random_uniform(sizeof(chars) - 1)];
    }
    return [NSString stringWithUTF8String:serial];
}

NSString *generate_apple_mac(void) {
    // Các tiền tố OUI thực tế thuộc sở hữu của Apple Inc.
    const char *ouis[] = {
        "f0:18:98", "ac:de:48", "88:66:5a", "dc:a9:04", "a4:83:e7",
        "e0:c7:67", "bc:d1:1f", "f4:34:f0", "70:3e:ac", "38:f9:d3",
        "40:6c:8f", "5c:96:9d", "64:a3:cb", "8c:85:90", "a8:5b:78"
    };
    const char *oui = ouis[arc4random_uniform(15)];
    return [NSString stringWithFormat:@"%s:%02x:%02x:%02x", oui, arc4random_uniform(256), arc4random_uniform(256), arc4random_uniform(256)];
}

static NSString *s_realHardwareMachine = nil;

static NSString *detect_real_system_machine(void) {
    if (s_realHardwareMachine && s_realHardwareMachine.length > 0) {
        return s_realHardwareMachine;
    }
    char buf[64] = {0};
    size_t size = sizeof(buf);
    if (sysctlbyname("hw.machine", buf, &size, NULL, 0) == 0 && strlen(buf) > 0) {
        return [NSString stringWithUTF8String:buf];
    }
    struct utsname u;
    if (uname(&u) == 0 && strlen(u.machine) > 0) {
        return [NSString stringWithUTF8String:u.machine];
    }
    return [NSString stringWithUTF8String:kAppleDeviceSpecs[0].machine];
}

@implementation ZTDeviceProfile

+ (void)setRealHardwareMachine:(nullable NSString *)machine {
    if (machine && machine.length > 0) {
        s_realHardwareMachine = [machine copy];
    }
}

+ (nullable NSString *)realHardwareMachine {
    return s_realHardwareMachine;
}

+ (void)getScreenDimensionsForMachine:(NSString *)machine width:(CGFloat *)outW height:(CGFloat *)outH scale:(CGFloat *)outS {
    size_t specCount = sizeof(kAppleDeviceSpecs) / sizeof(kAppleDeviceSpecs[0]);
    if (machine && machine.length > 0) {
        for (size_t i = 0; i < specCount; i++) {
            if ([machine isEqualToString:[NSString stringWithUTF8String:kAppleDeviceSpecs[i].machine]]) {
                if (outW) *outW = kAppleDeviceSpecs[i].width;
                if (outH) *outH = kAppleDeviceSpecs[i].height;
                if (outS) *outS = kAppleDeviceSpecs[i].scale;
                return;
            }
        }
    }
    if (outW) *outW = kAppleDeviceSpecs[0].width;
    if (outH) *outH = kAppleDeviceSpecs[0].height;
    if (outS) *outS = kAppleDeviceSpecs[0].scale;
}

+ (ZTDeviceProfile *)generateRandomProfileForRegion:(NSString *)region {
    return [self generateRandomProfileForRegion:region baseMachine:nil preferredCarrier:nil];
}

+ (ZTDeviceProfile *)generateRandomProfileForRegion:(NSString *)region baseMachine:(NSString *)baseMachine {
    return [self generateRandomProfileForRegion:region baseMachine:baseMachine preferredCarrier:nil];
}

+ (ZTDeviceProfile *)generateRandomProfileForRegion:(NSString *)region baseMachine:(nullable NSString *)baseMachine preferredCarrier:(nullable NSString *)preferredCarrier {
    ZTDeviceProfile *profile = [[ZTDeviceProfile alloc] init];

    NSString *physicalMachine = baseMachine ?: s_realHardwareMachine ?: detect_real_system_machine();
    size_t specCount = sizeof(kAppleDeviceSpecs) / sizeof(kAppleDeviceSpecs[0]);

    // 1. TÌM THÔNG SỐ VÀ DÒNG MÁY THỰC TẾ
    const AppleDeviceSpec *matchedBaseSpec = NULL;
    for (size_t i = 0; i < specCount; i++) {
        if ([physicalMachine isEqualToString:[NSString stringWithUTF8String:kAppleDeviceSpecs[i].machine]]) {
            matchedBaseSpec = &kAppleDeviceSpecs[i];
            break;
        }
    }

    // Nếu không khớp trực tiếp, sử dụng profile đầu tiên làm chuẩn
    if (matchedBaseSpec == NULL) {
        matchedBaseSpec = &kAppleDeviceSpecs[0];
    }

    NSMutableArray *candidateSpecs = [NSMutableArray array];
    if (matchedBaseSpec != NULL) {
        // Khóa chặt: Chỉ fake sang các biến thể CÙNG FAMILY dòng máy với thiết bị vật lý
        // (vd: iPhone 8 chỉ fake sang iPhone 8 khác; iPhone 13 chỉ fake sang iPhone 13 khác)
        for (size_t i = 0; i < specCount; i++) {
            if (strcmp(kAppleDeviceSpecs[i].family, matchedBaseSpec->family) == 0) {
                [candidateSpecs addObject:[NSValue valueWithPointer:&kAppleDeviceSpecs[i]]];
            }
        }
    }

    // Tuyệt đối không fallback sang danh sách máy thuộc dòng khác!
    if (candidateSpecs.count == 0) {
        if (matchedBaseSpec != NULL) {
            [candidateSpecs addObject:[NSValue valueWithPointer:matchedBaseSpec]];
        } else {
            // Mặc định an toàn cho máy iPhone 7
            [candidateSpecs addObject:[NSValue valueWithPointer:&kAppleDeviceSpecs[0]]];
        }
    }

    // Tuyệt đối không fallback sang danh sách máy khác thông số màn hình!
    if (candidateSpecs.count == 0) {
        if (matchedBaseSpec != NULL) {
            [candidateSpecs addObject:[NSValue valueWithPointer:matchedBaseSpec]];
        } else {
            // Mặc định an toàn cho máy iPhone 7
            [candidateSpecs addObject:[NSValue valueWithPointer:&kAppleDeviceSpecs[0]]];
        }
    }

    NSValue *chosenSpecVal = candidateSpecs[arc4random_uniform((uint32_t)candidateSpecs.count)];
    const AppleDeviceSpec *chosenSpec = (const AppleDeviceSpec *)[chosenSpecVal pointerValue];
    AppleDeviceSpec spec = *chosenSpec;

    profile.deviceMachine = [NSString stringWithUTF8String:spec.machine];
    profile.deviceModel = [NSString stringWithUTF8String:spec.model];
    profile.ncpu = spec.ncpu;
    profile.memsize = spec.ramBytes;
    profile.l2cacheSize = spec.l2cacheBytes;
    profile.screenWidth = spec.width;
    profile.screenHeight = spec.height;
    profile.screenScale = spec.scale;

    // 2. CHỌN BẢN iOS TƯƠNG THÍCH VỚI DÒNG MÁY (iPhone 7: 15.x, iPhone 16: 18+)
    size_t osCount = sizeof(kAppleOSReleases) / sizeof(kAppleOSReleases[0]);
    NSMutableArray *validOSList = [NSMutableArray array];
    BOOL isLegacyOnlyDevice = (spec.maxIOS <= 16); // Chỉ iPhone 6s/7/8/X
    for (size_t i = 0; i < osCount; i++) {
        if (kAppleOSReleases[i].major >= spec.minIOS && kAppleOSReleases[i].major <= spec.maxIOS) {
            // Máy hiện đại (iPhone XR/11/12/13/14/15/16) không bao giờ nhận các bản vá độc quyền của máy cũ ngừng hỗ trợ (16.7.x hay 15.8.x)
            if (kAppleOSReleases[i].legacyOnly && !isLegacyOnlyDevice) {
                continue;
            }
            [validOSList addObject:[NSValue valueWithPointer:&kAppleOSReleases[i]]];
        }
    }
    if (validOSList.count == 0) {
        for (size_t i = 0; i < osCount; i++) {
            if (kAppleOSReleases[i].major >= spec.minIOS && (!kAppleOSReleases[i].legacyOnly || isLegacyOnlyDevice)) {
                [validOSList addObject:[NSValue valueWithPointer:&kAppleOSReleases[i]]];
            }
        }
    }
    NSValue *chosenVal = validOSList[arc4random_uniform((uint32_t)validOSList.count)];
    const AppleOSRelease *chosenOS = (const AppleOSRelease *)[chosenVal pointerValue];

    profile.systemVersion = [NSString stringWithUTF8String:chosenOS->version];
    profile.kernOsVersion = [NSString stringWithUTF8String:chosenOS->build];
    profile.darwinKernelRelease = [NSString stringWithUTF8String:chosenOS->darwinRelease];

    // 3. CHỌN BỘ NHỚ Ổ CỨNG HỢP LỆ VỚI DÒNG MÁY ĐÓ (Mô hình APFS Space Sharing)
    int diskCount = 0;
    while (spec.supportedDisks[diskCount] != 0 && diskCount < 5) {
        diskCount++;
    }
    uint64_t nominalDisk = spec.supportedDisks[arc4random_uniform((uint32_t)diskCount)];

    // Dung lượng thực Flash NAND: Decimal GB (10^9 bytes)
    // Hệ thống APFS chia sẻ không gian: Phân vùng Data (/private/var) chia sẻ cùng Sealed System Volume (SSV)
    // SSV: iOS 15 (~4.2 - 4.9 GB), iOS 16 (~5.2 - 6.2 GB), iOS 17/18 (~7.8 - 9.4 GB)
    // Preboot, Recovery, VM, APFS metadata: ~1.0 - 1.8 GB
    double systemVolumeGB = 0;
    if (chosenOS->major <= 15) {
        systemVolumeGB = 4.2 + (((double)arc4random_uniform(700)) / 1000.0);
    } else if (chosenOS->major == 16) {
        systemVolumeGB = 5.2 + (((double)arc4random_uniform(1000)) / 1000.0);
    } else {
        systemVolumeGB = 7.8 + (((double)arc4random_uniform(1600)) / 1000.0);
    }
    double auxiliaryOverheadGB = 1.0 + (((double)arc4random_uniform(800)) / 1000.0);
    uint64_t nonDataBytes = (uint64_t)((systemVolumeGB + auxiliaryOverheadGB) * 1000000000.0);

    // 3. THIẾT LẬP DUNG LƯỢNG Ổ CỨNG: CHẾ ĐỘ NATIVE PASSTHROUGH CHUẨN TRUST
    // Passthrough phần cứng APFS thật: 0 = Không can thiệp, nhường quyền hoàn toàn cho Darwin Kernel & NAND Flash
    profile.diskTotalSize = 0;
    profile.diskFreeSize = 0;

    // 4. KHO HƠN 100 TÊN THIẾT BỊ TỰ NHIÊN THEO VÙNG
    NSString *curRegion = region ?: @"VN";
    if ([curRegion isEqualToString:@"US_STUDENT"]) {
        NSArray *names = @[
            @"Alex's iPhone", @"Nam's iPhone", @"Huy's iPhone", @"Kevin's iPhone",
            @"Minh's iPhone", @"Trang's iPhone", @"Linh's iPhone", @"Duc's iPhone",
            @"Vy's iPhone", @"Phong's iPhone", @"Dan's iPhone", @"Jenny's iPhone",
            @"Brian's iPhone", @"Eric's iPhone", @"Jason's iPhone", @"Ryan's iPhone",
            @"Justin's iPhone", @"Andrew's iPhone", @"Matthew's iPhone", @"Brandon's iPhone",
            @"Tyler's iPhone", @"Emily's iPhone", @"Hannah's iPhone", @"Rachel's iPhone",
            @"Megan's iPhone", @"Lauren's iPhone", @"iPhone", @"iPhone (1)", @"iPhone (2)",
            @"Nam", @"Huy", @"Kevin", @"Alex", @"Alex's Phone"
        ];
        profile.deviceName = names[arc4random_uniform((uint32_t)names.count)];

        NSArray *carriers = @[
            @{@"name": @"T-Mobile",    @"mcc": @"310", @"mnc": @"260"},
            @{@"name": @"AT&T",        @"mcc": @"310", @"mnc": @"410"},
            @{@"name": @"Mint Mobile", @"mcc": @"310", @"mnc": @"260"},
            @{@"name": @"Verizon",     @"mcc": @"311", @"mnc": @"480"},
            @{@"name": @"Cricket",     @"mcc": @"310", @"mnc": @"150"}
        ];
        NSDictionary *c = carriers[arc4random_uniform((uint32_t)carriers.count)];
        profile.carrierName = c[@"name"];
        profile.carrierMCC = c[@"mcc"];
        profile.carrierMNC = c[@"mnc"];
        profile.carrierCountryCode = @"us";
        profile.localeIdentifier = @"en_US";
        profile.preferredLanguages = @[@"en-US"];
        // Mặc định múi giờ Mỹ chuẩn (America/New_York) để bảo vệ danh tính khi đăng ký
        profile.timeZoneName = @"America/New_York";
    } else if ([curRegion isEqualToString:@"US"]) {
        NSArray *names = @[
            @"David's iPhone", @"Michael's iPhone", @"Sarah's iPhone", @"John's iPhone",
            @"Daniel's iPhone", @"Chris's iPhone", @"Jessica's iPhone", @"James's iPhone",
            @"Robert's iPhone", @"William's iPhone", @"Joseph's iPhone", @"Thomas's iPhone",
            @"Charles's iPhone", @"Christopher's iPhone", @"Anthony's iPhone", @"Mark's iPhone",
            @"Donald's iPhone", @"Steven's iPhone", @"Paul's iPhone", @"Andrew's iPhone",
            @"Joshua's iPhone", @"Kenneth's iPhone", @"Kevin's iPhone", @"Brian's iPhone",
            @"George's iPhone", @"Timothy's iPhone", @"Ronald's iPhone", @"Jason's iPhone",
            @"Edward's iPhone", @"Jeffrey's iPhone", @"iPhone", @"iPhone (1)", @"iPhone (2)", @"iPhone (3)"
        ];
        profile.deviceName = names[arc4random_uniform((uint32_t)names.count)];

        NSArray *carriers = @[
            @{@"name": @"Verizon",  @"mcc": @"311", @"mnc": @"480"},
            @{@"name": @"AT&T",     @"mcc": @"310", @"mnc": @"410"},
            @{@"name": @"T-Mobile", @"mcc": @"310", @"mnc": @"260"}
        ];
        NSDictionary *c = nil;
        if (preferredCarrier.length > 0) {
            NSString *cleanPref = [preferredCarrier lowercaseString];
            for (NSDictionary *item in carriers) {
                NSString *cName = [item[@"name"] lowercaseString];
                if ([cleanPref containsString:cName] || [cName containsString:cleanPref]) {
                    c = item;
                    break;
                }
            }
        }
        if (!c) {
            c = carriers[arc4random_uniform((uint32_t)carriers.count)];
        }
        profile.carrierName = c[@"name"];
        profile.carrierMCC = c[@"mcc"];
        profile.carrierMNC = c[@"mnc"];
        profile.carrierCountryCode = @"us";
        profile.localeIdentifier = @"en_US";
        profile.preferredLanguages = @[@"en-US"];
        NSArray *usTimezones = @[@"America/New_York", @"America/Chicago", @"America/Los_Angeles", @"America/Denver"];
        profile.timeZoneName = usTimezones[arc4random_uniform((uint32_t)usTimezones.count)];
    } else if ([curRegion isEqualToString:@"PL"]) {
        NSArray *names = @[
            @"iPhone Michała", @"iPhone Piotra", @"iPhone Jakuba", @"iPhone Mateusza",
            @"iPhone Bartosza", @"iPhone Szymona", @"iPhone Anny", @"iPhone Julii",
            @"iPhone Zuzanny", @"iPhone Mai", @"iPhone Aleksandry", @"iPhone Natalii",
            @"iPhone Wiktorii", @"iPhone Tomasza", @"iPhone Pawła", @"iPhone Kacpra",
            @"iPhone Filipa", @"iPhone Macieja", @"iPhone Marcina", @"iPhone Krzysztofa",
            @"iPhone Kamila", @"iPhone Dawida", @"iPhone Patryka", @"iPhone Łukasza",
            @"iPhone Wojciecha", @"iPhone Adama", @"iPhone Jana", @"iPhone (Michał)",
            @"iPhone (Jakub)", @"iPhone (Piotr)", @"iPhone (Anna)", @"iPhone",
            @"iPhone (1)", @"iPhone (2)", @"iPhone (3)",
            [NSString stringWithUTF8String:spec.family] ?: @"iPhone"
        ];
        profile.deviceName = names[arc4random_uniform((uint32_t)names.count)];

        NSArray *carriers = @[
            @{@"name": @"Play",     @"mcc": @"260", @"mnc": @"06"},
            @{@"name": @"Orange",   @"mcc": @"260", @"mnc": @"03"},
            @{@"name": @"Plus",     @"mcc": @"260", @"mnc": @"01"},
            @{@"name": @"T-Mobile", @"mcc": @"260", @"mnc": @"02"}
        ];
        NSDictionary *c = nil;
        if (preferredCarrier.length > 0) {
            NSString *cleanPref = [preferredCarrier lowercaseString];
            for (NSDictionary *item in carriers) {
                NSString *cName = [item[@"name"] lowercaseString];
                NSString *cMnc = item[@"mnc"];
                if ([cleanPref containsString:cName] || [cName containsString:cleanPref] ||
                    ([cleanPref containsString:@"play"] && [cName containsString:@"play"]) ||
                    ([cleanPref containsString:@"orange"] && [cName containsString:@"orange"]) ||
                    ([cleanPref containsString:@"plus"] && [cName containsString:@"plus"]) ||
                    ([cleanPref containsString:@"t-mobile"] && [cName containsString:@"t-mobile"]) ||
                    [cleanPref isEqualToString:cMnc]) {
                    c = item;
                    break;
                }
            }
        }
        if (!c) {
            c = carriers[arc4random_uniform((uint32_t)carriers.count)];
        }
        profile.carrierName = c[@"name"];
        profile.carrierMCC = c[@"mcc"];
        profile.carrierMNC = c[@"mnc"];
        profile.carrierCountryCode = @"pl";
        profile.localeIdentifier = @"pl_PL";
        profile.preferredLanguages = @[@"pl-PL", @"en-PL"];
        profile.timeZoneName = @"Europe/Warsaw";
    } else {
        NSArray *names = @[
            @"iPhone", @"iPhone (1)", @"iPhone (2)", @"iPhone (3)",
            @"iPhone của Tuấn", @"iPhone của Linh", @"iPhone của Huy", @"iPhone của Nam",
            @"iPhone của Trang", @"iPhone của Hoàng", @"iPhone của Mai", @"iPhone của Lan",
            @"iPhone của Minh", @"iPhone của Đức", @"iPhone của Hùng", @"iPhone của Thảo",
            @"iPhone của Dũng", @"iPhone của Ngọc", @"iPhone của Phong", @"iPhone của Hương",
            @"iPhone của Long", @"iPhone của Quỳnh", @"iPhone của Khánh", @"iPhone của Vy",
            @"iPhone của An", @"iPhone của Quân", @"iPhone của Sơn", @"iPhone của Hà",
            @"iPhone của Tiến", @"iPhone của Duy", @"iPhone của Phương", @"iPhone của Kiên",
            @"iPhone của Trâm", @"iPhone của Đạt", @"iPhone của Giang", @"iPhone của Việt",
            @"iPhone của Huyền", @"iPhone của Tâm", @"iPhone của Ly", @"iPhone của Bình",
            @"iPhone của Hằng", @"iPhone của Thành", @"iPhone của Yến", @"iPhone của Thắng",
            @"iPhone của Khoa", @"iPhone của Nhung", @"iPhone của Trung", @"iPhone của Hiếu",
            @"Tuấn", @"Linh", @"Huy", @"Nam", @"Trang", @"Hoàng", @"Mai", @"Đức",
            [NSString stringWithUTF8String:spec.family] ?: @"iPhone"
        ];
        profile.deviceName = names[arc4random_uniform((uint32_t)names.count)];

        NSArray *defaultCarriers = @[
            @{@"name": @"Viettel",       @"mcc": @"452", @"mnc": @"04"},
            @{@"name": @"VN MOBIFONE",   @"mcc": @"452", @"mnc": @"01"},
            @{@"name": @"VINAPHONE",     @"mcc": @"452", @"mnc": @"02"}
        ];
        NSArray *allCarriers = defaultCarriers;
        NSDictionary *c = nil;
        if (preferredCarrier.length > 0) {
            NSString *cleanPref = [preferredCarrier lowercaseString];
            for (NSDictionary *item in allCarriers) {
                NSString *cName = [item[@"name"] lowercaseString];
                NSString *cMnc = item[@"mnc"];
                if ([cleanPref isEqualToString:cName] ||
                    ([cleanPref containsString:@"viettel"] && [cName isEqualToString:@"viettel"]) ||
                    ([cleanPref containsString:@"vina"] && [cName isEqualToString:@"vinaphone"]) ||
                    ([cleanPref containsString:@"mobi"] && [cName isEqualToString:@"vn mobifone"]) ||
                    [cleanPref isEqualToString:cMnc]) {
                    c = item;
                    break;
                }
            }
        }
        if (!c) {
            c = defaultCarriers[arc4random_uniform((uint32_t)defaultCarriers.count)];
        }
        profile.carrierName = c[@"name"];
        profile.carrierMCC = c[@"mcc"];
        profile.carrierMNC = c[@"mnc"];
        profile.carrierCountryCode = @"vn";
        profile.localeIdentifier = @"vi_VN";
        profile.preferredLanguages = @[@"vi-VN", @"en-VN"];
        profile.timeZoneName = @"Asia/Ho_Chi_Minh";
    }

    profile.actualCarrier = profile.carrierName;

    // Áp dụng giới hạn bảo mật và hành vi thực tế của Apple theo phiên bản iOS:
    BOOL is_ios16_plus = (chosenOS->major >= 16);
    BOOL is_ios16_4_plus = (chosenOS->major >= 17);
    if (chosenOS->major == 16) {
        NSArray *parts = [[NSString stringWithUTF8String:chosenOS->version] componentsSeparatedByString:@"."];
        if (parts.count >= 2 && [parts[1] integerValue] >= 4) {
            is_ios16_4_plus = YES;
        }
    }

    if (is_ios16_plus) {
        // Trên iOS 16.0+, [UIDevice currentDevice].name luôn trả về generic "iPhone" cho App Store apps
        profile.deviceName = @"iPhone";
    }

    if (is_ios16_4_plus) {
        // Trên iOS 16.4+, CTCarrier bị Apple deprecate hoàn toàn, app App Store thông thường chỉ nhận placeholder
        profile.carrierName = @"--";
        profile.carrierMCC = @"65535";
        profile.carrierMNC = @"65535";
        profile.carrierCountryCode = @"";
    }

    // 5. CÁC THÔNG SỐ ĐỊNH DANH DUY NHẤT & MÃ BẢO VỆ
    profile.spoofedIDFV = [[NSUUID UUID] UUIDString];
    profile.spoofedIDFA = @"00000000-0000-0000-0000-000000000000"; // Chuẩn Apple ATT Denied
    profile.profileId = [[NSUUID UUID] UUIDString];
    profile.bootSessionUUID = [[NSUUID UUID] UUIDString];

    uint64_t nowSec = (uint64_t)[[NSDate date] timeIntervalSince1970];

    // Uptime ngẫu nhiên tự nhiên theo phân bố người dùng thiết bị di động thật:
    // 20% máy mới khởi động gần đây (12h - 3 ngày)
    // 60% máy hoạt động ổn định thông thường (3 - 24 ngày)
    // 20% máy chạy dài ngày không tắt (25 - 60 ngày)
    uint32_t uptimeRoll = arc4random_uniform(100);
    uint32_t uptimeSec = 0;
    if (uptimeRoll < 20) {
        uptimeSec = 43200 + arc4random_uniform(86400 * 3); // 12h - 3 ngày
    } else if (uptimeRoll < 80) {
        uptimeSec = 86400 * (3 + arc4random_uniform(21)) + arc4random_uniform(86399); // 3 - 24 ngày
    } else {
        uptimeSec = 86400 * (25 + arc4random_uniform(36)) + arc4random_uniform(86399); // 25 - 60 ngày
    }
    profile.bootTimeSec = nowSec - uptimeSec;
    if (profile.bootTimeSec % 60 == 0) profile.bootTimeSec += (1 + arc4random_uniform(58));

    // Ngày sinh phân vùng hệ thống APFS chuẩn xác theo chu kỳ ký số Apple SHSH (APFS Sealed Snapshot Timeline)
    // Xác định thời điểm đóng cửa sổ ký số (SHSH Signing Window) của Apple
    uint64_t signingClose = 0;
    const AppleOSRelease *nextOS = NULL;
    for (size_t i = 0; i < osCount; i++) {
        if (&kAppleOSReleases[i] == chosenOS) continue;
        if (kAppleOSReleases[i].major >= spec.minIOS && kAppleOSReleases[i].major <= spec.maxIOS) {
            if (kAppleOSReleases[i].legacyOnly && !isLegacyOnlyDevice) continue;
            if (kAppleOSReleases[i].releaseTimestamp > chosenOS->releaseTimestamp) {
                if (nextOS == NULL || kAppleOSReleases[i].releaseTimestamp < nextOS->releaseTimestamp) {
                    nextOS = &kAppleOSReleases[i];
                }
            }
        }
    }

    BOOL isEOLHardware = (spec.maxIOS <= 16);
    BOOL isFinalForHardware = isEOLHardware && (nextOS == NULL);
    if (!isFinalForHardware) {
        // Active devices hoặc bản OS trung gian:
        // Cửa sổ đóng ký số của Apple diễn ra trong ngày làm việc (thứ Hai - thứ Sáu), giờ làm việc California
        uint64_t baseRelease = nextOS ? nextOS->releaseTimestamp : (chosenOS->releaseTimestamp + 86400ULL * 14ULL);
        uint32_t daysOffset = 5 + arc4random_uniform(9); // 5 - 13 ngày sau bản kế tiếp
        // Thêm giờ/phút/giây ngẫu nhiên trong khung giờ làm việc California (17:00 - 00:30 UTC), không tròn phút/giây
        uint64_t rawClose = baseRelease + 86400ULL * daysOffset + (3600ULL * arc4random_uniform(7)) + (60ULL * arc4random_uniform(59)) + (1ULL + arc4random_uniform(58));
        // Kiểm tra thứ trong tuần: epoch ngày 0 (1970-01-01) là thứ Năm (Thursday = 4)
        uint32_t dayOfWeek = (uint32_t)((rawClose / 86400ULL + 4ULL) % 7ULL);
        if (dayOfWeek == 0) { // Chủ nhật -> chuyển sang thứ Hai (+1 ngày)
            rawClose += 86400ULL + (1ULL + arc4random_uniform(3600));
        } else if (dayOfWeek == 6) { // Thứ Bảy -> chuyển sang thứ Hai (+2 ngày)
            rawClose += 86400ULL * 2ULL + (1ULL + arc4random_uniform(3600));
        }
        signingClose = rawClose;
    } else {
        // Bản cập nhật cuối cùng của dòng máy EOL được Apple duy trì ký liên tục cho phần cứng đó
        signingClose = (profile.bootTimeSec > 86400ULL * 3) ? (profile.bootTimeSec - 86400ULL * 3) : nowSec;
    }

    uint64_t osRelease = chosenOS->releaseTimestamp ?: 1648746000ULL;
    // Bắt đầu cài đặt sau khi Apple phát hành từ vài giờ đến vài ngày
    uint64_t minBirth = osRelease + 3600ULL * (4ULL + arc4random_uniform(72)); // 4h - 3 ngày sau phát hành

    // Điểm kết thúc cài đặt không được vượt quá thời điểm đóng ký số và phải trước bootTimeSec
    uint64_t maxBirth = signingClose;
    if (maxBirth > profile.bootTimeSec) {
        maxBirth = (profile.bootTimeSec > 86400ULL * 3) ? (profile.bootTimeSec - 86400ULL * 3) : profile.bootTimeSec;
    }

    if (maxBirth > minBirth) {
        uint64_t span = maxBirth - minBirth;
        profile.birthTimeSec = minBirth + arc4random_uniform((uint32_t)MIN(span, 31536000ULL));
    } else {
        profile.birthTimeSec = minBirth;
    }

    // Bảo đảm ngày cài đặt hệ thống luôn trước BootTime và không tròn phút :00
    if (profile.birthTimeSec >= profile.bootTimeSec) {
        profile.birthTimeSec = profile.bootTimeSec - (86400ULL * (3ULL + arc4random_uniform(15)) + arc4random_uniform(86399));
    }
    if (profile.birthTimeSec % 60 == 0) profile.birthTimeSec += (1 + arc4random_uniform(58));

    // Tính toán dung lượng lưu trữ thực tế theo Tuổi thọ máy (Storage Wear Model)
    uint64_t deviceAgeDays = (nowSec > profile.birthTimeSec) ? ((nowSec - profile.birthTimeSec) / 86400ULL) : 0ULL;
    double freeBlockRatio;
    if (deviceAgeDays < 7) {
        // Máy mới thiết lập/cài đặt dưới 7 ngày: Dung lượng trống rất cao (75% - 90%)
        freeBlockRatio = 0.750 + (((double)arc4random_uniform(1500)) / 10000.0);
    } else if (deviceAgeDays < 60) {
        // Máy sử dụng ngắn hạn (1 - 2 tháng): Dung lượng trống trung bình (50% - 75%)
        freeBlockRatio = 0.500 + (((double)arc4random_uniform(2500)) / 10000.0);
    } else {
        // Máy đã qua sử dụng dài hạn (> 2 tháng): Dung lượng tích lũy theo mức tiêu hao thực tế
        if (nominalDisk <= 16000000000ULL) {
            freeBlockRatio = 0.160 + (((double)arc4random_uniform(1600)) / 10000.0); // 16% - 32%
        } else if (nominalDisk <= 64000000000ULL) {
            freeBlockRatio = 0.250 + (((double)arc4random_uniform(3000)) / 10000.0); // 25% - 55%
        } else {
            freeBlockRatio = 0.350 + (((double)arc4random_uniform(3500)) / 10000.0); // 35% - 70%
        }
    }
    if (profile.diskTotalSize > 0) {
        uint64_t totalBlocks = profile.diskTotalSize / 4096ULL;
        uint64_t freeBlocks = (uint64_t)(totalBlocks * freeBlockRatio) + (uint64_t)(100 + arc4random_uniform(1024));
        if (freeBlocks >= totalBlocks) {
            freeBlocks = totalBlocks - (610351ULL + (uint64_t)arc4random_uniform(4096));
        }
        profile.diskFreeSize = freeBlocks * 4096ULL;
    } else {
        profile.diskFreeSize = 0; // Chế độ Passthrough: Trả về 0 để hệ điều hành tự động đọc dữ liệu thật từ Kernel
    }

    // Độ lệch thời gian format /var và hoàn tất thiết lập hồ sơ người dùng /var/mobile
    // Phản ánh sự biến thiên hành vi người dùng trong Setup Assistant:
    profile.deltaVarSec = 18 + arc4random_uniform(58); // 18s - 75s
    uint32_t setupRoll = arc4random_uniform(100);
    if (setupRoll < 60) {
        // 60% thiết lập nhanh: 1.5 - 4.5 phút
        profile.deltaMobileSec = profile.deltaVarSec + 90 + arc4random_uniform(180);
    } else if (setupRoll < 90) {
        // 30% thiết lập bình thường (chọn Wi-Fi, Apple ID, Face ID): 5 - 15 phút
        profile.deltaMobileSec = profile.deltaVarSec + 300 + arc4random_uniform(600);
    } else {
        // 10% thiết lập gián đoạn hoặc đồng bộ dữ liệu: 18 - 45 phút
        profile.deltaMobileSec = profile.deltaVarSec + 1100 + arc4random_uniform(1600);
    }

    // 3. Sandbox Container: Được tạo sau khi có user profile /var/mobile và trước thời điểm hiện tại
    // Kịch bản tạo container:
    // 35% Kịch bản A: Ứng dụng khôi phục cùng với hệ thống ban đầu -> Tạo container trong 1h - 48h sau setup
    // 65% Kịch bản B: Ứng dụng tải mới từ App Store trong quá trình dùng máy -> Tạo container phân bố tự nhiên
    BOOL isContainerFromBackup = (arc4random_uniform(100) < 35);
    if (isContainerFromBackup) {
        profile.deltaSandboxSec = profile.deltaMobileSec + 3600ULL + arc4random_uniform(86400 * 2);
    } else {
        uint64_t minSandbox = profile.birthTimeSec + profile.deltaMobileSec + 60ULL;
        uint64_t maxSandbox = (nowSec > minSandbox + 3600ULL) ? (nowSec - 1800ULL) : minSandbox;
        if (maxSandbox > minSandbox) {
            uint64_t sandboxSpan = maxSandbox - minSandbox;
            profile.deltaSandboxSec = profile.deltaMobileSec + 60ULL + (uint32_t)((arc4random_uniform(10000) / 10000.0) * sandboxSpan);
        } else {
            profile.deltaSandboxSec = profile.deltaMobileSec + 3600ULL + arc4random_uniform(7200);
        }
    }

    // Khử triệt để hiện tượng giây tròn :00, trùng phút/giây và tròn giờ chẵn giữa T_sandbox và T_boot
    uint64_t candSandbox = profile.birthTimeSec + profile.deltaSandboxSec;
    if (candSandbox % 60 == 0) {
        profile.deltaSandboxSec += (1 + arc4random_uniform(58));
        candSandbox = profile.birthTimeSec + profile.deltaSandboxSec;
    }
    if (candSandbox % 60 == profile.bootTimeSec % 60) {
        profile.deltaSandboxSec += (1 + arc4random_uniform(58));
        candSandbox = profile.birthTimeSec + profile.deltaSandboxSec;
    }
    uint64_t diffBoot = (candSandbox > profile.bootTimeSec) ? (candSandbox - profile.bootTimeSec) : (profile.bootTimeSec - candSandbox);
    if (diffBoot % 3600 < 60) {
        profile.deltaSandboxSec += (67 + arc4random_uniform(280));
    }

    // Bảo đảm giới hạn trên không vượt quá thời điểm hiện tại
    if (profile.birthTimeSec + profile.deltaSandboxSec >= nowSec) {
        profile.deltaSandboxSec = (uint32_t)(nowSec - profile.birthTimeSec - (1800ULL + arc4random_uniform(1800)));
    }

    // Pin ngẫu nhiên (50% - 96%) và không cắm sạc
    profile.batteryLevel = 0.50f + ((float)arc4random_uniform(46)) / 100.0f;
    profile.batteryState = 1; // UIDeviceBatteryStateUnplugged

    // Serial & MAC chuẩn Apple:
    // Từ iOS 7+, getifaddrs/sysctl luôn trả về 02:00:00:00:00:00 cho third-party apps
    // App Store apps không có quyền đọc Serial (MGCopyAnswer trả NULL)
    profile.spoofedSerial = generate_apple_serial();
    profile.spoofedWifiMAC = @"02:00:00:00:00:00";
    profile.spoofedBluetoothMAC = @"02:00:00:00:00:00";

    profile.spoofedScreenSize = [NSString stringWithFormat:@"%dx%d", (int)(spec.width * spec.scale), (int)(spec.height * spec.scale)];

    // Tự sinh mã PushKit VoIP token 32-byte độc nhất chuẩn Apple theo hồ sơ máy mới
    unsigned char voipBytes[32];
    arc4random_buf(voipBytes, sizeof(voipBytes));
    NSMutableString *vHex = [NSMutableString stringWithCapacity:64];
    for (int i = 0; i < 32; i++) {
        [vHex appendFormat:@"%02x", voipBytes[i]];
    }
    profile.spoofedVoIPToken = [vHex copy];

    return profile;
}

@end
