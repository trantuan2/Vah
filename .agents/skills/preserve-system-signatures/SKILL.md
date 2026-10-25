---
name: preserve-system-signatures
description: >-
  Nguyên tắc kiến trúc can thiệp tầng hệ thống (System-Level Execution): Mọi can thiệp,
  fake và bypass cho Zalo phải được thực hiện ở tầng OS/daemon/kernel để Zalo tự xử lý
  và tự lấy dữ liệu, bảo toàn 100% tính toàn vẹn của chữ ký số (Apple Gateway, APNs,
  Secure Enclave, App Store Receipt, TLS).
---

# Nguyên Tắc Thiết Kế: Can Thiệp Tầng Hệ Thống & Bảo Toàn Chữ Ký (System-Level Signature Preservation)

## 1. Triết Lý Cốt Lõi
Tuyệt đối **KHÔNG** can thiệp chắp vá bằng cách mock, hardcode hoặc trả về chuỗi giả tùy tiện ở tầng Application nếu điều đó làm gãy hoặc mất chữ ký số của Apple / máy chủ.

Mọi giải pháp phải được thực thi ở **TẦNG HỆ THỐNG (OS / Daemon / POSIX / Kernel)** để:
1. Đảm bảo luồng thực thi là luồng chuẩn của hệ điều hành iOS.
2. Ứng dụng Zalo tự gọi API, tự nhận dữ liệu từ các Daemon hệ thống (`apsd`, `securityd`, `tccd`, `mobile_installation`).
3. Dữ liệu mang đầy đủ chữ ký số hợp lệ (Valid Cryptographic Signature), vượt qua mọi cơ chế kiểm tra tính toàn vẹn (Integrity Check / Anti-Tamper).

---

## 2. Các Quy Chuẩn Thực Thi Cụ Thể

### A. Token Thông Báo Đẩy (APNs & VoIP Push Token)
* **KHÔNG ĐƯỢC**: Trả về chuỗi hex ngẫu nhiên trong code Objective-C/Swift vì Zalo sẽ gửi token này lên máy chủ Zalo, và khi máy chủ Zalo gửi push sang Apple Gateway sẽ bị Apple phản hồi `BadDeviceToken` $\rightarrow$ Server Zalo phát hiện gian lận và khóa tài khoản.
* **PHẢI LÀM**: Can thiệp ở tầng daemon `apsd`:
  - Reset trạng thái push cấp hệ thống (`unregisterForRemoteNotifications`).
  - Dọn dẹp cache push identity của bundle Zalo trong `/var/mobile/Library/ApplePushService/`.
  - Khởi động lại `apsd` và luân chuyển kết nối mạng (IP mới) để `apsd` tự kết nối tới Apple Gateway và lấy về một APNs Token mới thật 100% có chữ ký của Apple.

### B. Ảo Hóa Container Sandbox (Path Virtualization)
* **KHÔNG ĐƯỢC**: Can thiệp đổi tên bundle ID hoặc chỉnh sửa cấu trúc thư mục làm mất tính hợp lệ của sandbox.
* **PHẢI LÀM**: Can thiệp ở tầng POSIX (`open`, `stat`, `access`, `getenv`):
  - Ánh xạ ảo hóa 2 chiều: Zalo đọc đường dẫn thì thấy UUID container mới tinh, nhưng khi đọc/ghi file thì tầng dưới tự chuyển hướng về thư mục vật lý thật.
  - Zalo tự xử lý I/O thông qua các API chuẩn của Cocoa/Foundation mà không nhận biết được sự can thiệp.

### C. Quyền Riêng Tư & TCC (Contacts, ATT, Camera, Mic)
* **KHÔNG ĐƯỢC**: Ép cứng trạng thái `Denied` (2) từ lúc vừa nạp tweak.
* **PHẢI LÀM**: Xử lý state machine mô phỏng đúng vòng đời cài mới:
  - Khởi đầu với `NotDetermined` (0).
  - Để Zalo tự phát động lệnh xin quyền lên hệ thống và hệ thống tự phản hồi sau một độ trễ tự nhiên (human delay).

### D. Định Danh Keychain & Mã Hóa
* **KHÔNG ĐƯỢC**: Can thiệp thô bạo vào các hàm `SecKeyGeneratePair` hoặc các chứng chỉ TLS/SSL nội bộ của Apple.
* **PHẢI LÀM**: Chỉ dọn sạch các Generic Password chứa ID của Zalo trước khi chạy; để Zalo tự giao tiếp với `securityd` và Secure Enclave tạo ra các bộ khóa định danh mới có chữ ký phần cứng hợp lệ.

---

## 3. Tiêu Chuẩn Đọc Log & Quy Tắc Nhận Diện Nghiêm Ngặt

### A. Đọc Log Sâu Sắc, Đối Chiếu Chéo Từng Dòng (Không Làm Qua Loa)
* **BẮT BUỘC CÓ BẰNG CHỨNG XÁC THỰC**: Khi phân tích nguyên nhân lỗi, phải chỉ ra bằng chứng cụ thể bằng cách trích dẫn chính xác: **số dòng, timestamp, tên hàm hệ thống, URL request, tham số payload và giá trị đối chiếu**.
* **ĐỐI CHIẾU CHÉO 2 CHIỀU**: Lần theo từng luồng logic giữa 2 tầng:
  1. **Tầng Hệ Thống (Audit Log)**: Zalo đã gọi hàm hệ thống nào (POSIX `stat`, `getattrlist`, `sysctl`, `Keychain`, `canOpenURL`...), hệ thống trả về giá trị gì.
  2. **Tầng Mạng/Máy Chủ (Traffic HAR)**: Zalo đã tự lấy dữ liệu đó để đóng gói, mã hóa và ký số (`sig`) gửi lên endpoint nào của máy chủ.
* **KHÔNG ĐƯỢC**: Phỏng đoán mơ hồ, suy diễn chung chung hoặc kết luận qua loa khi chưa lần ra nguồn gốc dữ liệu từ từng dòng log.

### B. Quy Tắc Nhận Diện Về Mã Lỗi 2012 & Token VoIP
* **Mã lỗi 2012 là mặc định của Zalo**: `{"error_code": 2012, "error_message": "Exceeded 3 sms per day"}` là cơ chế bắt buộc hiện nay của Zalo (chuyển sang MO-SMS gửi `8500`). Tuyệt đối không đem mã lỗi 2012 ra làm lý do nghi vấn, điểm rủi ro hay nguyên nhân khiến tài khoản bị khóa.
* **Bảo toàn Token VoIP gốc**: Zalo sẽ ping Token VoIP lên máy chủ Apple APNs để xác thực. Tuyệt đối không fake token ngẫu nhiên gây lỗi `BadDeviceToken` (410), phải giữ nguyên Token VoIP gốc do Apple Gateway cấp.

