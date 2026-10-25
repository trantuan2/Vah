# Quy Tắc Bất Biến & Kiến Trúc Dự Án ZaloTweak

## 1. Explain Before Code (Bắt Buộc)
Khi gặp lỗi (bug) hoặc yêu cầu sửa/thêm tính năng, PHẢI theo đúng trình tự:
1. **Phân tích trước**: Nêu rõ nguyên nhân gốc rễ (root cause) của lỗi, đối chiếu chéo log. Không được viết code khi chưa xác định nguyên nhân.
2. **Đề xuất hướng fix**: Trình bày giải pháp, liệt kê file bị ảnh hưởng, có thể minh họa pseudocode nhưng KHÔNG viết code thật.
3. **Chờ xác nhận**: Dừng lại và hỏi người dùng có đồng ý không. Chỉ viết code khi người dùng xác nhận rõ ràng ("ok", "làm đi"...).

## 2. Tiêu Chuẩn Đọc Log & Phân Tích Lỗi (Đối Chiếu Chéo Từng Dòng, Có Bằng Chứng Xác Thực)
- Khi đọc log phân tích lỗi, **BẮT BUỘC phải chỉ ra bằng chứng cụ thể** (trích dẫn chính xác số dòng, timestamp, tên hàm hệ thống, URL request, JSON body và giá trị đối chiếu).
- **Đối chiếu chéo 2 chiều**:
  1. *Tầng Hệ Thống (Audit Log)*: Zalo đã gọi hàm hệ thống nào (POSIX `stat`, `getattrlist`, `sysctl`, Keychain, `canOpenURL`...), hệ thống trả về giá trị gì.
  2. *Tầng Mạng (Traffic HAR)*: Zalo đã tự lấy dữ liệu đó để đóng gói, mã hóa và ký số (`sig`) gửi lên endpoint nào của máy chủ.
- **Tuyệt đối KHÔNG làm qua loa**, không phỏng đoán mơ hồ hay đưa ra kết luận thiếu căn cứ khi chưa tìm ra dòng log cụ thể làm bằng chứng.

## 3. Can Thiệp Tầng Hệ Thống & Bảo Toàn Chữ Ký Số (`sig`)
- Mọi cơ chế can thiệp, ngụy trang (Hardware, device IDs, st_birthtime, sysctl, uname, canOpenURL, carrier, timezone, UIDevice...) **BẮT BUỘC phải can thiệp ở TẦNG HỆ THỐNG** (POSIX syscalls: `stat`, `getattrlist`, `sysctl`, `sysctlbyname`; và các System Frameworks: UIKit, CoreTelephony, CoreFoundation, MobileGestalt).
- **TUYỆT ĐỐI KHÔNG** can thiệp hay sửa đè trực tiếp tham số gói tin HTTP / Payload / Query URL trên tầng Network.
- **Mục đích**: Để chính Zalo tự gọi hàm hệ thống, tự nhận dữ liệu đã được ngụy trang tự nhiên, và **Zalo tự tính toán ký chữ ký số (`sig`, HMAC, token) bằng private key nội bộ**. Khi đó chữ ký số gửi lên server luôn bảo toàn tính toàn vẹn 100%, không bao giờ bị phát hiện giả mạo hay sai chữ ký.

## 4. Quy Chuẩn Về Nhận Diện Zalo & Token VoIP
- **Mã lỗi 2012 là mặc định của Zalo**: `{"error_code": 2012, "error_message": "Exceeded 3 sms per day"}` là cơ chế bắt buộc hiện nay của Zalo (chuyển luồng sang gửi tin nhắn MO-SMS cú pháp `ZALO` gửi `8500`). Tuyệt đối không đem mã lỗi 2012 ra làm lý do nghi vấn, risk score hay nguyên nhân khiến tài khoản bị khóa.
- **Bảo toàn Token VoIP gốc (Không được fake VoIP Token)**: Zalo ping Token VoIP lên máy chủ Apple APNs để xác thực tính hợp lệ của thiết bị. Nếu fake token ngẫu nhiên, Apple APNs sẽ báo `BadDeviceToken` (410) và bị Zalo phát hiện gian lận ngay. Do đó phải giữ nguyên Token VoIP gốc do Apple Gateway cấp (Passthrough).
