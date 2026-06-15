# QuickAuth (TerAlone's Auth) ✨

Một công cụ xác thực hai yếu tố (2FA) đơn giản, mạnh mẽ, chạy trực tiếp trên terminal với giao diện TUI và Command Mode. Được viết hoàn toàn bằng Python mà không sử dụng thư viện bên ngoài (Zero Dependencies).

## ✨ Tính năng nổi bật

- **Hai chế độ hoạt động:**
  - **Command Mode:** Sử dụng dòng lệnh để thực hiện nhanh các tác vụ, hỗ trợ gợi ý lệnh thông minh (IntelliSense-like).
  - **TUI Mode:** Giao diện trực quan với menu, hỗ trợ phím mũi tên, multi-select và chuột.
- **Đồng bộ mã (Sync):** Tính năng đồng bộ mã TOTP qua máy chủ trung gian bảo mật (Access/Refresh/Session Token).
- **Bảo mật tối đa:**
  - Tự triển khai thuật toán TOTP (RFC 6238).
  - Mật khẩu máy chủ được hash bằng PBKDF2-HMAC-SHA256 (100k vòng).
  - Giới hạn IP và Token ràng buộc IP để ngăn chặn đánh cắp phiên.
  - Phân quyền file lưu trữ nội bộ (0600) ngăn người dùng khác truy cập.
- **Đa nền tảng:** Hỗ trợ tốt Linux, macOS, Android (Termux) và Windows (đã sửa lỗi màu sắc).
- **Độc lập:** Không phụ thuộc vào bất kỳ thư viện bên thứ ba nào.

## 🚀 Cách sử dụng

### Chạy từ mã nguồn (Python)
Yêu cầu Python 3.8 trở lên.

```bash
python3 teralone_auth.py
```

### Chạy Sync Server (Dành cho đồng bộ)
Nếu bạn muốn tự chạy máy chủ đồng bộ riêng:
```bash
python3 teralone_auth-server.py
```
*Lưu ý: Server không cho phép chạy dưới dạng file compile sẵn để đảm bảo tính minh bạch.*

### Phiên bản Compile sẵn (Nuitka)
Nếu bạn tải về phiên bản đã được compile (trong phần [Release](https://github.com/TerAlone6300/QuickAuth/releases/)):

- **Linux/macOS/Android (Termux):**
  ```bash
  chmod +x teralone_auth
  ./teralone_auth
  ```
- **Windows:**
  Chạy file `teralone_auth.exe`.

## 🛠 Các lệnh trong Command Mode

- `imp`: Thêm một mã bí mật mới.
- `imp --once`: Lấy mã OTP nhanh mà không lưu lại.
- `key all`: Hiển thị tất cả mã OTP hiện có.
- `key all --loop`: Cập nhật mã OTP liên tục theo thời gian thực (nhấn phím bất kỳ để dừng).
- `resync`: Buộc đồng bộ lại dữ liệu với server.
- `mchange`: Chuyển sang giao diện TUI.
- `help`: Xem hướng dẫn chi tiết.
- `exit`: Thoát chương trình.

## 📦 Build từ mã nguồn
Nếu bạn muốn tự compile bằng [Nuitka](https://nuitka.net/):

```bash
# Cài đặt Nuitka
pip install nuitka

# Compile (Ví dụ trên Linux/Termux)
python3 -m nuitka --onefile --standalone teralone_auth.py
```

## 📝 Giấy phép
Dự án này được phát hành dưới bản quyền [MIT License](LICENSE).

---
Phát triển bởi **TerAlone**.
