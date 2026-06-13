# QuickAuth (TerAlone's Auth) ✨

Một công cụ xác thực hai yếu tố (2FA) đơn giản, mạnh mẽ, chạy trực tiếp trên terminal với giao diện TUI và Command Mode. Được viết hoàn toàn bằng Python mà không sử dụng thư viện bên ngoài (ngoại trừ các module có sẵn).

## ✨ Tính năng

- **Hai chế độ hoạt động:**
  - **Command Mode:** Sử dụng dòng lệnh để thực hiện nhanh các tác vụ.
  - **TUI Mode:** Giao diện trực quan với menu, hỗ trợ phím mũi tên và chuột.
- **Bảo mật:** Tự triển khai thuật toán TOTP (RFC 6238).
- **Lưu trữ:** Tự động lưu trữ bí mật vào thư mục người dùng (`~/.teralone_auth/`).
- **Giao diện:** Hỗ trợ màu sắc, gợi ý lệnh thông minh và cập nhật mã OTP theo thời gian thực.
- **Độc lập:** Không phụ thuộc vào thư viện bên thứ ba.

## 🚀 Cách sử dụng

### Phiên bản Compile sẵn (Nuitka)
Nếu bạn tải về phiên bản đã được compile (trong phần [Release](https://github.com/TerAlone6300/QuickAuth/releases/)), bạn chỉ cần chạy trực tiếp file thực thi:

- **Linux/macOS/Android (Termux):**
  ```bash
  chmod +x teralone_auth
  ./teralone_auth
  ```
- **Windows:**
  Chạy file `teralone_auth.exe`.

### Chạy từ mã nguồn (Python)
Yêu cầu Python 3.8 trở lên.

```bash
python3 teralone_auth.py
```

## 🛠 Các lệnh trong Command Mode

- `imp`: Thêm một mã bí mật mới.
- `imp --once`: Lấy mã OTP nhanh mà không lưu lại.
- `key all`: Hiển thị tất cả mã OTP hiện có.
- `key all --loop`: Cập nhật mã OTP liên tục theo thời gian thực.
- `mchange`: Chuyển sang giao diện TUI.
- `exit`: Thoát chương trình.

## 📦 Build từ mã nguồn
Nếu bạn muốn tự compile bằng [Nuitka](https://nuitka.net/):

```bash
pip install nuitka
python3 -m nuitka --onefile --standalone teralone_auth.py
```

## 📝 Giấy phép
Dự án này được phát hành dưới bản quyền [MIT License](LICENSE).

---
Phát triển bởi **TerAlone**.
