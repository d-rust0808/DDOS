# HƯỚNG DẪN THAY ĐỔI TARGET VÀ CẤU HÌNH

## 🎯 Cách thay đổi target server:

### 1. Sử dụng Domain:

```
TARGET_SERVER=example.com
TARGET_PORT=443
PROTOCOL=https
```

### 2. Sử dụng IP trực tiếp:

```
TARGET_SERVER=192.168.1.100
TARGET_PORT=80
PROTOCOL=http
```

### 3. Port tùy chỉnh:

```
TARGET_SERVER=target.com
TARGET_PORT=8080
PROTOCOL=http
```

## 📍 Cách thêm/thay đổi endpoints:

Trong file `config.txt`, thêm các dòng:

```
ENDPOINTS=/
ENDPOINTS=/api/login
ENDPOINTS=/admin/dashboard
ENDPOINTS=/api/v1/users
ENDPOINTS=/search
```

## ⚙️ Cách thay đổi hiệu suất:

```
MAX_CONCURRENT=500     # Số goroutines đồng thời (càng cao càng mạnh)
DELAY_MS=50           # Độ trễ giữa requests (ms)
```

## 🔄 Ví dụ cấu hình hoàn chỉnh:

### Target 1: Website WordPress

```
TARGET_SERVER=example.com
TARGET_PORT=443
PROTOCOL=https
ENDPOINTS=/
ENDPOINTS=/wp-admin/
ENDPOINTS=/wp-login.php
ENDPOINTS=/xmlrpc.php
MAX_CONCURRENT=800
```

### Target 2: API Server

```
TARGET_SERVER=api.example.com
TARGET_PORT=80
PROTOCOL=http
ENDPOINTS=/api/v1/auth
ENDPOINTS=/api/v1/data
ENDPOINTS=/health
MAX_CONCURRENT=1000
```

### Target 3: Server nội bộ

```
TARGET_SERVER=192.168.1.50
TARGET_PORT=8080
PROTOCOL=http
ENDPOINTS=/admin
ENDPOINTS=/login
ENDPOINTS=/dashboard
MAX_CONCURRENT=500
```

## 🚀 Cách sử dụng:

1. **Chỉnh sửa file `config.txt`** với target và endpoints mong muốn
2. **Chạy chương trình**: `go run main.go`
3. **Dừng chương trình**: Nhấn `Ctrl+C`

## ⚠️ Lưu ý quan trọng:

- **100% sử dụng proxy** - không bao giờ lộ IP thật
- **Chỉ test trên server của bạn** - không tấn công server người khác
- **Backup cấu hình** trước khi thay đổi
- **Monitor tài nguyên** để tránh quá tải hệ thống
