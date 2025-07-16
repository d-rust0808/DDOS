# Advanced Network Security Testing Tool v3.0 🚀

## Tính năng mới v3.0

### 🛡️ Anti-Detection Nâng Cao

- **User-Agent Rotation**: Tự động xoay User-Agent theo browser, mobile, crawler
- **Header Randomization**: Randomize headers để tránh fingerprinting
- **TLS Fingerprint Protection**: Chống phát hiện TLS fingerprint
- **Geographic Spoofing**: Giả mạo địa lý từ Việt Nam

### 🌐 Proxy Management Thông Minh

- **Quality Scoring**: Đánh giá chất lượng proxy theo tốc độ và success rate
- **Auto-Banning**: Tự động cấm proxy kém chất lượng
- **Round-Robin Load Balancing**: Phân tải thông minh
- **Support SOCKS5 + HTTP**: Hỗ trợ đa giao thức proxy

### ⚡ Performance Optimization

- **Adaptive Delay**: Tự động điều chỉnh delay dựa trên success rate
- **Context Timeout**: Timeout thông minh cho từng request
- **Memory Optimization**: Tối ưu memory usage
- **Concurrent Request Management**: Quản lý request đồng thời hiệu quả

### 📊 Advanced Analytics

- **Real-time Statistics**: Thống kê chi tiết theo thời gian thực
- **Success Rate Tracking**: Theo dõi tỷ lệ thành công
- **Proxy Pool Health**: Giám sát sức khỏe proxy pool
- **Performance Metrics**: Đo lường hiệu suất chi tiết

## Cách sử dụng

### 1. Cấu hình File `config.txt`

```bash
# Target
TARGET_SERVER=your-target.com
TARGET_PORT=443
PROTOCOL=https

# Performance
MAX_CONCURRENT=1000
DELAY_MS=2

# Strategy
BYPASS_MODE=balanced
DIRECT_CONN_RATIO=0.4
```

### 2. Cấu hình Proxy `proxies.txt`

```bash
# HTTP Proxy
proxy1.com:8080:user:pass

# SOCKS5 Proxy
proxy2.com:1080:user:pass:socks5

# Free Proxy (no auth)
1.2.3.4:3128
```

### 3. Chạy chương trình

```bash
go run main.go
```

## Bypass Modes

### 🔥 Aggressive Mode

- Sử dụng Crawler User-Agent
- Headers mạnh mẽ để bypass
- Retry nhiều lần
- Phù hợp: Target có bảo mật thấp

### 🥷 Stealth Mode

- Mobile User-Agent
- Headers nhẹ nhàng
- Delay cao hơn
- Phù hợp: Target có monitoring chặt

### ⚖️ Balanced Mode (Recommended)

- Mix Browser/Mobile UA
- Headers cân bằng
- Adaptive delay
- Phù hợp: Hầu hết các target

## Advanced Features

### Geographic Spoofing

- Fake IP Việt Nam trong headers
- ISP spoofing (VNPT, Viettel, FPT)
- Timezone và language headers
- Mobile carrier simulation

### Request Randomization

- Random payload generation
- Multiple content-type support
- Variable request timing
- Protocol switching (HTTP/HTTPS)

### Intelligent Retry

- Exponential backoff
- Context-aware timeout
- Error type classification
- Adaptive strategy switching

## Monitoring & Analytics

### Real-time Dashboard

```
⏱️  Thời gian: 5m30s | Tốc độ: 234.5 req/s (187.2 success/s)
📊 Tổng requests: 70,350 | Thành công: 56,280 (80.0%)
❌ Lỗi: 14,070 | Timeout: 2,840 | Blocked: 1,230
🔗 Proxy: 42,210 | Direct: 28,140
⚡ Thời gian phản hồi TB: 1.2s
🌐 Proxy Pool: 12/15 khả dụng (avg score: 0.85)
💾 Memory: 45.2 MB | Goroutines: 1,500
```

### Success Rate Optimization

- Tự động điều chỉnh strategy dựa trên success rate
- Dynamic delay adjustment
- Proxy quality management
- Error pattern analysis

## Troubleshooting

### Lỗi thường gặp

1. **All proxy failed**: Check proxy credentials và format
2. **High timeout rate**: Giảm MAX_CONCURRENT hoặc tăng DELAY_MS
3. **Blocked**: Chuyển sang STEALTH mode
4. **Memory leak**: Restart sau thời gian dài chạy

### Optimization Tips

1. **Proxy tốt**: Sử dụng residential proxy chất lượng cao
2. **Target analysis**: Phân tích response để tối ưu strategy
3. **Resource monitoring**: Theo dõi CPU/Memory usage
4. **Network bandwidth**: Đảm bảo băng thông đủ lớn

## Security Notes ⚠️

- Tool này chỉ để kiểm thử bảo mật hợp pháp
- Chỉ test trên hệ thống bạn sở hữu hoặc có permission
- Tuân thủ luật pháp địa phương
- Sử dụng có trách nhiệm

## Contributing

Để contribute:

1. Fork repository
2. Tạo feature branch
3. Commit changes
4. Submit pull request

## License

MIT License - Sử dụng tự do cho mục đích hợp pháp

---

**v3.0** - Advanced AI-Powered Network Security Testing
