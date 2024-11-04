package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"

	"golang.org/x/net/proxy"

	"github.com/lwnmengjing/sock5-relay/config"
)

type proxyHandler struct {
	transport *http.Transport
}

func (p *proxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Println("Received HTTP request:", r.Method, r.URL)

	// 从 Authorization header 提取用户名和密码
	socks5User, socks5Pass, region, index, port, err := extractUserPassAndPort(r)
	if err != nil {
		log.Printf("Authorization error: %v", err)
		respondWithError(w, http.StatusUnauthorized, "Invalid authentication", err)
		return
	}

	// 使用提取的用户名、端口和密码配置 SOCKS5 代理拨号器
	err = p.setDialer(socks5User, socks5Pass, region, index, port)
	if err != nil {
		log.Printf("Failed to configure SOCKS5 proxy for user %s on port %s: %v", socks5User, port, err)
		respondWithError(w, http.StatusServiceUnavailable, "Failed to configure SOCKS5 proxy", err)
		return
	}

	// 根据请求方法处理请求
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
	} else {
		p.handleHTTP(w, r)
	}
}

func (p *proxyHandler) setDialer(socks5User, socks5Pass, region string, index, port int) error {
	ip := config.Cfg.GetIP(region, index)
	if ip == "" {
		return fmt.Errorf("failed to get IP for region: %s and index: %d", region, index)
	}
	// 拼接 SOCKS5 地址
	socks5FullAddr := fmt.Sprintf("%s:%d", ip, port)
	log.Printf("Setting SOCKS5 dialer with address %s, username: %s", socks5FullAddr, socks5User)

	// 创建带认证信息的 SOCKS5 代理拨号器
	auth := proxy.Auth{User: socks5User, Password: socks5Pass}
	dialer, err := proxy.SOCKS5("tcp", socks5FullAddr, &auth, proxy.Direct)
	if err != nil {
		return fmt.Errorf("failed to create SOCKS5 dialer: %v", err)
	}

	// 更新 transport 的 Dial
	p.transport.Dial = dialer.Dial
	log.Println("SOCKS5 dialer set successfully")
	return nil
}

func (p *proxyHandler) handleHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("Handling HTTP request to %s", r.URL)
	resp, err := p.transport.RoundTrip(r)
	if err != nil {
		log.Printf("HTTP request failed for %s: %v", r.URL, err)
		respondWithError(w, http.StatusServiceUnavailable, "Failed to reach destination", err)
		return
	}
	defer resp.Body.Close()

	log.Printf("Received response with status %d from %s", resp.StatusCode, r.URL)
	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func (p *proxyHandler) handleConnect(w http.ResponseWriter, r *http.Request) {
	log.Printf("Received CONNECT request for: %s", r.Host)

	// 提取用户名和端口（示例逻辑，根据你的需求修改）
	socks5User, socks5Pass, region, index, port, err := extractUserPassAndPort(r)
	if err != nil {
		log.Printf("Authorization error: %v", err)
		respondWithError(w, http.StatusUnauthorized, "Invalid authentication", err)
		return
	}
	log.Printf("Authenticating user: %s with port: %s", socks5User, port)

	// SOCKS5 代理创建
	auth := proxy.Auth{User: socks5User, Password: socks5Pass}
	ip := config.Cfg.GetIP(region, index)
	if ip == "" {
		log.Printf("Failed to get IP for region: %s and index: %d", region, index)
		respondWithError(w, http.StatusServiceUnavailable, "Failed to get IP", nil)
		return
	}
	dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("%s:%d", ip, port), &auth, proxy.Direct) // 替换为你的 SOCKS5 地址
	if err != nil {
		log.Printf("Failed to create SOCKS5 dialer: %v", err)
		respondWithError(w, http.StatusServiceUnavailable, "Failed to create SOCKS5 dialer", err)
		return
	}

	// 建立到目标主机的连接
	destConn, err := dialer.Dial("tcp", r.Host)
	if err != nil {
		log.Printf("Failed to connect to destination: %v", err)
		respondWithError(w, http.StatusServiceUnavailable, "Failed to connect to destination", err)
		return
	}
	defer destConn.Close()

	// 响应 200 状态，表明连接成功
	w.WriteHeader(http.StatusOK)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		log.Printf("Hijacking not supported")
		respondWithError(w, http.StatusInternalServerError, "Hijacking not supported", nil)
		return
	}

	// Hijack the connection
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		log.Printf("Failed to hijack connection: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Failed to hijack connection", err)
		return
	}
	defer clientConn.Close()

	// 转发数据
	go io.Copy(destConn, clientConn)
	io.Copy(clientConn, destConn)
	log.Printf("Successfully established a tunnel to %s", r.Host)
}

// extractUserPassAndPort 从 Authorization 提取 SOCKS5 的用户名、端口、sessionID和密码
func extractUserPassAndPort(r *http.Request) (username, password, region string, index, port int, err error) {
	auth := r.Header.Get("Proxy-Authorization") // 确保获取的是 Proxy-Authorization
	if auth == "" || !strings.HasPrefix(auth, "Basic ") {
		err = errors.New("missing or invalid authorization header")
		return
	}

	payload, err := base64.StdEncoding.DecodeString(auth[6:])
	if err != nil {
		err = errors.New("failed to decode authorization header")
		return
	}
	credentials := strings.SplitN(string(payload), ":", 2)
	if len(credentials) != 2 {
		err = errors.New("invalid authorization format")
		return
	}

	parts := strings.Split(credentials[0], "-")
	if len(parts) < 3 {
		err = errors.New("username must be in format {socks5username}-{port}-{region}-{index} or {socks5username}-{port}-{region}")
		return
	}
	port, err = strconv.Atoi(parts[1])
	if err != nil {
		return
	}
	if len(parts) == 4 {
		index, err = strconv.Atoi(parts[3])
		if err != nil {
			return
		}
	}
	username = parts[0]
	region = parts[2]
	password = credentials[1]

	return
}

func respondWithError(w http.ResponseWriter, code int, message string, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	response := map[string]string{"error": message}
	if err != nil {
		response["details"] = err.Error()
		log.Printf("Error: %s - %v", message, err)
	}
	_ = json.NewEncoder(w).Encode(response)
}

func startHTTPProxy() error {
	handler := &proxyHandler{
		transport: &http.Transport{},
	}
	proxyServer := &http.Server{
		Addr:    ":9000",
		Handler: handler,
	}

	go func() {
		log.Printf("Starting HTTP proxy on port 9000")
		if err := proxyServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("HTTP proxy error on port 9000: %v", err)
		}
	}()

	return nil
}

func main() {
	config.Cfg.Init()
	if err := startHTTPProxy(); err != nil {
		log.Fatalf("Failed to start HTTP proxy: %v", err)
	}
	select {} // 保持主线程运行
}
