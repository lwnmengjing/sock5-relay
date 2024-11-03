package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/net/proxy"
)

type ProxyInfo struct {
	Port int
}

var (
	portCounter = 9000
	portMutex   sync.Mutex
	proxyMap    = make(map[string]*ProxyInfo)
	mapMutex    sync.RWMutex
)

type proxyHandler struct {
	transport *http.Transport
	dialer    proxy.Dialer
}

func (p *proxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
	} else {
		p.handleHTTP(w, r)
	}
}

func (p *proxyHandler) handleHTTP(w http.ResponseWriter, r *http.Request) {
	resp, err := p.transport.RoundTrip(r)
	if err != nil {
		respondWithError(w, http.StatusServiceUnavailable, "Failed to reach destination", err)
		return
	}
	defer resp.Body.Close()
	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func (p *proxyHandler) handleConnect(w http.ResponseWriter, r *http.Request) {
	destConn, err := p.dialer.Dial("tcp", r.Host)
	if err != nil {
		respondWithError(w, http.StatusServiceUnavailable, "Failed to connect to destination", err)
		return
	}
	defer destConn.Close()
	w.WriteHeader(http.StatusOK)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		respondWithError(w, http.StatusInternalServerError, "Hijacking not supported", nil)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to hijack connection", err)
		return
	}
	defer clientConn.Close()
	go io.Copy(destConn, clientConn)
	io.Copy(clientConn, destConn)
}

func startHTTPProxy(socks5Addr, socks5User, socks5Pass string) (int, error) {
	auth := proxy.Auth{User: socks5User, Password: socks5Pass}
	dialer, err := proxy.SOCKS5("tcp", socks5Addr, &auth, proxy.Direct)
	if err != nil {
		return 0, fmt.Errorf("failed to create SOCKS5 dialer: %v", err)
	}

	portMutex.Lock()
	port := portCounter
	portCounter++
	portMutex.Unlock()

	proxyServer := &http.Server{
		Addr:    ":" + strconv.Itoa(port),
		Handler: &proxyHandler{transport: &http.Transport{Dial: dialer.Dial}, dialer: dialer},
	}

	go func() {
		log.Printf("Starting HTTP proxy on port %d", port)
		if err = proxyServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("HTTP proxy error on port %d: %v", port, err)
		}
	}()

	return port, nil
}

func requestHandler(w http.ResponseWriter, r *http.Request) {
	socks5Addr := r.URL.Query().Get("socks5_address")
	socks5User := r.URL.Query().Get("socks5_username")
	socks5Pass := r.URL.Query().Get("socks5_password")

	if socks5Addr == "" || socks5User == "" || socks5Pass == "" {
		respondWithError(w, http.StatusBadRequest, "Missing SOCKS5 proxy information", nil)
		return
	}

	proxyKey := fmt.Sprintf("%s|%s|%s", socks5Addr, socks5User, socks5Pass)

	mapMutex.RLock()
	proxyInfo, exists := proxyMap[proxyKey]
	mapMutex.RUnlock()

	if exists {
		host := getHostFromRequest(r)
		proxyURL := fmt.Sprintf("http://%s:%d", host, proxyInfo.Port)
		respondWithJSON(w, map[string]string{"proxy_url": proxyURL, "status": "existing"})
		return
	}

	port, err := startHTTPProxy(socks5Addr, socks5User, socks5Pass)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to start HTTP proxy", err)
		return
	}

	mapMutex.Lock()
	proxyMap[proxyKey] = &ProxyInfo{Port: port}
	mapMutex.Unlock()

	host := getHostFromRequest(r)
	proxyURL := fmt.Sprintf("http://%s:%d", host, port)
	respondWithJSON(w, map[string]string{"proxy_url": proxyURL, "status": "created"})
}

func getHostFromRequest(r *http.Request) string {
	host := r.Host
	if strings.Contains(host, ":") {
		host = strings.Split(host, ":")[0]
	}
	return host
}

func respondWithJSON(w http.ResponseWriter, data map[string]string) {
	w.Header().Set("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(data)
	if err != nil {
		log.Printf("Failed to write response: %v", err)
		return
	}
}

func respondWithError(w http.ResponseWriter, code int, message string, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	response := map[string]string{"error": message}
	if err != nil {
		response["details"] = err.Error()
	}
	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		log.Printf("Failed to write response: %v", err)
		return
	}
}

func main() {
	http.HandleFunc("/create_http_proxy", requestHandler)
	log.Printf("Server listening on :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
