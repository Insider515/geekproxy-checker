package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shadowsocks/go-shadowsocks2/core"
	"golang.org/x/net/proxy"
)

type SingleRequest struct {
	ProxyStr string `json:"proxy"`
}

type BulkRequest struct {
	Proxies []string `json:"proxies"`
}

type BulkResult struct {
	Original string `json:"original"`
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Country  string `json:"country"`
	Type     string `json:"type"`
	Status   bool   `json:"status"`
	Error    string `json:"error,omitempty"`
}

type CheckResult struct {
	UDP    UDPResult    `json:"udp"`
	UDPGoogle UDPResult `json:"udp_google"` // Добавлено для проверки UDP на Google
	IPInfo IPInfoResult `json:"ip_info"`
	Error  string       `json:"error,omitempty"`
}
type UDPResult struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}
type IPInfoResult struct {
	IP       string `json:"ip"`
	City     string `json:"city"`
	Country  string `json:"country"`
	Org      string `json:"org"`
	Type     string `json:"type"`
	Hostname string `json:"hostname"`
	Error    string `json:"error,omitempty"`
}
type IpInfoRaw struct {
	IP       string `json:"ip"`
	City     string `json:"city"`
	Country  string `json:"country"`
	Org      string `json:"org"`
	Hostname string `json:"hostname"`
}

func main() {
	fs := http.FileServer(http.Dir("./"))
	http.Handle("/", fs)
	http.HandleFunc("/check-proxy", handleSingleCheck)
	http.HandleFunc("/check-bulk", handleBulkCheck)
	fmt.Println("🚀 Server running on http://127.0.0.1:8081")
	if err := http.ListenAndServe("127.0.0.1:8081", nil); err != nil {
		panic(err)
	}
}

func handleSingleCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req SingleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ip, port, user, pass, err := parseProxy(req.ProxyStr)
	if err != nil {
		json.NewEncoder(w).Encode(CheckResult{Error: "Invalid format"})
		return
	}
	udpSuccess, udpMsg := checkSocks5UDP(ip, port, user, pass)
	udpGoogleSuccess, udpGoogleMsg := checkSocks5UDPToRemote(ip, port, user, pass, "8.8.8.8:53")
	
	ipResult := checkIPInfoFull(ip, port, user, pass)

	resp := CheckResult{
		UDP:       UDPResult{Success: udpSuccess, Message: udpMsg},
		UDPGoogle: UDPResult{Success: udpGoogleSuccess, Message: udpGoogleMsg},
		IPInfo:    ipResult,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func handleBulkCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req BulkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	results := make([]BulkResult, len(req.Proxies))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 50)

	for i, pStr := range req.Proxies {
		wg.Add(1)
		go func(idx int, p string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[idx] = checkOneBulk(p)
		}(i, pStr)
	}
	wg.Wait()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

func checkOneBulk(rawProxy string) BulkResult {
	res := BulkResult{Original: rawProxy, Status: false, Type: "Dead"}
	rawProxy = strings.TrimSpace(rawProxy)
	if rawProxy == "" {
		res.Error = "Empty"
		return res
	}
	//SHADOWSOCKS (ss://)
	if strings.HasPrefix(rawProxy, "ss://") {
		host, port, method, password, err := parseShadowsocks(rawProxy)
		if err != nil {
			res.Error = "Invalid SS Link"
			return res
		}
		res.IP = host
		res.Port = port

		geo, err := getGeoViaShadowsocks(host, port, method, password)
		if err == nil {
			res.Status = true
			res.Type = "Shadowsocks"
			res.Country = geo.Country
			return res
		}
		res.Error = fmt.Sprintf("Fail: %v", err)
		return res
	}
	//(IP:PORT:USER:PASS)
	ip, port, user, pass, err := parseProxy(rawProxy)
	if err != nil {
		res.Error = "Format Error"
		return res
	}
	res.IP = ip
	res.Port = port
	geo, errSocks := getGeoViaSocks5(ip, port, user, pass)
	if errSocks == nil {
		res.Status = true
		res.Type = "SOCKS5"
		res.Country = geo.Country
		return res
	}
	geoHttp, errHttp := getGeoViaHTTP(ip, port, user, pass)
	if errHttp == nil {
		res.Status = true
		res.Type = "HTTP"
		res.Country = geoHttp.Country
		return res
	}

	res.Error = "Connection Failed"
	return res
}

// --- SHADOWSOCKS IMPLEMENTATION ---
func serializeTargetAddr(targetAddr string) []byte {
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		host = targetAddr
		portStr = "80"
	}
	port, _ := strconv.Atoi(portStr)
	var buf []byte
	ip := net.ParseIP(host)
	if ip4 := ip.To4(); ip4 != nil {
		buf = append(buf, 1) // Type IPv4
		buf = append(buf, ip4...)
	} else if ip6 := ip.To16(); ip6 != nil {
		buf = append(buf, 4) // Type IPv6
		buf = append(buf, ip6...)
	} else {
		buf = append(buf, 3) // Type Domain
		buf = append(buf, byte(len(host)))
		buf = append(buf, host...)
	}
	// Port Big Endian
	buf = append(buf, byte(port>>8), byte(port))
	return buf
}

func parseShadowsocks(raw string) (host string, port int, method string, password string, err error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", 0, "", "", err
	}
	if u.User != nil {
		method = u.User.Username()
		password, _ = u.User.Password()
		host = u.Hostname()
		port, _ = strconv.Atoi(u.Port())
		return
	}
	decodedBytes, err := base64.RawURLEncoding.DecodeString(u.Host)
	if err != nil {
		decodedBytes, err = base64.StdEncoding.DecodeString(u.Host)
	}
	if err == nil {
		parts := strings.Split(string(decodedBytes), "@")
		if len(parts) == 2 {
			creds := strings.Split(parts[0], ":")
			if len(creds) >= 2 {
				method = creds[0]
				password = strings.Join(creds[1:], ":")
			}
			addrParts := strings.Split(parts[1], ":")
			if len(addrParts) == 2 {
				host = addrParts[0]
				port, _ = strconv.Atoi(addrParts[1])
				return host, port, method, password, nil
			}
		}
	}
	return "", 0, "", "", fmt.Errorf("unknown ss format")
}

func getGeoViaShadowsocks(host string, port int, method, password string) (IpInfoRaw, error) {
	cipher, err := core.PickCipher(method, []byte{}, password)
	if err != nil {
		return IpInfoRaw{}, fmt.Errorf("bad cipher: %v", err)
	}
	proxyAddr := fmt.Sprintf("%s:%d", host, port)
	transport := &http.Transport{
		Dial: func(network, targetAddr string) (net.Conn, error) {
			c, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
			if err != nil {
				return nil, err
			}
			c = cipher.StreamConn(c)
			tgt := serializeTargetAddr(targetAddr)
			if _, err := c.Write(tgt); err != nil {
				c.Close()
				return nil, err
			}
			return c, nil
		},
		DisableKeepAlives: true,
	}
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	return fetchGeo(client)
}

// --- PROXY UTILS ---
func getGeoViaSocks5(host string, port int, user, password string) (IpInfoRaw, error) {
	auth := proxy.Auth{User: user, Password: password}
	addr := fmt.Sprintf("%s:%d", host, port)
	dialer, err := proxy.SOCKS5("tcp", addr, &auth, proxy.Direct)
	if err != nil {
		return IpInfoRaw{}, err
	}
	client := &http.Client{Transport: &http.Transport{Dial: dialer.Dial}, Timeout: 5 * time.Second}
	return fetchGeo(client)
}

func getGeoViaHTTP(host string, port int, user, password string) (IpInfoRaw, error) {
	proxyUrl := &url.URL{Scheme: "http", User: url.UserPassword(user, password), Host: fmt.Sprintf("%s:%d", host, port)}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyUrl)}, Timeout: 5 * time.Second}
	return fetchGeo(client)
}

func fetchGeo(client *http.Client) (IpInfoRaw, error) {
	resp, err := client.Get("https://ipinfo.io/json")
	if err != nil {
		return IpInfoRaw{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return IpInfoRaw{}, fmt.Errorf("bad status")
	}
	var raw IpInfoRaw
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return IpInfoRaw{}, err
	}
	return raw, nil
}

func parseProxy(s string) (string, int, string, string, error) {
	parts := strings.Split(strings.TrimSpace(s), ":")
	if len(parts) != 4 {
		return "", 0, "", "", fmt.Errorf("format err")
	}
	port, err := strconv.Atoi(parts[1])
	if err != nil {
		return "", 0, "", "", err
	}
	return parts[0], port, parts[2], parts[3], nil
}

func checkIPInfoFull(host string, port int, user, password string) IPInfoResult {
	geo, err := getGeoViaSocks5(host, port, user, password)
	if err != nil {
		return IPInfoResult{Error: "Failed"}
	}
	ipType := "Residential"
	kw := []string{"Amazon", "AWS", "Google", "Azure", "OVH", "Hetzner", "DigitalOcean", "Contabo", "Linode", "Data Center", "Hosting"}
	txt := strings.ToLower(geo.Org + " " + geo.Hostname)
	for _, k := range kw {
		if strings.Contains(txt, strings.ToLower(k)) {
			ipType = "Hosting"
			break
		}
	}
	return IPInfoResult{IP: geo.IP, City: geo.City, Country: geo.Country, Org: geo.Org, Hostname: geo.Hostname, Type: ipType}
}

func checkSocks5UDP(host string, port int, user, password string) (bool, string) {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return false, fmt.Sprintf("%v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	conn.Write([]byte{0x05, 0x02, 0x00, 0x02})
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return false, "Greet fail"
	}
	if header[1] == 0x02 {
		authPayload := []byte{0x01, byte(len(user))}
		authPayload = append(authPayload, []byte(user)...)
		authPayload = append(authPayload, byte(len(password)))
		authPayload = append(authPayload, []byte(password)...)
		conn.Write(authPayload)
		authResp := make([]byte, 2)
		if _, err := io.ReadFull(conn, authResp); err != nil || authResp[1] != 0x00 {
			return false, "Auth fail"
		}
	}
	conn.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	respHeader := make([]byte, 10)
	if _, err := io.ReadFull(conn, respHeader); err != nil {
		return false, "UDP association fail"
	}
	if respHeader[1] == 0x00 { // BND.ADDR (Bound Address)
		return true, "UDP OK (local)"
	}
	return false, "No UDP (local)"
}

func checkSocks5UDPToRemote(host string, port int, user, password string, remoteAddr string) (bool, string) {
	proxyAddr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		return false, fmt.Sprintf("TCP dial fail: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	//No Auth (0x00) Username/Password (0x02)
	if _, err := conn.Write([]byte{0x05, 0x02, 0x00, 0x02}); err != nil {
		return false, fmt.Sprintf("Handshake send fail: %v", err)
	}
	
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return false, fmt.Sprintf("Handshake read fail: %v", err)
	}
	if header[0] != 0x05 { // SOCKS5 Version
		return false, fmt.Sprintf("Invalid SOCKS version: %x", header[0])
	}

	if header[1] == 0x02 {
		authPayload := []byte{0x01, byte(len(user))}
		authPayload = append(authPayload, []byte(user)...)
		authPayload = append(authPayload, byte(len(password)))
		authPayload = append(authPayload, []byte(password)...)
		
		if _, err := conn.Write(authPayload); err != nil {
			return false, fmt.Sprintf("Auth send fail: %v", err)
		}
		
		authResp := make([]byte, 2)
		if _, err := io.ReadFull(conn, authResp); err != nil || authResp[1] != 0x00 {
			return false, fmt.Sprintf("Auth fail: %v (resp: %x)", err, authResp[1])
		}
	} else if header[1] != 0x00 { //No Auth
		return false, fmt.Sprintf("Unsupported auth method: %x", header[1])
	}


	// 4. UDP ASSOCIATE Command
	// CMD = 0x03 (UDP ASSOCIATE)
	// RSV = 0x00
	// ATYP = 0x01 (IPv4)
	// BND.ADDR (0.0.0.0) и BND.PORT (0)
	if _, err := conn.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return false, fmt.Sprintf("UDP ASSOCIATE send fail: %v", err)
	}

	//UDP ASSOCIATE
	respHeader := make([]byte, 10) // BND.ADDR, BND.PORT
	if _, err := io.ReadFull(conn, respHeader); err != nil {
		return false, fmt.Sprintf("UDP ASSOCIATE read fail: %v", err)
	}

	if respHeader[1] != 0x00 { // (REP field)
		return false, fmt.Sprintf("UDP ASSOCIATE rejected: %x", respHeader[1])
	}

	bndAddr := net.IP(respHeader[4:8]).String()
	bndPort := int(respHeader[8])<<8 | int(respHeader[9])
	
	udpConn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP(bndAddr), Port: bndPort})
	if err != nil {
		return false, fmt.Sprintf("Failed to dial UDP for proxy: %v", err)
	}
	defer udpConn.Close()
	udpConn.SetDeadline(time.Now().Add(5 * time.Second))
	
	dnsQuery := []byte{
		0x12, 0x34, // ID
		0x01, 0x00, // Flags: Standard query
		0x00, 0x01, // Questions: 1
		0x00, 0x00, // Answer RRs: 0
		0x00, 0x00, // Authority RRs: 0
		0x00, 0x00, // Additional RRs: 0
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', // QNAME: example
		0x03, 'c', 'o', 'm', // QNAME: com
		0x00,       // QNAME: null terminator
		0x00, 0x01, // QTYPE: A (Host Address)
		0x00, 0x01, // QCLASS: IN (Internet)
	}

	socks5UdpHeader := []byte{
		0x00, 0x00, 0x00, // RSV, FRAG
		0x01,             // ATYP: IPv4
		0x08, 0x08, 0x08, 0x08, // DST.ADDR: 8.8.8.8
		0x00, 0x35, // DST.PORT: 53 (0x0035)
	}

	packet := append(socks5UdpHeader, dnsQuery...)

	if _, err := udpConn.Write(packet); err != nil {
		return false, fmt.Sprintf("UDP send fail via proxy: %v", err)
	}

	response := make([]byte, 1024)
	n, _, err := udpConn.ReadFromUDP(response)
	if err != nil {
		return false, fmt.Sprintf("UDP read fail via proxy: %v", err)
	}

	if n < len(socks5UdpHeader) + 12 {
		return false, "Short UDP response"
	}

	if response[len(socks5UdpHeader)+2] & 0x80 == 0 {
		return false, "Invalid DNS response (not a response)"
	}
	
	return true, "UDP OK (Google DNS)"
}