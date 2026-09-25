package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
	"unsafe"

	tls "github.com/refraction-networking/utls"
	"golang.org/x/net/proxy"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
)

const maxBody = 10 << 20

var (
	defaultTimeout  = 30
	lastStatus      int
	lastErr         string
	lastRespHeaders string
	lastSetCookie   string
	lastReqHeaders  string

	lastErrPtr    *C.char
	lastHeaderPtr *C.char
	lastCookiePtr *C.char
	lastRespPtr   *C.char

	globalFPName string
	globalFP     tls.ClientHelloID
	extraHeaders string
)

// ---------------------------------------------------------------------------
// 编码转换
// ---------------------------------------------------------------------------

func utf8ToGBK(s string) string {
	out, _, err := transform.String(simplifiedchinese.GBK.NewEncoder(), s)
	if err != nil {
		return s
	}
	return out
}

func gbkToUtf8(s string) string {
	out, _, err := transform.String(simplifiedchinese.GBK.NewDecoder(), s)
	if err != nil {
		return s
	}
	return out
}

// ---------------------------------------------------------------------------
// 工具
// ---------------------------------------------------------------------------

func goStr(p *C.char) string {
	if p == nil {
		return ""
	}
	return C.GoString(p)
}

func freeRet(ptr *C.char) {
	if ptr != nil {
		C.free(unsafe.Pointer(ptr))
	}
}

func cstrRet(s string) *C.char {
	return C.CString(utf8ToGBK(s))
}

// ---------------------------------------------------------------------------
// bufferedConn：HTTP 代理 CONNECT 后，bufio 里可能已经读了 TLS 数据，要封回去
// ---------------------------------------------------------------------------

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

// ---------------------------------------------------------------------------
// 普通 Transport
// ---------------------------------------------------------------------------

func buildTransport(proxyURL string) *http.Transport {
	// 开了指纹：无论什么代理都走指纹通道
	if globalFPName != "" {
		return newFPTransport(proxyURL)
	}

	tr := &http.Transport{
		DisableKeepAlives:   true,
		DialContext:         (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout: 10 * time.Second,
		MaxIdleConnsPerHost: 10,
		ForceAttemptHTTP2:   false,
		TLSNextProto:        make(map[string]func(string, *tls.Conn) http.RoundTripper),
	}

	if proxyURL == "" {
		return tr
	}
	u, err := url.Parse(proxyURL)
	if err != nil {
		return tr
	}
	if u.Scheme == "socks5" || u.Scheme == "socks5h" {
		if d, err := proxy.FromURL(u, proxy.Direct); err == nil {
			if dc, ok := d.(proxy.ContextDialer); ok {
				tr.DialContext = dc.DialContext
			} else {
				tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
					return d.Dial(network, addr)
				}
			}
		}
	} else {
		tr.Proxy = http.ProxyURL(u)
	}
	return tr
}

// ---------------------------------------------------------------------------
// 指纹 Transport（支持直连 / SOCKS5 / HTTP 代理）
// ---------------------------------------------------------------------------

var fpSessionCache = tls.NewLRUClientSessionCache(128)

func newFPTransport(proxyURL string) *http.Transport {
	var socks *url.URL
	var httpProxy *url.URL

	if strings.HasPrefix(proxyURL, "socks5") {
		if u, err := url.Parse(proxyURL); err == nil {
			socks = u
		}
	} else if strings.HasPrefix(proxyURL, "http://") || strings.HasPrefix(proxyURL, "https://") {
		if u, err := url.Parse(proxyURL); err == nil {
			httpProxy = u
		}
	}

	tr := &http.Transport{
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: 10 * time.Second,
		MaxIdleConnsPerHost: 10,
		ForceAttemptHTTP2:   false,
	}

	tr.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		var raw net.Conn
		var err error

		switch {
		case socks != nil:
			d, derr := proxy.FromURL(socks, proxy.Direct)
			if derr != nil {
				return nil, derr
			}
			raw, err = d.Dial(network, addr)

		case httpProxy != nil:
			raw, err = (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, "tcp", httpProxy.Host)
			if err != nil {
				return nil, err
			}
			connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", addr, addr)
			if httpProxy.User != nil {
				user := httpProxy.User.Username()
				pass, _ := httpProxy.User.Password()
				auth := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
				connectReq += "Proxy-Authorization: Basic " + auth + "\r\n"
			}
			connectReq += "\r\n"
			if _, err := raw.Write([]byte(connectReq)); err != nil {
				raw.Close()
				return nil, err
			}
			br := bufio.NewReader(raw)
			statusLine, err := br.ReadString('\n')
			if err != nil {
				raw.Close()
				return nil, err
			}
			if !strings.Contains(statusLine, "200") {
				raw.Close()
				return nil, fmt.Errorf("代理 CONNECT 失败: %s", strings.TrimSpace(statusLine))
			}
			for {
				line, err := br.ReadString('\n')
				if err != nil || strings.TrimSpace(line) == "" {
					break
				}
			}
			raw = &bufferedConn{Conn: raw, r: br}

		default:
			raw, err = (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, network, addr)
		}

		if err != nil {
			return nil, err
		}

		host, _, _ := net.SplitHostPort(addr)
		uconn := tls.UClient(raw, &tls.Config{
			ServerName:         host,
			MinVersion:         tls.VersionTLS12,
			NextProtos:         []string{"http/1.1"},
			ClientSessionCache: fpSessionCache,
		}, globalFP)
		if err := uconn.HandshakeContext(ctx); err != nil {
			raw.Close()
			return nil, err
		}
		return uconn, nil
	}
	return tr
}

// ---------------------------------------------------------------------------
// 指纹解析
// ---------------------------------------------------------------------------

func parseFingerprint(name string) (tls.ClientHelloID, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "chrome":
		return tls.HelloChrome_100, nil
	case "chrome_96":
		return tls.HelloChrome_96, nil
	case "firefox":
		return tls.HelloFirefox_102, nil
	case "firefox_99":
		return tls.HelloFirefox_99, nil
	case "firefox_105":
		return tls.HelloFirefox_105, nil
	case "edge":
		return tls.HelloEdge_106, nil
	case "edge_85":
		return tls.HelloEdge_85, nil
	case "safari":
		return tls.HelloSafari_16_0, nil
	case "ios":
		return tls.HelloIOS_14, nil
	case "android":
		return tls.HelloAndroid_11_OkHttp, nil
	case "360":
		return tls.Hello360_7_5, nil
	case "qq":
		return tls.HelloQQ_11_1, nil
	case "random":
		return tls.HelloRandomized, nil
	case "randomalpn":
		return tls.HelloRandomizedALPN, nil
	case "randomalpnnoalpn", "randomnoalpn":
		return tls.HelloRandomizedNoALPN, nil
	}
	return tls.ClientHelloID{}, fmt.Errorf("未知指纹名称: %s", name)
}

// ---------------------------------------------------------------------------
// 响应头 / Cookie 提取
// ---------------------------------------------------------------------------

func flattenHeaders(h http.Header) string {
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	for _, k := range keys {
		for _, v := range h[k] {
			b.WriteString(k)
			b.WriteString(": ")
			b.WriteString(v)
			b.WriteString("\r\n")
		}
	}
	return strings.TrimRight(b.String(), "\r\n")
}

func extractCookies(h http.Header) string {
	vals := h.Values("Set-Cookie")
	parts := make([]string, 0, len(vals))
	for _, v := range vals {
		if i := strings.Index(v, ";"); i >= 0 {
			v = v[:i]
		}
		v = strings.TrimSpace(v)
		if v != "" {
			parts = append(parts, v)
		}
	}
	return strings.Join(parts, "; ")
}

// ---------------------------------------------------------------------------
// 指纹对应 UA / 默认请求头
// ---------------------------------------------------------------------------

func uaForFingerprint() string {
	switch strings.ToLower(strings.TrimSpace(globalFPName)) {
	case "chrome", "chrome_96", "random", "randomalpn", "randomnoalpn", "":
		return "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36"
	case "firefox", "firefox_99", "firefox_105":
		return "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
	case "edge", "edge_85":
		return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36 Edg/132.0.0.0"
	case "safari", "ios":
		return "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1"
	case "android":
		return "Dalvik/2.1.0 (Linux; U; Android 9; okhttp/3.12.1)"
	case "360":
		return "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36"
	}
	return "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36"
}

func defaultReqHeaders() string {
	var b strings.Builder
	b.WriteString("User-Agent: " + uaForFingerprint() + "\r\n")
	b.WriteString("Accept: */*\r\n")
	b.WriteString("Accept-Language: zh-CN,zh;q=0.9\r\n")
	b.WriteString("Cache-Control: no-cache\r\n")
	b.WriteString("DNT: 1\r\n")
	b.WriteString("Pragma: no-cache\r\n")
	b.WriteString("Sec-Fetch-Dest: empty\r\n")
	b.WriteString("Sec-Fetch-Mode: cors\r\n")
	b.WriteString("Sec-Fetch-Site: same-site\r\n")
	if strings.Contains(uaForFingerprint(), "Chrome") {
		b.WriteString("sec-ch-ua: \"Not A(Brand\";v=\"8\", \"Chromium\";v=\"132\", \"Google Chrome\";v=\"132\"\r\n")
		b.WriteString("sec-ch-ua-mobile: ?0\r\n")
		b.WriteString("sec-ch-ua-platform: \"Windows\"\r\n")
	}
	return strings.TrimRight(b.String(), "\r\n")
}

// ---------------------------------------------------------------------------
// 核心请求
// ---------------------------------------------------------------------------

func doRequest(method, url, data, cookie, headerText, proxyURL string) (string, string) {
	var body io.Reader
	if data != "" {
		body = strings.NewReader(data)
	}
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return "", err.Error()
	}
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	for _, line := range strings.Split(headerText, "\n") {
		line = strings.Trim(line, " \r\t")
		if line == "" {
			continue
		}
		i := strings.Index(line, ":")
		if i <= 0 {
			continue
		}
		req.Header.Set(strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+1:]))
	}

	client := &http.Client{
		Timeout:   time.Duration(defaultTimeout) * time.Second,
		Transport: buildTransport(proxyURL),
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err.Error()
	}
	defer resp.Body.Close()

	lastStatus = resp.StatusCode
	lastRespHeaders = flattenHeaders(resp.Header)
	lastSetCookie = extractCookies(resp.Header)
	lastReqHeaders = defaultReqHeaders()
	if extraHeaders != "" {
		lastReqHeaders += "\r\n" + extraHeaders
	}
	if lastSetCookie != "" {
		lastReqHeaders += "\r\nCookie: " + lastSetCookie
	}

	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return "", err.Error()
	}
	return string(b), ""
}

func requestP(method, url, data, cookie, headers, proxyURL string, timeout int) *C.char {
	defer func() {
		if r := recover(); r != nil {
			lastErr = fmt.Sprintf("panic: %v", r)
		}
	}()
	if timeout > 0 {
		defaultTimeout = timeout
	}
	lastErr = ""
	body, errMsg := doRequest(method, url, data, cookie, headers, proxyURL)
	if errMsg != "" {
		lastErr = errMsg
		return nil
	}
	return cstrRet(body)
}

// ---------------------------------------------------------------------------
// 导出函数
// ---------------------------------------------------------------------------

//export http_Init
func http_Init() C.int {
	lastStatus = 0
	lastErr = ""
	defaultTimeout = 30
	globalFPName = ""
	extraHeaders = ""
	return 1
}

//export http_SetTimeout
func http_SetTimeout(cTimeout C.int) {
	if cTimeout > 0 {
		defaultTimeout = int(cTimeout)
	}
}

//export http_SetFingerprint
func http_SetFingerprint(cName *C.char) C.int {
	name := goStr(cName)
	if name == "" {
		globalFPName = ""
		return 0
	}
	id, err := parseFingerprint(name)
	if err != nil {
		lastErr = err.Error()
		return -1
	}
	globalFP = id
	globalFPName = name
	return 0
}

//export http_SetExtraHeaders
func http_SetExtraHeaders(cHeaders *C.char) {
	extraHeaders = strings.TrimRight(goStr(cHeaders), "\r\n")
}

//export http_Request
func http_Request(cMethod, cURL, cData, cCookie, cHeaders, cProxy *C.char, cTimeout C.int) *C.char {
	return requestP(goStr(cMethod), goStr(cURL), goStr(cData), goStr(cCookie), goStr(cHeaders), goStr(cProxy), int(cTimeout))
}

//export http_Get
func http_Get(cURL, cCookie, cHeaders, cProxy *C.char, cTimeout C.int) *C.char {
	return requestP("GET", goStr(cURL), "", goStr(cCookie), goStr(cHeaders), goStr(cProxy), int(cTimeout))
}

//export http_Post
func http_Post(cURL, cData, cCookie, cHeaders, cProxy *C.char, cTimeout C.int) *C.char {
	return requestP("POST", goStr(cURL), goStr(cData), goStr(cCookie), goStr(cHeaders), goStr(cProxy), int(cTimeout))
}

//export http_PostJson
func http_PostJson(cURL, cJSON, cCookie, cHeaders, cProxy *C.char, cTimeout C.int) *C.char {
	hs := "Content-Type: application/json\r\n" + goStr(cHeaders)
	return requestP("POST", goStr(cURL), goStr(cJSON), goStr(cCookie), hs, goStr(cProxy), int(cTimeout))
}

//export http_Put
func http_Put(cURL, cData, cCookie, cHeaders, cProxy *C.char, cTimeout C.int) *C.char {
	return requestP("PUT", goStr(cURL), goStr(cData), goStr(cCookie), goStr(cHeaders), goStr(cProxy), int(cTimeout))
}

//export http_Delete
func http_Delete(cURL, cCookie, cHeaders, cProxy *C.char, cTimeout C.int) *C.char {
	return requestP("DELETE", goStr(cURL), "", goStr(cCookie), goStr(cHeaders), goStr(cProxy), int(cTimeout))
}

//export http_LastStatus
func http_LastStatus() C.int {
	return C.int(lastStatus)
}

//export http_LastHeader
func http_LastHeader() *C.char {
	freeRet(lastHeaderPtr)
	lastHeaderPtr = cstrRet(lastReqHeaders)
	return lastHeaderPtr
}

//export http_LastRespHeader
func http_LastRespHeader() *C.char {
	freeRet(lastRespPtr)
	lastRespPtr = cstrRet(lastRespHeaders)
	return lastRespPtr
}

//export http_LastCookie
func http_LastCookie() *C.char {
	freeRet(lastCookiePtr)
	lastCookiePtr = cstrRet(lastSetCookie)
	return lastCookiePtr
}

//export http_LastError
func http_LastError() *C.char {
	freeRet(lastErrPtr)
	lastErrPtr = cstrRet(lastErr)
	return lastErrPtr
}

//export http_Free
func http_Free(cPtr *C.char) {
	freeRet(cPtr)
}

func main() {}
