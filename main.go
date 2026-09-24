package main

/*
#include "types.h"
#include <stdlib.h>
*/
import "C"

import (
    "bytes"
    "context"
    "crypto/tls"
    "encoding/base64"
    "fmt"
    "io"
    "mime/multipart"
    "net"
    "net/http"
    "net/http/cookiejar"
    "net/url"
    "os"
    "path/filepath"
    "strings"
    "sync"
    "time"
    "unsafe"

    utls "github.com/refraction-networking/utls"
    "golang.org/x/net/publicsuffix"
)

// ============================================================
// 全局默认配置（线程安全）
// ============================================================
var (
    globalMu          sync.RWMutex
    globalFingerprint string
    globalProxy       string
    globalTimeout     int
    globalHeaders     = map[string]string{}
    globalCookies     = map[string]string{}
    lastError         string
    lastErrorMu       sync.Mutex
)

// ============================================================
// 内存 / 字符串辅助
// ============================================================
func cString(s string) *C.char {
    if s == "" {
        return nil
    }
    return C.CString(s)
}

func goString(p *C.char) string {
    if p == nil {
        return ""
    }
    return C.GoString(p)
}

func setLastError(msg string) {
    lastErrorMu.Lock()
    lastError = msg
    lastErrorMu.Unlock()
}

func kvListToMap(l C.KVList) map[string]string {
    if l.count == 0 || l.items == nil {
        return nil
    }
    m := make(map[string]string, int(l.count))
    items := unsafe.Slice(l.items, int(l.count))
    for i := 0; i < int(l.count); i++ {
        m[goString(items[i].key)] = goString(items[i].value)
    }
    return m
}

func mapToKVList(m map[string]string) (C.KVList, []*C.char) {
    if len(m) == 0 {
        return C.KVList{}, nil
    }
    n := len(m)
    mem := C.malloc(C.size_t(n) * C.size_t(unsafe.Sizeof(C.KV{})))
    items := unsafe.Slice((*C.KV)(mem), n)
    kept := make([]*C.char, 0, n*2)
    i := 0
    for k, v := range m {
        ck, cv := cString(k), cString(v)
        items[i] = C.KV{key: ck, value: cv}
        kept = append(kept, ck, cv)
        i++
    }
    return C.KVList{items: (*C.KV)(mem), count: C.int(n)}, kept
}

func freeKVList(l *C.KVList) {
    if l.items == nil || l.count == 0 {
        return
    }
    items := unsafe.Slice(l.items, int(l.count))
    for i := 0; i < int(l.count); i++ {
        if items[i].key != nil {
            C.free(unsafe.Pointer(items[i].key))
        }
        if items[i].value != nil {
            C.free(unsafe.Pointer(items[i].value))
        }
    }
    C.free(unsafe.Pointer(l.items))
    l.items, l.count = nil, 0
}

// ============================================================
// uTLS 指纹传输层（带代理支持）
// ============================================================
func pickHelloID(fp string) utls.ClientHelloID {
    switch strings.ToLower(fp) {
    case "chrome":
        return utls.HelloChrome_Auto
    case "firefox":
        return utls.HelloFirefox_Auto
    case "safari":
        return utls.HelloSafari_Auto
    case "edge":
        return utls.HelloEdge_Auto
    case "random":
        return utls.HelloRandomized
    default:
        return utls.ClientHelloID{}
    }
}

// 统一构建 Transport
func buildTransport(cfg *C.HttpRequest) (*http.Transport, error) {
    proxy := goString(cfg.proxy)
    fp := goString(cfg.fingerprint)
    if fp == "" {
        fp = globalFingerprint
    }
    if proxy == "" {
        proxy = globalProxy
    }

    timeout := time.Duration(cfg.timeout_sec) * time.Second
    if cfg.timeout_sec <= 0 {
        if globalTimeout > 0 {
            timeout = time.Duration(globalTimeout) * time.Second
        } else {
            timeout = 30 * time.Second
        }
    }

    dialer := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}

    var proxyURL *url.URL
    if proxy != "" {
        pu, err := url.Parse(proxy)
        if err != nil {
            return nil, fmt.Errorf("解析代理失败: %v", err)
        }
        proxyURL = pu
    }

    tr := &http.Transport{
        MaxIdleConns:        200,
        MaxIdleConnsPerHost: 20,
        IdleConnTimeout:     90 * time.Second,
        ForceAttemptHTTP2:   cfg.http_version != 1,
        TLSClientConfig: &tls.Config{
            InsecureSkipVerify: cfg.insecure_skip_verify == 1,
        },
        DisableCompression: cfg.auto_decompress == 0,
    }

    if proxyURL != nil {
        tr.Proxy = http.ProxyURL(proxyURL)
    }

    // 带指纹：替换 TLS 握手
    if fp != "" {
        helloID := pickHelloID(fp)
        tr.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
            var raw net.Conn
            var err error

            // HTTP 代理 CONNECT 隧道
            if proxyURL != nil && proxyURL.Scheme != "socks5" {
                raw, err = dialer.DialContext(ctx, "tcp", proxyURL.Host)
                if err != nil {
                    return nil, err
                }
                host := addr
                fmt.Fprintf(raw, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", host, host)
                buf := make([]byte, 4096)
                n, _ := raw.Read(buf)
                if !strings.Contains(string(buf[:n]), "200") {
                    raw.Close()
                    return nil, fmt.Errorf("代理 CONNECT 失败")
                }
            } else {
                raw, err = dialer.DialContext(ctx, network, addr)
                if err != nil {
                    return nil, err
                }
            }

            host := addr
            if i := strings.LastIndex(addr, ":"); i > 0 {
                host = addr[:i]
            }
            uconn := utls.UClient(raw, &utls.Config{
                ServerName:         host,
                InsecureSkipVerify: cfg.insecure_skip_verify == 1,
            }, helloID)
            if err := uconn.HandshakeContext(ctx); err != nil {
                raw.Close()
                return nil, err
            }
            return uconn, nil
        }
    }

    return tr, nil
}

// ============================================================
// 核心请求执行
// ============================================================
func doRequest(cReq *C.HttpRequest) *C.HttpRequest {
    if cReq == nil {
        return errResp("HttpRequest 为空")
    }
    start := time.Now()
    req := (*C.HttpRequest)(unsafe.Pointer(cReq))

    method := goString(req.method)
    if method == "" {
        method = "GET"
    }
    rawURL := goString(req.url)
    if rawURL == "" {
        return errResp("URL 为空")
    }

    // Body
    var bodyReader io.Reader
    if req.body != nil {
        bodyReader = bytes.NewBufferString(goString(req.body))
    } else if req.body_base64 != nil {
        data, err := base64.StdEncoding.DecodeString(goString(req.body_base64))
        if err == nil {
            bodyReader = bytes.NewReader(data)
        }
    }

    // 超时
    timeout := time.Duration(req.timeout_sec) * time.Second
    if req.timeout_sec <= 0 {
        if globalTimeout > 0 {
            timeout = time.Duration(globalTimeout) * time.Second
        } else {
            timeout = 30 * time.Second
        }
    }

    // Cookie Jar
    jar, _ := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})

    // 提前注入全局 + 请求 Cookie 到 Jar
    if u, err := url.Parse(rawURL); err == nil {
        var cookies []*http.Cookie
        globalMu.RLock()
        for k, v := range globalCookies {
            cookies = append(cookies, &http.Cookie{Name: k, Value: v})
        }
        globalMu.RUnlock()
        for k, v := range kvListToMap(req.request_cookies) {
            cookies = append(cookies, &http.Cookie{Name: k, Value: v})
        }
        if len(cookies) > 0 {
            jar.SetCookies(u, cookies)
        }
    }

    tr, err := buildTransport(req)
    if err != nil {
        return errResp(err.Error())
    }

    client := &http.Client{
        Transport: tr,
        Jar:       jar,
        Timeout:   timeout,
    }
    if req.follow_redirect == 0 {
        client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
            return http.ErrUseLastResponse
        }
    } else if req.max_redirects > 0 {
        maxR := int(req.max_redirects)
        client.CheckRedirect = func(_ *http.Request, via []*http.Request) error {
            if len(via) >= maxR {
                return fmt.Errorf("重定向次数超过 %d", maxR)
            }
            return nil
        }
    }

    hReq, err := http.NewRequest(method, rawURL, bodyReader)
    if err != nil {
        return errResp(fmt.Sprintf("构造请求失败: %v", err))
    }

    // 全局头
    globalMu.RLock()
    for k, v := range globalHeaders {
        hReq.Header.Set(k, v)
    }
    globalMu.RUnlock()
    // 请求头
    for k, v := range kvListToMap(req.request_headers) {
        hReq.Header.Set(k, v)
    }
    // 默认 UA（没设置时）
    if hReq.Header.Get("User-Agent") == "" {
        hReq.Header.Set("User-Agent", "GoHttpDLL/2.0")
    }

    // 执行
    resp, err := client.Do(hReq)
    elapsed := int(time.Since(start).Milliseconds())
    if err != nil {
        setLastError(err.Error())
        return errResp(err.Error())
    }
    defer resp.Body.Close()

    // 读取 body
    rawBody, err := io.ReadAll(resp.Body)
    if err != nil {
        return errResp(fmt.Sprintf("读取响应失败: %v", err))
    }

    // 组装输出
    out := &C.HttpRequest{
        status_code:       C.int(resp.StatusCode),
        response_body:     cString(string(rawBody)),
        response_body_len: C.int(len(rawBody)),
        final_url:         cString(resp.Request.URL.String()),
        proto:             cString(resp.Proto),
        remote_addr:       cString(resp.Request.URL.Host),
        elapsed_ms:        C.int(elapsed),
        status_text:       cString(http.StatusText(resp.StatusCode)),
    }

    // base64 body（二进制安全）
    if len(rawBody) > 0 {
        out.response_body_base64 = cString(base64.StdEncoding.EncodeToString(rawBody))
    }

    // 响应头（多值合并）
    rh := make(map[string]string, len(resp.Header))
    for k, vs := range resp.Header {
        rh[k] = strings.Join(vs, ", ")
    }
    out.response_headers, _ = mapToKVList(rh)

    // 响应 Cookie
    rc := make(map[string]string)
    for _, c := range resp.Cookies() {
        rc[c.Name] = c.Value
    }
    out.response_cookies, _ = mapToKVList(rc)

    // TLS 信息
    if resp.TLS != nil {
        out.tls_version = cString(tlsVersionName(resp.TLS.Version))
        out.tls_server_name = cString(resp.TLS.ServerName)
    }

    return out
}

func tlsVersionName(v uint16) string {
    switch v {
    case tls.VersionTLS10:
        return "TLS 1.0"
    case tls.VersionTLS11:
        return "TLS 1.1"
    case tls.VersionTLS12:
        return "TLS 1.2"
    case tls.VersionTLS13:
        return "TLS 1.3"
    }
    return fmt.Sprintf("0x%04x", v)
}

func errResp(msg string) *C.HttpRequest {
    setLastError(msg)
    return &C.HttpRequest{
        status_code:   C.int(-1),
        response_body: cString(msg),
        error:         cString(msg),
    }
}

// ============================================================
// 导出：核心请求
// ============================================================

//export HttpDo
func HttpDo(cReq *C.HttpRequest) *C.HttpRequest {
    return doRequest(cReq)
}

//export HttpGet
func HttpGet(url, proxy, fingerprint *C.char) *C.HttpRequest {
    req := &C.HttpRequest{
        method:      cString("GET"),
        url:         cString(goString(url)),
        proxy:       cString(goString(proxy)),
        fingerprint: cString(goString(fingerprint)),
        timeout_sec: 30,
        follow_redirect: 1,
        auto_decompress: 1,
    }
    return doRequest(req)
}

//export HttpPost
func HttpPost(url, body, contentType, proxy, fingerprint *C.char) *C.HttpRequest {
    req := &C.HttpRequest{
        method:      cString("POST"),
        url:         cString(goString(url)),
        body:        cString(goString(body)),
        proxy:       cString(goString(proxy)),
        fingerprint: cString(goString(fingerprint)),
        timeout_sec: 30,
        follow_redirect: 1,
        auto_decompress: 1,
    }
    if contentType != nil {
        req.request_headers, _ = mapToKVList(map[string]string{
            "Content-Type": goString(contentType),
        })
    }
    return doRequest(req)
}

//export HttpPut
func HttpPut(url, body, contentType, proxy, fingerprint *C.char) *C.HttpRequest {
    req := &C.HttpRequest{
        method:      cString("PUT"),
        url:         cString(goString(url)),
        body:        cString(goString(body)),
        proxy:       cString(goString(proxy)),
        fingerprint: cString(goString(fingerprint)),
        timeout_sec: 30, follow_redirect: 1, auto_decompress: 1,
    }
    if contentType != nil {
        req.request_headers, _ = mapToKVList(map[string]string{"Content-Type": goString(contentType)})
    }
    return doRequest(req)
}

//export HttpDelete
func HttpDelete(url, proxy, fingerprint *C.char) *C.HttpRequest {
    req := &C.HttpRequest{
        method:      cString("DELETE"),
        url:         cString(goString(url)),
        proxy:       cString(goString(proxy)),
        fingerprint: cString(goString(fingerprint)),
        timeout_sec: 30, follow_redirect: 1, auto_decompress: 1,
    }
    return doRequest(req)
}

//export HttpPatch
func HttpPatch(url, body, contentType, proxy, fingerprint *C.char) *C.HttpRequest {
    req := &C.HttpRequest{
        method:      cString("PATCH"),
        url:         cString(goString(url)),
        body:        cString(goString(body)),
        proxy:       cString(goString(proxy)),
        fingerprint: cString(goString(fingerprint)),
        timeout_sec: 30, follow_redirect: 1, auto_decompress: 1,
    }
    if contentType != nil {
        req.request_headers, _ = mapToKVList(map[string]string{"Content-Type": goString(contentType)})
    }
    return doRequest(req)
}

//export HttpHead
func HttpHead(url, proxy, fingerprint *C.char) *C.HttpRequest {
    req := &C.HttpRequest{
        method:      cString("HEAD"),
        url:         cString(goString(url)),
        proxy:       cString(goString(proxy)),
        fingerprint: cString(goString(fingerprint)),
        timeout_sec: 30, follow_redirect: 1, auto_decompress: 1,
    }
    return doRequest(req)
}

//export HttpOptions
func HttpOptions(url, proxy, fingerprint *C.char) *C.HttpRequest {
    req := &C.HttpRequest{
        method:      cString("OPTIONS"),
        url:         cString(goString(url)),
        proxy:       cString(goString(proxy)),
        fingerprint: cString(goString(fingerprint)),
        timeout_sec: 30, follow_redirect: 1, auto_decompress: 1,
    }
    return doRequest(req)
}

// ============================================================
// 文件上传（multipart）
// ============================================================

//export HttpUploadFile
func HttpUploadFile(url, filePath, fieldName, proxy, fingerprint *C.char) *C.HttpRequest {
    fp := goString(filePath)
    fn := goString(fieldName)
    if fn == "" {
        fn = "file"
    }
    f, err := os.Open(fp)
    if err != nil {
        return errResp(fmt.Sprintf("打开文件失败: %v", err))
    }
    defer f.Close()

    var buf bytes.Buffer
    w := multipart.NewWriter(&buf)
    part, err := w.CreateFormFile(fn, filepath.Base(fp))
    if err != nil {
        return errResp(fmt.Sprintf("创建表单失败: %v", err))
    }
    if _, err := io.Copy(part, f); err != nil {
        return errResp(fmt.Sprintf("复制文件失败: %v", err))
    }
    w.Close()

    req := &C.HttpRequest{
        method:      cString("POST"),
        url:         cString(goString(url)),
        body:        cString(buf.String()),
        proxy:       cString(goString(proxy)),
        fingerprint: cString(goString(fingerprint)),
        timeout_sec: 120, follow_redirect: 1, auto_decompress: 1,
    }
    req.request_headers, _ = mapToKVList(map[string]string{
        "Content-Type": w.FormDataContentType(),
    })
    return doRequest(req)
}

// ============================================================
// 下载到文件
// ============================================================

//export HttpDownloadFile
func HttpDownloadFile(url, savePath, proxy, fingerprint *C.char) *C.HttpRequest {
    resp := HttpGet(url, proxy, fingerprint)
    if resp == nil || resp.status_code < 0 {
        return resp
    }
    if resp.response_body_base64 == nil {
        return resp
    }
    data, err := base64.StdEncoding.DecodeString(goString(resp.response_body_base64))
    if err != nil {
        return errResp(fmt.Sprintf("base64 解码失败: %v", err))
    }
    if err := os.WriteFile(goString(savePath), data, 0644); err != nil {
        return errResp(fmt.Sprintf("写文件失败: %v", err))
    }
    return resp
}

// ============================================================
// 全局配置
// ============================================================

//export HttpSetDefaultFingerprint
func HttpSetDefaultFingerprint(fp *C.char) {
    globalMu.Lock()
    globalFingerprint = goString(fp)
    globalMu.Unlock()
}

//export HttpSetDefaultProxy
func HttpSetDefaultProxy(p *C.char) {
    globalMu.Lock()
    globalProxy = goString(p)
    globalMu.Unlock()
}

//export HttpSetDefaultTimeout
func HttpSetDefaultTimeout(sec C.int) {
    globalMu.Lock()
    globalTimeout = int(sec)
    globalMu.Unlock()
}

//export HttpSetDefaultHeader
func HttpSetDefaultHeader(k, v *C.char) {
    globalMu.Lock()
    globalHeaders[goString(k)] = goString(v)
    globalMu.Unlock()
}

//export HttpSetDefaultCookie
func HttpSetDefaultCookie(k, v *C.char) {
    globalMu.Lock()
    globalCookies[goString(k)] = goString(v)
    globalMu.Unlock()
}

//export HttpClearDefaults
func HttpClearDefaults() {
    globalMu.Lock()
    globalFingerprint = ""
    globalProxy = ""
    globalTimeout = 0
    globalHeaders = map[string]string{}
    globalCookies = map[string]string{}
    globalMu.Unlock()
}

//export HttpGetLastError
func HttpGetLastError() *C.char {
    lastErrorMu.Lock()
    defer lastErrorMu.Unlock()
    if lastError == "" {
        return nil
    }
    return cString(lastError)
}

// ============================================================
// 释放
// ============================================================

//export FreeHttpRequest
func FreeHttpRequest(req *C.HttpRequest) {
    if req == nil {
        return
    }
    freeStr := func(p **C.char) {
        if *p != nil {
            C.free(unsafe.Pointer(*p))
            *p = nil
        }
    }
    freeStr(&req.method)
    freeStr(&req.url)
    freeStr(&req.body)
    freeStr(&req.body_base64)
    freeStr(&req.proxy)
    freeStr(&req.fingerprint)
    freeStr(&req.status_text)
    freeStr(&req.response_body)
    freeStr(&req.response_body_base64)
    freeStr(&req.final_url)
    freeStr(&req.proto)
    freeStr(&req.remote_addr)
    freeStr(&req.tls_version)
    freeStr(&req.tls_server_name)
    freeStr(&req.error)
    freeKVList(&req.request_headers)
    freeKVList(&req.request_cookies)
    freeKVList(&req.response_headers)
    freeKVList(&req.response_cookies)
}

//export FreeString
func FreeString(p *C.char) {
    if p != nil {
        C.free(unsafe.Pointer(p))
    }
}

//export GoFree
func GoFree(p unsafe.Pointer) {
    if p != nil {
        C.free(p)
    }
}

func main() {}
