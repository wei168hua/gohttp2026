package main

/*
#include "types.h"
#include <stdlib.h>
*/
import "C"

import (
    "bytes"
    "fmt"
    "io"
    "net/http"
    "net/http/cookiejar"
    "net/url"
    "strings"
    "time"
    "unsafe"

    "golang.org/x/net/publicsuffix"
)

//export GoFree
func GoFree(p unsafe.Pointer) { if p != nil { C.free(p) } }

func cString(s string) *C.char { return C.CString(s) }

func kvListToMap(l C.KVList) map[string]string {
    if l.count == 0 || l.items == nil { return nil }
    m := make(map[string]string, int(l.count))
    items := unsafe.Slice(l.items, int(l.count))
    for i := 0; i < int(l.count); i++ {
        m[C.GoString(items[i].key)] = C.GoString(items[i].value)
    }
    return m
}

func mapToKVList(m map[string]string) C.KVList {
    if len(m) == 0 { return C.KVList{} }
    n := len(m)
    mem := C.malloc(C.size_t(n) * C.size_t(unsafe.Sizeof(C.KV{})))
    items := unsafe.Slice((*C.KV)(mem), n)
    i := 0
    for k, v := range m {
        items[i] = C.KV{key: cString(k), value: cString(v)}
        i++
    }
    return C.KVList{items: (*C.KV)(mem), count: C.int(n)}
}

func freeKVList(l *C.KVList) {
    if l.items == nil || l.count == 0 { return }
    items := unsafe.Slice(l.items, int(l.count))
    for i := 0; i < int(l.count); i++ {
        if items[i].key != nil { C.free(unsafe.Pointer(items[i].key)) }
        if items[i].value != nil { C.free(unsafe.Pointer(items[i].value)) }
    }
    C.free(unsafe.Pointer(l.items))
    l.items, l.count = nil, 0
}

//export HttpDo
func HttpDo(cReq *C.HttpRequest) *C.HttpRequest {
    if cReq == nil { return nil }
    req := (*C.HttpRequest)(unsafe.Pointer(cReq))

    method := "GET"
    if req.method != nil { method = C.GoString(req.method) }

    var body io.Reader
    if req.body != nil { body = bytes.NewBufferString(C.GoString(req.body)) }

    timeout := 30 * time.Second
    if req.timeout_sec > 0 { timeout = time.Duration(req.timeout_sec) * time.Second }

    jar, _ := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})

    transport := &http.Transport{MaxIdleConns: 100, IdleConnTimeout: 90 * time.Second}
    if req.proxy != nil && C.GoString(req.proxy) != "" {
        if pu, err := url.Parse(C.GoString(req.proxy)); err == nil {
            transport.Proxy = http.ProxyURL(pu)
        }
    }

    client := &http.Client{Transport: transport, Jar: jar, Timeout: timeout}

    hReq, err := http.NewRequest(method, C.GoString(req.url), body)
    if err != nil { return errResp(fmt.Sprintf("new request: %v", err)) }

    for k, v := range kvListToMap(req.request_headers) { hReq.Header.Set(k, v) }
    for k, v := range kvListToMap(req.request_cookies) {
        hReq.AddCookie(&http.Cookie{Name: k, Value: v})
    }

    resp, err := client.Do(hReq)
    if err != nil { return errResp(fmt.Sprintf("do request: %v", err)) }
    defer resp.Body.Close()

    respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 50*1024*1024))

    out := &C.HttpRequest{
        status_code:   C.int(resp.StatusCode),
        response_body: cString(string(respBody)),
    }

    rh := make(map[string]string)
    for k, vs := range resp.Header { rh[k] = strings.Join(vs, ", ") }
    out.response_headers = mapToKVList(rh)

    rc := make(map[string]string)
    for _, c := range resp.Cookies() { rc[c.Name] = c.Value }
    out.response_cookies = mapToKVList(rc)

    return out
}

func errResp(msg string) *C.HttpRequest {
    return &C.HttpRequest{status_code: C.int(-1), response_body: cString(msg)}
}

//export HttpGet
func HttpGet(url, proxy *C.char) *C.HttpRequest {
    return HttpDo(&C.HttpRequest{
        method:      cString("GET"),
        url:         cString(C.GoString(url)),
        proxy:       cString(C.GoString(proxy)),
        timeout_sec: 30,
    })
}

//export HttpPost
func HttpPost(url, body, contentType, proxy *C.char) *C.HttpRequest {
    req := &C.HttpRequest{
        method:      cString("POST"),
        url:         cString(C.GoString(url)),
        body:        cString(C.GoString(body)),
        proxy:       cString(C.GoString(proxy)),
        timeout_sec: 30,
    }
    if contentType != nil {
        req.request_headers = mapToKVList(map[string]string{"Content-Type": C.GoString(contentType)})
    }
    return HttpDo(req)
}

//export FreeHttpRequest
func FreeHttpRequest(req *C.HttpRequest) {
    if req == nil { return }
    for _, p := range []*C.char{req.method, req.url, req.body, req.response_body, req.proxy} {
        if p != nil { C.free(unsafe.Pointer(p)) }
    }
    freeKVList(&req.request_headers)
    freeKVList(&req.request_cookies)
    freeKVList(&req.response_headers)
    freeKVList(&req.response_cookies)
}

func main() {}
