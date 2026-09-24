#ifndef GOHTTPDLL_TYPES_H
#define GOHTTPDLL_TYPES_H

#include <stdint.h>

/* 键值对 */
typedef struct {
    char* key;
    char* value;
} KV;

/* 键值对列表 */
typedef struct {
    KV*   items;
    int   count;
} KVList;

/* 完整请求/响应结构体 */
typedef struct {
    /* ========== 请求参数（调用方填） ========== */
    char*  method;              /* HTTP 方法，NULL 默认 GET */
    char*  url;                 /* 完整 URL，必填 */
    char*  body;                /* 请求体字符串，可为 NULL */
    char*  body_base64;         /* 请求体 base64（二进制用），与 body 二选一 */
    KVList request_headers;     /* 请求头 */
    KVList request_cookies;     /* 请求 Cookie */

    /* ========== 配置参数 ========== */
    char*  proxy;               /* 代理，如 http://127.0.0.1:8080，NULL 不用 */
    char*  fingerprint;         /* TLS 指纹：chrome/firefox/safari/edge/random，NULL 原生 */
    int    timeout_sec;         /* 超时秒，0 默认 30 */
    int    follow_redirect;     /* 是否跟随重定向，1 是 0 否 */
    int    max_redirects;       /* 最大重定向次数，0 默认 10 */
    int    insecure_skip_verify;/* 跳过 TLS 校验，1 是 0 否 */
    int    auto_decompress;     /* 自动 gzip/deflate 解压，1 是 0 否（默认 1） */
    int    http_version;        /* 1=HTTP1.1, 2=HTTP2, 3=自动 */

    /* ========== 响应结果（DLL 填，调用方读） ========== */
    int    status_code;         /* HTTP 状态码，-1 表示请求失败 */
    char*  status_text;         /* 状态文本，如 "OK" */
    char*  response_body;       /* 响应体字符串 */
    char*  response_body_base64;/* 响应体 base64（二进制安全） */
    int    response_body_len;   /* 响应体字节长度 */
    KVList response_headers;    /* 响应头（多值用 ", " 连接） */
    KVList response_cookies;    /* 响应 Set-Cookie 解析 */
    char*  final_url;           /* 重定向后的最终 URL */
    char*  proto;               /* 实际协议，如 "HTTP/2.0" */
    char*  remote_addr;         /* 对端地址 */
    char*  tls_version;         /* TLS 版本，如 "TLS 1.3" */
    char*  tls_server_name;     /* SNI */
    int    elapsed_ms;          /* 请求耗时（毫秒） */
    char*  error;               /* 错误信息，NULL 表示成功 */
} HttpRequest;

#endif
