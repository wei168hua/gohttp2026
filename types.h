#ifndef GOHTTPDLL_TYPES_H
#define GOHTTPDLL_TYPES_H

typedef struct { char* key; char* value; } KV;
typedef struct { KV* items; int count; } KVList;

typedef struct {
    char*  method;
    char*  url;
    char*  body;
    KVList request_headers;
    KVList request_cookies;

    int    status_code;
    char*  response_body;
    KVList response_headers;
    KVList response_cookies;

    char*  proxy;
    int    timeout_sec;
} HttpRequest;

#endif
