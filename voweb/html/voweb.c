/* VoWeb: simple, light weight, embedded web server.
 *
 * TODO:
 *   put mime in header.
 *   file server.
 *   dynamic load cgi library.
 *
 */

#include <stdlib.h>
#include <memory.h>
#include <stdio.h>

typedef unsigned char uchar;
typedef unsigned int  uint;
#define safe_free(p)  if(p) { free(p); p = NULL; }


/* linear hash, every unit must start with its key. */
#define LINEAR_HASH_NULL         ((uint)(-1))
#define linear_hash_key(h, p)    (*(uint *)((h)->data + (p) * (h)->unit))
#define linear_hash_value(h, p)  ((h)->data + (p) * (h)->unit)
#define linear_hash_empty(h, p)  (linear_hash_key((h), (p)) == LINEAR_HASH_NULL)
#define linear_hash_clear(h, p)  {linear_hash_key((h), (p)) = LINEAR_HASH_NULL;}

typedef struct _linear_hash {
    uint   unit;            // the size for each unit.
    uint   max;             // the max allowed unit.

    uchar  data[1];
}linear_hash;

linear_hash* linear_hash_alloc(uint unit, uint max)
{
    linear_hash *lh =
        (linear_hash *)malloc(max * unit + sizeof(linear_hash));
    if(lh == NULL)
        return NULL;

    lh->unit = unit;
    lh->max = max;

    while(max--)
        linear_hash_clear(lh, max);
    return lh;
}

uchar* linear_hash_get(linear_hash *lh, uint key)
{
    uint pos = key % lh->max, i;
    // match node in the first hit.
    if(linear_hash_key(lh, pos) == key)
        return linear_hash_value(lh, pos);

    // try to hit next node if we miss the first.
    for(i = pos + 1; ; i++) {
        if(i >= lh->max)
            i = 0;
        if(i == pos)
            break;

        if(linear_hash_key(lh, i) == key)
            return linear_hash_value(lh, i);
    }
    return NULL;
}

uchar* linear_hash_set(linear_hash *lh, uint key)
{
    uint pos = key % lh->max, i;
    // first hit, this hash node is empty.
    if(linear_hash_empty(lh, pos))
        return linear_hash_value(lh, pos);

    // try to find another empty node.
    for(i = pos + 1; ; i++) {
        if(i >= lh->max)
            i = 0;
        if(i == pos)
            break;

        if(linear_hash_empty(lh, i))
            return linear_hash_value(lh, i);
    }
    return NULL;
}

void linear_hash_remove(linear_hash *lh, uint key)
{
    uchar* d = linear_hash_get(lh, key);
    if(d == NULL)
        return;
    linear_hash_clear(lh, (d - lh->data) / lh->unit);
}


/* string hash, get data by string, make it faster. */
typedef linear_hash              string_hash;
#define string_hash_p1(h, p)     ((char *)((h->data + p) + sizeof(uchar *)))
#define string_hash_p2(h, p)     (*((uchar **)(h->data + p)))
#define string_hash_empty(h, p)  (*string_hash_p1((h), (p)) == '\0')
#define string_hash_clear(h, p)  {*string_hash_p1((h), (p)) = '\0';}

string_hash* string_hash_alloc(uint unit, uint max)
{
    string_hash *sh =
        (string_hash *)malloc(max * (unit + sizeof(uchar *)) + sizeof(string_hash));
    if(sh == NULL)
        return NULL;
    memset(sh, 0, max * (unit + sizeof(uchar *)) + sizeof(string_hash));

    sh->unit = unit + sizeof(uchar *);
    sh->max = max;
    return sh;
}

uint string_hash_from(char *str)
{
    uint hash = *str;
    while(*str++)
        hash = hash * 31 + *str;
    return hash;
}

uchar* string_hash_get(string_hash *sh, char *key)
{
    uint pos = (string_hash_from(key) % sh->max) * sh->unit, i;
    // match node in the first hit.
    if(strcmp(string_hash_p1(sh, pos), key) == 0)
        return string_hash_p2(sh, pos);

    // try to hit next node if we miss the first.
    for(i = pos + sh->unit;; i += sh->unit) {
        if(i >= sh->unit * sh->max)
            i = 0;
        if(i == pos)
            break;
        if(strcmp(string_hash_p1(sh, i), key) == 0)
            return string_hash_p2(sh, i);
    }
    return NULL;
}

uchar* string_hash_set(string_hash *sh, char *key, uchar *value)
{
    uint pos = (string_hash_from(key) % sh->max) * sh->unit, i;
    // first hit, this hash node is empty.
    if(string_hash_empty(sh, pos)) {
        strcpy(string_hash_p1(sh, pos), key);
        memcpy(&string_hash_p2(sh, pos), &value, sizeof(uchar *));
        return string_hash_p2(sh, pos);
    }

    // try to find another empty node.
    for(i = pos + sh->unit;; i += sh->unit) {
        if(i >= sh->unit * sh->max)
            i = 0;
        if(i == pos)
            break;

        if(string_hash_empty(sh, i)) {
            strcpy(string_hash_p1(sh, i), key);
            memcpy(&string_hash_p2(sh, i), &value, sizeof(uchar *));
            return string_hash_p2(sh, i);
        }
    }
    return NULL;
}

void string_hash_remove(string_hash *sh, char *key)
{
    uint pos = (string_hash_from(key) % sh->max) * sh->unit, i;
    // match node in the first hit.
    if(strcmp(string_hash_p1(sh, pos), key) == 0) {
        string_hash_clear(sh, pos);
        return;
    }

    // try to hit next node if we miss the first.
    for(i = pos + sh->unit;; i += sh->unit) {
        if(i >= sh->unit * sh->max)
            i = 0;
        if(i == pos)
            break;
        if(strcmp(string_hash_p1(sh, i), key) == 0) {
            string_hash_clear(sh, i);
            return;
        }
    }
}


#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/signal.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>

#define RECVBUF_SIZE        4096
#define SENDBUF_SIZE        4096
#define MESSAGE_SIZE        256
#define BUFFER_COUNT        12
#define FUNCTION_SIZE       32
#define FUNCTION_COUNT      256
#define TIMEOUT             3000

#define HTTP_HEADER_END     "\r\n\r\n"
#define HTTP_CONTENT_LENGTH "Content-Length"
#define HTTP_CONNECTION     "Connection"
#define HTTP_GET            "GET"
#define HTTP_POST           "POST"
#define HTTP_CGI_BIN        "/cgi-bin/"

struct _setting {
    unsigned short port;
    char*          base;
} g_set;

typedef struct _socket_data {
    int   sock;

    // this static buffer is used to store http header.
    // if post header + body size < RECVBUF_SIZE, all store here.
    uint   used;        // received header size.
    char   head[RECVBUF_SIZE];

    // if in post mode the receive buffer exceed our head buffer size,
    // we alloc a buffer for the body.
    uint   size;        // max size of the body buffer.
    uint   recv;        // received data size.
    char*  body;        // point to head + used if head buffer is enough.
}socket_data;

typedef struct _string_reference {
    char*   ref;
    uint    size;
}string_reference;

typedef int (*voweb_func)(socket_data *, string_reference *pa);

/* check str->size to make sure buffer is enough for the string */
char* string_reference_dup(string_reference *str, char *buf)
{
    if(str == NULL)
        return "";

    memcpy(buf, str->ref, str->size);
    *(buf + str->size) = '\0';
    return buf;
}

void socketdata_init(socket_data *d)
{
    if(d->body < d->head || d->body >= d->head + RECVBUF_SIZE)
        safe_free(d->body);
    memset(d->head, 0, RECVBUF_SIZE);

    d->recv = 0;
    d->size = 0;
    d->used = 0;
}

void socketdata_remove(linear_hash *socks, int sock)
{
    socket_data *d = (socket_data *)linear_hash_get(socks, sock);
    close(sock);
    // check if the body point to head, if so we do not release it.
    if(d->body < d->head || d->body >= d->head + RECVBUF_SIZE)
        safe_free(d->body);
    linear_hash_remove(socks, sock);
}

uint voweb_content_size(socket_data *d)
{
    char *p;

    p = strstr(d->head, HTTP_CONTENT_LENGTH);
    if(p == NULL)
        return 0;
    p += sizeof(HTTP_CONTENT_LENGTH);

    while((*p < '0' || *p > '9') && *p != '\r' && *p != '\n')
        p++;

    return (uint)atoi(p);
}

uint voweb_connection(socket_data *d)
{
    char *p, *end;
    uint ret;

    p = strstr(d->head, HTTP_CONNECTION);
    if(p == NULL)
        return 0;
    p += sizeof(HTTP_CONNECTION);

    end = strstr(p, "\r\n");
    if(end == NULL)
        return 0;

    *end = '\0';
    ret = strstr(p, "keep-alive") ? 1 : 0;
    *end = '\r';

    return ret;
}

int voweb_reply_head(char *d, int code, const char *msg)
{
    int size = 0;
    size += sprintf(d + size, "HTTP/1.1 %d %s\r\n", code, msg);
    size += sprintf(d + size, "Server: VoCore's Web Server\r\n");
    return size;
}

const char *voweb_code_message(int code)
{
    switch(code) {
    case 200:
        return "OK";
    case 403:
        return "Forbidden";
    case 404:
        return "Not Found";
    case 405:
        return "Access Denied";
    case 413:
        return "Request too large";
    case 501:
        return "Not Implemented";
    default:
        return "Unknown";
    }
}

int voweb_error_page(socket_data *d, int code)
{
    char head[MESSAGE_SIZE], body[MESSAGE_SIZE];
    const char *msg;
    int  size, total = 0;

    msg = voweb_code_message(code);
    size = sprintf(body,
        "<html><head><title>%d %s</title></head><body style=\"font-family: "
        "Arial\"><h1 style=\"color:#0040F0\">%d %s</h1><hr><p>Sorry, I have "
        "tried my best... :'(</p></body></html>", code, msg, code, msg);

    voweb_reply_head(head, code, msg);
    sprintf(head + strlen(head), "%s: %d\r\n", HTTP_CONTENT_LENGTH, size);
    strcat(head, "\r\n");

    size = send(d->sock, head, strlen(head), 0);
    if(size <= 0)
        return -1;
    total += size;
    size = send(d->sock, body, strlen(body), 0);
    if(size <= 0)
        return -1;
    total += size;
    return total;
}

uint voweb_file_size(const char *path)
{
    FILE *fp;
    uint size;

    fp = fopen(path, "rb");
    if(fp == NULL)
        return (uint)(-1);
    fseek(fp, 0, SEEK_END);
    size = (uint)ftell(fp);

    fclose(fp);
    return size;
}

int voweb_default(socket_data *d, string_reference *fn)
{
    char head[MESSAGE_SIZE], body[SENDBUF_SIZE];
    char path[MESSAGE_SIZE];
    int size, total = 0;
    FILE *fp;

    string_reference_dup(fn, head);
    if(strstr(head, ".."))
        return voweb_error_page(d, 403);

    if(strcmp(head, "/") == 0)
        sprintf(path, "%s/index.html", g_set.base);
    else
        sprintf(path, "%s%s", g_set.base, head);

    size = voweb_file_size(path);
    if(size == -1)
        return voweb_error_page(d, 404);

    voweb_reply_head(head, 200, voweb_code_message(200));
    sprintf(head + strlen(head), "%s: %d\r\n", HTTP_CONTENT_LENGTH, size);
    sprintf(head + strlen(head), "%s: %s\r\n", HTTP_CONNECTION, "close");
    strcat(head, "\r\n");

    size = send(d->sock, head, strlen(head), 0);
    if(size <= 0)
        return -1;

    fp = fopen(path, "rb");
    if(fp == NULL)
        return voweb_error_page(d, 405);

    while(!feof(fp)) {
        size = fread(body, 1, SENDBUF_SIZE, fp);
        if(size <= 0)
            break;
        size = send(d->sock, body, size, 0);
        if(size <= 0)
            break;
        total += size;
    }
    fclose(fp);

    return total;
}

int voweb_function(socket_data *d, string_hash *funcs, string_reference *fn, string_reference *pa)
{
    char buf[MESSAGE_SIZE];
    voweb_func func;

    string_reference_dup(fn, buf);
    if(strlen(buf) >= FUNCTION_SIZE)
        return voweb_error_page(d, 403);

    func = (voweb_func)string_hash_get(funcs, buf);
    if(func == NULL)
        return voweb_error_page(d, 404);

    return func(d, pa);
}

// return:
//  0: get header do not have special request.
//  1: get header contains function.
//  2: get header contains function and parameters.
//  < 0: not a valid header.
int voweb_decode_get(socket_data *d, string_reference *fn, string_reference *pa)
{
    char *p, *e, *f1, *f2;
    int ret;

    p = d->head + sizeof(HTTP_GET);
    e = strstr(p, "\r\n");
    if(e == NULL)
        return -1;

    while(*p == ' ' && e != p)
        p++;
    if(e == p)
        return -1;
    while(*e != ' ' && e != p)
        e--;
    if(e == p)
        return -1;

    *e = '\0';

    f1 = strstr(p, HTTP_CGI_BIN);
    if(f1 == NULL) {
        ret = 0;
        fn->ref = p;
        fn->size = e - p;
    } else {
        f1 += sizeof(HTTP_CGI_BIN) - 1;
        f2 = strchr(f1, '?');
        if(f2 == NULL) {
            fn->ref = f1;
            fn->size = e - f1;
            ret = 1;
        } else {
            fn->ref = f1;
            fn->size = f2 - f1;
            ret = 2;
            pa->ref = ++f2;
            pa->size = e - f2;
        }
    }

    *e = ' ';
    return ret;
}

int voweb_decode_post(socket_data *d, string_reference *fn, string_reference *pa)
{
    char *p, *e, *f1;
    int ret;

    p = d->head + sizeof(HTTP_POST);
    e = strstr(p, "\r\n");
    if(e == NULL)
        return -1;

    while(*p == ' ' && e != p)
        p++;
    if(e == p)
        return -1;
    while(*e != ' ' && e != p)
        e--;
    if(e == p)
        return -1;

    *e = '\0';
    f1 = strstr(p, HTTP_CGI_BIN);
    *e = ' ';

    ret = 0;
    if(f1 != NULL) {
        f1 += sizeof(HTTP_CGI_BIN) - 1;

        fn->ref = f1;
        fn->size = e - f1;

        pa->ref = d->body;
        pa->size = d->recv;

        ret = 2;
    }

    return ret;
}

// return:
//  0: "Connection: close", close and remove socket.
//  1: "Connection: keep-alive", wait for next request.
int voweb_filter(string_hash *funcs, socket_data *d)
{
    string_reference fn, pa;
    if(memcmp(d->head, "GET", 3) == 0) {
        switch(voweb_decode_get(d, &fn, &pa)) {
        case 0:
            voweb_default(d, &fn);
            break;
        case 1:
            voweb_function(d, funcs, &fn, NULL);
            break;
        case 2:
            voweb_function(d, funcs, &fn, &pa);
            break;
        default:
            voweb_error_page(d, 404);
            break;
        }
    } else if(memcmp(d->head, "POST", 4) == 0) {
        switch(voweb_decode_post(d, &fn, &pa)) {
        case 2:
            voweb_function(d, funcs, &fn, &pa);
            break;
        default:
            voweb_error_page(d, 404);
            break;
        }
    } else {
        voweb_error_page(d, 501);
    }

    return 0;
}

int voweb_func_gpio0ctrl(socket_data *d, string_reference *pa)
{
    char buf[MESSAGE_SIZE] = "Invalid parameter.";
    FILE *fp;

    fp = fopen("/sys/class/gpio/gpio0/direction", "w");
    if(fp == NULL) {
        sprintf(buf, "update gpio 0 direction failed.");
        return send(d->sock, buf, strlen(buf), 0);
    }
    fwrite("out", 1, 4, fp);
    fclose(fp);

    if(memcmp(pa->ref, "on", 2) == 0) {
        fp = fopen("/sys/class/gpio/gpio0/value", "w");
        if(fp != NULL) {
            fwrite("1", 1, 2, fp);
            fclose(fp);

            sprintf(buf, "update gpio 0 value to 1 success.");
        } else {
            sprintf(buf, "update gpio 0 value to 1 failed.");
        }
    }
    if(memcmp(pa->ref, "off", 3) == 0) {
        fp = fopen("/sys/class/gpio/gpio0/value", "w");
        if(fp != NULL) {
            fwrite("0", 1, 2, fp);
            fclose(fp);

            sprintf(buf, "update gpio 0 value to 0 success.");
        } else {
            sprintf(buf, "update gpio 0 value to 0 failed.");
        }
    }

    return send(d->sock, buf, strlen(buf), 0);
}

int main(int argc, char *argv[])
{
    string_hash* funcs;
    linear_hash* socks;

    int socksrv, sockmax, sock, b = 1;
    uint i, count, size;
    char *p;

    struct sockaddr_in addr;
    socklen_t len;
    struct timeval tmv;
    fd_set fdr;
    socket_data *d;

    switch(argc) {
    case 1:
        g_set.port = 8080;
        g_set.base = "/var/www/html";
        break;

    case 2:
        g_set.port = atoi(argv[1]);
        g_set.base = "/var/www/html";
        break;

    case 3:
        g_set.port = atoi(argv[1]);
        g_set.base = argv[2];
        break;

    default:
        printf("usage: voweb [port] [home]\n");
        return -1;
    }

    // ignore the signal, or it will stop our server once client disconnected.
    signal(SIGPIPE, SIG_IGN);

    funcs = string_hash_alloc(FUNCTION_SIZE, FUNCTION_COUNT);
    socks = linear_hash_alloc(sizeof(socket_data), BUFFER_COUNT);

    string_hash_set(funcs, "gpio0ctrl", (uchar *)voweb_func_gpio0ctrl);

    memset(&addr, 0, sizeof(struct sockaddr_in));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(g_set.port);
    len = sizeof(struct sockaddr_in);

    socksrv = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    setsockopt(socksrv, SOL_SOCKET, SO_REUSEADDR, (const char *)&b, sizeof(int));
    if(bind(socksrv, (struct sockaddr*)&addr, sizeof(struct sockaddr)) < 0) {
        printf("can not bind to address, %d:%s.\n", errno, strerror(errno));
        return -1;
    }

    if(listen(socksrv, SOMAXCONN) < 0) {
        printf("can not listen to port, %d:%s.\n", errno, strerror(errno));
        return -1;
    }

    // for simple embed server, my choice is select for better compatible.
    // but for heavy load situation in linux, better to change this to epoll.
    while(1) {
        FD_ZERO(&fdr);
        FD_SET(socksrv, &fdr);

        // queue the hash and pickout the max socket.
        sockmax = socksrv;
        for(i = 0; i < socks->max; i++) {
            d = (socket_data *)linear_hash_value(socks, i);
            sockmax = (d->sock > sockmax ? d->sock : sockmax);
            if(d->sock != (int)LINEAR_HASH_NULL)
                FD_SET(d->sock, &fdr);
        }

        tmv.tv_sec = TIMEOUT / 1000;
        tmv.tv_usec = TIMEOUT % 1000 * 1000;

        count = select(sockmax + 1, &fdr, NULL, NULL, &tmv);
        if(count <= 0) {
            // clean up all sockets, they are time out.
            for(i = 0; i < socks->max; i++) {
                d = (socket_data *)linear_hash_value(socks, i);
                if(d->sock == (int)LINEAR_HASH_NULL)
                    continue;
                linear_hash_remove(socks, (uint)d->sock);
                close(d->sock);
            }
            continue;
        }

        if(FD_ISSET(socksrv, &fdr)) {
            count--;
            memset(&addr, 0, sizeof(struct sockaddr_in));

            sock = accept(socksrv, (struct sockaddr*)&addr, &len);
            d = (socket_data *)linear_hash_set(socks, (uint)sock);
            if(d == NULL) {
                close(sock);     // no free buffer.
                continue;
            }
            memset(d, 0, sizeof(socket_data));
            d->sock = sock;
        }

        for(i = 0; i < socks->max; i++) {
            if(count <= 0)
                break;

            d = (socket_data *)linear_hash_value(socks, i);
            if((uint)d->sock == LINEAR_HASH_NULL)
                continue;

            if(FD_ISSET(d->sock, &fdr)) {
                count--;

                if(d->size == 0) {

                    // receive http head data.
                    size = recv(d->sock, d->head + d->used, RECVBUF_SIZE - d->used, 0);
                    if(size <= 0) {
                        socketdata_remove(socks, d->sock);
                        continue;
                    }
                    d->used += size;

                    p = strstr(d->head, HTTP_HEADER_END);
                    if(p == NULL) {
                        if(d->used >= RECVBUF_SIZE) {
                            voweb_error_page(d, 413);
                            socketdata_remove(socks, d->sock);
                        }
                        continue;
                    }

                    p += sizeof(HTTP_HEADER_END) - 1;

                    // now check the content size.
                    d->recv = p - d->head;
                    d->size = voweb_content_size(d);
                    if(d->size == 0) {// no content.
                        if(!voweb_filter(funcs, d))
                            socketdata_remove(socks, d->sock);
                        continue;
                    }
                    // the head buffer can not contain the body data
                    // we have to alloc memory for it.
                    if(d->size > RECVBUF_SIZE - d->used + d->recv) {
                        d->body = malloc(d->size);
                        memset(d->body, 0, d->size);
                        memcpy(d->body, d->head, d->recv);

                        // now we should goto body data receive process.
                    }

                } else {

                    // receive http body data.
                    size = recv(d->sock, d->body + d->recv, d->size - d->recv, 0);
                    if(size <= 0) {
                        socketdata_remove(socks, d->sock);
                        continue;
                    }
                    d->recv += size;
                    if(d->recv >= d->size) {
                        if(!voweb_filter(funcs, d))
                            socketdata_remove(socks, d->sock);
                        continue;
                    }
                }
            }
        }

        // do some clean up for next loop.
    }

    close(socksrv);
    safe_free(funcs);
    safe_free(socks);
    return 0;
}

