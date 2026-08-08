#include "xboxtls/xboxtls.h"

#if defined(_XBOX)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

using namespace xboxtls;

static bool load_file(const char* path, xt_u8** data, size_t* size) {
    if (!path || !data || !size)
        return false;
    *data = 0;
    *size = 0;
    FILE* f = fopen(path, "rb");
    if (!f)
        return false;
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return false;
    }
    long n = ftell(f);
    if (n <= 0 || fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return false;
    }
    xt_u8* p = (xt_u8*)malloc((size_t)n);
    if (!p) {
        fclose(f);
        return false;
    }
    if (fread(p, 1, (size_t)n, f) != (size_t)n) {
        free(p);
        fclose(f);
        return false;
    }
    fclose(f);
    *data = p;
    *size = (size_t)n;
    return true;
}

int main() {
    const char* host = "example.com";
    xt_u8* roots = 0;
    size_t roots_size = 0;
    if (!load_file("game:\\roots.xts", &roots, &roots_size)) {
        printf("XboxTLS: could not load game:\\roots.xts\n");
        return 1;
    }

    Error e = xbox360_network_startup();
    if (e != XT_OK) {
        printf("XboxTLS: network startup failed: %d\n", (int)e);
        free(roots);
        return 1;
    }

    Xbox360Platform platform;
    NativeServerAuthVerifier verifier(&platform);
    size_t anchors = 0;
    e = verifier.load_trust_store(ByteSpan(roots, roots_size), &anchors);
    if (e != XT_OK || anchors == 0) {
        printf("XboxTLS: trust store failed: %d\n", (int)e);
        xbox360_network_cleanup();
        free(roots);
        return 1;
    }

    Xbox360SocketStream socket;
    e = socket.connect_tcp(host, 443);
    if (e != XT_OK) {
        printf("XboxTLS: TCP connect failed: %d\n", (int)e);
        xbox360_network_cleanup();
        free(roots);
        return 1;
    }

    ClientConfig cfg;
    cfg.platform = &platform;
    cfg.stream = &socket;
    cfg.verifier = &verifier;
    cfg.hostname = host;
    cfg.alpn = "http/1.1";
    TlsClient tls;
    e = tls.connect(cfg);
    if (e != XT_OK) {
        printf("XboxTLS: TLS handshake failed: %d alert=%u/%u\n", (int)e,
               (unsigned)tls.last_alert_level(), (unsigned)tls.last_alert_description());
        xbox360_network_cleanup();
        free(roots);
        return 1;
    }

    const char req[] = "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: "
                       "XboxTLS13/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n";
    e = tls.send(ByteSpan((const xt_u8*)req, sizeof(req) - 1));
    if (e != XT_OK)
        printf("XboxTLS: send failed: %d\n", (int)e);
    else {
        xt_u8 buf[1024];
        for (;;) {
            size_t got = 0;
            e = tls.recv(MutableByteSpan(buf, sizeof(buf)), &got);
            if (e == XT_ERR_CLOSED)
                break;
            if (e != XT_OK) {
                printf("XboxTLS: recv failed: %d\n", (int)e);
                break;
            }
            if (got)
                fwrite(buf, 1, got, stdout);
        }
    }

    tls.close();
    xbox360_network_cleanup();
    free(roots);
    return e == XT_OK || e == XT_ERR_CLOSED ? 0 : 1;
}
#else
int main() {
    return 0;
}
#endif
